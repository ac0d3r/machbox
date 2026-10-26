package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/plugin"

	"github.com/sirupsen/logrus"
)

// Layout of the read-only share. The workdir mirrors inputs/ so tools get
// writable copies at the same relative paths.
const (
	sharePlugin = "plugin"
	shareInputs = "inputs"
)

// A sample controls the guest once it runs, including the agent: nothing
// the guest sends is trusted to be small or to arrive in time.
const (
	// MaxOutputSize caps a step output copied back from the guest.
	MaxOutputSize = 512 << 20

	inputCopyTimeout = 30 * time.Minute
	mkdirTimeout     = time.Minute
	pullTimeout      = 10 * time.Minute
	maxErrorLen      = 4 << 10
)

var (
	// maxLogSize caps a step log; output beyond it is dropped.
	maxLogSize int64 = 64 << 20
	// hostGrace is how long past a task's timeout the host waits for the
	// guest agent to end it before giving up itself.
	hostGrace = 30 * time.Second
)

// Guest is the part of the guest agent a job uses; *agent.Client
// implements it.
type Guest interface {
	RunTask(ctx context.Context, task *agent.Task) (string, error)
	CopyTask(ctx context.Context, task *agent.Task, stdout io.Writer) error
	OpenFile(ctx context.Context, root, name string) (io.ReadCloser, error)
}

// share lays out the plugin directory and file inputs for the guest;
// shareCopy puts a host path into the share at a relative name.
func (j *Job) share(shareCopy func(hostPath, name string) error) error {
	if err := shareCopy(j.plugin.Dir, sharePlugin); err != nil {
		return err
	}
	for _, in := range j.workflow.Inputs {
		if hostPath := j.Inputs[in.Name]; in.Type == plugin.InputFile && hostPath != "" {
			if err := shareCopy(hostPath, inputPath(in.Name, hostPath)); err != nil {
				return fmt.Errorf("input %s: %w", in.Name, err)
			}
		}
	}
	return nil
}

// inputPath keeps the original file name (tools may care about it) under a
// per-input directory, so two inputs with the same name do not collide.
func inputPath(name, hostPath string) string {
	return path.Join(shareInputs, name, filepath.Base(hostPath))
}

// execute runs the workflow's steps in the guest workdir. echo, if not
// nil, also receives every step's stdout.
func (j *Job) execute(ctx context.Context, g Guest, wd agent.WorkDir, echo io.Writer) error {
	vars := plugin.Vars{
		Inputs:    map[string]string{},
		Outputs:   map[string]string{},
		PluginDir: path.Join(wd.SharePath, sharePlugin),
	}
	for _, in := range j.workflow.Inputs {
		val := j.Inputs[in.Name]
		if in.Type == plugin.InputFile && val != "" {
			val = inputPath(in.Name, val)
		}
		vars.Inputs[in.Name] = val
	}
	// Validation only lets steps reference earlier ones. The path is passed
	// even if that step was skipped or failed; tools check it exists.
	for _, st := range j.workflow.Steps {
		if st.Output != "" {
			vars.Outputs[st.ID] = st.Output
		}
	}
	if err := j.prepare(ctx, g, wd); err != nil {
		return err
	}

	var firstErr error
	for i, st := range j.workflow.Steps {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rec := j.Steps[i]
		if !st.When.Runs(firstErr != nil) {
			rec.Status = StatusSkipped
			j.trySave()
			logrus.Infof("step %s: skipped", st.ID)
			continue
		}
		err := j.runStep(ctx, g, wd, st, rec, vars, echo)
		if err != nil && !st.ContinueOnError && firstErr == nil {
			firstErr = fmt.Errorf("step %s: %w", st.ID, err)
		}
	}
	return firstErr
}

// prepare copies file inputs from the share into the workdir, writable,
// and creates the directories outputs are written to.
func (j *Job) prepare(ctx context.Context, g Guest, wd agent.WorkDir) error {
	for _, in := range j.workflow.Inputs {
		if in.Type == plugin.InputFile && j.Inputs[in.Name] != "" {
			if err := runTask(ctx, g, &agent.Task{
				Command: "/bin/sh",
				Args:    []string{"-c", `/bin/cp -R "$0" . && /bin/chmod -R u+w ` + shareInputs, path.Join(wd.SharePath, shareInputs)},
				WorkDir: wd.WorkPath,
				Timeout: int(inputCopyTimeout / time.Second),
			}); err != nil {
				return fmt.Errorf("copy inputs into the workdir: %w", err)
			}
			break
		}
	}

	var dirs []string
	for _, st := range j.workflow.Steps {
		if d := path.Dir(st.Output); st.Output != "" && d != "." {
			dirs = append(dirs, d)
		}
	}
	if len(dirs) > 0 {
		if err := runTask(ctx, g, &agent.Task{
			Command: "/bin/mkdir",
			Args:    append([]string{"-p", "--"}, dirs...),
			WorkDir: wd.WorkPath,
			Timeout: int(mkdirTimeout / time.Second),
		}); err != nil {
			return fmt.Errorf("create output directories: %w", err)
		}
	}
	return nil
}

func (j *Job) runStep(ctx context.Context, g Guest, wd agent.WorkDir, st *plugin.Step,
	rec *StepRecord, vars plugin.Vars, echo io.Writer) (err error) {
	start := time.Now()
	rec.StartedAt = &start
	rec.Status = StatusRunning
	defer func() {
		end := time.Now()
		rec.FinishedAt = &end
		switch {
		case err == nil:
			rec.Status = StatusSucceeded
			logrus.Infof("step %s: succeeded (%s)", st.ID, end.Sub(start).Round(time.Second))
		case errors.Is(err, agent.ErrTaskTimedOut):
			rec.Status = StatusTimedOut
		default:
			rec.Status = StatusFailed
		}
		if err != nil {
			// Error text can carry guest output (stderr).
			rec.Error = sanitize(err.Error())
			err = errors.New(rec.Error)
			logrus.Errorf("step %s: %s: %s", st.ID, rec.Status, rec.Error)
		}
		j.trySave()
	}()

	args, err := st.Args(vars)
	if err != nil {
		return err
	}
	env, err := st.Environ(j.workflow.Env, vars)
	if err != nil {
		return err
	}
	cmd := args[0]
	if !path.IsAbs(cmd) && strings.Contains(cmd, "/") {
		cmd = path.Join(vars.PluginDir, cmd)
	}

	rec.Log = path.Join(logsDir, st.ID+".log")
	// #nosec G304 -- inside the job directory; step ids are validated identifiers.
	logf, err := os.Create(filepath.Join(j.Dir, filepath.FromSlash(rec.Log)))
	if err != nil {
		return fmt.Errorf("create step log: %w", err)
	}
	defer logf.Close()
	var stdout io.Writer = logf
	if echo != nil {
		stdout = io.MultiWriter(logf, echo)
	}
	capped := &capWriter{w: stdout, n: maxLogSize}
	j.trySave()

	logrus.Infof("step %s: %s", st.ID, strings.Join(args, " "))
	timeout := (st.TimeoutOrDefault() + time.Second - 1) / time.Second * time.Second
	taskCtx, cancel := context.WithTimeout(ctx, timeout+hostGrace)
	err = g.CopyTask(taskCtx, &agent.Task{
		Command:        cmd,
		Args:           args[1:],
		WorkDir:        wd.WorkPath,
		Timeout:        int(timeout / time.Second),
		Env:            env,
		CombinedOutput: true,
	}, capped)
	if err != nil && ctx.Err() == nil && errors.Is(taskCtx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("%w: the guest did not end the task within %s", agent.ErrTaskTimedOut, timeout+hostGrace)
	}
	cancel()
	if capped.dropped > 0 {
		fmt.Fprintf(logf, "\n[machbox: log truncated at %d bytes, %d bytes dropped]\n", maxLogSize, capped.dropped)
		logrus.Warnf("step %s: log truncated at %d bytes", st.ID, maxLogSize)
	}

	// A failed step may still have written (part of) its output; it is
	// collected so later steps and the user can look at it.
	if st.Output != "" && ctx.Err() == nil {
		out, pullErr := j.pullOutput(ctx, g, wd, st.Output)
		switch {
		case pullErr == nil:
			rec.Output = out
		case err == nil:
			err = pullErr
		case !errors.Is(pullErr, agent.ErrNotFound):
			logrus.Warnf("step %s: %v", st.ID, pullErr)
		}
	}
	return err
}

// pullOutput copies the guest file name (relative to the workdir) to the
// job's outputs directory and returns its path relative to the job dir.
func (j *Job) pullOutput(ctx context.Context, g Guest, wd agent.WorkDir, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, pullTimeout)
	defer cancel()
	rc, err := g.OpenFile(ctx, wd.WorkPath, name)
	if err != nil {
		return "", fmt.Errorf("collect output: %w", err)
	}
	defer rc.Close()

	rel := path.Join(outputsDir, name)
	dst := filepath.Join(j.Dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".pull-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after rename

	n, err := io.Copy(tmp, io.LimitReader(rc, MaxOutputSize+1))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return "", fmt.Errorf("collect output %s: %w", name, err)
	case n > MaxOutputSize:
		return "", fmt.Errorf("output %s is larger than %d bytes", name, int64(MaxOutputSize))
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}
	return rel, nil
}

// runTask runs a short preparation task, also enforcing its timeout on
// the host.
func runTask(ctx context.Context, g Guest, task *agent.Task) error {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.Timeout)*time.Second+hostGrace)
	defer cancel()
	_, err := g.RunTask(ctx, task)
	return err
}

// capWriter passes the first n bytes to w and drops the rest, so a task
// flooding its output keeps running but cannot fill the host disk.
type capWriter struct {
	w       io.Writer
	n       int64
	dropped int64
}

func (c *capWriter) Write(p []byte) (int, error) {
	keep := p
	if int64(len(keep)) > c.n {
		keep = keep[:max(c.n, 0)]
	}
	k, err := c.w.Write(keep)
	c.n -= int64(k)
	if err != nil {
		return k, err
	}
	c.dropped += int64(len(p) - len(keep))
	return len(p), nil
}

// sanitize makes guest-controlled text safe to store and print: control
// characters (terminal escapes) are replaced and the length is capped.
func sanitize(s string) string {
	if len(s) > maxErrorLen {
		s = s[:maxErrorLen] + "… (truncated)"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || r >= 0x80 && r < 0xa0 {
			return '?'
		}
		return r
	}, strings.ToValidUTF8(s, "?"))
}

func (j *Job) trySave() {
	if err := j.save(); err != nil {
		logrus.Warnf("%v", err)
	}
}
