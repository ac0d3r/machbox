// Package job runs plugin workflows. A job executes one workflow in a fresh
// disposable run; its host directory (~/.machbox/jobs/<id>/) keeps only the
// record, step logs and the outputs copied back from the guest:
//
//	job.json          inputs, guest, status of every step
//	logs/<step>.log   step stdout (stderr is in the step error)
//	outputs/<path>    each step's declared output
//	network.pcap      guest traffic, with --network Internet
package job

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"

	"github.com/sirupsen/logrus"
)

const (
	recordName = "job.json"
	logsDir    = "logs"
	outputsDir = "outputs"
	// captureName sits outside outputsDir, so no step output collides.
	captureName = "network.pcap"
)

// Status is the state of a job or step.
type Status string

const (
	StatusPending   Status = "pending"
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusTimedOut  Status = "timed_out"
	StatusSkipped   Status = "skipped"
)

// Record is persisted as job.json and rewritten on every state change.
type Record struct {
	ID            string `json:"id"`
	Plugin        string `json:"plugin"`
	PluginVersion string `json:"plugin_version,omitempty"`
	Workflow      string `json:"workflow"`
	// Inputs as given; file inputs are absolute host paths.
	Inputs   map[string]string `json:"inputs"`
	Baseline BaselineRecord    `json:"baseline"`
	Guest    *agent.GuestInfo  `json:"guest,omitempty"`

	Status     Status        `json:"status"`
	Error      string        `json:"error,omitempty"`
	StartedAt  time.Time     `json:"started_at"`
	FinishedAt *time.Time    `json:"finished_at,omitempty"`
	Steps      []*StepRecord `json:"steps"`
}

// BaselineRecord identifies the baseline a job booted.
type BaselineRecord struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// StepRecord is the state of one step. Paths are relative to the job dir.
type StepRecord struct {
	ID         string     `json:"id"`
	Status     Status     `json:"status"`
	Error      string     `json:"error,omitempty"`
	Log        string     `json:"log,omitempty"`
	Output     string     `json:"output,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Job is one execution of a workflow.
type Job struct {
	// Dir is the job directory on the host.
	Dir string
	Record

	plugin   *plugin.Plugin
	workflow *plugin.Workflow
}

// New validates inputs (as returned by Workflow.ParseArgs) and creates the
// job directory under assets.JobsDir.
func New(p *plugin.Plugin, wf *plugin.Workflow, inputs map[string]string, baseline *db.VM) (*Job, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return create(filepath.Join(assets.JobsDir(), id), p, wf, inputs, baseline)
}

func create(dir string, p *plugin.Plugin, wf *plugin.Workflow, inputs map[string]string, baseline *db.VM) (*Job, error) {
	resolved := make(map[string]string, len(inputs))
	for _, in := range wf.Inputs {
		val := inputs[in.Name]
		if in.Type == plugin.InputFile && val != "" {
			abs, err := filepath.Abs(val)
			if err != nil {
				return nil, err
			}
			if _, err := os.Stat(abs); err != nil {
				return nil, fmt.Errorf("input %s: %w", in.Name, err)
			}
			val = abs
		}
		resolved[in.Name] = val
	}

	j := &Job{
		Dir: dir,
		Record: Record{
			ID:            filepath.Base(dir),
			Plugin:        p.Name,
			PluginVersion: p.Version,
			Workflow:      wf.Name,
			Inputs:        resolved,
			Baseline:      BaselineRecord{UUID: baseline.UUID, Name: baseline.Name},
			Status:        StatusRunning,
			StartedAt:     time.Now(),
		},
		plugin:   p,
		workflow: wf,
	}
	for _, st := range wf.Steps {
		j.Steps = append(j.Steps, &StepRecord{ID: st.ID, Status: StatusPending})
	}

	for _, d := range []string{dir, filepath.Join(dir, logsDir), filepath.Join(dir, outputsDir)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("create job directory: %w", err)
		}
	}
	if err := j.save(); err != nil {
		return nil, err
	}
	return j, nil
}

// finish records how the job ended; steps that never started are skipped.
func (j *Job) finish(err error) {
	now := time.Now()
	j.FinishedAt = &now
	j.Status = StatusSucceeded
	if err != nil {
		j.Status = StatusFailed
		j.Error = sanitize(err.Error())
	}
	for _, s := range j.Steps {
		if s.Status == StatusPending {
			s.Status = StatusSkipped
		}
	}
	if err := j.save(); err != nil {
		logrus.Warnf("save job record: %v", err)
	}
}

func (j *Job) save() error {
	data, err := json.MarshalIndent(&j.Record, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(j.Dir, "."+recordName+"-*")
	if err != nil {
		return fmt.Errorf("save job record: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after rename
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save job record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("save job record: %w", err)
	}
	if err := os.Rename(tmp.Name(), filepath.Join(j.Dir, recordName)); err != nil {
		return fmt.Errorf("save job record: %w", err)
	}
	return nil
}

func newID() (string, error) {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate job id: %w", err)
	}
	return time.Now().Format("20060102-150405") + "-" + hex.EncodeToString(b[:]), nil
}
