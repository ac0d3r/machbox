package analyze

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/report"
	"github.com/ac0d3r/machbox/internal/version"
	baselines "github.com/ac0d3r/machbox/internal/vm"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	vz "github.com/Code-Hex/vz/v3"
	"github.com/sirupsen/logrus"
)

// How long to wait for the guest agent after the VM starts.
const agentWaitTimeout = 15 * time.Minute

// Options configures a sandbox analysis run against an imported baseline.
type Options struct {
	// VM is an optional baseline UUID or unique name. Empty means use the
	// only imported baseline; if several exist, VM is required.
	VM string

	SamplePath     string
	SampleArgs     []string
	SamplePassword string
	Timeout        int // seconds for guest tasks; default 60

	DisplayWidth  int64
	DisplayHeight int64
	Headless      bool
	Network       config.Network
}

// Run prepares the share/snapshot, boots the VM, runs static then dynamic
// analysis, and saves the report. Must be called from the process main
// goroutine when Headless is false (ShowGraphic / AppKit).
func Run(ctx context.Context, opts Options) error {
	if opts.Timeout <= 0 {
		opts.Timeout = 60
	}

	samplePath, sampleName, err := resolveSample(opts.SamplePath)
	if err != nil {
		return err
	}

	if err := db.InitDB(); err != nil {
		return err
	}
	defer func() { _ = db.CloseDB() }()

	baseline, err := pickBaseline(opts.VM)
	if err != nil {
		return err
	}
	vbvmPath := assets.VMPath(baseline.UUID)
	logrus.Infof("using baseline %s (%s)", baseline.Name, baseline.UUID)

	shared, err := assets.NewShareDir(sampleName,
		samplePath, "statictool", "dynamictool", "DTrace/network.d")
	if err != nil {
		return fmt.Errorf("prepare shared directory: %w", err)
	}
	logrus.Infof("creating shared directory at %s", shared.Path())
	defer func() {
		logrus.Info("cleaning up shared directory")
		if err := shared.Clean(); err != nil {
			logrus.Warnf("failed to remove shared directory: %v", err)
		}
	}()

	vbvmcfg, err := config.DecodeVBVMPath(vbvmPath)
	if err != nil {
		return fmt.Errorf("decode baseline %s: %w", baseline.UUID, err)
	}

	if err = vbvmcfg.CreateSnapshot(); err != nil {
		return fmt.Errorf("create VM snapshot: %w", err)
	}
	logrus.Infof("creating VM snapshot at %s", vbvmcfg.SnapshotPath)
	defer func() {
		logrus.Info("cleaning up VM snapshot")
		if err := vbvmcfg.RemoveSnapshot(); err != nil {
			logrus.Warnf("failed to remove snapshot: %v", err)
		}
	}()

	vmcfg, err := config.NewMacVMConf(vbvmcfg, &config.VMOptions{
		DisplayWidth:  opts.DisplayWidth,
		DisplayHeight: opts.DisplayHeight,
		Shares:        []config.ShareDir{{Dir: shared.Path(), Tag: "machbox", ReadOnly: true}},
		Network:       opts.Network,
	})
	if err != nil {
		return fmt.Errorf("create VM config: %w", err)
	}

	sess := &session{
		sampleName: sampleName,
		sampleArgs: opts.SampleArgs,
		password:   opts.SamplePassword,
		timeout:    opts.Timeout,
	}
	return runVM(ctx, opts, vmcfg, sess.run)
}

func pickBaseline(identifier string) (*db.VM, error) {
	if identifier != "" {
		return baselines.Resolve(identifier)
	}

	vms, err := baselines.List()
	if err != nil {
		return nil, err
	}
	switch len(vms) {
	case 0:
		return nil, fmt.Errorf("no imported baselines; run: machbox vm import <path.vbvm> <name>")
	case 1:
		return &vms[0], nil
	default:
		return nil, fmt.Errorf("multiple baselines; specify --vm <uuid-or-name> (see: machbox vm list)")
	}
}

type session struct {
	sampleName string
	sampleArgs []string
	password   string
	timeout    int

	workpath  string
	sharepath string
}

func (s *session) vmSamplePath() string {
	return filepath.Join(s.sharepath, s.sampleName)
}

func resolveSample(path string) (abs, name string, err error) {
	if path == "" {
		return "", "", fmt.Errorf("sample path is required")
	}
	if !filepath.IsAbs(path) {
		path, err = filepath.Abs(path)
		if err != nil {
			return "", "", err
		}
	}
	abs = filepath.Clean(string(os.PathSeparator) + path)
	return abs, filepath.Base(abs), nil
}

// runVM starts the VM, optionally shows the GUI on the calling (main) thread,
// and waits for the analysis session to finish (or a signal).
func runVM(ctx context.Context, opts Options, vmcfg *vz.VirtualMachineConfiguration,
	run func(context.Context, *boxvm.VMInstance) error) error {

	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vmi, err := boxvm.New(ctx, vmcfg)
	if err != nil {
		return fmt.Errorf("create VM instance: %w", err)
	}
	if err := vmi.Start(); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}
	logrus.Info("VM started successfully")

	errCh := make(chan error, 1)
	go func() {
		err := run(ctx, vmi)
		errCh <- err
		// Analysis finished: stop the VM. With a GUI, StartGraphicApplication
		// may still block until the window is closed — nudge the user.
		cancel()
		_ = vmi.Shutdown()
		if !opts.Headless {
			logrus.Info("analysis finished — close the VM window to exit")
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		select {
		case <-sigCh:
			logrus.Info("interrupt received, stopping analysis")
			cancel()
			_ = vmi.Shutdown()
		case <-ctx.Done():
		}
	}()

	var graphicErr error
	if !opts.Headless {
		logrus.Infof("showing GUI window (%dx%d)", opts.DisplayWidth, opts.DisplayHeight)
		graphicErr = vmi.ShowGraphic(opts.DisplayWidth, opts.DisplayHeight)
		cancel()
		_ = vmi.Shutdown()
	}

	runErr := <-errCh
	_ = vmi.Shutdown()
	waitVMStop(vmi)

	logrus.Info("VM fully stopped")
	if graphicErr != nil && (runErr == nil || errors.Is(runErr, context.Canceled)) {
		return fmt.Errorf("show graphic: %w", graphicErr)
	}
	return runErr
}

func waitVMStop(vmi *boxvm.VMInstance) {
	select {
	case <-vmi.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for analysis VM to stop")
	}
}

func (s *session) run(ctx context.Context, vmi *boxvm.VMInstance) (err error) {
	defer func() {
		logrus.Info("analysis session ending, shutting down VM")
		_ = vmi.Shutdown()
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(2 * time.Second):
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, agentWaitTimeout)
	defer waitCancel()

	dial := func(ctx context.Context) (net.Conn, error) {
		return vmi.ConnectVsock(ctx, agent.DefaultVsockPort)
	}

	client, info, err := agent.WaitReady(waitCtx, dial, time.Second)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("timed out after %s waiting for guest agent %q",
				agentWaitTimeout, version.Version)
		}
		return fmt.Errorf("wait for guest agent: %w", err)
	}
	defer client.Close()

	if info.AgentVersion != version.Version {
		return fmt.Errorf("guest agent version %q != expected %q; re-import the baseline",
			info.AgentVersion, version.Version)
	}

	s.workpath, s.sharepath, err = client.SetWorkdir(ctx)
	if err != nil {
		return err
	}
	logrus.Infof("set WorkDir: %s, ShareDir: %s", s.workpath, s.sharepath)

	retp := report.New(info)

	if err := s.runStatic(ctx, client, retp); err != nil {
		return fmt.Errorf("static analysis: %w", err)
	}

	dynErr := s.runDynamic(ctx, client, retp)
	if dynErr != nil {
		logrus.Errorf("dynamic analysis: %v", dynErr)
	}

	if err := retp.Save(); err != nil {
		if dynErr != nil {
			return fmt.Errorf("dynamic analysis: %v; save report: %w", dynErr, err)
		}
		return fmt.Errorf("save report: %w", err)
	}
	if dynErr != nil {
		return fmt.Errorf("dynamic analysis: %w", dynErr)
	}
	return nil
}

func (s *session) runStatic(ctx context.Context, client *agent.Client, retp *report.Parser) error {
	logrus.Infoln("run static analysis task")

	args := []string{}
	if s.password != "" {
		args = append(args, "--password", s.password)
	}
	args = append(args, s.vmSamplePath())

	output, err := client.RunTask(ctx, &agent.Task{
		Command: filepath.Join(s.sharepath, "statictool"),
		Args:    args,
		WorkDir: s.workpath,
		Timeout: s.timeout,
	})
	if err != nil {
		return err
	}
	return retp.StaticResult(output, s.vmSamplePath(), s.workpath)
}

func (s *session) runDynamic(ctx context.Context, client *agent.Client, retp *report.Parser) error {
	logrus.Infoln("run dynamic analysis task")

	samplePath, pickTyp := retp.GetPickFile()
	if samplePath == "" {
		logrus.Warnf("no executable found, skipping dynamic analysis")
		return nil
	}
	if samplePath != s.vmSamplePath() {
		logrus.Infof("main sample for dynamic analysis: %s (%s)", samplePath, pickTyp)
	}

	runPath := samplePath
	// Share is mounted read-only; copy onto the writable workdir before chmod/exec.
	if s.sharepath != "" && (samplePath == s.sharepath || strings.HasPrefix(samplePath, s.sharepath+string(os.PathSeparator))) {
		dst := filepath.Join(s.workpath, filepath.Base(samplePath))
		if _, err := client.RunTask(ctx, &agent.Task{
			Command: "cp",
			Args:    []string{"-R", samplePath, dst},
			WorkDir: s.workpath,
			Timeout: s.timeout,
		}); err != nil {
			return fmt.Errorf("copy sample to workdir: %w", err)
		}
		runPath = dst
		retp.SetPickFile(runPath)
	}

	switch pickTyp {
	case "mach-o", "appbundle":
		if _, err := client.RunTask(ctx, &agent.Task{
			Command: "chmod",
			Args:    []string{"-R", "+x", runPath},
			WorkDir: s.workpath,
			Timeout: s.timeout,
		}); err != nil {
			return fmt.Errorf("chmod +x: %w", err)
		}
	}

	dynamicArgs := []string{"run", "-ds",
		filepath.Join(s.sharepath, "DTrace", "network.d"), "-o", "-", runPath}
	dynamicArgs = append(dynamicArgs, s.sampleArgs...)

	reader, err := client.RunStreamTask(ctx, &agent.Task{
		Command: filepath.Join(s.sharepath, "dynamictool"),
		Args:    dynamicArgs,
		WorkDir: s.workpath,
		Timeout: s.timeout,
	})
	if err != nil {
		return err
	}
	defer reader.Close()
	return retp.ParseDynamicResult(reader)
}
