package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/sirupsen/logrus"
)

const bootTimeout = 15 * time.Minute

// setupTimeout covers the user working through Machbox Setup and whatever
// else they set up: Command Line Tools alone can take most of an hour on a
// slow link.
const setupTimeout = 2 * time.Hour

// checkInterval is how often setup runs `machbox-guest check`.
const checkInterval = 3 * time.Second

const setupHint = "run Machbox Setup from the MachboxGuest volume in the VM window"

type setupPurpose int

const (
	purposeImport setupPurpose = iota
	purposeReconfigure
)

// setupResult is what a finished setup records about the baseline.
type setupResult struct {
	Info     agent.GuestInfo
	Features []string
}

// setup boots the VBVM with the guest DMG attached and a GUI, and checks the
// guest until the window is closed. The baseline is ready once a matching
// agent runs with automatic login; it records the features of the last check
// that was ready, so what the user sets up after that counts too. SIP may be
// in either state; plugins that need it disabled say so in their requirements.
// The caller holds the baseline's exclusive lock until it has saved the result.
func setup(ctx context.Context, dir string, purpose setupPurpose) (*setupResult, error) {
	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := loadBundle(dir)
	if err != nil {
		return nil, fmt.Errorf("load baseline bundle: %w", err)
	}

	guestDMG, err := assets.GuestDMG()
	if err != nil {
		return nil, err
	}

	vmcfg, err := config.NewMacVMConf(bundle, &config.VMOptions{
		DisplayWidth:  config.DefaultDisplayWidth,
		DisplayHeight: config.DefaultDisplayHeight,
		Disks:         []config.StorageDisk{{Path: guestDMG, ReadOnly: true}},
		Network:       config.Network{Enable: true, Mode: config.NetworkNAT},
	})
	if err != nil {
		return nil, fmt.Errorf("create vm configuration: %w", err)
	}

	inst, err := boxvm.New(vmcfg)
	if err != nil {
		return nil, fmt.Errorf("create vm instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("start vm: %w", err)
	}
	logrus.Info("VM started successfully")

	type outcome struct {
		info *setupResult
		err  error
	}
	done := make(chan outcome, 1)

	waitCtx, waitCancel := context.WithTimeout(ctx, setupTimeout)
	defer waitCancel()

	finishVerb := "finish import"
	if purpose == purposeReconfigure {
		finishVerb = "finish setup"
	}

	go func() {
		// Let StartGraphicApplication settle before the first Connect.
		select {
		case <-waitCtx.Done():
			done <- outcome{err: waitCtx.Err()}
			return
		case <-time.After(2 * time.Second):
		}

		info, err := watchGuest(waitCtx, inst, func() {
			logrus.Infof("setup checks passed — close the VM window to %s", finishVerb)
		})
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf(
					"timed out after %s waiting for guest setup with agent %q; %s",
					setupTimeout, agent.AgentVersion, setupHint)
			}
			logrus.Errorf("setup checks failed: %v — close the VM window to abort", err)
			done <- outcome{err: err}
			return
		}
		if err := finalizeBaseline(dir); err != nil {
			done <- outcome{err: err}
			return
		}
		done <- outcome{info: info}
	}()

	logrus.Infof("showing GUI (%dx%d); %s",
		config.DefaultDisplayWidth, config.DefaultDisplayHeight, setupHint)
	logrus.Infof("waiting for guest setup with agent version %q…", agent.AgentVersion)
	graphicErr := inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
	cancel()

	if err := inst.Shutdown(); err != nil {
		logrus.Warnf("failed to stop baseline vm: %v", err)
	}
	// Wait for the VM to fully release disk files before Import's cleanup
	// RemoveAll runs; otherwise an aborted import can leave ~/.machbox/vms/<uuid>.
	select {
	case <-inst.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for baseline VM to stop")
	}

	r := <-done
	if graphicErr != nil && r.err == nil {
		return nil, fmt.Errorf("show graphic: %w", graphicErr)
	}
	if r.info == nil && r.err == nil {
		return nil, context.Canceled
	}
	return r.info, r.err
}

// watchGuest checks the guest until ctx ends and returns the last result
// that was ready; an error if none was. ready is called the first time one is.
func watchGuest(ctx context.Context, inst *boxvm.VMInstance, ready func()) (*setupResult, error) {
	c := agent.NewClient(agentDialer(inst))
	var latest *setupResult
	lastWaiting, lastFeatures := "", ""
	for {
		res, waiting, err := pollGuest(ctx, c)
		switch {
		case err != nil:
			// The agent restarts while Machbox Setup updates it.
			logrus.Debugf("guest not ready: %v", err)
		case waiting != "":
			latest = nil
			if waiting != lastWaiting {
				logrus.Infof("guest not ready: %s", waiting)
			}
		default:
			if lastWaiting != "ready" {
				agent.LogGuest(res.Info)
				ready()
			}
			latest = &res
			waiting = "ready"
		}
		if err == nil {
			lastWaiting = waiting
			if f := strings.Join(res.Features, ","); f != lastFeatures {
				logrus.Infof("guest features: %s", f)
				lastFeatures = f
			}
		}
		select {
		case <-ctx.Done():
			if latest != nil {
				return latest, nil
			}
			return nil, ctx.Err()
		case <-time.After(checkInterval):
		}
	}
}

// pollGuest returns the guest's setup result, and what it is still waiting
// for: "" once it has a matching agent and automatic login.
func pollGuest(ctx context.Context, c *agent.Client) (setupResult, string, error) {
	var res setupResult
	info, err := c.Info(ctx)
	if err != nil {
		return res, "", err
	}
	if info.OSName == "" {
		info.OSName = "macOS"
	}
	res.Info = info
	if err := agent.CompatibleAgent(info.AgentVersion); err != nil {
		return res, fmt.Sprintf("%v; %s", err, setupHint), nil
	}
	report, err := c.Check(ctx)
	if err != nil {
		return res, "", err
	}
	res.Features = checkFeatures(&report)
	if report.AutoLoginUser == "" {
		return res, "automatic login is off; " + setupHint, nil
	}
	return res, "", nil
}

// checkFeatures returns the baseline features a check found, the agent
// included: it ran the check.
func checkFeatures(r *agent.CheckReport) []string {
	features := []string{agent.FeatureAgent}
	for _, f := range r.Features {
		if agent.KnownFeature(f) && !slices.Contains(features, f) {
			features = append(features, f)
		}
	}
	return agent.WithSIP(features, r.SIPDisabled)
}

// finalizeBaseline drops runs_* snapshot directories that older versions
// created inside the baseline bundle (runs now live in assets.RunsDir).
func finalizeBaseline(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("inspect baseline directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "runs_") {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("remove stale snapshot %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}
