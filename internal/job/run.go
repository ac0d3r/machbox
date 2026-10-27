package job

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"
	"github.com/ac0d3r/machbox/internal/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/sirupsen/logrus"
)

// sessionTimeout bounds the wait for the baseline's automatic login.
const sessionTimeout = 5 * time.Minute

var sessionPoll = 2 * time.Second

// Options configures Run.
type Options struct {
	// Baseline is a UUID or unique name. Empty picks the only baseline that
	// meets the plugin's requirements.
	Baseline string
	Boot     vm.BootOptions
	// Echo, if not nil, also receives every step's stdout.
	Echo io.Writer
}

// Run executes workflow wf with inputs in a fresh run of a baseline. The
// job is returned once its directory exists, also when it then fails.
func Run(ctx context.Context, p *plugin.Plugin, wf *plugin.Workflow, inputs map[string]string, opts Options) (*Job, error) {
	baseline, err := pickBaseline(opts.Baseline, p.Requires)
	if err != nil {
		return nil, err
	}
	j, err := New(p, wf, inputs, baseline)
	if err != nil {
		return nil, err
	}
	logrus.Infof("job %s: %s/%s on baseline %s (%s)", j.ID, p.Name, wf.Name, baseline.Name, baseline.UUID)

	err = j.run(ctx, baseline, opts)
	j.finish(err)
	return j, err
}

func (j *Job) run(ctx context.Context, baseline *db.VM, opts Options) error {
	r, err := vm.NewRun(baseline)
	if err != nil {
		return err
	}
	defer func() {
		if err := r.Close(); err != nil {
			logrus.Warnf("%v", err)
		}
	}()
	if err := j.share(r.ShareCopy); err != nil {
		return err
	}
	if opts.Boot.Network.Enable && opts.Boot.Network.Mode == config.NetworkInternet {
		opts.Boot.Capture = filepath.Join(j.Dir, captureName)
	}

	return r.Boot(ctx, opts.Boot, func(ctx context.Context, c *agent.Client, info agent.GuestInfo) error {
		j.Guest = &info
		j.trySave()
		if err := j.plugin.Requires.Check(info.OSVersion, info.SIPDisabled); err != nil {
			return fmt.Errorf("guest does not meet plugin requirements: %w", err)
		}
		user, err := waitSession(ctx, c)
		if err != nil {
			return err
		}
		j.Guest.ConsoleUser = user
		j.trySave()
		wd, err := c.SetWorkdir(ctx)
		if err != nil {
			return err
		}
		logrus.Debugf("guest workdir %s, share %s", wd.WorkPath, wd.SharePath)
		return j.execute(ctx, c, wd, opts.Echo)
	})
}

// waitSession waits until a user is logged in at the guest console with
// their desktop up. The agent starts before that; baselines log in
// automatically, so samples get a real GUI session.
func waitSession(ctx context.Context, g interface {
	Info(context.Context) (agent.GuestInfo, error)
}) (string, error) {
	waitCtx, cancel := context.WithTimeout(ctx, sessionTimeout)
	defer cancel()
	logrus.Info("waiting for the guest user session")
	for {
		info, err := g.Info(waitCtx)
		if err == nil && info.ConsoleUser != "" {
			logrus.Infof("guest user %s logged in", info.ConsoleUser)
			return info.ConsoleUser, nil
		}
		select {
		case <-waitCtx.Done():
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			return "", fmt.Errorf("no user logged in at the guest console after %s; "+
				"enable automatic login on the baseline (see docs/environment-setup.md)", sessionTimeout)
		case <-time.After(sessionPoll):
		}
	}
}

func pickBaseline(identifier string, req plugin.Requires) (*db.VM, error) {
	if identifier != "" {
		b, err := vm.Resolve(identifier)
		if err != nil {
			return nil, err
		}
		if err := req.Check(b.OSVersion, b.SIPDisabled); err != nil {
			return nil, fmt.Errorf("baseline %s: %w", b.Name, err)
		}
		return b, nil
	}

	all, err := vm.List()
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return nil, errors.New("no imported baselines; run: machbox vm import <path.vbvm> <name>")
	}
	var ok []*db.VM
	for i := range all {
		if req.Check(all[i].OSVersion, all[i].SIPDisabled) == nil {
			ok = append(ok, &all[i])
		}
	}
	switch len(ok) {
	case 0:
		return nil, fmt.Errorf("no baseline meets the plugin's requirements (%s); see: machbox vm list", req)
	case 1:
		return ok[0], nil
	default:
		return nil, errors.New("several baselines meet the plugin's requirements; choose one with --vm (see: machbox vm list)")
	}
}
