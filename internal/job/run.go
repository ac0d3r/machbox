package job

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"
	"github.com/ac0d3r/machbox/internal/vm"

	"github.com/sirupsen/logrus"
)

// Options configures Run.
type Options struct {
	// Baseline is a UUID or unique name. Empty picks the only baseline that
	// satisfies the plugin's macOS requirement.
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

	return r.Boot(ctx, opts.Boot, func(ctx context.Context, c *agent.Client, info agent.GuestInfo) error {
		j.Guest = &info
		j.trySave()
		if err := j.plugin.Requires.Check(info.OSVersion, info.SIPDisabled); err != nil {
			return fmt.Errorf("guest does not meet plugin requirements: %w", err)
		}
		wd, err := c.SetWorkdir(ctx)
		if err != nil {
			return err
		}
		logrus.Debugf("guest workdir %s, share %s", wd.WorkPath, wd.SharePath)
		return j.execute(ctx, c, wd, opts.Echo)
	})
}

func pickBaseline(identifier string, req plugin.Requires) (*db.VM, error) {
	if identifier != "" {
		b, err := vm.Resolve(identifier)
		if err != nil {
			return nil, err
		}
		if err := req.CheckOS(b.OSVersion); err != nil {
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
		if req.CheckOS(all[i].OSVersion) == nil {
			ok = append(ok, &all[i])
		}
	}
	switch len(ok) {
	case 0:
		return nil, fmt.Errorf("no baseline runs macOS %s (see: machbox vm list)", req.MacOS)
	case 1:
		return ok[0], nil
	default:
		return nil, errors.New("several baselines meet the plugin's requirements; choose one with --vm (see: machbox vm list)")
	}
}
