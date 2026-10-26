package vm

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	vz "github.com/Code-Hex/vz/v4"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	runSnapshotDir = "vm"
	runShareDir    = "share"
	runLockFile    = ".lock"

	// A run directory without a lock file is only treated as stale after
	// this long, so a run that is still being set up is not swept.
	unlockedRunGrace = time.Minute
)

// Run is a disposable boot of a baseline. Everything it owns lives under one
// directory (~/.machbox/runs/<id>/):
//
//	vm/     APFS snapshot of the baseline's writable files
//	share/  host directory exposed read-only to the guest (agent.ShareTag)
//
// The directory holds an exclusive flock for the run's lifetime. Close
// removes it; runs left behind by a crashed process are swept by the next
// NewRun.
type Run struct {
	Baseline *db.VM
	// Config is the baseline bundle pointing at the snapshot files.
	Config *config.Bundle

	dir  string
	lock *os.File
}

// NewRun sweeps stale runs, then snapshots baseline into a new run directory.
func NewRun(baseline *db.VM) (r *Run, err error) {
	SweepRuns()

	bundle, err := loadBundle(assets.VMPath(baseline.UUID))
	if err != nil {
		return nil, fmt.Errorf("load baseline %s: %w", baseline.UUID, err)
	}

	dir, err := os.MkdirTemp(assets.RunsDir(), "run-")
	if err != nil {
		return nil, fmt.Errorf("create run directory: %w", err)
	}
	r = &Run{Baseline: baseline, dir: dir}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()

	if r.lock, err = lockRun(dir); err != nil {
		return nil, err
	}

	snapDir := filepath.Join(dir, runSnapshotDir)
	if err = os.Mkdir(snapDir, 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	if r.Config, err = bundle.Snapshot(snapDir); err != nil {
		return nil, fmt.Errorf("snapshot baseline %s: %w", baseline.UUID, err)
	}

	if err = os.Mkdir(r.ShareDir(), 0o700); err != nil {
		return nil, fmt.Errorf("create share directory: %w", err)
	}

	logrus.Debugf("created run %s for baseline %s", dir, baseline.UUID)
	return r, nil
}

// Dir returns the run directory.
func (r *Run) Dir() string { return r.dir }

// ShareDir returns the host directory shared with the guest.
func (r *Run) ShareDir() string { return filepath.Join(r.dir, runShareDir) }

// ShareFile writes src into the share at name (a relative path) with mode.
func (r *Run) ShareFile(name string, src io.Reader, mode os.FileMode) error {
	dst, err := r.sharePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return writeFile(dst, src, mode)
}

// SharePath copies a host file or directory into the share root under its
// base name and returns that name.
func (r *Run) SharePath(hostPath string) (string, error) {
	name := filepath.Base(hostPath)
	dst, err := r.sharePath(name)
	if err != nil {
		return "", err
	}
	if err := copyPath(hostPath, dst); err != nil {
		return "", fmt.Errorf("share %s: %w", hostPath, err)
	}
	return name, nil
}

func (r *Run) sharePath(name string) (string, error) {
	if !filepath.IsLocal(name) {
		return "", fmt.Errorf("share path %q must be relative and stay inside the share", name)
	}
	return filepath.Join(r.ShareDir(), name), nil
}

// VMConfig builds the VM configuration for the snapshot with the share
// attached read-only under agent.ShareTag. Shares already in opts are kept.
func (r *Run) VMConfig(opts config.VMOptions) (*vz.VirtualMachineConfiguration, error) {
	opts.Shares = append(opts.Shares, config.ShareDir{
		Dir:      r.ShareDir(),
		Tag:      agent.ShareTag,
		ReadOnly: true,
	})
	return config.NewMacVMConf(r.Config, &opts)
}

// Close discards the snapshot and share. The VM must be stopped first.
func (r *Run) Close() error {
	if r.dir == "" {
		return nil
	}
	err := os.RemoveAll(r.dir)
	if r.lock != nil {
		_ = r.lock.Close() // releases the flock
		r.lock = nil
	}
	if err != nil {
		return fmt.Errorf("remove run %s: %w", r.dir, err)
	}
	logrus.Debugf("removed run %s", r.dir)
	r.dir = ""
	return nil
}

// SweepRuns removes run directories whose owning process has exited.
func SweepRuns() {
	entries, err := os.ReadDir(assets.RunsDir())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logrus.Warnf("list runs: %v", err)
		}
		return
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(assets.RunsDir(), e.Name())
		if !runIsStale(dir) {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			logrus.Warnf("remove stale run %s: %v", dir, err)
			continue
		}
		logrus.Infof("removed stale run %s", dir)
	}
}

func runIsStale(dir string) bool {
	// #nosec G304 -- dir is a child of the managed runs directory.
	f, err := os.OpenFile(filepath.Join(dir, runLockFile), os.O_RDWR, 0)
	if err != nil {
		info, statErr := os.Stat(dir)
		return errors.Is(err, os.ErrNotExist) && statErr == nil &&
			time.Since(info.ModTime()) > unlockedRunGrace
	}
	defer f.Close()

	// Holding the lock only while we decide is fine: a live run never
	// releases its lock, so acquiring it means the owner is gone.
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil
}

func lockRun(dir string) (*os.File, error) {
	// #nosec G304 -- dir was just created under the managed runs directory.
	f, err := os.OpenFile(filepath.Join(dir, runLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create run lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock run %s: %w", dir, err)
	}
	return f, nil
}

func copyPath(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst, info.Mode())
}

func copyFile(src, dst string, mode os.FileMode) error {
	// #nosec G304 -- src is a caller-provided host path intentionally copied into the share.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return writeFile(dst, in, mode)
}

func writeFile(dst string, src io.Reader, mode os.FileMode) error {
	// #nosec G304 -- dst is inside the run's share directory.
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// copyDir copies the tree at src to dst (which must not exist). Both sides
// are accessed through os.Root so an entry swapped for a symlink mid-copy
// cannot redirect reads or writes outside src/dst. Symlinks are copied as
// links: bundles rely on them (e.g. Versions/Current).
func copyDir(src, dst string) error {
	srcRoot, err := os.OpenRoot(src)
	if err != nil {
		return err
	}
	defer srcRoot.Close()

	if err := os.Mkdir(dst, 0o700); err != nil {
		return err
	}
	dstRoot, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer dstRoot.Close()

	return fs.WalkDir(srcRoot.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || path == "." {
			return err
		}

		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := srcRoot.Readlink(path)
			if err != nil {
				return err
			}
			return dstRoot.Symlink(target, path)

		case d.IsDir():
			info, err := d.Info()
			if err != nil {
				return err
			}
			// Keep directories writable by us so their contents can be copied.
			return dstRoot.Mkdir(path, info.Mode().Perm()|0o700)

		case d.Type().IsRegular():
			info, err := d.Info()
			if err != nil {
				return err
			}
			in, err := srcRoot.Open(path)
			if err != nil {
				return err
			}
			defer in.Close()
			out, err := dstRoot.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, in); err != nil {
				_ = out.Close()
				return err
			}
			return out.Close()

		default:
			logrus.Debugf("share: skipping special file %s", filepath.Join(src, path))
			return nil
		}
	})
}
