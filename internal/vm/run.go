package vm

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

	// Only while the snapshot is taken: never of a baseline being set up,
	// and never torn by one starting midway, file by file.
	baseLock, err := readLockBaseline(assets.VMPath(baseline.UUID))
	if err != nil {
		return nil, fmt.Errorf("baseline %s: %w", baseline.Name, err)
	}
	defer baseLock.Close()

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

// ShareCopy copies a host file or directory into the share at name (a
// relative path).
func (r *Run) ShareCopy(hostPath, name string) error {
	dst, err := r.sharePath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := copyPath(hostPath, dst); err != nil {
		return fmt.Errorf("share %s: %w", hostPath, err)
	}
	return nil
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
	return copyFile(src, dst, info.Mode().Perm())
}

func copyFile(src, dst string, perm os.FileMode) error {
	// #nosec G304 -- src is a caller-provided host path intentionally copied into the share.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dstRoot, err := os.OpenRoot(filepath.Dir(dst))
	if err != nil {
		return err
	}
	defer dstRoot.Close()
	return copyRegular(in, dstRoot, filepath.Base(dst), perm)
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
			return copyRegular(in, dstRoot, path, info.Mode().Perm())

		default:
			logrus.Debugf("share: skipping special file %s", filepath.Join(src, path))
			return nil
		}
	})
}

// copyRegular creates name (which must not exist) in dst with in's content
// and mode perm. It clones in when the volume allows, which takes no time
// or space however large the file, and copies otherwise (another volume,
// not APFS).
func copyRegular(in *os.File, dst *os.Root, name string, perm os.FileMode) error {
	err := cloneRegular(in, dst, name, perm)
	if err == nil {
		return nil
	}
	logrus.Debugf("share: clone %s: %v; copying", name, err)

	out, err := dst.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// cloneFile clones the open file src to name in the directory dir; a
// variable so tests can make it fail.
var cloneFile = func(src, dir *os.File, name string) error {
	return unix.Fclonefileat(int(src.Fd()), int(dir.Fd()), name, unix.CLONE_NOOWNERCOPY)
}

// lockFlags make a file unremovable; a clone would keep them and the run
// directory could not be removed.
const lockFlags = unix.UF_IMMUTABLE | unix.UF_APPEND | unix.SF_IMMUTABLE | unix.SF_APPEND

// cloneRegular clones in to name in dst, then strips what a copy would not
// carry: extended attributes (quarantine among them) and mode bits beyond
// perm. On error nothing is left at name.
func cloneRegular(in *os.File, dst *os.Root, name string, perm os.FileMode) (err error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(in.Fd()), &st); err != nil {
		return err
	}
	if st.Flags&lockFlags != 0 {
		return errors.New("source has immutable or append-only flags")
	}

	dir, err := dst.Open(filepath.Dir(name))
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := cloneFile(in, dir, filepath.Base(name)); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = dst.Remove(name)
		}
	}()

	out, err := dst.Open(name)
	if err != nil {
		return err
	}
	defer out.Close()
	fd := int(out.Fd())
	// The clone has the source's mode; xattrs need it writable.
	if err := unix.Fchmod(fd, 0o600); err != nil {
		return err
	}
	if err := stripXattrs(fd); err != nil {
		return err
	}
	return unix.Fchmod(fd, uint32(perm))
}

func stripXattrs(fd int) error {
	size, err := unix.Flistxattr(fd, nil)
	if err != nil || size == 0 {
		return err
	}
	buf := make([]byte, size)
	if size, err = unix.Flistxattr(fd, buf); err != nil {
		return err
	}
	for name := range strings.SplitSeq(strings.TrimRight(string(buf[:size]), "\x00"), "\x00") {
		if err := unix.Fremovexattr(fd, name); err != nil {
			return fmt.Errorf("remove xattr %s: %w", name, err)
		}
	}
	return nil
}
