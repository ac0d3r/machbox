package job

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ac0d3r/machbox/internal/assets"

	"golang.org/x/sys/unix"
)

const lockName = ".lock"

// newJobGrace covers a job directory created but not yet locked.
var newJobGrace = time.Minute

// ErrRunning is returned for a job that is still running.
var ErrRunning = errors.New("job is running")

// Finished returns the ids of the jobs in assets.JobsDir that are not running.
func Finished() ([]string, error) {
	return finished(assets.JobsDir())
}

func finished(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		release, err := tryLock(filepath.Join(root, e.Name()))
		if err != nil {
			continue
		}
		release()
		ids = append(ids, e.Name())
	}
	return ids, nil
}

// Remove deletes a finished job's directory.
func Remove(id string) error {
	return remove(assets.JobsDir(), id)
}

func remove(root, id string) error {
	if !filepath.IsLocal(id) || filepath.Base(id) != id {
		return fmt.Errorf("invalid job id %q", id)
	}
	dir := filepath.Join(root, id)
	release, err := tryLock(dir)
	if err != nil {
		return fmt.Errorf("job %s: %w", id, err)
	}
	defer release()
	return os.RemoveAll(dir)
}

// tryLock takes the lock a running job holds. Jobs from the last minute
// are left alone: one may be created but not yet locked.
func tryLock(dir string) (release func(), err error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if time.Since(info.ModTime()) < newJobGrace {
		return nil, ErrRunning
	}
	// #nosec G304 -- dir is under the managed jobs directory.
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, ErrRunning
	}
	return func() { _ = f.Close() }, nil
}

// lock is held by a running job until finish.
func lock(dir string) (*os.File, error) {
	// #nosec G304 -- dir was just created under the managed jobs directory.
	f, err := os.OpenFile(filepath.Join(dir, lockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create job lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock job %s: %w", dir, err)
	}
	return f, nil
}
