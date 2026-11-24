package vm

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func newTestRun(t *testing.T) *Run {
	t.Helper()
	r := &Run{dir: t.TempDir()}
	if err := os.Mkdir(r.ShareDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestShareCopyBundleWithSymlinks(t *testing.T) {
	src := filepath.Join(t.TempDir(), "Sample.app")
	fw := filepath.Join(src, "Contents", "Frameworks", "X.framework")
	if err := os.MkdirAll(filepath.Join(fw, "Versions", "A"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fw, "Versions", "A", "X"), []byte("bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("A", filepath.Join(fw, "Versions", "Current")); err != nil {
		t.Fatal(err)
	}

	r := newTestRun(t)
	if err := r.ShareCopy(src, "Sample.app"); err != nil {
		t.Fatal(err)
	}

	dstFW := filepath.Join(r.ShareDir(), "Sample.app", "Contents", "Frameworks", "X.framework")
	if target, err := os.Readlink(filepath.Join(dstFW, "Versions", "Current")); err != nil || target != "A" {
		t.Errorf("Current link = %q, %v", target, err)
	}
	info, err := os.Stat(filepath.Join(dstFW, "Versions", "Current", "X"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Errorf("mode = %v, want 0755", info.Mode().Perm())
	}
}

func TestShareCopyRejectsEscape(t *testing.T) {
	r := newTestRun(t)
	src := filepath.Join(t.TempDir(), "net.d")
	if err := os.WriteFile(src, []byte("x"), 0o500); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../evil", "/abs", ""} {
		if err := r.ShareCopy(src, name); err == nil {
			t.Errorf("ShareCopy(%q) succeeded", name)
		}
	}
	if err := r.ShareCopy(src, "DTrace/net.d"); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(r.ShareDir(), "DTrace", "net.d")); string(got) != "x" {
		t.Errorf("content = %q", got)
	}
}

// TestShareCopyClonesOrCopies shares a file and a tree, once cloned and once
// with clonefile failing, and checks both give the same result: content and
// mode kept, extended attributes dropped.
func TestShareCopyClonesOrCopies(t *testing.T) {
	src := t.TempDir()
	file := filepath.Join(src, "Sample.bin")
	if err := os.WriteFile(file, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(file, "com.apple.quarantine", []byte("0081;00000000;Safari;"), 0); err != nil {
		t.Fatal(err)
	}
	// Read-only, as samples often are: the clone must still lose the xattr.
	if err := os.Chmod(file, 0o444); err != nil {
		t.Fatal(err)
	}

	orig := cloneFile
	t.Cleanup(func() { cloneFile = orig })
	for _, clone := range []bool{true, false} {
		clones := 0
		cloneFile = func(src, dir *os.File, name string) error {
			if !clone {
				return unix.ENOTSUP
			}
			err := orig(src, dir, name)
			if err == nil {
				clones++
			}
			return err
		}

		r := newTestRun(t)
		if err := r.ShareCopy(file, "file/Sample.bin"); err != nil {
			t.Fatal(err)
		}
		if err := r.ShareCopy(src, "dir"); err != nil {
			t.Fatal(err)
		}
		if clone && clones != 2 {
			t.Skipf("temp directory volume cannot clone (%d of 2 cloned)", clones)
		}
		if !clone && clones != 0 {
			t.Fatal("cloned although clonefile failed")
		}

		for _, got := range []string{
			filepath.Join(r.ShareDir(), "file", "Sample.bin"),
			filepath.Join(r.ShareDir(), "dir", "Sample.bin"),
		} {
			data, err := os.ReadFile(got)
			if err != nil || string(data) != "MZ" {
				t.Errorf("clone=%v %s: content %q, %v", clone, got, data, err)
			}
			info, err := os.Stat(got)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o444 {
				t.Errorf("clone=%v %s: mode %v, want 0444", clone, got, info.Mode().Perm())
			}
			if _, err := unix.Getxattr(got, "com.apple.quarantine", nil); !errors.Is(err, unix.ENOATTR) {
				t.Errorf("clone=%v %s: quarantine kept (%v)", clone, got, err)
			}
		}
	}
}

func TestRunIsStale(t *testing.T) {
	live := t.TempDir()
	lock, err := lockRun(live)
	if err != nil {
		t.Fatal(err)
	}
	if runIsStale(live) {
		t.Error("locked run reported stale")
	}
	lock.Close()
	if !runIsStale(live) {
		t.Error("unlocked run not reported stale")
	}

	fresh := t.TempDir()
	if runIsStale(fresh) {
		t.Error("fresh run without lock reported stale")
	}
	old := time.Now().Add(-2 * unlockedRunGrace)
	if err := os.Chtimes(fresh, old, old); err != nil {
		t.Fatal(err)
	}
	if !runIsStale(fresh) {
		t.Error("old run without lock not reported stale")
	}
}

func TestCloseRemovesRun(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run-x")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockRun(dir)
	if err != nil {
		t.Fatal(err)
	}
	r := &Run{dir: dir, lock: lock}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("run dir still exists: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}
