package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestRun(t *testing.T) *Run {
	t.Helper()
	r := &Run{dir: t.TempDir()}
	if err := os.Mkdir(r.ShareDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSharePathCopiesBundleWithSymlinks(t *testing.T) {
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
	name, err := r.SharePath(src)
	if err != nil {
		t.Fatal(err)
	}
	if name != "Sample.app" {
		t.Errorf("name = %q", name)
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

func TestShareFileRejectsEscape(t *testing.T) {
	r := newTestRun(t)
	for _, name := range []string{"../evil", "/abs", ""} {
		if err := r.ShareFile(name, strings.NewReader("x"), 0o600); err == nil {
			t.Errorf("ShareFile(%q) succeeded", name)
		}
	}
	if err := r.ShareFile("DTrace/net.d", strings.NewReader("x"), 0o500); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(r.ShareDir(), "DTrace", "net.d")); string(got) != "x" {
		t.Errorf("content = %q", got)
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
