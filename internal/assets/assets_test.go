package assets

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func dirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func TestExtractContentAddressed(t *testing.T) {
	dir := t.TempDir()
	v1 := fstest.MapFS{"data/guest.dmg": {Data: []byte("v1")}}

	p1, err := extractContentAddressed(v1, "data/guest.dmg", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(filepath.Base(p1), "guest-") || filepath.Ext(p1) != ".dmg" {
		t.Errorf("path = %s", p1)
	}
	if got, _ := os.ReadFile(p1); string(got) != "v1" {
		t.Errorf("content = %q", got)
	}
	info, err := os.Stat(p1)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Errorf("mode = %v, want 0400", info.Mode().Perm())
	}

	// Same content: reuse without rewriting.
	again, err := extractContentAddressed(v1, "data/guest.dmg", dir)
	if err != nil || again != p1 {
		t.Fatalf("second extract = %s, %v", again, err)
	}
	if info2, _ := os.Stat(p1); !info2.ModTime().Equal(info.ModTime()) {
		t.Error("unchanged image was rewritten")
	}

	// Leftovers from older layouts and interrupted extractions.
	for _, n := range []string{"guest.dmg", "guest.dmg.sha256", ".guest-old.tmp", ".guest-fresh.tmp", "other.txt"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * staleTempAge)
	if err := os.Chtimes(filepath.Join(dir, ".guest-old.tmp"), old, old); err != nil {
		t.Fatal(err)
	}

	// New content: new name, previous version and legacy files removed.
	v2 := fstest.MapFS{"data/guest.dmg": {Data: []byte("v2")}}
	p2, err := extractContentAddressed(v2, "data/guest.dmg", dir)
	if err != nil {
		t.Fatal(err)
	}
	if p2 == p1 {
		t.Fatal("different content reused the same path")
	}
	want := []string{".guest-fresh.tmp", filepath.Base(p2), "other.txt"}
	sort.Strings(want)
	if got := dirNames(t, dir); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("dir = %v, want %v", got, want)
	}
}

func TestExtractContentAddressedMissing(t *testing.T) {
	if _, err := extractContentAddressed(fstest.MapFS{}, "data/guest.dmg", t.TempDir()); err == nil {
		t.Fatal("expected error for missing embedded file")
	}
}
