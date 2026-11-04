package vm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/pkg/vm/config"
)

func TestCreateInstanceClonesIntoBaseline(t *testing.T) {
	base := writeBaseline(t)
	in, err := createInstanceAt(base, "u", "cc", config.NetworkGatewayPublic)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, instancesDirName, "cc"); in.Dir != want {
		t.Errorf("dir = %s, want %s", in.Dir, want)
	}
	if _, err := config.LoadBundle(in.Dir); err != nil {
		t.Errorf("instance is not a bundle: %v", err)
	}

	// The instance is the baseline's own subdirectory, but not part of it:
	// cloning the baseline again (duplicate, another instance) leaves it out.
	if _, err := createInstanceAt(base, "u", "other", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, instancesDirName, "other", instancesDirName)); !os.IsNotExist(err) {
		t.Errorf("an instance's clone holds instances: %v", err)
	}

	got, err := instancesAt(filepath.Join(base, instancesDirName), "u")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "cc" || got[1].Name != "other" {
		t.Fatalf("instances = %+v", got)
	}
	if got[0].Meta.Network != config.NetworkGatewayPublic || got[0].Meta.CreatedAt.IsZero() || got[1].Meta.Network != "" {
		t.Errorf("meta = %+v, %+v", got[0].Meta, got[1].Meta)
	}
}

func TestCreateInstanceKeepsExisting(t *testing.T) {
	base := writeBaseline(t)
	in, err := createInstanceAt(base, "u", "cc", "")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(in.Dir, "marker")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := createInstanceAt(base, "u", "cc", ""); err == nil {
		t.Fatal("second instance with the same name created")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Errorf("existing instance changed: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(base, instancesDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestInstanceLock(t *testing.T) {
	in, err := createInstanceAt(writeBaseline(t), "u", "cc", "")
	if err != nil {
		t.Fatal(err)
	}
	if in.Running() {
		t.Error("never started, reported running")
	}
	lock, err := in.lock()
	if err != nil {
		t.Fatal(err)
	}
	if !in.Running() {
		t.Error("locked, reported stopped")
	}
	if _, err := in.lock(); err == nil || !strings.Contains(err.Error(), "running") {
		t.Errorf("second lock: %v", err)
	}
	if err := RemoveInstance(in); err == nil {
		t.Error("removed a running instance")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if in.Running() {
		t.Error("unlocked, reported running")
	}
	if err := RemoveInstance(in); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(in.Dir); !os.IsNotExist(err) {
		t.Errorf("instance left behind: %v", err)
	}
}

func TestInstanceNames(t *testing.T) {
	for name, ok := range map[string]bool{
		"cc": true, "claude-1": true, "a.b_c": true,
		"": false, ".hidden": false, "-x": false, "a/b": false, "..": false, "with space": false,
		strings.Repeat("a", 65): false,
	} {
		if instanceNameRe.MatchString(name) != ok {
			t.Errorf("%q: valid = %v", name, !ok)
		}
	}
}

func TestAutomountShares(t *testing.T) {
	root := t.TempDir()
	a, b := filepath.Join(root, "a", "proj"), filepath.Join(root, "b", "proj")
	file := filepath.Join(root, "file")
	for _, d := range []string{a, b} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := automountShares([]InstanceShare{{Path: a}, {Path: root, ReadOnly: true}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Tag != "proj" || got[0].ReadOnly || got[1].Tag != filepath.Base(root) || !got[1].ReadOnly {
		t.Errorf("shares = %+v", got)
	}
	if p := (InstanceShare{Path: a}).GuestPath(); p != "/Volumes/My Shared Files/proj" {
		t.Errorf("guest path = %s", p)
	}

	for name, shares := range map[string][]InstanceShare{
		"same name": {{Path: a}, {Path: b}},
		"missing":   {{Path: filepath.Join(root, "nope")}},
		"file":      {{Path: file}},
	} {
		if _, err := automountShares(shares); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
