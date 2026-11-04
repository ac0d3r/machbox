package vm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/pkg/vm/config"
)

func writeBaseline(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "src")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		config.AuxiliaryStorageName, config.HardwareModelName,
		config.MachineIdentifierName, config.DiskName,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := json.Marshal(map[string]any{"version": 1, "cpu_count": 2, "memory_size": 4 << 30})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, config.BundleConfigName), cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestCloneBaselineIsIndependent(t *testing.T) {
	src := writeBaseline(t)
	dst := filepath.Join(t.TempDir(), "dst")
	if err := cloneBaseline(src, dst); err != nil {
		t.Fatal(err)
	}

	got, err := config.LoadBundle(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got.CPUCount != 2 || got.MemorySize != 4<<30 {
		t.Errorf("hardware = %d cpu, %d bytes", got.CPUCount, got.MemorySize)
	}
	id, err := os.ReadFile(got.MachineIdentifierPath)
	if err != nil || string(id) != config.MachineIdentifierName {
		t.Errorf("machine identifier = %q, %v", id, err)
	}

	if err := os.WriteFile(got.DiskPath, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(src, config.DiskName))
	if err != nil || string(disk) != config.DiskName {
		t.Errorf("source disk = %q, %v", disk, err)
	}
}

func TestCloneBaselineRefusesLockedSource(t *testing.T) {
	src := writeBaseline(t)
	lock, err := lockBaseline(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	err = cloneBaseline(src, dst)
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("err = %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("dst left behind: %v", err)
	}

	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cloneBaseline(src, dst); err != nil {
		t.Errorf("after unlock: %v", err)
	}
}

func TestBaselineLocks(t *testing.T) {
	dir := writeBaseline(t)
	r1, err := readLockBaseline(dir)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := readLockBaseline(dir)
	if err != nil {
		t.Fatalf("second shared lock: %v", err)
	}
	if _, err := lockBaseline(dir); !errors.Is(err, errBaselineInUse) {
		t.Errorf("exclusive lock under shared ones: err = %v", err)
	}
	_ = r1.Close()
	_ = r2.Close()

	w, err := lockBaseline(dir)
	if err != nil {
		t.Fatalf("exclusive lock once released: %v", err)
	}
	if _, err := readLockBaseline(dir); !errors.Is(err, errBaselineInUse) {
		t.Errorf("shared lock under an exclusive one: err = %v", err)
	}
	_ = w.Close()
	if _, err := lockBaseline(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing baseline: err = %v", err)
	}
}

func TestCloneBaselineRemovesPartialClone(t *testing.T) {
	src := writeBaseline(t)
	if err := os.Remove(filepath.Join(src, config.DiskName)); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "dst")
	if err := cloneBaseline(src, dst); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("dst left behind: %v", err)
	}
}
