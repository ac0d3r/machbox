package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotClonesWithoutMutatingBaseline(t *testing.T) {
	root := t.TempDir()
	base := &VBVMConfig{
		RootPath:              root,
		AuxiliaryStoragePath:  filepath.Join(root, "AuxiliaryStorage"),
		HardwareModelPath:     filepath.Join(root, "HardwareModel"),
		MachineIdentifierPath: filepath.Join(root, "MachineIdentifier"),
		DiskPath:              filepath.Join(root, "Disk.img"),
	}
	for _, p := range []string{base.AuxiliaryStoragePath, base.HardwareModelPath,
		base.MachineIdentifierPath, base.DiskPath} {
		if err := os.WriteFile(p, []byte(filepath.Base(p)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	orig := *base

	dir := t.TempDir()
	snap, err := base.Snapshot(dir)
	if err != nil {
		t.Fatal(err)
	}

	if *base != orig {
		t.Fatalf("baseline config mutated: %+v", base)
	}
	if snap.RootPath != dir {
		t.Errorf("RootPath = %q, want %q", snap.RootPath, dir)
	}
	for _, p := range []string{snap.AuxiliaryStoragePath, snap.HardwareModelPath,
		snap.MachineIdentifierPath, snap.DiskPath} {
		if filepath.Dir(p) != dir {
			t.Errorf("%s not inside snapshot dir", p)
		}
		got, err := os.ReadFile(p)
		if err != nil || string(got) != filepath.Base(p) {
			t.Errorf("%s = %q, %v", p, got, err)
		}
	}

	// Writes to the snapshot must not reach the baseline (copy-on-write).
	if err := os.WriteFile(snap.DiskPath, []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(base.DiskPath); string(got) != "Disk.img" {
		t.Errorf("baseline disk changed: %q", got)
	}
}
