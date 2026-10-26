package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

const (
	testCPU    = 2
	testMemory = 4 << 30
)

// writeVBVM creates a minimal VirtualBuddy bundle whose boot disk is
// <diskName>.img.
func writeVBVM(t *testing.T, diskName string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "Test.vbvm")
	if err := os.MkdirAll(filepath.Join(dir, ".vbdata"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{AuxiliaryStorageName, HardwareModelName, MachineIdentifierName, diskName + ".img"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	plistXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>hardware</key><dict>
<key>cpuCount</key><integer>%d</integer>
<key>memorySize</key><integer>%d</integer>
<key>_storageDevices</key><array><dict><key>backing</key><dict><key>managedImage</key><dict>
<key>_0</key><dict><key>filename</key><string>%s</string><key>format</key><integer>0</integer></dict>
</dict></dict></dict></array>
</dict></dict></plist>`, testCPU, testMemory, diskName)
	for name, data := range map[string]string{"Config.plist": plistXML, "Metadata.plist": "<plist/>"} {
		if err := os.WriteFile(filepath.Join(dir, ".vbdata", name), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func listDir(t *testing.T, dir string) []string {
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

func TestImportKeepsOnlyBundleFiles(t *testing.T) {
	src, err := DecodeVBVM(writeVBVM(t, "Boot"))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(src.DiskPath) != "Boot.img" || src.CPUCount != testCPU || src.MemorySize != testMemory {
		t.Fatalf("decoded %+v", src)
	}

	dir := filepath.Join(t.TempDir(), "baseline")
	if _, err := src.Import(dir); err != nil {
		t.Fatal(err)
	}

	want := []string{AuxiliaryStorageName, DiskName, HardwareModelName, MachineIdentifierName, BundleConfigName}
	sort.Strings(want)
	if got := listDir(t, dir); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("baseline files = %v, want %v", got, want)
	}

	b, err := LoadBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.CPUCount != testCPU || b.MemorySize != testMemory {
		t.Errorf("loaded hardware = %d CPUs / %d bytes", b.CPUCount, b.MemorySize)
	}
	if got, _ := os.ReadFile(b.DiskPath); string(got) != "Boot.img" {
		t.Errorf("disk content = %q", got)
	}

	if _, err := src.Import(dir); err == nil {
		t.Error("Import into an existing directory succeeded")
	}
}

func TestLoadBundleWithoutConfig(t *testing.T) {
	if _, err := LoadBundle(t.TempDir()); !errors.Is(err, ErrNoBundleConfig) {
		t.Fatalf("err = %v, want ErrNoBundleConfig", err)
	}
}

func TestMigrateVBVMInPlace(t *testing.T) {
	dir := writeVBVM(t, "Boot")

	b, err := MigrateVBVM(dir)
	if err != nil {
		t.Fatal(err)
	}
	if b.DiskPath != filepath.Join(dir, DiskName) {
		t.Errorf("DiskPath = %q", b.DiskPath)
	}
	if _, err := os.Stat(filepath.Join(dir, "Boot.img")); !os.IsNotExist(err) {
		t.Errorf("old disk name still present: %v", err)
	}
	if _, err := LoadBundle(dir); err != nil {
		t.Errorf("LoadBundle after migration: %v", err)
	}
}

func TestSnapshotClonesWithoutMutatingBaseline(t *testing.T) {
	src, err := DecodeVBVM(writeVBVM(t, "Disk"))
	if err != nil {
		t.Fatal(err)
	}
	base, err := src.Import(filepath.Join(t.TempDir(), "baseline"))
	if err != nil {
		t.Fatal(err)
	}
	orig := *base

	dir := t.TempDir()
	snap, err := base.Snapshot(dir)
	if err != nil {
		t.Fatal(err)
	}

	if *base != orig {
		t.Fatalf("baseline bundle mutated: %+v", base)
	}
	if snap.RootPath != dir || snap.CPUCount != base.CPUCount || snap.MemorySize != base.MemorySize {
		t.Errorf("snapshot = %+v", snap)
	}
	for _, p := range []string{snap.AuxiliaryStoragePath, snap.HardwareModelPath,
		snap.MachineIdentifierPath, snap.DiskPath} {
		if filepath.Dir(p) != dir {
			t.Errorf("%s not inside snapshot dir", p)
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
