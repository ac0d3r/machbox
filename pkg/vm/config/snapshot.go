package config

import (
	"fmt"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Snapshot APFS-clones the bundle files a VM writes to (auxiliary storage,
// machine identifier, hardware model, disk) into dir and returns a copy of v
// that points at the clones. v itself is not modified, so the baseline stays
// pristine while the snapshot boots. dir must exist and be on the same APFS
// volume as the bundle; removing dir discards the snapshot.
func (v *VBVMConfig) Snapshot(dir string) (*VBVMConfig, error) {
	snap := *v
	snap.RootPath = dir

	files := []struct {
		name string
		ptr  *string
	}{
		{"AuxiliaryStorage", &snap.AuxiliaryStoragePath},
		{"MachineIdentifier", &snap.MachineIdentifierPath},
		{"HardwareModel", &snap.HardwareModelPath},
		{filepath.Base(v.DiskPath), &snap.DiskPath},
	}

	for _, f := range files {
		if *f.ptr == "" {
			continue
		}
		dst := filepath.Join(dir, f.name)
		if err := CloneFile(*f.ptr, dst); err != nil {
			return nil, err
		}
		*f.ptr = dst
	}

	return &snap, nil
}

// CloneFile APFS-clones src (a file or directory) to dst copy-on-write. dst
// must not exist, and both must be on the same APFS volume.
func CloneFile(src, dst string) error {
	if err := unix.Clonefile(src, dst, 0); err != nil {
		return fmt.Errorf("APFS clonefile %s → %s: %w", src, dst, err)
	}
	return nil
}
