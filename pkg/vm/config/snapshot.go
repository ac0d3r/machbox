package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func (v *VBVMConfig) CreateSnapshot() error {
	runs := filepath.Join(v.RootPath, fmt.Sprintf("runs_%s", strconv.FormatInt(time.Now().UnixNano(), 36)))
	if err := os.MkdirAll(runs, 0o700); err != nil {
		return fmt.Errorf("create snapshot dir: %w", err)
	}

	v.SnapshotPath = runs

	files := []struct {
		src  string
		name string
		ptr  *string
	}{
		{v.AuxiliaryStoragePath, "AuxiliaryStorage", &v.AuxiliaryStoragePath},
		{v.MachineIdentifierPath, "MachineIdentifier", &v.MachineIdentifierPath},
		{v.HardwareModelPath, "HardwareModel", &v.HardwareModelPath},
		{v.DiskPath, filepath.Base(v.DiskPath), &v.DiskPath},
	}

	for _, f := range files {
		if f.src == "" {
			continue
		}
		dst := filepath.Join(runs, f.name)
		if err := cloneFile(f.src, dst); err != nil {
			return fmt.Errorf("clone %s: %w", f.src, err)
		}
		*f.ptr = dst
	}

	return nil
}

func cloneFile(src, dst string) error {
	if err := unix.Clonefile(src, dst, 0); err != nil {
		logrus.Debugf("APFS clonefile failed for %s, falling back to regular copy", src)
		return err
	}

	return nil
}

func (v *VBVMConfig) RemoveSnapshot() error {
	if v.SnapshotPath == "" {
		return nil
	}

	if err := os.RemoveAll(v.SnapshotPath); err != nil {
		return fmt.Errorf("remove snapshot: %w", err)
	}

	logrus.Debugf("removed snapshot %s", v.SnapshotPath)
	return nil
}
