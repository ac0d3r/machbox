package config

import (
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

const (
	rawDisk = 0
)

type vbvmPlist struct {
	Hardware struct {
		CPUCount       uint   `plist:"cpuCount,omitempty"`
		MemorySize     uint64 `plist:"memorySize,omitempty"`
		StorageDevices []struct {
			Backing struct {
				ManagedImage struct {
					Disk struct {
						Filename string `plist:"filename,omitempty"`
						Format   int    `plist:"format,omitempty"`
					} `plist:"_0,omitempty"`
				} `plist:"managedImage,omitempty"`
			} `plist:"backing,omitempty"`
		} `plist:"_storageDevices,omitempty"`
	} `plist:"hardware,omitempty"`
}

// DecodeVBVM reads a VirtualBuddy .vbvm bundle and returns a Bundle that
// points at its files. Only import needs this: once imported, a baseline is a
// machbox bundle (see Bundle.Import) and the VirtualBuddy metadata is unused.
func DecodeVBVM(path string) (*Bundle, error) {
	if path == "" {
		return nil, fmt.Errorf("vbvm path is empty")
	}

	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat vbvm path %q: %w", path, err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("vbvm path %q is not a directory", path)
	}

	// parse .vbdata/Config.plist
	plistPath := filepath.Join(path, ".vbdata", "Config.plist")
	// #nosec G304 -- plistPath is constructed from validated directory path.
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return nil, fmt.Errorf("read VirtualBuddy config plist %q: %w", plistPath, err)
	}

	var pcfg vbvmPlist
	if _, err := plist.Unmarshal(data, &pcfg); err != nil {
		return nil, fmt.Errorf("decode VirtualBuddy config plist %q: %w", plistPath, err)
	}

	diskPath, err := decodeDiskPath(path, pcfg)
	if err != nil {
		return nil, err
	}

	b := bundleAt(path)
	b.DiskPath = diskPath
	b.CPUCount = pcfg.Hardware.CPUCount
	b.MemorySize = pcfg.Hardware.MemorySize
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("invalid vbvm bundle %q: %w", path, err)
	}
	return b, nil
}

// MigrateVBVM converts, in place, a baseline imported as a whole VirtualBuddy
// bundle by older machbox versions: it renames the disk to DiskName and
// writes the bundle config. The .vbdata metadata is left as is but unused.
func MigrateVBVM(dir string) (*Bundle, error) {
	src, err := DecodeVBVM(dir)
	if err != nil {
		return nil, err
	}

	dst := bundleAt(dir)
	if src.DiskPath != dst.DiskPath {
		if err := os.Rename(src.DiskPath, dst.DiskPath); err != nil {
			return nil, fmt.Errorf("rename disk image: %w", err)
		}
	}
	dst.CPUCount = src.CPUCount
	dst.MemorySize = src.MemorySize
	if err := dst.writeConfig(); err != nil {
		return nil, err
	}
	return LoadBundle(dir)
}

func decodeDiskPath(rootPath string, pcfg vbvmPlist) (string, error) {
	if len(pcfg.Hardware.StorageDevices) == 0 {
		return "", fmt.Errorf("VirtualBuddy config has no storage devices")
	}

	disk := pcfg.Hardware.StorageDevices[0].Backing.ManagedImage.Disk

	var diskName string
	switch disk.Format {
	case rawDisk:
		diskName = disk.Filename + ".img"
	default:
		return "", fmt.Errorf("unsupported VirtualBuddy disk format %d for disk %q", disk.Format, disk.Filename)
	}

	diskPath := filepath.Join(rootPath, diskName)
	if err := requireFile(diskPath); err != nil {
		return "", err
	}

	return diskPath, nil
}
