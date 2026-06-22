package config

import (
	"fmt"
	"os"
	"path/filepath"

	vz "github.com/Code-Hex/vz/v3"
	"howett.net/plist"
)

const (
	rawDisk = 0
)

type VBVMConfig struct {
	RootPath     string
	SnapshotPath string

	AuxiliaryStoragePath  string
	HardwareModelPath     string
	MachineIdentifierPath string
	DiskPath              string

	CPUCount   uint
	MemorySize uint64
}

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

func DecodeVBVMPath(path string) (*VBVMConfig, error) {
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

	cfg := &VBVMConfig{
		RootPath:              path,
		AuxiliaryStoragePath:  filepath.Join(path, "AuxiliaryStorage"),
		HardwareModelPath:     filepath.Join(path, "HardwareModel"),
		MachineIdentifierPath: filepath.Join(path, "MachineIdentifier"),
	}

	if err := requireFile(cfg.AuxiliaryStoragePath); err != nil {
		return nil, err
	}

	if err := requireFile(cfg.HardwareModelPath); err != nil {
		return nil, err
	}

	if err := requireFile(cfg.MachineIdentifierPath); err != nil {
		return nil, err
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

	// check cpu & memory
	cpuCount, err := ValidateCPUCount(pcfg.Hardware.CPUCount)
	if err != nil {
		return nil, fmt.Errorf("invalid CPU count %d: %w", pcfg.Hardware.CPUCount, err)
	}
	memorySize, err := ValidateMemorySize(pcfg.Hardware.MemorySize)
	if err != nil {
		return nil, fmt.Errorf("invalid memory size %d: %w", pcfg.Hardware.MemorySize, err)
	}
	cfg.CPUCount = cpuCount
	cfg.MemorySize = memorySize

	// parse disk image
	diskPath, err := decodeDiskPath(path, pcfg)
	if err != nil {
		return nil, err
	}
	cfg.DiskPath = diskPath

	return cfg, nil
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

func requireFile(path string) error {
	stat, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("required file %q is missing or inaccessible: %w", path, err)
	}

	if stat.IsDir() {
		return fmt.Errorf("required file %q is a directory", path)
	}

	return nil
}

func NewPlatformConfWithVbvm(vbvmcfg *VBVMConfig) (pconf *vz.MacPlatformConfiguration, err error) {
	if vbvmcfg == nil {
		return nil, fmt.Errorf("VBVM config is nil")
	}

	storage, err := vz.NewMacAuxiliaryStorage(vbvmcfg.AuxiliaryStoragePath)
	if err != nil {
		return nil, fmt.Errorf("create Mac auxiliary storage from %q: %w", vbvmcfg.AuxiliaryStoragePath, err)
	}

	hardware, err := vz.NewMacHardwareModelWithDataPath(vbvmcfg.HardwareModelPath)
	if err != nil {
		return nil, fmt.Errorf("create Mac hardware model from %q: %w", vbvmcfg.HardwareModelPath, err)
	}

	mid, err := vz.NewMacMachineIdentifierWithDataPath(vbvmcfg.MachineIdentifierPath)
	if err != nil {
		return nil, fmt.Errorf("create Mac machine identifier from %q: %w", vbvmcfg.MachineIdentifierPath, err)
	}

	c, err := vz.NewMacPlatformConfiguration(
		vz.WithMacAuxiliaryStorage(storage),
		vz.WithMacHardwareModel(hardware),
		vz.WithMacMachineIdentifier(mid),
	)
	if err != nil {
		return nil, fmt.Errorf("create Mac platform configuration: %w", err)
	}

	return c, nil
}

// ValidateCPUCount validates the CPU count and returns the validated CPU count.
// If the CPU count is less than the minimum allowed CPU count, the function returns the minimum allowed CPU count and an error.
func ValidateCPUCount(cpuCount uint) (uint, error) {
	maxAllowed := vz.VirtualMachineConfigurationMaximumAllowedCPUCount()
	if cpuCount > maxAllowed {
		return maxAllowed, fmt.Errorf("cpu count %d is greater than the maximum allowed cpu count %d", cpuCount, maxAllowed)
	}

	minAllowed := vz.VirtualMachineConfigurationMinimumAllowedCPUCount()
	if cpuCount < minAllowed {
		return minAllowed, fmt.Errorf("cpu count %d is less than the minimum allowed cpu count %d", cpuCount, minAllowed)
	}

	return cpuCount, nil
}

// ValidateMemorySize validates the memory size and returns the validated memory size.
// If the memory size is less than the minimum allowed memory size, the function returns the minimum allowed memory size and an error.
func ValidateMemorySize(memorySize uint64) (uint64, error) {
	maxAllowed := vz.VirtualMachineConfigurationMaximumAllowedMemorySize()
	if memorySize > maxAllowed {
		return maxAllowed, fmt.Errorf("memory size %d is greater than the maximum allowed memory size %d", memorySize, maxAllowed)
	}

	minAllowed := vz.VirtualMachineConfigurationMinimumAllowedMemorySize()
	if memorySize < minAllowed {
		return minAllowed, fmt.Errorf("memory size %d is less than the minimum allowed memory size %d", memorySize, minAllowed)
	}

	return memorySize, nil
}
