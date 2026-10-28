package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	vz "github.com/Code-Hex/vz/v4"
)

// Fixed file names of a machbox baseline bundle.
const (
	AuxiliaryStorageName  = "AuxiliaryStorage"
	HardwareModelName     = "HardwareModel"
	MachineIdentifierName = "MachineIdentifier"
	DiskName              = "Disk.img"
	BundleConfigName      = "config.json"

	bundleConfigVersion = 1
)

// ErrNoBundleConfig is returned by LoadBundle when dir has no config.json
// (e.g. a baseline imported before the machbox bundle format).
var ErrNoBundleConfig = errors.New("bundle config not found")

// Bundle describes a macOS VM on disk: the platform files Virtualization
// framework needs, the boot disk, and the hardware to boot it with.
//
// A machbox baseline is a directory holding exactly the files named by the
// constants above. Importers (see DecodeVBVM) produce a Bundle that points
// at foreign files; Import turns it into a baseline.
type Bundle struct {
	RootPath string

	AuxiliaryStoragePath  string
	HardwareModelPath     string
	MachineIdentifierPath string
	DiskPath              string

	CPUCount   uint
	MemorySize uint64
}

type bundleConfig struct {
	Version    int    `json:"version"`
	CPUCount   uint   `json:"cpu_count"`
	MemorySize uint64 `json:"memory_size"`
}

// LoadBundle opens a machbox baseline directory.
func LoadBundle(dir string) (*Bundle, error) {
	// #nosec G304 -- dir is a managed baseline directory.
	data, err := os.ReadFile(filepath.Join(dir, BundleConfigName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w in %s", ErrNoBundleConfig, dir)
		}
		return nil, fmt.Errorf("read bundle config: %w", err)
	}

	var cfg bundleConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("decode bundle config %s: %w", dir, err)
	}
	if cfg.Version != bundleConfigVersion {
		return nil, fmt.Errorf("unsupported bundle config version %d in %s", cfg.Version, dir)
	}

	b := bundleAt(dir)
	b.CPUCount = cfg.CPUCount
	b.MemorySize = cfg.MemorySize
	if err := b.validate(); err != nil {
		return nil, fmt.Errorf("invalid bundle %s: %w", dir, err)
	}
	return b, nil
}

// Import APFS-clones the bundle's files into dir, which must not exist, and
// writes its config, producing a machbox baseline. b is not modified.
func (b *Bundle) Import(dir string) (*Bundle, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create bundle directory: %w", err)
	}
	dst, err := b.cloneInto(dir)
	if err != nil {
		return nil, err
	}
	if err := dst.writeConfig(); err != nil {
		return nil, err
	}
	return dst, nil
}

// Snapshot APFS-clones the files a VM writes to into dir (which must exist)
// and returns a Bundle pointing at the clones. b is not modified, so the
// baseline stays pristine while the snapshot boots; removing dir discards it.
func (b *Bundle) Snapshot(dir string) (*Bundle, error) {
	return b.cloneInto(dir)
}

func bundleAt(dir string) *Bundle {
	return &Bundle{
		RootPath:              dir,
		AuxiliaryStoragePath:  filepath.Join(dir, AuxiliaryStorageName),
		HardwareModelPath:     filepath.Join(dir, HardwareModelName),
		MachineIdentifierPath: filepath.Join(dir, MachineIdentifierName),
		DiskPath:              filepath.Join(dir, DiskName),
	}
}

func (b *Bundle) files() []struct{ src, dst string } {
	d := bundleAt("")
	return []struct{ src, dst string }{
		{b.AuxiliaryStoragePath, d.AuxiliaryStoragePath},
		{b.HardwareModelPath, d.HardwareModelPath},
		{b.MachineIdentifierPath, d.MachineIdentifierPath},
		{b.DiskPath, d.DiskPath},
	}
}

func (b *Bundle) cloneInto(dir string) (*Bundle, error) {
	for _, f := range b.files() {
		if err := CloneFile(f.src, filepath.Join(dir, f.dst)); err != nil {
			return nil, err
		}
	}
	dst := bundleAt(dir)
	dst.CPUCount = b.CPUCount
	dst.MemorySize = b.MemorySize
	return dst, nil
}

func (b *Bundle) writeConfig() error {
	data, err := json.MarshalIndent(bundleConfig{
		Version:    bundleConfigVersion,
		CPUCount:   b.CPUCount,
		MemorySize: b.MemorySize,
	}, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(b.RootPath, BundleConfigName)
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("write bundle config: %w", err)
	}
	return nil
}

func (b *Bundle) validate() error {
	for _, f := range b.files() {
		if err := requireFile(f.src); err != nil {
			return err
		}
	}
	if _, err := ValidateCPUCount(b.CPUCount); err != nil {
		return fmt.Errorf("invalid CPU count %d: %w", b.CPUCount, err)
	}
	if _, err := ValidateMemorySize(b.MemorySize); err != nil {
		return fmt.Errorf("invalid memory size %d: %w", b.MemorySize, err)
	}
	return nil
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

func newPlatformConf(b *Bundle) (*vz.MacPlatformConfiguration, error) {
	storage, err := vz.NewMacAuxiliaryStorage(b.AuxiliaryStoragePath)
	if err != nil {
		return nil, fmt.Errorf("create Mac auxiliary storage from %q: %w", b.AuxiliaryStoragePath, err)
	}

	hardware, err := vz.NewMacHardwareModelWithDataPath(b.HardwareModelPath)
	if err != nil {
		return nil, fmt.Errorf("create Mac hardware model from %q: %w", b.HardwareModelPath, err)
	}

	mid, err := vz.NewMacMachineIdentifierWithDataPath(b.MachineIdentifierPath)
	if err != nil {
		return nil, fmt.Errorf("create Mac machine identifier from %q: %w", b.MachineIdentifierPath, err)
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
