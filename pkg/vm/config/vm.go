package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	vz "github.com/Code-Hex/vz/v4"
)

const (
	DefaultDisplayWidth         = int64(1920)
	DefaultDisplayHeight        = int64(1200)
	DefaultDisplayPixelsPerInch = int64(80)

	// NetworkNAT is vz NAT (vmnet): the system forwards the traffic.
	NetworkNAT = "nat"
	// NetworkGateway goes through machbox's user-mode gateway on the host,
	// which can capture the traffic.
	NetworkGateway = "gateway"
	// NetworkGatewayPublic is NetworkGateway limited to public addresses.
	NetworkGatewayPublic = "gateway-public"
)

var NetworkModes = []string{NetworkNAT, NetworkGateway, NetworkGatewayPublic}

// ParseNetwork returns the network for mode: "none" (or empty) or one of
// NetworkModes, case-insensitively.
func ParseNetwork(mode string) (Network, error) {
	if strings.EqualFold(mode, "none") || mode == "" {
		return Network{}, nil
	}
	for _, m := range NetworkModes {
		if strings.EqualFold(mode, m) {
			return Network{Enable: true, Mode: m}, nil
		}
	}
	return Network{}, fmt.Errorf("unknown network %q (none, %s)", mode, strings.Join(NetworkModes, ", "))
}

type Network struct {
	Enable bool
	Mode   string
	// File is the VM end of a connected datagram socket (the gateway modes).
	File *os.File
}

// Gateway reports whether n goes through the host gateway.
func (n Network) Gateway() bool {
	return n.Enable && (n.Mode == NetworkGateway || n.Mode == NetworkGatewayPublic)
}

type VMOptions struct {
	DisplayWidth  int64
	DisplayHeight int64
	Disks         []StorageDisk
	Shares        []ShareDir
	// AutomountShares appear in a macOS guest under
	// /Volumes/My Shared Files/<Tag> with nothing to mount; Tag is the
	// directory name there and must be unique.
	AutomountShares []ShareDir
	Network         Network
}

type ShareDir struct {
	Dir      string
	Tag      string
	ReadOnly bool
}

type StorageDisk struct {
	Path     string
	ReadOnly bool
}

func NewMacVMConf(
	bundle *Bundle,
	opts *VMOptions,
) (*vz.VirtualMachineConfiguration, error) {
	if bundle == nil {
		return nil, fmt.Errorf("bundle is nil")
	}
	if bundle.DiskPath == "" {
		return nil, fmt.Errorf("bundle disk path is empty")
	}

	pcfg, err := newPlatformConf(bundle)
	if err != nil {
		return nil, fmt.Errorf("failed to create platform configuration: %w", err)
	}

	if opts == nil {
		opts = &VMOptions{}
	}

	if opts.DisplayWidth <= 0 {
		opts.DisplayWidth = DefaultDisplayWidth
	}

	if opts.DisplayHeight <= 0 {
		opts.DisplayHeight = DefaultDisplayHeight
	}

	opts.Disks = normalizeDisks(
		bundle.DiskPath,
		opts.Disks)

	bootloader, err := vz.NewMacOSBootLoader()
	if err != nil {
		return nil, fmt.Errorf("create macOS bootloader: %w", err)
	}

	vmcfg, err := vz.NewVirtualMachineConfiguration(
		bootloader,
		bundle.CPUCount,
		bundle.MemorySize,
	)
	if err != nil {
		return nil, fmt.Errorf("create virtual machine configuration: %w", err)
	}

	vmcfg.SetPlatformVirtualMachineConfiguration(pcfg)

	if err := configureGraphics(vmcfg, opts.DisplayWidth, opts.DisplayHeight); err != nil {
		return nil, err
	}

	if err := configureStorage(vmcfg, opts.Disks); err != nil {
		return nil, err
	}

	if err := configurePointingDevices(vmcfg); err != nil {
		return nil, err
	}

	if err := configureKeyboard(vmcfg); err != nil {
		return nil, err
	}

	if err := configureEntropy(vmcfg); err != nil {
		return nil, err
	}

	if err := configureVirtioSocket(vmcfg); err != nil {
		return nil, err
	}

	if err := configureFileSystemDevice(vmcfg, opts.Shares, opts.AutomountShares); err != nil {
		return nil, err
	}

	if err := configureNetwork(vmcfg, opts.Network); err != nil {
		return nil, err
	}

	validated, err := vmcfg.Validate()
	if err != nil {
		return nil, fmt.Errorf("invalid virtual machine configuration: %w", err)
	}
	if !validated {
		return nil, errors.New("invalid virtual machine configuration")
	}

	return vmcfg, nil
}

func configureGraphics(
	vmcfg *vz.VirtualMachineConfiguration,
	width, height int64,
) error {
	dev, err := vz.NewMacGraphicsDeviceConfiguration()
	if err != nil {
		return fmt.Errorf("create graphics device configuration: %w", err)
	}

	display, err := vz.NewMacGraphicsDisplayConfiguration(
		width,
		height,
		DefaultDisplayPixelsPerInch,
	)
	if err != nil {
		return fmt.Errorf("create graphics device configuration: %w", err)
	}

	dev.SetDisplays(display)

	vmcfg.SetGraphicsDevicesVirtualMachineConfiguration(
		[]vz.GraphicsDeviceConfiguration{dev},
	)

	return nil
}

func configureStorage(
	vmcfg *vz.VirtualMachineConfiguration,
	disks []StorageDisk,
) error {
	var devices []vz.StorageDeviceConfiguration

	for _, d := range disks {
		dick, err := vz.NewDiskImageStorageDeviceAttachment(d.Path, d.ReadOnly)
		if err != nil {
			return fmt.Errorf("create disk attachment for %q: %w", d.Path, err)
		}

		block, err := vz.NewVirtioBlockDeviceConfiguration(dick)
		if err != nil {
			return fmt.Errorf("create block device for %q: %w", d.Path, err)
		}

		devices = append(devices, block)
	}

	vmcfg.SetStorageDevicesVirtualMachineConfiguration(devices)
	return nil
}

func configurePointingDevices(
	vmcfg *vz.VirtualMachineConfiguration,
) error {
	usbPointer, err := vz.NewUSBScreenCoordinatePointingDeviceConfiguration()
	if err != nil {
		return fmt.Errorf("create USB pointing device configuration: %w", err)
	}

	devices := []vz.PointingDeviceConfiguration{usbPointer}

	if trackpad, err := vz.NewMacTrackpadConfiguration(); err == nil {
		devices = append(devices, trackpad)
	}

	vmcfg.SetPointingDevicesVirtualMachineConfiguration(devices)
	return nil
}

func configureKeyboard(
	vmcfg *vz.VirtualMachineConfiguration,
) error {
	keyboard, err := vz.NewUSBKeyboardConfiguration()
	if err != nil {
		return fmt.Errorf("create USB keyboard configuration: %w", err)
	}

	vmcfg.SetKeyboardsVirtualMachineConfiguration(
		[]vz.KeyboardConfiguration{keyboard},
	)

	return nil
}

func configureEntropy(
	vmcfg *vz.VirtualMachineConfiguration,
) error {
	entropy, err := vz.NewVirtioEntropyDeviceConfiguration()
	if err != nil {
		return fmt.Errorf("create entropy device configuration: %w", err)
	}

	vmcfg.SetEntropyDevicesVirtualMachineConfiguration(
		[]*vz.VirtioEntropyDeviceConfiguration{entropy},
	)

	return nil
}

func configureVirtioSocket(
	vmcfg *vz.VirtualMachineConfiguration,
) error {
	socket, err := vz.NewVirtioSocketDeviceConfiguration()
	if err != nil {
		return fmt.Errorf("create virtio socket device configuration: %w", err)
	}

	vmcfg.SetSocketDevicesVirtualMachineConfiguration(
		[]vz.SocketDeviceConfiguration{socket},
	)

	return nil
}

func configureFileSystemDevice(
	vmcfg *vz.VirtualMachineConfiguration,
	shares, automount []ShareDir,
) error {
	var devices []vz.DirectorySharingDeviceConfiguration

	if len(automount) > 0 {
		dirs := make(map[string]*vz.SharedDirectory, len(automount))
		for _, s := range automount {
			if _, dup := dirs[s.Tag]; dup {
				return fmt.Errorf("two shared directories named %q", s.Tag)
			}
			dir, err := vz.NewSharedDirectory(s.Dir, s.ReadOnly)
			if err != nil {
				return fmt.Errorf("create shared directory %s: %w", s.Dir, err)
			}
			dirs[s.Tag] = dir
		}
		share, err := vz.NewMultipleDirectoryShare(dirs)
		if err != nil {
			return fmt.Errorf("create multiple directory share: %w", err)
		}
		tag, err := vz.MacOSGuestAutomountTag()
		if err != nil {
			return fmt.Errorf("macOS automount tag: %w", err)
		}
		fsDev, err := vz.NewVirtioFileSystemDeviceConfiguration(tag)
		if err != nil {
			return fmt.Errorf("create virtio filesystem device configuration: %w", err)
		}
		fsDev.SetDirectoryShare(share)
		devices = append(devices, fsDev)
	}

	for _, s := range shares {
		dir, err := vz.NewSharedDirectory(s.Dir, s.ReadOnly)
		if err != nil {
			return fmt.Errorf("create shared directory: %w", err)
		}

		share, err := vz.NewSingleDirectoryShare(dir)
		if err != nil {
			return fmt.Errorf("create single directory share: %w", err)
		}

		fsDev, err := vz.NewVirtioFileSystemDeviceConfiguration(s.Tag)
		if err != nil {
			return fmt.Errorf("create virtio filesystem device configuration: %w", err)
		}
		fsDev.SetDirectoryShare(share)

		devices = append(devices, fsDev)
	}

	vmcfg.SetDirectorySharingDevicesVirtualMachineConfiguration(devices)
	return nil
}

func configureNetwork(
	vmcfg *vz.VirtualMachineConfiguration,
	cfg Network,
) error {
	if !cfg.Enable {
		return nil
	}

	devices := []*vz.VirtioNetworkDeviceConfiguration{}
	var attachment vz.NetworkDeviceAttachment
	var err error

	switch cfg.Mode {
	case NetworkNAT:
		if attachment, err = vz.NewNATNetworkDeviceAttachment(); err != nil {
			return fmt.Errorf("create NAT network device attachment: %w", err)
		}
	case NetworkGateway, NetworkGatewayPublic:
		if cfg.File == nil {
			return errors.New("gateway network needs a socket")
		}
		if attachment, err = vz.NewFileHandleNetworkDeviceAttachment(cfg.File); err != nil {
			return fmt.Errorf("create file handle network device attachment: %w", err)
		}
	}

	if attachment != nil {
		dev, err := vz.NewVirtioNetworkDeviceConfiguration(attachment)
		if err != nil {
			return fmt.Errorf("create virtio network device configuration: %w", err)
		}
		devices = append(devices, dev)
	}

	vmcfg.SetNetworkDevicesVirtualMachineConfiguration(devices)
	return nil
}

func normalizeDisks(
	mainDisk string,
	disks []StorageDisk,
) []StorageDisk {
	var normalized []StorageDisk

	seen := make(map[string]struct{})
	hasMainDisk := false

	for _, d := range disks {
		if d.Path == "" {
			continue
		}

		if _, ok := seen[d.Path]; ok {
			continue
		}

		seen[d.Path] = struct{}{}

		// main system disk must always be writable
		if d.Path == mainDisk {
			hasMainDisk = true

			normalized = append(normalized, StorageDisk{
				Path:     d.Path,
				ReadOnly: false,
			})

			continue
		}

		normalized = append(normalized, d)
	}

	if !hasMainDisk {
		normalized = append(
			[]StorageDisk{
				{
					Path:     mainDisk,
					ReadOnly: false,
				},
			},
			normalized...,
		)
	}

	return normalized
}
