package config

import (
	"testing"

	vz "github.com/Code-Hex/vz/v4"
)

func TestAutomountSharesConfigure(t *testing.T) {
	boot, err := vz.NewMacOSBootLoader()
	if err != nil {
		t.Fatal(err)
	}
	vmcfg, err := vz.NewVirtualMachineConfiguration(boot, 2, 4<<30)
	if err != nil {
		t.Fatal(err)
	}
	a, b := t.TempDir(), t.TempDir()
	if err := configureFileSystemDevice(vmcfg, nil, []ShareDir{
		{Dir: a, Tag: "a"}, {Dir: b, Tag: "b", ReadOnly: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := configureFileSystemDevice(vmcfg, nil, []ShareDir{{Dir: a, Tag: "x"}, {Dir: b, Tag: "x"}}); err == nil {
		t.Error("duplicate tags accepted")
	}
}
