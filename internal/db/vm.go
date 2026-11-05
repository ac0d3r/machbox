package db

import (
	"errors"
	"slices"
	"time"

	"gorm.io/gorm"
)

type VM struct {
	UUID string `gorm:"primaryKey;type:text" json:"uuid"`
	// Name is unique: baselines are looked up by name.
	Name string `gorm:"uniqueIndex:idx_vms_name;type:text" json:"name"`

	OSName    string `json:"os_name"`
	OSVersion string `json:"os_version"`
	OSBuild   string `json:"os_build"`

	AgentVersion string `json:"agent_version"`
	// Features are what the baseline had when setup last finished (see
	// agent.Features); only import and setup change a baseline.
	Features []string `gorm:"serializer:json" json:"features"`

	Error string `json:"error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (VM) TableName() string { return "vms" }

// HasFeature reports whether the baseline has feature f.
func (vm *VM) HasFeature(f string) bool { return slices.Contains(vm.Features, f) }

func SaveVM(vm *VM) error {
	return nameTaken(_db.Save(vm).Error)
}

func CreateVM(vm *VM) error {
	return nameTaken(_db.Create(vm).Error)
}

// nameTaken turns a unique-constraint error, which only the name can raise
// (UUIDs are random), into ErrNameTaken.
func nameTaken(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return ErrNameTaken
	}
	return err
}

func DeleteVM(uuid string) error {
	return _db.Delete(&VM{}, "uuid = ?", uuid).Error
}

func GetVMByUUID(uuid string) (*VM, error) {
	var vm VM
	if err := _db.First(&vm, "uuid = ?", uuid).Error; err != nil {
		return nil, err
	}
	return &vm, nil
}

func FindVMsByName(name string) ([]VM, error) {
	var vms []VM
	if err := _db.Where("name = ?", name).Order("created_at asc").Find(&vms).Error; err != nil {
		return nil, err
	}
	return vms, nil
}

func ListVMs() ([]VM, error) {
	var vms []VM
	err := _db.Order("created_at asc").Find(&vms).Error
	return vms, err
}
