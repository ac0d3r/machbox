package db

import (
	"time"
)

type VM struct {
	UUID string `gorm:"primaryKey;type:text" json:"uuid"`
	Name string `gorm:"index;type:text" json:"name"`

	OSName    string `json:"os_name"`
	OSVersion string `json:"os_version"`
	OSBuild   string `json:"os_build"`

	AgentVersion string `json:"agent_version"`

	Error string `json:"error,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (VM) TableName() string { return "vms" }

func SaveVM(vm *VM) error {
	return _db.Save(vm).Error
}

func CreateVM(vm *VM) error {
	return _db.Create(vm).Error
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
