package db

import (
	"path/filepath"
	"testing"

	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// vmV1 is the baselines table before SIP state was recorded.
type vmV1 struct {
	UUID string `gorm:"primaryKey;type:text"`
	Name string
}

func (vmV1) TableName() string { return "vms" }

func TestMigrateMarksExistingBaselinesSIPDisabled(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "old.sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&vmV1{}); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&vmV1{UUID: "old", Name: "old"}).Error; err != nil {
		t.Fatal(err)
	}

	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&VM{UUID: "new", Name: "new"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil { // already migrated: leaves records alone
		t.Fatal(err)
	}

	var old, fresh VM
	db.First(&old, "uuid = ?", "old")
	db.First(&fresh, "uuid = ?", "new")
	if !old.SIPDisabled || fresh.SIPDisabled {
		t.Errorf("old SIPDisabled=%v (want true), new SIPDisabled=%v (want false)", old.SIPDisabled, fresh.SIPDisabled)
	}
}
