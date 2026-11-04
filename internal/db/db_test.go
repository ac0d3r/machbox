package db

import (
	"path/filepath"
	"reflect"
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

// vmV2 is the baselines table with SIP state in its own column.
type vmV2 struct {
	UUID        string `gorm:"primaryKey;type:text"`
	Name        string
	SIPDisabled bool `gorm:"column:sip_disabled"`
}

func (vmV2) TableName() string { return "vms" }

func openTestDB(t *testing.T, model any, rows ...any) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "old.sqlite")))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(model); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if err := db.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func features(t *testing.T, db *gorm.DB, uuid string) []string {
	t.Helper()
	var vm VM
	if err := db.First(&vm, "uuid = ?", uuid).Error; err != nil {
		t.Fatal(err)
	}
	return vm.Features
}

func TestMigrateV1MarksBaselinesSIPDisabled(t *testing.T) {
	db := openTestDB(t, &vmV1{}, &vmV1{UUID: "old", Name: "old"})
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&VM{UUID: "new", Name: "new"}).Error; err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil { // already migrated: leaves records alone
		t.Fatal(err)
	}
	if got := features(t, db, "old"); !reflect.DeepEqual(got, []string{"sip-disabled"}) {
		t.Errorf("old features = %v", got)
	}
	if got := features(t, db, "new"); len(got) != 0 {
		t.Errorf("new features = %v", got)
	}
}

func TestMigrateV2MovesSIPColumnIntoFeatures(t *testing.T) {
	db := openTestDB(t, &vmV2{},
		&vmV2{UUID: "off", Name: "off", SIPDisabled: true},
		&vmV2{UUID: "on", Name: "on"})
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if got := features(t, db, "off"); !reflect.DeepEqual(got, []string{"sip-disabled"}) {
		t.Errorf("off features = %v", got)
	}
	if got := features(t, db, "on"); len(got) != 0 {
		t.Errorf("on features = %v", got)
	}
	if db.Migrator().HasColumn(&VM{}, "sip_disabled") {
		t.Error("sip_disabled column kept")
	}
}
