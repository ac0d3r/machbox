package db

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
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
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "old.sqlite")), &gorm.Config{TranslateError: true})
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

// vmV3 is the baselines table with a non-unique index on name.
type vmV3 struct {
	UUID     string   `gorm:"primaryKey;type:text"`
	Name     string   `gorm:"index;type:text"`
	Features []string `gorm:"serializer:json"`
}

func (vmV3) TableName() string { return "vms" }

func TestMigrateMakesNamesUnique(t *testing.T) {
	db := openTestDB(t, &vmV3{}, &vmV3{UUID: "a", Name: "a"})
	if err := migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := migrate(db); err != nil { // already unique: nothing to do
		t.Fatal(err)
	}
	_db = db
	t.Cleanup(func() { _db = nil })
	if err := CreateVM(&VM{UUID: "b", Name: "a"}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("duplicate create: err = %v, want ErrNameTaken", err)
	}
	b := &VM{UUID: "b", Name: "b"}
	if err := CreateVM(b); err != nil {
		t.Fatal(err)
	}
	b.Name = "a"
	if err := SaveVM(b); !errors.Is(err, ErrNameTaken) {
		t.Errorf("duplicate rename: err = %v, want ErrNameTaken", err)
	}
}

func TestMigrateRefusesDuplicateNames(t *testing.T) {
	db := openTestDB(t, &vmV2{},
		&vmV2{UUID: "a", Name: "same", SIPDisabled: true},
		&vmV2{UUID: "b", Name: "same"})
	err := migrate(db)
	if err == nil || !strings.Contains(err.Error(), "same") {
		t.Fatalf("err = %v, want one naming the duplicate", err)
	}
	// All or nothing: the old schema is still there to migrate again.
	if !db.Migrator().HasColumn(&VM{}, "sip_disabled") || db.Migrator().HasColumn(&VM{}, "features") {
		t.Error("failed migration left a partial schema")
	}
}
