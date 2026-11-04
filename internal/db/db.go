package db

import (
	"fmt"

	"github.com/ac0d3r/machbox/internal/assets"

	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var _db *gorm.DB

func InitDB() (err error) {
	_db, err = gorm.Open(sqlite.Open(assets.DBPath()))
	if err != nil {
		return err
	}
	return migrate(_db)
}

// sipDisabledFeatures is the features column of a baseline known only to
// have SIP disabled.
const sipDisabledFeatures = `["sip-disabled"]`

func migrate(db *gorm.DB) error {
	m := db.Migrator()
	old := m.HasTable(&VM{}) && !m.HasColumn(&VM{}, "features")
	hasSIPColumn := old && m.HasColumn(&VM{}, "sip_disabled")
	if err := db.AutoMigrate(&VM{}); err != nil {
		return err
	}
	if !old {
		return nil
	}
	// SIP state used to be a column, and before that imports required SIP
	// disabled. Nothing else was recorded: setup records it from now on.
	where := "1 = 1"
	if hasSIPColumn {
		where = "sip_disabled = 1"
	}
	if err := db.Exec("UPDATE vms SET features = ? WHERE "+where, sipDisabledFeatures).Error; err != nil {
		return fmt.Errorf("migrate baselines: %w", err)
	}
	if hasSIPColumn {
		// Not m.DropColumn: it rebuilds the table from parsed DDL.
		if err := db.Exec("ALTER TABLE vms DROP COLUMN sip_disabled").Error; err != nil {
			return fmt.Errorf("migrate baselines: %w", err)
		}
	}
	return nil
}

func CloseDB() error {
	if _db == nil {
		return nil
	}

	sqldb, err := _db.DB()
	if err != nil {
		return err
	}

	err = sqldb.Close()
	_db = nil

	if err != nil {
		return fmt.Errorf("close db: %w", err)
	}
	return nil
}
