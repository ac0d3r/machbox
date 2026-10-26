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

func migrate(db *gorm.DB) error {
	m := db.Migrator()
	addsSIP := m.HasTable(&VM{}) && !m.HasColumn(&VM{}, "SIPDisabled")
	if err := db.AutoMigrate(&VM{}); err != nil {
		return err
	}
	if addsSIP {
		// Imports used to require SIP disabled, so every existing baseline has it.
		err := db.Session(&gorm.Session{AllowGlobalUpdate: true}).
			Model(&VM{}).UpdateColumn("SIPDisabled", true).Error
		if err != nil {
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
