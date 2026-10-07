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

	return _db.AutoMigrate(&VM{}, &Report{})
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
