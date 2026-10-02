package db

import (
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

	return _db.AutoMigrate()
}

func CloseDB() error {
	sqldb, err := _db.DB()
	if err != nil {
		return err
	}
	return sqldb.Close()
}
