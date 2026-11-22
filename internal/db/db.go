package db

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ac0d3r/machbox/internal/assets"

	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var _db *gorm.DB

func InitDB() (err error) {
	_db, err = gorm.Open(sqlite.Open(assets.DBPath()), &gorm.Config{TranslateError: true})
	if err != nil {
		return err
	}
	return migrate(_db)
}

// ErrNameTaken is returned when a baseline would get the name of another.
var ErrNameTaken = errors.New("a baseline with that name already exists")

// sipDisabledFeatures is the features column of a baseline known only to
// have SIP disabled.
const sipDisabledFeatures = `["sip-disabled"]`

// migrate brings the database to the current schema, all or nothing: a
// failed step leaves it as it was, to be migrated again on the next start.
func migrate(db *gorm.DB) error {
	return db.Transaction(func(tx *gorm.DB) error {
		if err := migrateTx(tx); err != nil {
			return fmt.Errorf("migrate baselines: %w", err)
		}
		return nil
	})
}

func migrateTx(db *gorm.DB) error {
	m := db.Migrator()
	old := m.HasTable(&VM{}) && !m.HasColumn(&VM{}, "features")
	hasSIPColumn := old && m.HasColumn(&VM{}, "sip_disabled")
	if m.HasTable(&VM{}) {
		if err := dropNonUniqueNameIndex(db); err != nil {
			return err
		}
	}
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
		return err
	}
	if hasSIPColumn {
		// Not m.DropColumn: it rebuilds the table from parsed DDL.
		if err := db.Exec("ALTER TABLE vms DROP COLUMN sip_disabled").Error; err != nil {
			return err
		}
	}
	return nil
}

// nameIndex is the index on vms.name, unique since baseline names are.
const nameIndex = "idx_vms_name"

// dropNonUniqueNameIndex drops nameIndex if it is the old, non-unique one,
// for AutoMigrate to create it again unique. Duplicate names, which an old
// version may have let in, are reported instead.
func dropNonUniqueNameIndex(db *gorm.DB) error {
	var dups []string
	if err := db.Raw("SELECT name FROM vms GROUP BY name HAVING COUNT(*) > 1").Scan(&dups).Error; err != nil {
		return err
	}
	if len(dups) > 0 {
		return fmt.Errorf("baseline names must be unique, but several baselines are named %s; "+
			"rename all but one with the machbox version that made them", strings.Join(dups, ", "))
	}
	var ddl []string
	if err := db.Raw("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?", nameIndex).Scan(&ddl).Error; err != nil {
		return err
	}
	if len(ddl) == 0 || strings.Contains(strings.ToUpper(ddl[0]), "UNIQUE") {
		return nil
	}
	return db.Exec("DROP INDEX " + nameIndex).Error
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
