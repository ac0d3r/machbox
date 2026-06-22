package report

import (
	"time"

	"github.com/ac0d3r/machbox/core/assets"
	"github.com/ac0d3r/machbox/core/vsock/protocol"

	sqlite "gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Report struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SHA256     string `gorm:"index" json:"sha256"`
	SampleName string `json:"sample_name"`
	FileSize   int64  `json:"file_size"`
	FileType   string `json:"file_type"`

	AnalysisEnv   protocol.GuestInfo `gorm:"serializer:json" json:"analysis_env"`
	StaticResult  map[string]any     `gorm:"serializer:json" json:"static_result"`
	DynamicResult *DynamicReport     `gorm:"serializer:json" json:"dynamic_result,omitempty"`
	Verdict       string             `json:"verdict"` // basic verdict: clean, suspicious, malicious, unknown
	Error         string             `json:"error"`
}

var _db *gorm.DB

func InitDB() (err error) {
	_db, err = gorm.Open(sqlite.Open(assets.DBPath()))
	if err != nil {
		return err
	}

	return _db.AutoMigrate(&Report{})
}

func CloseDB() error {
	sqldb, err := _db.DB()
	if err != nil {
		return err
	}
	return sqldb.Close()
}

func CreateReport(r *Report) error {
	return _db.Create(r).Error
}

func ListReports() ([]Report, error) {
	var reports []Report
	err := _db.Order("created_at desc").Find(&reports).Error
	return reports, err
}

func GetReport(id uint) (*Report, error) {
	var r Report
	err := _db.First(&r, id).Error
	if err != nil {
		return nil, err
	}
	return &r, nil
}
