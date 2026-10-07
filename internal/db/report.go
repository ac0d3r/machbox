package db

import (
	"time"

	"github.com/ac0d3r/machbox/internal/agent"

	"gorm.io/gorm"
)

// Report is a persisted analysis result.
// DynamicResult is JSON (typically report.DynamicReport when written).
type Report struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	SHA256     string `gorm:"index" json:"sha256"`
	SampleName string `json:"sample_name"`
	FileSize   int64  `json:"file_size"`
	FileType   string `json:"file_type"`

	AnalysisEnv   agent.GuestInfo `gorm:"serializer:json" json:"analysis_env"`
	StaticResult  map[string]any  `gorm:"serializer:json" json:"static_result"`
	DynamicResult any             `gorm:"serializer:json" json:"dynamic_result,omitempty"`
	Verdict       string          `json:"verdict"` // clean, suspicious, malicious, unknown
	Error         string          `json:"error"`
}

func (Report) TableName() string { return "reports" }

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
	if err := _db.First(&r, id).Error; err != nil {
		return nil, err
	}
	return &r, nil
}
