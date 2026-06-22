package logger

import (
	"io"
	"os"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	TimeFormat = "2006-01-02T15:04:05.000Z0700"

	DefaultMaxSize   = 100 // MB
	DefaultMaxAge    = 30  // Day
	DefaultMaxBackup = 10
)

type Config struct {
	Level     string `yaml:"level" json:"level,omitempty"`
	Output    string `yaml:"output" json:"output,omitempty"`
	MaxSize   int    `yaml:"max_size" json:"max_size,omitempty"`
	MaxAge    int    `yaml:"max_age" json:"max_age,omitempty"`
	MaxBackup int    `yaml:"max_backup" json:"max_backup,omitempty"`
	Format    bool   `yaml:"format" json:"format,omitempty"`
}

func Init(cfg *Config) error {
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = DefaultMaxSize
	}
	if cfg.MaxAge <= 0 {
		cfg.MaxAge = DefaultMaxAge
	}
	if cfg.MaxBackup <= 0 {
		cfg.MaxBackup = DefaultMaxBackup
	}
	if cfg.Level == "" {
		cfg.Level = "info"
	}

	if cfg.Format {
		logrus.SetFormatter(&logrus.JSONFormatter{TimestampFormat: TimeFormat})
	} else {
		logrus.SetFormatter(&nested.Formatter{
			TimestampFormat: TimeFormat,
			HideKeys:        false,
		})
	}

	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	logrus.SetLevel(level)

	var writers []io.Writer
	writers = append(writers, os.Stdout)
	if cfg.Output != "" {
		fileWriter := &lumberjack.Logger{
			Filename:   cfg.Output,
			MaxSize:    cfg.MaxSize,
			MaxAge:     cfg.MaxAge,
			MaxBackups: cfg.MaxBackup,
			Compress:   true,
		}
		writers = append(writers, fileWriter)
	}

	logrus.SetOutput(io.MultiWriter(writers...))
	return nil
}
