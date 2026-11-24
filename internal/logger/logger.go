package logger

import (
	"os"

	nested "github.com/antonfisher/nested-logrus-formatter"
	"github.com/sirupsen/logrus"
)

const TimeFormat = "2006-01-02T15:04:05.000Z0700"

type Config struct {
	Level string
	JSON  bool
}

// Init sets up logging to stderr, which keeps stdout for command output.
func Init(cfg *Config) error {
	if cfg.Level == "" {
		cfg.Level = "info"
	}

	if cfg.JSON {
		logrus.SetFormatter(&logrus.JSONFormatter{TimestampFormat: TimeFormat})
	} else {
		logrus.SetFormatter(&nested.Formatter{
			TimestampFormat: TimeFormat,
			HideKeys:        false,
			// Escape codes are for a terminal: a pipe or a file gets plain text.
			NoColors: !isTerminal(os.Stderr),
		})
	}

	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		return err
	}
	logrus.SetLevel(level)
	logrus.SetOutput(os.Stderr)
	return nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
