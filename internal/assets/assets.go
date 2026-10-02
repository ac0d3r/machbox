package assets

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed data
var dataFS embed.FS

const (
	appDirName = ".machbox"

	dbName = "machbox.sqlite"

	dataDirName     = "data"
	guestDMGName    = "guest.dmg"
	guestDMGSum     = guestDMGName + ".sha256"
	dynamicToolName = "dynamictool"
	staticToolName  = "statictool"
)

var (
	appDir  string
	dataDir string

	initOnce sync.Once
)

func init() {
	home, _ := os.UserHomeDir()
	appDir = filepath.Join(home, appDirName)
	dataDir = filepath.Join(appDir, dataDirName)
}

func Init() (err error) {
	initOnce.Do(func() {
		err = doInit()
	})
	return
}

func doInit() error {
	for _, dir := range []string{appDir, dataDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	if err := extracDatatFile(guestDMGName, guestDMGSum); err != nil {
		return fmt.Errorf("extract %s: %w", guestDMGName, err)
	}

	return nil
}

func extracDatatFile(name, sumName string) error {
	srcPath := "data/" + name
	srcSumPath := "data/" + sumName

	sumBytes, err := fs.ReadFile(dataFS, srcSumPath)
	if err != nil {
		return fmt.Errorf("read embedded checksum %q: %w", srcSumPath, err)
	}
	expectedSum := strings.TrimSpace(string(sumBytes))

	dstPath := filepath.Join(dataDir, name)
	dstSumPath := filepath.Join(dataDir, sumName)

	// Skip if already extracted with the same checksum.
	// #nosec G304 -- dstSumPath is constructed internally from hardcoded sumName and app dataDir.
	if actualSum, err := os.ReadFile(dstSumPath); err == nil {
		if strings.TrimSpace(string(actualSum)) == expectedSum {
			return nil
		}
	}

	data, err := dataFS.ReadFile(srcPath)
	if err != nil {
		return fmt.Errorf("embedded file %q not found: %w", name, err)
	}

	// #nosec G304 -- dstPath is constructed internally from hardcoded name and app dataDir.
	if err := os.WriteFile(dstPath, data, 0o600); err != nil {
		return err
	}

	// Persist the checksum so the next run can skip extraction cheaply.
	if err := os.WriteFile(dstSumPath, []byte(expectedSum), 0o600); err != nil {
		return fmt.Errorf("write checksum %q: %w", dstSumPath, err)
	}

	return nil
}

// Dir returns the root application directory (~/.machbox).
func AppDir() string { return appDir }

// DBPath returns the SQLite database path (~/.machbox/machbox.db).
func DBPath() string { return filepath.Join(appDir, dbName) }

func GuestDMGPath() string { return filepath.Join(dataDir, guestDMGName) }

func OpenFS(name string) (fs.File, error) {
	return dataFS.Open("data/" + name)
}
