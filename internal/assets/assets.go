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

	vmsDirName   = "vms"
	runsDirName  = "runs"
	dataDirName  = "data"
	guestDMGName = "guest.dmg"
	guestDMGSum  = guestDMGName + ".sha256"
)

var (
	appDir  string
	dataDir string
	vmsDir  string
	runsDir string

	initOnce sync.Once
)

func init() {
	appDir = resolveAppDir()
	dataDir = filepath.Join(appDir, dataDirName)
	vmsDir = filepath.Join(appDir, vmsDirName)
	runsDir = filepath.Join(appDir, runsDirName)
}

func resolveAppDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, appDirName)
}

func Init() (err error) {
	initOnce.Do(func() {
		err = doInit()
	})
	return
}

func doInit() error {
	for _, dir := range []string{appDir, dataDir, vmsDir, runsDir} {
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

// VMsDir returns the directory that holds imported VM baselines
// (~/.machbox/vms). Each baseline lives in its own UUID-named subdirectory.
func VMsDir() string { return vmsDir }

// VMPath returns the baseline directory for the given VM UUID
// (~/.machbox/vms/<uuid>).
func VMPath(uuid string) string { return filepath.Join(VMsDir(), uuid) }

// RunsDir returns the directory that holds disposable VM runs
// (~/.machbox/runs). It is on the same volume as VMsDir so snapshots can be
// APFS-cloned from baselines.
func RunsDir() string { return runsDir }

func GuestDMGPath() string { return filepath.Join(dataDir, guestDMGName) }
