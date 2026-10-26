package assets

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

//go:embed data
var dataFS embed.FS

const (
	appDirName = ".machbox"

	dbName = "machbox.sqlite"

	vmsDirName   = "vms"
	runsDirName  = "runs"
	jobsDirName  = "jobs"
	dataDirName  = "data"
	guestDMGName = "guest.dmg"

	// Temp files from an interrupted extraction are removed once older
	// than this, so a concurrent extraction in progress is left alone.
	staleTempAge = 10 * time.Minute
)

var (
	appDir  string
	dataDir string
	vmsDir  string
	runsDir string
	jobsDir string

	initOnce sync.Once
)

func init() {
	appDir = resolveAppDir()
	dataDir = filepath.Join(appDir, dataDirName)
	vmsDir = filepath.Join(appDir, vmsDirName)
	runsDir = filepath.Join(appDir, runsDirName)
	jobsDir = filepath.Join(appDir, jobsDirName)
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
	for _, dir := range []string{appDir, dataDir, vmsDir, runsDir, jobsDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create dir %s: %w", dir, err)
		}
	}
	return nil
}

var (
	guestDMGOnce sync.Once
	guestDMGPath string
	guestDMGErr  error
)

// GuestDMG returns the path of the embedded guest disk image, extracting it
// on first use. Only commands that attach it to a VM need to call this.
func GuestDMG() (string, error) {
	guestDMGOnce.Do(func() {
		guestDMGPath, guestDMGErr = extractContentAddressed(dataFS, "data/"+guestDMGName, dataDir)
		if guestDMGErr != nil {
			guestDMGErr = fmt.Errorf("extract %s: %w", guestDMGName, guestDMGErr)
		}
	})
	return guestDMGPath, guestDMGErr
}

// extractContentAddressed writes the embedded file name to
// dir/<stem>-<sha256[:12]><ext> unless it is already there, and returns
// that path. The file is written to a temp file and renamed into place, so
// a version of the image attached to a running VM is never overwritten and
// concurrent extractions cannot produce a torn file. Older versions are
// removed; a VM that still has one attached keeps its open file.
func extractContentAddressed(fsys fs.FS, name, dir string) (string, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return "", fmt.Errorf("read embedded %s: %w", name, err)
	}

	sum := sha256.Sum256(data)
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(filepath.Base(name), ext)
	prefix := stem + "-"
	dst := filepath.Join(dir, prefix+hex.EncodeToString(sum[:])[:12]+ext)

	if info, err := os.Stat(dst); err == nil && info.Size() == int64(len(data)) {
		return dst, nil
	}

	tmp, err := os.CreateTemp(dir, "."+prefix+"*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	// The image is only ever attached read-only.
	if err := os.Chmod(tmp.Name(), 0o400); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return "", err
	}

	removeOldExtractions(dir, stem, ext, dst)
	return dst, nil
}

func removeOldExtractions(dir, stem, ext, keep string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		n := e.Name()
		path := filepath.Join(dir, n)
		switch {
		case path == keep:
			continue
		case strings.HasPrefix(n, stem+"-") && strings.HasSuffix(n, ext),
			// Layout used before content-addressed names.
			n == stem+ext, n == stem+ext+".sha256":
		case strings.HasPrefix(n, "."+stem+"-") && strings.HasSuffix(n, ".tmp"):
			info, err := e.Info()
			if err != nil || time.Since(info.ModTime()) < staleTempAge {
				continue
			}
		default:
			continue
		}
		if err := os.Remove(path); err != nil {
			logrus.Debugf("remove old %s: %v", path, err)
		}
	}
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

// JobsDir returns the directory that holds workflow job records
// (~/.machbox/jobs/<id>/).
func JobsDir() string { return jobsDir }
