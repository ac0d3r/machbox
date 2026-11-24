package db

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/assets"

	"github.com/sirupsen/logrus"
)

// legacyDB returns the SQLite database earlier versions kept records in;
// tests point it elsewhere.
var legacyDB = assets.LegacyDBPath

// sqlite3 is the command line shell macOS ships, which reads the legacy
// database without machbox linking SQLite.
var sqlite3 = "/usr/bin/sqlite3"

// Init moves the records of a legacy database, if there is one, into
// baseline.json files, then renames the database to <name>.migrated.
func Init() error {
	path := legacyDB()
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return withLock(func() error {
		// Again under the lock: another machbox may have migrated meanwhile.
		if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err := migrate(path); err != nil {
			return fmt.Errorf("migrate baselines from %s: %w", path, err)
		}
		if err := os.Rename(path, path+".migrated"); err != nil {
			return err
		}
		logrus.Infof("baseline records moved from %s into each baseline's %s", path, recordName)
		return nil
	})
}

func migrate(path string) error {
	tables, err := query(path, "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'vms'")
	if err != nil || len(tables) == 0 {
		return err
	}
	rows, err := query(path, "SELECT * FROM vms")
	if err != nil {
		return err
	}
	seen := map[string]string{} // name -> uuid
	var vms []*VM
	for _, row := range rows {
		vm := legacyVM(row)
		if vm.UUID == "" || strings.ContainsAny(vm.UUID, `/\`) || strings.HasPrefix(vm.UUID, ".") {
			continue
		}
		if _, err := os.Stat(recordPath(vm.UUID)); err == nil {
			continue // already migrated
		}
		if _, err := os.Stat(filepath.Join(root(), vm.UUID)); err != nil {
			logrus.Warnf("skipping the record of baseline %s (%s): its directory is gone", vm.Name, vm.UUID)
			continue
		}
		if other, ok := seen[vm.Name]; ok {
			return fmt.Errorf("baselines %s and %s are both named %q; "+
				"rename one with the machbox version that made them", other, vm.UUID, vm.Name)
		}
		seen[vm.Name] = vm.UUID
		vms = append(vms, vm)
	}
	for _, vm := range vms {
		if err := nameFree(vm.Name, vm.UUID); err != nil {
			return fmt.Errorf("baseline %s: %w: %q", vm.UUID, err, vm.Name)
		}
	}
	for _, vm := range vms {
		if err := write(vm); err != nil {
			return err
		}
	}
	return nil
}

// legacyVM converts a row of the vms table, of any of its schemas.
func legacyVM(row map[string]any) *VM {
	str := func(k string) string { s, _ := row[k].(string); return s }
	vm := &VM{
		UUID:         str("uuid"),
		Name:         str("name"),
		OSName:       str("os_name"),
		OSVersion:    str("os_version"),
		OSBuild:      str("os_build"),
		AgentVersion: str("agent_version"),
		CreatedAt:    legacyTime(str("created_at")),
		UpdatedAt:    legacyTime(str("updated_at")),
	}
	switch f, ok := row["features"]; {
	case ok:
		if s, _ := f.(string); s != "" {
			_ = json.Unmarshal([]byte(s), &vm.Features)
		}
	case row["sip_disabled"] != nil:
		// SIP state used to be a column of its own.
		if n, _ := row["sip_disabled"].(float64); n != 0 {
			vm.Features = []string{"sip-disabled"}
		}
	default:
		// Before that, imports required SIP disabled.
		vm.Features = []string{"sip-disabled"}
	}
	return vm
}

func legacyTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func query(path, sql string) ([]map[string]any, error) {
	var stderr bytes.Buffer
	cmd := exec.Command(sqlite3, "-readonly", "-json", path, sql) // #nosec G204 -- fixed queries
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", sqlite3, err, strings.TrimSpace(stderr.String()))
	}
	var rows []map[string]any
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil // no rows: sqlite3 prints nothing
	}
	if err := json.Unmarshal(out, &rows); err != nil {
		return nil, fmt.Errorf("parse %s output: %w", sqlite3, err)
	}
	return rows, nil
}
