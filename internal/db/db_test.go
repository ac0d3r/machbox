package db

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// useDir points the store at a temporary vms directory holding dirs.
func useDir(t *testing.T, dirs ...string) string {
	t.Helper()
	d := t.TempDir()
	old := root
	root = func() string { return d }
	t.Cleanup(func() { root = old })
	for _, name := range dirs {
		if err := os.MkdirAll(filepath.Join(d, name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

func TestRecords(t *testing.T) {
	dir := useDir(t, "a", "b", "importing")
	if err := CreateVM(&VM{UUID: "a", Name: "one", Features: []string{"agent"}}); err != nil {
		t.Fatal(err)
	}
	if err := CreateVM(&VM{UUID: "b", Name: "two"}); err != nil {
		t.Fatal(err)
	}
	if err := CreateVM(&VM{UUID: "a", Name: "three"}); err == nil {
		t.Error("recording a baseline twice succeeded")
	}
	if err := CreateVM(&VM{UUID: "missing", Name: "x"}); err == nil {
		t.Error("recording a baseline without a directory succeeded")
	}

	list, err := ListVMs()
	if err != nil || len(list) != 2 || list[0].UUID != "a" || list[1].UUID != "b" {
		t.Fatalf("list = %+v, %v; want a, b (a directory without a record is no baseline)", list, err)
	}
	vm, err := GetVMByUUID("a")
	if err != nil || vm.Name != "one" || !vm.HasFeature("agent") || vm.CreatedAt.IsZero() {
		t.Fatalf("get = %+v, %v", vm, err)
	}
	if _, err := GetVMByUUID("importing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("get without record: %v", err)
	}
	if found, err := FindVMsByName("two"); err != nil || len(found) != 1 || found[0].UUID != "b" {
		t.Errorf("find = %+v, %v", found, err)
	}

	if vm, err := UpdateVM("a", func(vm *VM) { vm.Name = "uno" }); err != nil || vm.Name != "uno" {
		t.Fatalf("update = %+v, %v", vm, err)
	}
	if _, err := UpdateVM("missing", func(*VM) {}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update without record: %v", err)
	}

	if err := DeleteVM("b"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteVM("b"); err != nil {
		t.Errorf("second delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b")); err != nil {
		t.Errorf("delete removed the directory: %v", err)
	}
	if list, _ := ListVMs(); len(list) != 1 {
		t.Errorf("list after delete: %+v", list)
	}
}

func TestNamesStayUnique(t *testing.T) {
	useDir(t, "a", "b")
	if err := CreateVM(&VM{UUID: "a", Name: "same"}); err != nil {
		t.Fatal(err)
	}
	if err := CreateVM(&VM{UUID: "b", Name: "same"}); !errors.Is(err, ErrNameTaken) {
		t.Errorf("duplicate create: %v, want ErrNameTaken", err)
	}
	if err := CreateVM(&VM{UUID: "b", Name: "other"}); err != nil {
		t.Fatal(err)
	}
	if _, err := UpdateVM("b", func(vm *VM) { vm.Name = "same" }); !errors.Is(err, ErrNameTaken) {
		t.Errorf("duplicate rename: %v, want ErrNameTaken", err)
	}
	if vm, _ := GetVMByUUID("b"); vm.Name != "other" {
		t.Errorf("refused rename saved %q", vm.Name)
	}
}

// Concurrent renames to one name: the lock lets exactly one through.
func TestConcurrentRenames(t *testing.T) {
	ids := []string{"a", "b", "c", "d"}
	useDir(t, ids...)
	for _, id := range ids {
		if err := CreateVM(&VM{UUID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(ids))
	for _, id := range ids {
		wg.Go(func() {
			_, err := UpdateVM(id, func(vm *VM) { vm.Name = "same" })
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrNameTaken) {
			t.Error(err)
		}
	}
	if ok != 1 {
		t.Errorf("%d renames succeeded, want 1", ok)
	}
}

// legacy creates a legacy database with the given SQL and points Init at it.
func legacy(t *testing.T, sql string) string {
	t.Helper()
	if _, err := os.Stat(sqlite3); err != nil {
		t.Skip("no sqlite3")
	}
	path := filepath.Join(t.TempDir(), "machbox.sqlite")
	if out, err := exec.Command(sqlite3, path, sql).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	old := legacyDB
	legacyDB = func() string { return path }
	t.Cleanup(func() { legacyDB = old })
	return path
}

func TestInitMigratesLegacyDatabase(t *testing.T) {
	useDir(t, "cur", "off", "on")
	path := legacy(t, `
CREATE TABLE vms (uuid text PRIMARY KEY, name text, os_name text, os_version text, os_build text,
  agent_version text, features text, error text, created_at datetime, updated_at datetime);
CREATE UNIQUE INDEX idx_vms_name ON vms(name);
INSERT INTO vms VALUES ('cur', 'current', 'macOS', '15.1', '24B83', '8', '["agent","clt"]', '',
  '2026-11-05 10:00:00.123456+08:00', '2026-11-06 10:00:00+08:00');
INSERT INTO vms (uuid, name) VALUES ('gone', 'gone');`)

	if err := Init(); err != nil {
		t.Fatal(err)
	}
	vm, err := GetVMByUUID("cur")
	if err != nil {
		t.Fatal(err)
	}
	if vm.Name != "current" || vm.OSVersion != "15.1" || vm.AgentVersion != "8" ||
		!reflect.DeepEqual(vm.Features, []string{"agent", "clt"}) || vm.CreatedAt.Year() != 2026 {
		t.Errorf("migrated %+v", vm)
	}
	if list, _ := ListVMs(); len(list) != 1 {
		t.Errorf("list = %+v; a record without its directory is dropped", list)
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("legacy database still in place")
	}
	if _, err := os.Stat(path + ".migrated"); err != nil {
		t.Error(err)
	}
	if err := Init(); err != nil { // nothing left to migrate
		t.Fatal(err)
	}
}

func TestInitMigratesOldSchemas(t *testing.T) {
	useDir(t, "v1", "off", "on")
	legacy(t, `
CREATE TABLE vms (uuid text PRIMARY KEY, name text, sip_disabled numeric);
INSERT INTO vms VALUES ('off', 'off', 1), ('on', 'on', 0);`)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if vm, _ := GetVMByUUID("off"); vm == nil || !reflect.DeepEqual(vm.Features, []string{"sip-disabled"}) {
		t.Errorf("off: %+v", vm)
	}
	if vm, _ := GetVMByUUID("on"); vm == nil || len(vm.Features) != 0 {
		t.Errorf("on: %+v", vm)
	}

	// Before the SIP column, imports required SIP disabled.
	legacy(t, `CREATE TABLE vms (uuid text PRIMARY KEY, name text); INSERT INTO vms VALUES ('v1', 'v1');`)
	if err := Init(); err != nil {
		t.Fatal(err)
	}
	if vm, _ := GetVMByUUID("v1"); vm == nil || !reflect.DeepEqual(vm.Features, []string{"sip-disabled"}) {
		t.Errorf("v1: %+v", vm)
	}
}

func TestInitRefusesDuplicateNames(t *testing.T) {
	useDir(t, "a", "b")
	path := legacy(t, `
CREATE TABLE vms (uuid text PRIMARY KEY, name text, features text);
INSERT INTO vms VALUES ('a', 'same', '[]'), ('b', 'same', '[]');`)
	err := Init()
	if err == nil || !strings.Contains(err.Error(), "same") {
		t.Fatalf("err = %v, want one naming the duplicate", err)
	}
	if list, _ := ListVMs(); len(list) != 0 {
		t.Errorf("failed migration recorded %+v", list)
	}
	if _, err := os.Stat(path); err != nil {
		t.Error("legacy database moved after a failed migration")
	}
}

func TestInitWithoutLegacyDatabase(t *testing.T) {
	useDir(t)
	old := legacyDB
	legacyDB = func() string { return filepath.Join(t.TempDir(), "none.sqlite") }
	t.Cleanup(func() { legacyDB = old })
	if err := Init(); err != nil {
		t.Fatal(err)
	}
}

// Commands starting together: the first migrates, the others find
// nothing left to do.
func TestConcurrentInit(t *testing.T) {
	useDir(t, "a")
	legacy(t, `CREATE TABLE vms (uuid text PRIMARY KEY, name text, features text);
INSERT INTO vms VALUES ('a', 'a', '[]');`)
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Go(func() { errs <- Init() })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if list, _ := ListVMs(); len(list) != 1 {
		t.Errorf("list = %+v", list)
	}
}
