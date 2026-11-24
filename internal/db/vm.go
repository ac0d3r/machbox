// Package db keeps baseline records: one baseline.json in each baseline
// directory (~/.machbox/vms/<uuid>/), like jobs and plugins keep theirs. A directory without one is not a baseline: an import in progress,
// or one that was interrupted.
package db

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/assets"

	"golang.org/x/sys/unix"
)

const (
	recordName = "baseline.json"
	// lockName serializes record writes, so that names stay unique.
	lockName = ".records.lock"
)

var (
	// ErrNameTaken is returned when a baseline would get the name of another.
	ErrNameTaken = errors.New("a baseline with that name already exists")
	// ErrNotFound is returned for a UUID with no baseline record.
	ErrNotFound = errors.New("baseline not found")
)

// root returns the directory holding baselines; tests point it elsewhere.
var root = assets.VMsDir

type VM struct {
	UUID string `json:"uuid"`
	// Name is unique: baselines are looked up by name.
	Name string `json:"name"`

	OSName    string `json:"os_name"`
	OSVersion string `json:"os_version"`
	OSBuild   string `json:"os_build"`

	AgentVersion string `json:"agent_version"`
	// Features are what the baseline had when setup last finished (see
	// agent.Features); only import and setup change a baseline.
	Features []string `json:"features"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// HasFeature reports whether the baseline has feature f.
func (vm *VM) HasFeature(f string) bool { return slices.Contains(vm.Features, f) }

func recordPath(uuid string) string { return filepath.Join(root(), uuid, recordName) }

// CreateVM records a new baseline, whose directory must exist.
func CreateVM(vm *VM) error {
	return withLock(func() error {
		if _, err := os.Stat(recordPath(vm.UUID)); err == nil {
			return fmt.Errorf("baseline %s is already recorded", vm.UUID)
		}
		if err := nameFree(vm.Name, vm.UUID); err != nil {
			return err
		}
		now := time.Now()
		if vm.CreatedAt.IsZero() {
			vm.CreatedAt = now
		}
		vm.UpdatedAt = now
		return write(vm)
	})
}

// UpdateVM changes the record of uuid with fn and saves it. The record is
// read again under the lock, so concurrent updates (a rename during a
// setup) are not lost.
func UpdateVM(uuid string, fn func(*VM)) (*VM, error) {
	var vm *VM
	err := withLock(func() (err error) {
		if vm, err = GetVMByUUID(uuid); err != nil {
			return err
		}
		fn(vm)
		if err := nameFree(vm.Name, vm.UUID); err != nil {
			return err
		}
		vm.UpdatedAt = time.Now()
		return write(vm)
	})
	if err != nil {
		return nil, err
	}
	return vm, nil
}

// DeleteVM removes the record of uuid; its directory is the caller's. It
// takes the lock so that an update in progress cannot bring the record back.
func DeleteVM(uuid string) error {
	return withLock(func() error {
		if err := os.Remove(recordPath(uuid)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	})
}

func GetVMByUUID(uuid string) (*VM, error) {
	data, err := os.ReadFile(recordPath(uuid))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var vm VM
	if err := json.Unmarshal(data, &vm); err != nil {
		return nil, fmt.Errorf("read %s: %w", recordPath(uuid), err)
	}
	return &vm, nil
}

func FindVMsByName(name string) ([]VM, error) {
	vms, err := ListVMs()
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(vms, func(vm VM) bool { return vm.Name != name }), nil
}

// ListVMs returns every recorded baseline, oldest first.
func ListVMs() ([]VM, error) {
	entries, err := os.ReadDir(root())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var vms []VM
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		vm, err := GetVMByUUID(e.Name())
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		vms = append(vms, *vm)
	}
	slices.SortFunc(vms, func(a, b VM) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.UUID, b.UUID)
	})
	return vms, nil
}

// nameFree fails if a baseline other than uuid is named name.
func nameFree(name, uuid string) error {
	same, err := FindVMsByName(name)
	if err != nil {
		return err
	}
	for i := range same {
		if same[i].UUID != uuid {
			return ErrNameTaken
		}
	}
	return nil
}

// write saves vm's record atomically: readers see the old or the new one.
func write(vm *VM) error {
	data, err := json.MarshalIndent(vm, "", "  ")
	if err != nil {
		return err
	}
	dst := recordPath(vm.UUID)
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".baseline-*.json")
	if err != nil {
		return fmt.Errorf("save baseline record: %w", err)
	}
	defer os.Remove(tmp.Name()) // no-op after rename
	_, err = tmp.Write(append(data, '\n'))
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), dst)
	}
	if err != nil {
		return fmt.Errorf("save baseline record: %w", err)
	}
	return nil
}

// withLock runs fn holding the records lock. Writes are quick, so it waits.
func withLock(fn func() error) error {
	if err := os.MkdirAll(root(), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root(), lockName), os.O_CREATE|os.O_RDONLY, 0o600)
	if err != nil {
		return fmt.Errorf("lock baseline records: %w", err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock baseline records: %w", err)
	}
	return fn()
}
