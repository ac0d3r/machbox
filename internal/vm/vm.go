package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
)

// ImportOptions configures a baseline import.
type ImportOptions struct {
	VbvmPath string // source VirtualBuddy bundle; never modified
	Name     string // display name (may be duplicated)
}

// Import APFS-clones a VBVM into the managed baseline directory, runs setup
// (GUI + guest agent handshake), and records the baseline. On failure the
// clone is removed and the database is left unchanged.
func Import(ctx context.Context, opts ImportOptions) (vm *db.VM, err error) {
	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return nil, errors.New("name is required")
	}
	if strings.TrimSpace(opts.VbvmPath) == "" {
		return nil, errors.New("vbvm path is required")
	}

	src, err := filepath.Abs(opts.VbvmPath)
	if err != nil {
		return nil, fmt.Errorf("resolve vbvm path: %w", err)
	}
	if _, err := config.DecodeVBVMPath(src); err != nil {
		return nil, fmt.Errorf("invalid vbvm bundle %q: %w", src, err)
	}

	id, err := newUUID()
	if err != nil {
		return nil, err
	}

	vmsDir := assets.VMsDir()
	dir := filepath.Join(vmsDir, id)
	if err := os.MkdirAll(vmsDir, 0o700); err != nil {
		return nil, fmt.Errorf("create baseline directory: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			logrus.Warnf("failed to remove incomplete baseline %s: %v", dir, rmErr)
		} else {
			logrus.Infof("removed incomplete baseline %s", id)
		}
	}()

	logrus.Infof("importing baseline %q from %s", name, src)
	if err = cloneFile(src, dir); err != nil {
		return nil, fmt.Errorf("clone vm bundle: %w", err)
	}

	info, err := setup(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("import %s failed: %w", id, err)
	}
	if info == nil {
		return nil, fmt.Errorf("import %s failed: setup returned no guest info (aborted?)", id)
	}

	vm = &db.VM{
		UUID:         id,
		Name:         name,
		OSName:       info.OSName,
		OSVersion:    info.OSVersion,
		OSBuild:      info.BuildVersion,
		AgentVersion: info.AgentVersion,
	}
	if err = db.CreateVM(vm); err != nil {
		return nil, fmt.Errorf("save baseline: %w", err)
	}

	logrus.Infof("baseline %s is ready", id)
	return vm, nil
}

// List returns imported baselines.
func List() ([]db.VM, error) {
	return db.ListVMs()
}

// Rename changes the display name of a baseline.
func Rename(identifier, newName string) (*db.VM, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return nil, errors.New("name is required")
	}

	vm, err := Resolve(identifier)
	if err != nil {
		return nil, err
	}

	vm.Name = newName
	if err := db.SaveVM(vm); err != nil {
		return nil, fmt.Errorf("rename baseline: %w", err)
	}
	return vm, nil
}

// Remove deletes a baseline record and its on-disk bundle.
func Remove(identifier string) (*db.VM, error) {
	vm, err := Resolve(identifier)
	if err != nil {
		return nil, err
	}

	dir := assets.VMPath(vm.UUID)
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("remove baseline files %s: %w", dir, err)
	}
	if err := db.DeleteVM(vm.UUID); err != nil {
		return nil, fmt.Errorf("remove baseline record: %w", err)
	}

	logrus.Infof("removed baseline %s (%s)", vm.Name, vm.UUID)
	return vm, nil
}

// Resolve looks up a baseline by UUID or unique name.
func Resolve(identifier string) (*db.VM, error) {
	identifier = strings.TrimSpace(identifier)
	if identifier == "" {
		return nil, &ErrBaselineNotFound{Identifier: identifier}
	}

	if looksLikeUUID(identifier) {
		vm, err := db.GetVMByUUID(strings.ToLower(identifier))
		if err == nil {
			return vm, nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
	}

	vms, err := db.FindVMsByName(identifier)
	if err != nil {
		return nil, err
	}
	switch len(vms) {
	case 0:
		return nil, &ErrBaselineNotFound{Identifier: identifier}
	case 1:
		return &vms[0], nil
	default:
		return nil, &ErrAmbiguousName{Name: identifier}
	}
}

func newUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	return id.String(), nil
}

func looksLikeUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// cloneFile APFS-clones src to dst (copy-on-write). dst must not exist;
// src and dst must be on the same APFS volume.
func cloneFile(src, dst string) error {
	if err := unix.Clonefile(src, dst, 0); err != nil {
		logrus.Debugf("APFS clonefile failed for %s, falling back to regular copy", src)
		return err
	}

	return nil
}
