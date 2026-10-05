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
	"github.com/ac0d3r/machbox/internal/version"
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
func Import(ctx context.Context, opts ImportOptions) (*db.VM, error) {
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

	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(dir)
		}
	}()

	logrus.Infof("importing baseline %q from %s", name, src)
	if err := cloneFile(src, dir); err != nil {
		return nil, fmt.Errorf("clone vm bundle: %w", err)
	}

	info, err := setup(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("import %s failed: %w", id, err)
	}

	vm := &db.VM{
		UUID:         id,
		Name:         name,
		OSName:       info.OSName,
		OSVersion:    info.OSVersion,
		OSBuild:      info.BuildVersion,
		AgentVersion: info.AgentVersion,
	}
	if err := db.CreateVM(vm); err != nil {
		return nil, fmt.Errorf("save baseline: %w", err)
	}

	ok = true
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

	vm, err := resolve(identifier)
	if err != nil {
		return nil, err
	}

	vm.Name = newName
	if err := db.SaveVM(vm); err != nil {
		return nil, fmt.Errorf("rename baseline: %w", err)
	}
	return vm, nil
}

// DoctorResult is the health check for one baseline.
type DoctorResult struct {
	VM       *db.VM
	Path     string
	Problems []string
}

// Healthy reports whether the baseline has no recorded problems.
func (r *DoctorResult) Healthy() bool { return len(r.Problems) == 0 }

// Doctor inspects a baseline identified by UUID or unique name.
func Doctor(identifier string) (*DoctorResult, error) {
	vm, err := resolve(identifier)
	if err != nil {
		return nil, err
	}

	res := &DoctorResult{VM: vm, Path: assets.VMPath(vm.UUID)}

	if stat, err := os.Stat(res.Path); err != nil {
		res.Problems = append(res.Problems, "baseline directory is missing: "+res.Path)
	} else if !stat.IsDir() {
		res.Problems = append(res.Problems, "baseline path is not a directory: "+res.Path)
	} else if _, err := config.DecodeVBVMPath(res.Path); err != nil {
		res.Problems = append(res.Problems, "baseline files invalid: "+err.Error())
	}

	if vm.AgentVersion != version.Version {
		res.Problems = append(res.Problems, fmt.Sprintf(
			"guest agent version %q does not match expected %q",
			vm.AgentVersion, version.Version))
	}

	return res, nil
}

func resolve(identifier string) (*db.VM, error) {
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
