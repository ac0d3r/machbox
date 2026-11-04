package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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
	Name     string // display name, unique among baselines
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
	if err := checkNameFree(name, ""); err != nil {
		return nil, err
	}

	src, err := filepath.Abs(opts.VbvmPath)
	if err != nil {
		return nil, fmt.Errorf("resolve vbvm path: %w", err)
	}
	srcBundle, err := config.DecodeVBVM(src)
	if err != nil {
		return nil, err
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
	// Keep only what machbox boots from; VirtualBuddy metadata stays behind.
	if _, err = srcBundle.Import(dir); err != nil {
		return nil, fmt.Errorf("import vm bundle: %w", err)
	}
	lock, err := lockBaseline(dir)
	if err != nil {
		return nil, err
	}
	// Held until the record exists. Nothing can look dir up before that,
	// but setup expects its caller to hold the lock.
	defer lock.Close()

	res, err := setup(ctx, dir, purposeImport)
	if err != nil {
		return nil, fmt.Errorf("import %s failed: %w", id, err)
	}
	if res == nil {
		return nil, fmt.Errorf("import %s failed: setup returned no guest info (aborted?)", id)
	}

	// Again: setup took long enough for another baseline to take the name.
	if err := checkNameFree(name, ""); err != nil {
		return nil, err
	}
	vm = &db.VM{
		UUID:         id,
		Name:         name,
		OSName:       res.Info.OSName,
		OSVersion:    res.Info.OSVersion,
		OSBuild:      res.Info.BuildVersion,
		AgentVersion: res.Info.AgentVersion,
		Features:     res.Features,
	}
	if err = db.CreateVM(vm); err != nil {
		return nil, fmt.Errorf("save baseline: %w", err)
	}

	logrus.Infof("baseline %s is ready", id)
	return vm, nil
}

// Reconfigure boots an imported baseline with the current guest.dmg attached
// so the user can run Machbox Setup, then refreshes guest metadata in the
// database. The on-disk baseline is kept on failure.
func Reconfigure(ctx context.Context, identifier string) (*db.VM, error) {
	vm, err := Resolve(identifier)
	if err != nil {
		return nil, err
	}

	dir := assets.VMPath(vm.UUID)
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("baseline files %s: %w", dir, err)
	}
	// Held until the record is saved: released any earlier, a vm remove could
	// delete the baseline and the save would bring its record back.
	lock, err := lockBaseline(dir)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	logrus.Infof("configuring baseline %s (%s)", vm.Name, vm.UUID)
	res, err := setup(ctx, dir, purposeReconfigure)
	if err != nil {
		return nil, fmt.Errorf("setup of %s failed: %w", vm.UUID, err)
	}
	if res == nil {
		return nil, fmt.Errorf("setup of %s failed: no guest info (aborted?)", vm.UUID)
	}

	vm.OSName = res.Info.OSName
	vm.OSVersion = res.Info.OSVersion
	vm.OSBuild = res.Info.BuildVersion
	vm.AgentVersion = res.Info.AgentVersion
	vm.Features = res.Features
	vm.Error = ""
	if err := db.SaveVM(vm); err != nil {
		return nil, fmt.Errorf("save baseline after setup: %w", err)
	}

	logrus.Infof("baseline %s configured, agent version %q", vm.UUID, vm.AgentVersion)
	return vm, nil
}

// Duplicate APFS-clones an imported baseline into a new one named newName. The
// clone shares blocks with the source until either is written to, and is
// configured independently from then on. On failure nothing is left behind.
func Duplicate(identifier, newName string) (*db.VM, error) {
	newName = strings.TrimSpace(newName)
	if newName == "" {
		return nil, errors.New("name is required")
	}
	src, err := Resolve(identifier)
	if err != nil {
		return nil, err
	}
	if err := checkNameFree(newName, ""); err != nil {
		return nil, err
	}

	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	dir := assets.VMPath(id)
	if err := cloneBaseline(assets.VMPath(src.UUID), dir); err != nil {
		return nil, fmt.Errorf("duplicate %s: %w", src.UUID, err)
	}

	dup := *src
	dup.UUID, dup.Name = id, newName
	dup.Features = slices.Clone(src.Features)
	dup.CreatedAt, dup.UpdatedAt = time.Time{}, time.Time{}
	if err := db.CreateVM(&dup); err != nil {
		if rmErr := os.RemoveAll(dir); rmErr != nil {
			logrus.Warnf("failed to remove incomplete baseline %s: %v", dir, rmErr)
		}
		return nil, fmt.Errorf("save baseline: %w", err)
	}

	logrus.Infof("duplicated baseline %s (%s) as %s (%s)", src.Name, src.UUID, dup.Name, dup.UUID)
	return &dup, nil
}

// cloneBaseline clones the baseline at src to dst, which must not exist. It
// holds src's shared lock: a baseline being configured is mid-write.
func cloneBaseline(src, dst string) (err error) {
	lock, err := readLockBaseline(src)
	if err != nil {
		return err
	}
	defer lock.Close()

	bundle, err := loadBundle(src)
	if err != nil {
		return fmt.Errorf("load baseline bundle: %w", err)
	}
	if _, err := bundle.Import(dst); err != nil {
		if rmErr := os.RemoveAll(dst); rmErr != nil {
			logrus.Warnf("failed to remove incomplete baseline %s: %v", dst, rmErr)
		}
		return err
	}
	return nil
}

// errBaselineInUse is returned when another machbox process holds a
// conflicting lock on a baseline.
var errBaselineInUse = errors.New("baseline is in use by another machbox command " +
	"(vm import, setup, duplicate or remove, or a run or instance being created); try again when it is done")

// lockBaseline takes the exclusive lock of a baseline directory, held by
// whatever writes to the baseline or removes it: no other lock, shared or
// exclusive, is granted meanwhile. Closing the file releases it.
func lockBaseline(dir string) (*os.File, error) {
	return flockBaseline(dir, unix.LOCK_EX)
}

// readLockBaseline takes a shared lock of a baseline directory, held while
// copying it (a run's snapshot, a duplicate, a new instance): copies go on
// together, never while the baseline is written or removed.
func readLockBaseline(dir string) (*os.File, error) {
	return flockBaseline(dir, unix.LOCK_SH)
}

// flockBaseline locks dir without waiting: a conflicting holder is a
// command that can take an hour (setup), so it fails at once instead.
func flockBaseline(dir string, how int) (*os.File, error) {
	f, err := os.Open(dir) // #nosec G304 -- a managed baseline directory
	if err != nil {
		return nil, fmt.Errorf("open baseline: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), how|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errBaselineInUse
		}
		return nil, fmt.Errorf("lock baseline: %w", err)
	}
	return f, nil
}

// checkNameFree fails if a baseline other than except (a UUID, or "") is
// named name. Baselines are looked up by name, so a second one would make
// both ambiguous.
func checkNameFree(name, except string) error {
	same, err := db.FindVMsByName(name)
	if err != nil {
		return err
	}
	for i := range same {
		if same[i].UUID != except {
			return fmt.Errorf("a baseline named %q already exists", name)
		}
	}
	return nil
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
	if err := checkNameFree(newName, vm.UUID); err != nil {
		return nil, err
	}

	vm.Name = newName
	if err := db.SaveVM(vm); err != nil {
		return nil, fmt.Errorf("rename baseline: %w", err)
	}
	return vm, nil
}

// Remove deletes a baseline record and its on-disk bundle, its instances
// included; it refuses while the baseline or any instance is in use.
func Remove(identifier string) (*db.VM, error) {
	vm, err := Resolve(identifier)
	if err != nil {
		return nil, err
	}

	dir := assets.VMPath(vm.UUID)
	lock, err := lockBaseline(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if lock != nil {
		defer lock.Close()
	}
	instances, err := Instances(vm.UUID)
	if err != nil {
		return nil, err
	}
	locks := make([]*os.File, 0, len(instances))
	defer func() {
		for _, l := range locks {
			_ = l.Close()
		}
	}()
	for i := range instances {
		l, err := instances[i].lock()
		if err != nil {
			return nil, err
		}
		locks = append(locks, l)
	}
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("remove baseline files %s: %w", dir, err)
	}
	if err := db.DeleteVM(vm.UUID); err != nil {
		return nil, fmt.Errorf("remove baseline record: %w", err)
	}

	logrus.Infof("removed baseline %s (%s)", vm.Name, vm.UUID)
	return vm, nil
}

// loadBundle opens a baseline directory. Baselines imported by old versions,
// as a whole VirtualBuddy bundle, are no longer read: they have to be
// imported again.
func loadBundle(dir string) (*config.Bundle, error) {
	b, err := config.LoadBundle(dir)
	if errors.Is(err, config.ErrNoBundleConfig) {
		return nil, fmt.Errorf("%w: the baseline was imported by an old machbox version; "+
			"remove it with `machbox vm remove` and import its VirtualBuddy VM again", err)
	}
	return b, err
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
