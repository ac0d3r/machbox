package vm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/db"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// An instance is a persistent clone of a baseline, started with machbox
// start and kept across shutdowns. It lives in its baseline's directory, so
// removing the baseline removes it too; the directory is the whole record:
//
//	vms/<uuid>/instances/<name>/
//	  Disk.img …       the bundle, cloned from the baseline when created
//	  instance.json    InstanceMeta
//	  .lock            held while the instance runs
//
// machbox run only picks baselines from the database, so an instance, and
// whatever was signed in to in it, never runs a plugin's samples.
const (
	instancesDirName = "instances"
	instanceMetaName = "instance.json"
	instanceLockName = ".lock"

	// shutdownTimeout is how long a guest gets to shut down before it is
	// forced off.
	shutdownTimeout = 2 * time.Minute
)

// Instance names are directory names and global: start looks them up
// across baselines.
var instanceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// SharedFolder is the macOS guest's automount directory for shares.
const SharedFolder = "/Volumes/My Shared Files"

// InstanceShare is a host directory shared with an instance, at
// SharedFolder/<base name of Path> in the guest.
type InstanceShare struct {
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// GuestPath is where the guest sees the share.
func (s InstanceShare) GuestPath() string {
	return filepath.Join(SharedFolder, filepath.Base(s.Path))
}

// InstanceMeta is instance.json.
type InstanceMeta struct {
	// Network is what the instance last started with, the default of the
	// next start; empty is none. Shares are not kept: each start grants
	// them anew, so a read-write share never outlives the command that
	// asked for it.
	Network   string    `json:"network,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	StartedAt time.Time `json:"started_at,omitzero"`
}

// Instance is an instance directory.
type Instance struct {
	Name         string
	Dir          string
	BaselineUUID string
	Meta         InstanceMeta
}

func instancesDir(baselineUUID string) string {
	return filepath.Join(assets.VMPath(baselineUUID), instancesDirName)
}

// Instances returns the instances of a baseline, by name.
func Instances(baselineUUID string) ([]Instance, error) {
	return instancesAt(instancesDir(baselineUUID), baselineUUID)
}

func instancesAt(dir, baselineUUID string) ([]Instance, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list instances: %w", err)
	}
	var out []Instance
	for _, e := range entries {
		// Dot entries are instances being created.
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		in := Instance{Name: e.Name(), Dir: filepath.Join(dir, e.Name()), BaselineUUID: baselineUUID}
		if err := in.loadMeta(); err != nil {
			logrus.Warnf("instance %s: %v", in.Name, err)
		}
		out = append(out, in)
	}
	return out, nil
}

// ListInstances returns the instances of every baseline.
func ListInstances() ([]Instance, error) {
	entries, err := os.ReadDir(assets.VMsDir())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("list baselines: %w", err)
	}
	var out []Instance
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ins, err := Instances(e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, ins...)
	}
	slices.SortFunc(out, func(a, b Instance) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// ErrInstanceNotFound is returned by FindInstance.
var ErrInstanceNotFound = errors.New("instance not found")

// FindInstance returns the instance called name.
func FindInstance(name string) (*Instance, error) {
	all, err := ListInstances()
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Name == name {
			return &all[i], nil
		}
	}
	return nil, fmt.Errorf("%w: %s", ErrInstanceNotFound, name)
}

// CreateInstance clones baseline into a new instance called name, with
// network as its default.
func CreateInstance(baseline *db.VM, name string, network config.Network) (*Instance, error) {
	if !instanceNameRe.MatchString(name) {
		return nil, fmt.Errorf("invalid instance name %q: use letters, digits, '.', '_' and '-' (up to 64)", name)
	}
	if _, err := FindInstance(name); err == nil {
		return nil, fmt.Errorf("an instance named %q already exists", name)
	} else if !errors.Is(err, ErrInstanceNotFound) {
		return nil, err
	}

	in, err := createInstanceAt(assets.VMPath(baseline.UUID), baseline.UUID, name, networkName(network))
	if err != nil {
		return nil, err
	}
	logrus.Infof("created instance %s from baseline %s (%s)", name, baseline.Name, baseline.UUID)
	return in, nil
}

// createInstanceAt clones the baseline at baselineDir into its instance
// called name.
func createInstanceAt(baselineDir, baselineUUID, name, network string) (*Instance, error) {
	// Through the rename: vm remove must not delete the baseline in between.
	lock, err := readLockBaseline(baselineDir)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	parent := filepath.Join(baselineDir, instancesDirName)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("create instances directory: %w", err)
	}
	// Clone under a hidden name and rename into place, so nothing sees a
	// half-cloned instance and two creates cannot share a directory.
	tmp := filepath.Join(parent, ".new-"+uuid.NewString())
	if err := cloneBaseline(baselineDir, tmp); err != nil {
		return nil, fmt.Errorf("clone baseline: %w", err)
	}
	in := &Instance{
		Name:         name,
		Dir:          filepath.Join(parent, name),
		BaselineUUID: baselineUUID,
		Meta:         InstanceMeta{Network: network, CreatedAt: time.Now()},
	}
	err = writeJSON(filepath.Join(tmp, instanceMetaName), &in.Meta)
	if err == nil {
		err = os.Rename(tmp, in.Dir)
	}
	if err != nil {
		if rmErr := os.RemoveAll(tmp); rmErr != nil {
			logrus.Warnf("remove incomplete instance %s: %v", tmp, rmErr)
		}
		return nil, fmt.Errorf("create instance %s: %w", name, err)
	}
	return in, nil
}

func (in *Instance) loadMeta() error {
	data, err := os.ReadFile(filepath.Join(in.Dir, instanceMetaName))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &in.Meta)
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Running reports whether the instance is running.
func (in *Instance) Running() bool {
	f, err := os.Open(filepath.Join(in.Dir, instanceLockName))
	if err != nil {
		return false
	}
	defer f.Close()
	// A shared lock only fails while start holds the exclusive one.
	return unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) != nil
}

// lock takes the instance's lock, held while it runs or is removed.
// Closing the file releases it.
func (in *Instance) lock() (*os.File, error) {
	// #nosec G304 -- a managed instance directory
	f, err := os.OpenFile(filepath.Join(in.Dir, instanceLockName), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open instance lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("instance %s is running", in.Name)
		}
		return nil, fmt.Errorf("lock instance %s: %w", in.Name, err)
	}
	return f, nil
}

// RemoveInstance deletes a stopped instance.
func RemoveInstance(in *Instance) error {
	lock, err := in.lock()
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := os.RemoveAll(in.Dir); err != nil {
		return fmt.Errorf("remove instance %s: %w", in.Name, err)
	}
	logrus.Infof("removed instance %s", in.Name)
	return nil
}

// StartOptions configures Start.
type StartOptions struct {
	Network config.Network
	Shares  []InstanceShare
	// GUI shows the VM window. Start must then be called on the main thread.
	GUI bool
	// Force, once closed, forces the VM off instead of waiting for the
	// guest to shut down.
	Force <-chan struct{}
}

// Start boots the instance in place and returns once it has stopped: when
// the guest shuts itself down, the window is closed, or ctx is cancelled,
// which shuts the guest down cleanly. The host does not idle-sleep
// meanwhile. opts' network becomes the instance's default.
func (in *Instance) Start(ctx context.Context, opts StartOptions) error {
	lock, err := in.lock()
	if err != nil {
		return err
	}
	defer lock.Close()

	bundle, err := config.LoadBundle(in.Dir)
	if err != nil {
		return fmt.Errorf("load instance %s: %w", in.Name, err)
	}
	shares, err := automountShares(opts.Shares)
	if err != nil {
		return err
	}

	network, stopNetwork, err := startNetwork(opts.Network, "")
	if err != nil {
		return err
	}
	// Start only returns once the VM has stopped (or the stop timed out).
	defer stopNetwork()

	vmcfg, err := config.NewMacVMConf(bundle, &config.VMOptions{
		DisplayWidth:    config.DefaultDisplayWidth,
		DisplayHeight:   config.DefaultDisplayHeight,
		Network:         network,
		AutomountShares: shares,
	})
	if err != nil {
		return fmt.Errorf("create vm configuration: %w", err)
	}
	inst, err := boxvm.New(vmcfg)
	if err != nil {
		return fmt.Errorf("create vm instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("start vm: %w", err)
	}
	logrus.Infof("instance %s started (network %s)", in.Name, orNone(networkName(opts.Network)))
	for _, s := range opts.Shares {
		if s.ReadOnly {
			logrus.Infof("sharing %s read-only at %s", s.Path, s.GuestPath())
		} else {
			logrus.Infof("sharing %s read-write at %s", s.Path, s.GuestPath())
			logrus.Warnf("the guest can change anything in %s, including what the host runs from it later (git hooks, build scripts)", s.Path)
		}
	}
	in.Meta.Network = networkName(opts.Network)
	in.Meta.StartedAt = time.Now()
	if err := writeJSON(filepath.Join(in.Dir, instanceMetaName), &in.Meta); err != nil {
		logrus.Warnf("save instance %s: %v", in.Name, err)
	}
	defer keepAwake()()

	// The agent is only needed to shut the guest down cleanly; an instance
	// without one still runs.
	agentCtx, stopAgent := context.WithCancel(context.Background())
	defer stopAgent()
	var client atomic.Pointer[agent.Client]
	go func() {
		waitCtx, cancel := context.WithTimeout(agentCtx, bootTimeout)
		defer cancel()
		c, info, err := agent.WaitReady(waitCtx, agentDialer(inst), time.Second)
		if err != nil {
			if agentCtx.Err() == nil {
				logrus.Warnf("guest agent not reachable: %v; the instance keeps running", err)
			}
			return
		}
		if err := agent.CompatibleAgent(info.AgentVersion); err != nil {
			logrus.Warnf("%v; the instance keeps running", err)
		}
		// An instance drifts from its baseline: check what it has now.
		features := agent.WithSIP(nil, info.SIPDisabled)
		if report, err := c.Check(waitCtx); err == nil {
			features = checkFeatures(&report)
		} else {
			logrus.Debugf("guest check: %v", err)
		}
		agent.LogGuest(info, features)
		client.Store(c)
		logrus.Infof("instance %s is up; press Ctrl-C to shut it down", in.Name)
	}()

	var stopOnce sync.Once
	stopRequested := make(chan struct{})
	requestStop := func() { stopOnce.Do(func() { close(stopRequested) }) }
	go func() {
		select {
		case <-ctx.Done():
			requestStop()
		case <-inst.AlreadyShutdown():
		}
	}()

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-inst.AlreadyShutdown():
			logrus.Info("guest shut down")
			return
		case <-stopRequested:
		}
		stopAgent()
		shutdownGuest(inst, client.Load(), opts.Force)
	}()

	var graphicErr error
	if opts.GUI {
		graphicErr = inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
		requestStop()
	}
	<-stopped
	logrus.Infof("instance %s stopped", in.Name)
	if graphicErr != nil {
		return fmt.Errorf("show graphic: %w", graphicErr)
	}
	return nil
}

// shutdownGuest shuts the guest down through its agent, or the power button
// without one, and forces the VM off if that takes too long or force is
// closed.
func shutdownGuest(inst *boxvm.VMInstance, c *agent.Client, force <-chan struct{}) {
	if c == nil {
		// macOS may answer the power button with a dialog nobody sees.
		logrus.Warn("guest agent not connected; pressing the power button instead")
	}
	logrus.Infof("shutting down the guest (forced off after %s); press Ctrl-C again to force it off now", shutdownTimeout)
	asked := false
	if c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := c.RunTask(ctx, &agent.Task{Command: "/sbin/shutdown", Args: []string{"-h", "now"}})
		cancel()
		if err != nil {
			logrus.Debugf("shut down through the agent: %v", err)
		} else {
			asked = true
		}
	}
	if !asked {
		if err := inst.RequestStop(); err != nil {
			logrus.Warnf("%v", err)
		} else {
			asked = true
		}
	}
	if asked {
		select {
		case <-inst.AlreadyShutdown():
			return
		case <-time.After(shutdownTimeout):
			logrus.Warnf("guest did not shut down within %s; forcing it off", shutdownTimeout)
		case <-force:
			logrus.Warn("forcing the VM off")
		}
	}
	_ = inst.Shutdown()
	select {
	case <-inst.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for the VM to stop")
	}
}

// keepAwake keeps the host from idle-sleeping, which would pause the
// guest, until the returned func is called or machbox exits.
func keepAwake() func() {
	cmd := exec.Command("/usr/bin/caffeinate", "-i", "-w", strconv.Itoa(os.Getpid())) // #nosec G204 -- fixed command, our pid
	if err := cmd.Start(); err != nil {
		logrus.Warnf("keep the host awake: %v", err)
		return func() {}
	}
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// networkName is the instance.json form of n: empty for none.
func networkName(n config.Network) string {
	if !n.Enable {
		return ""
	}
	return n.Mode
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// CheckShares reports what Start would refuse in shares: a missing
// directory, a file, or two shares with one name in the guest.
func CheckShares(shares []InstanceShare) error {
	_, err := automountShares(shares)
	return err
}

// automountShares checks shares and returns them for the VM configuration.
func automountShares(shares []InstanceShare) ([]config.ShareDir, error) {
	out := make([]config.ShareDir, 0, len(shares))
	byName := map[string]string{}
	for _, s := range shares {
		fi, err := os.Stat(s.Path)
		if err != nil {
			return nil, fmt.Errorf("share: %w", err) // the error names the path
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("share %s: not a directory", s.Path)
		}
		name := filepath.Base(s.Path)
		if other, dup := byName[name]; dup {
			return nil, fmt.Errorf("shares %s and %s would both be %s in the guest", other, s.Path, s.GuestPath())
		}
		byName[name] = s.Path
		out = append(out, config.ShareDir{Dir: s.Path, Tag: name, ReadOnly: s.ReadOnly})
	}
	return out, nil
}
