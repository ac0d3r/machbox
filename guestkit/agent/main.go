package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/version"
	"github.com/ac0d3r/machbox/pkg/vsock"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	info := collectGuestInfo()

	ln, err := vsock.Listen(agent.DefaultVsockPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock listen: %v\n", err)
		return 1
	}
	defer ln.Close()

	srv := &agent.Server{
		Info:       func() (agent.GuestInfo, error) { return info, nil },
		MountShare: mountVirtioFS,
	}
	fmt.Printf("[agent] listening on vsock %d\n", agent.DefaultVsockPort)
	if err := srv.Serve(ctx, ln); err != nil {
		fmt.Fprintf(os.Stderr, "agent serve: %v\n", err)
		return 1
	}
	return 0
}

func collectGuestInfo() agent.GuestInfo {
	info := agent.GuestInfo{
		OSName:       "macOS",
		AgentVersion: version.Version,
		Username:     "root",
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		info.Username = u.Username
	}

	if v, err := runTrim(exec.Command("scutil", "--get", "ComputerName")); err == nil {
		info.Hostname = v
	}
	if v, err := runTrim(exec.Command("sw_vers", "-productName")); err == nil {
		info.OSName = v
	}
	if v, err := runTrim(exec.Command("sw_vers", "-productVersion")); err == nil {
		info.OSVersion = v
	}
	if v, err := runTrim(exec.Command("sw_vers", "-buildVersion")); err == nil {
		info.BuildVersion = v
	}
	if csr, err := runTrim(exec.Command("csrutil", "status")); err == nil {
		info.SIPDisabled = strings.Contains(strings.ToLower(csr), "disabled")
	}
	return info
}

func mountVirtioFS(mountpoint string) error {
	mountpoint = filepath.Clean(mountpoint)
	if err := os.MkdirAll(mountpoint, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountpoint, err)
	}
	if mounted, err := isMounted(mountpoint); err != nil {
		return err
	} else if mounted {
		return nil
	}

	// #nosec G204 -- tag is fixed; mountpoint comes from the trusted host.
	out, err := exec.Command("mount_virtiofs", "machbox", mountpoint).CombinedOutput()
	if err != nil {
		// Another session may have won the race.
		if mounted, _ := isMounted(mountpoint); mounted {
			return nil
		}
		return fmt.Errorf("mount_virtiofs: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func isMounted(mountpoint string) (bool, error) {
	out, err := exec.Command("mount").Output()
	if err != nil {
		return false, fmt.Errorf("mount: %w", err)
	}
	// mount(8) lines look like: "machbox on /tmp/machbox_s (virtiofs, ...)"
	needle := " on " + mountpoint + " "
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, needle) || strings.HasSuffix(line, " on "+mountpoint) {
			return true, nil
		}
	}
	return false, nil
}

func runTrim(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
