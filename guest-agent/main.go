package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strings"
	"syscall"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/version"
	"github.com/ac0d3r/machbox/pkg/vsock"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ln, err := vsock.Listen(vsock.DefaultPort)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vsock listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()

	srv := &agent.Server{
		Info:       collectGuestInfo,
		MountShare: mountVirtioFS,
	}
	fmt.Printf("[agent] listening on vsock %d\n", vsock.DefaultPort)
	if err := srv.Serve(ctx, ln); err != nil {
		fmt.Fprintf(os.Stderr, "agent serve: %v\n", err)
		os.Exit(1)
	}
}

func collectGuestInfo() (agent.GuestInfo, error) {
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

	if v, err := runTrim("scutil", "--get", "ComputerName"); err == nil {
		info.Hostname = v
	}
	if v, err := runTrim("sw_vers", "-productName"); err == nil {
		info.OSName = v
	}
	if v, err := runTrim("sw_vers", "-productVersion"); err == nil {
		info.OSVersion = v
	}
	if v, err := runTrim("sw_vers", "-buildVersion"); err == nil {
		info.BuildVersion = v
	}
	if csr, err := runTrim("csrutil", "status"); err == nil {
		info.SIPDisabled = strings.Contains(strings.ToLower(csr), "disabled")
	}
	return info, nil
}

func mountVirtioFS(mountpoint string) error {
	if err := os.MkdirAll(mountpoint, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountpoint, err)
	}
	// #nosec G204 -- tag is fixed; mountpoint comes from the trusted host.
	out, err := exec.Command("mount_virtiofs", "machbox", mountpoint).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount_virtiofs: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runTrim(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}
