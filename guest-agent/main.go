package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/core/vsock"
	"github.com/ac0d3r/machbox/core/vsock/protocol"
)

func CollectGuestInfo() (*protocol.GuestInfo, error) {
	out, err := exec.Command("scutil", "--get", "ComputerName").Output()
	if err != nil {
		return nil, err
	}
	hostname := strings.TrimSpace(string(out))

	out, err = exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return nil, err
	}
	osVersion := strings.TrimSpace(string(out))

	out, err = exec.Command("sw_vers", "-buildVersion").Output()
	if err != nil {
		return nil, err
	}
	buildVersion := strings.TrimSpace(string(out))

	out, err = exec.Command("csrutil", "status").Output()
	if err != nil {
		return nil, err
	}
	sipDisabled := strings.Contains(strings.ToLower(string(out)), "disabled")

	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	return &protocol.GuestInfo{
		Hostname:     hostname,
		Username:     u.Username,
		OSVersion:    osVersion,
		BuildVersion: buildVersion,
		SIPDisabled:  sipDisabled,
	}, nil
}

func MountVirtioFS(tag, mountpoint string) error {
	if err := os.MkdirAll(mountpoint, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", mountpoint, err)
	}

	// #nosec G204 -- tag is a hardcoded virtiofs tag, mountpoint is the workdir set by the trusted host.
	cmd := exec.Command("mount_virtiofs", tag, mountpoint)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mount_virtiofs %s %s: %w (%s)", tag, mountpoint, err, strings.TrimSpace(string(out)))
	}
	return nil
}

var errKeepRunning = errors.New("keep running")

func runAgent(ctx context.Context, nc net.Conn) error {
	pc := vsock.GuestConnWrap(nc)
	defer pc.Close()

	info, err := CollectGuestInfo()
	if err != nil {
		return fmt.Errorf("collect guest info: %w", err)
	}

	if err := pc.Handshake(info); err != nil {
		return fmt.Errorf("guest handshake failed: %w", err)
	}

	for {
		msg, err := pc.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("recv: %w", err)
		}

		switch msg.Type {
		case protocol.MsgSetWorkDir:
			var wd protocol.WorkDir
			if err := json.Unmarshal(msg.Payload, &wd); err != nil {
				return fmt.Errorf("decode workdir: %w", err)
			}

			if wd.SharePath != "" {
				if err := MountVirtioFS("machbox", wd.SharePath); err != nil {
					return fmt.Errorf("mount virtiofs: %w", err)
				}
			}

			if wd.WorkPath != "" {
				if err := os.MkdirAll(wd.WorkPath, 0o750); err != nil {
					return fmt.Errorf("create workdir %s: %w", wd.WorkPath, err)
				}
			}
		case protocol.MsgTask:
			task := &protocol.Task{}
			if err := json.Unmarshal(msg.Payload, task); err != nil {
				return fmt.Errorf("decode task: %w", err)
			}

			if err := pc.ExecuteTask(ctx, task); err != nil {
				return fmt.Errorf("execute task: %w", err)
			}
		case protocol.MsgSessionEnd:
			var se protocol.SessionEnd
			if err := json.Unmarshal(msg.Payload, &se); err != nil {
				return fmt.Errorf("decode session end: %w", err)
			}
			if se.KeepRunning {
				return errKeepRunning
			}
			return nil
		default:
			return fmt.Errorf("unexpected message type: %d", msg.Type)
		}
	}
}

func main() {
	var conn net.Conn
	var err error

	ctx := context.Background()

	for range 120 {
		conn, err = vsock.Dial()
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to connect to host vsock: %v\n", err)
		os.Exit(1)
	}

	if err := runAgent(ctx, conn); err != nil {
		if errors.Is(err, errKeepRunning) {
			fmt.Println("[agent] analysis complete, entering keep-running mode")
			select {}
		}
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}
