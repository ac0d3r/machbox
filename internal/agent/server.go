package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Server is the guest-agent session handler.
type Server struct {
	Info       func() (GuestInfo, error)
	MountShare func(sharePath string) error
}

// Serve accepts connections until ctx is cancelled or the listener fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, nc)
	}
}

func (s *Server) handleConn(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	c := wrapConn(nc)
	info, err := s.Info()
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect guest info: %v\n", err)
		return
	}
	if err := c.sendJSON(msgGuestInfo, info); err != nil {
		fmt.Fprintf(os.Stderr, "send guest info: %v\n", err)
		return
	}
	var a ack
	if err := c.recvJSON(msgACK, &a); err != nil {
		fmt.Fprintf(os.Stderr, "recv handshake ack: %v\n", err)
		return
	}
	if !a.OK {
		fmt.Fprintf(os.Stderr, "host rejected guest info: %s\n", a.Error)
		return
	}

	for {
		msg, err := c.recv()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				fmt.Fprintf(os.Stderr, "recv: %v\n", err)
			}
			return
		}
		switch msg.Type {
		case msgSetWorkDir:
			var wd WorkDir
			if err := json.Unmarshal(msg.Payload, &wd); err != nil {
				fmt.Fprintf(os.Stderr, "decode workdir: %v\n", err)
				return
			}
			if err := s.applyWorkDir(&wd); err != nil {
				_ = c.sendJSON(msgACK, ack{OK: false, Error: err.Error()})
				return
			}
			if err := c.sendJSON(msgACK, ack{OK: true}); err != nil {
				fmt.Fprintf(os.Stderr, "ack workdir: %v\n", err)
				return
			}
		case msgTask:
			var task Task
			if err := json.Unmarshal(msg.Payload, &task); err != nil {
				fmt.Fprintf(os.Stderr, "decode task: %v\n", err)
				return
			}
			if err := executeTask(ctx, c, &task); err != nil {
				fmt.Fprintf(os.Stderr, "execute task: %v\n", err)
				return
			}
		default:
			fmt.Fprintf(os.Stderr, "unexpected message type: %d\n", msg.Type)
			return
		}
	}
}

func (s *Server) applyWorkDir(wd *WorkDir) error {
	if wd.SharePath != "" && s.MountShare != nil {
		if err := s.MountShare(wd.SharePath); err != nil {
			return fmt.Errorf("mount share: %w", err)
		}
	}
	if wd.WorkPath != "" {
		if err := os.MkdirAll(wd.WorkPath, 0o750); err != nil {
			return fmt.Errorf("mkdir workdir: %w", err)
		}
	}
	return nil
}

func executeTask(ctx context.Context, c *conn, task *Task) error {
	if task.Timeout <= 0 {
		task.Timeout = 60
	}
	tctx, cancel := context.WithTimeout(ctx, time.Duration(task.Timeout)*time.Second)
	defer cancel()

	// #nosec G204 -- guest-agent executes commands from the trusted host.
	cmd := exec.CommandContext(tctx, task.Command, task.Args...)
	cmd.Dir = task.WorkDir

	if task.Stream {
		return executeStreamTask(tctx, c, cmd)
	}
	return executeOneShotTask(c, cmd)
}

func executeOneShotTask(c *conn, cmd *exec.Cmd) error {
	var ret TaskResult
	out, err := cmd.Output()
	if err != nil {
		ret.Error = execErr(err)
	} else {
		ret.OK = true
		ret.Output = string(out)
	}
	return c.sendJSON(msgTaskResult, ret)
}

func executeStreamTask(ctx context.Context, c *conn, cmd *exec.Cmd) error {
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return c.sendJSON(msgACK, ack{OK: false, Error: err.Error()})
	}
	if err := cmd.Start(); err != nil {
		return c.sendJSON(msgACK, ack{OK: false, Error: err.Error()})
	}
	if err := c.sendJSON(msgACK, ack{OK: true}); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return err
	}

	var ferr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		<-ctx.Done()
		_ = stdout.Close()
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 4*1024)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				if err := c.send(msgStreamTaskData, buf[:n]); err != nil {
					ferr = err
					_ = stdout.Close()
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					if errors.Is(ctx.Err(), context.DeadlineExceeded) {
						ferr = context.DeadlineExceeded
					} else {
						ferr = err
					}
				}
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	timedOut := errors.Is(ferr, context.DeadlineExceeded) ||
		errors.Is(waitErr, context.DeadlineExceeded) ||
		errors.Is(ctx.Err(), context.DeadlineExceeded)

	var errStr string
	switch {
	case ferr != nil:
		errStr = ferr.Error()
	case waitErr != nil:
		errStr = waitErr.Error()
	}
	if s := strings.TrimSpace(stderrBuf.String()); s != "" {
		if errStr == "" {
			errStr = s
		} else {
			errStr = fmt.Sprintf("%s (stderr: %s)", errStr, s)
		}
	}
	return c.sendJSON(msgStreamTaskEnd, streamTaskEnd{Error: errStr, TimedOut: timedOut})
}

func execErr(err error) string {
	var eerr *exec.ExitError
	if errors.As(err, &eerr) {
		return fmt.Sprintf("%s (stderr: %s)", err.Error(), strings.TrimSpace(string(eerr.Stderr)))
	}
	return err.Error()
}
