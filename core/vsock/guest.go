package vsock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/ac0d3r/machbox/core/vsock/protocol"
)

type GuestConn struct {
	conn *protocol.Conn
}

func GuestConnWrap(nc net.Conn) *GuestConn {
	return &GuestConn{conn: protocol.Wrap(nc)}
}

func (c *GuestConn) Handshake(info *protocol.GuestInfo) (err error) {
	if err = c.conn.SendJSON(protocol.MsgGuestInfo, info); err != nil {
		return
	}
	var ack protocol.ACK
	if err = c.conn.RecvJSON(protocol.MsgACK, &ack); err != nil {
		return
	}
	if !ack.OK {
		return fmt.Errorf("host rejected guest info: %s", ack.Error)
	}
	return
}

func (c *GuestConn) ExecuteTask(ctx context.Context, task *protocol.Task) error {
	if task.Timeout <= 0 {
		task.Timeout = 60
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(task.Timeout)*time.Second)
	defer cancel()

	// #nosec G204 -- guest-agent intentionally executes commands received from the trusted host.
	cmd := exec.CommandContext(ctx, task.Command, task.Args...)
	cmd.Dir = task.WorkDir

	if task.Stream {
		return c.executeStreamTask(ctx, cmd)
	}

	return c.executeTask(cmd)
}

func (c *GuestConn) executeTask(cmd *exec.Cmd) error {
	var ret protocol.TaskResult

	out, err := cmd.Output()
	if err != nil {
		var eerr *exec.ExitError
		if errors.As(err, &eerr) {
			ret.Error = fmt.Sprintf("%s (stderr: %s)", err.Error(), strings.TrimSpace(string(eerr.Stderr)))
		} else {
			ret.Error = err.Error()
		}
	} else {
		ret.OK = true
		ret.Output = string(out)
	}
	return c.conn.SendJSON(protocol.MsgTaskResult, ret)
}

func (c *GuestConn) sendACK(ok bool, errMsg string) error {
	return c.conn.SendJSON(protocol.MsgACK, protocol.ACK{OK: ok, Error: errMsg})
}

func (c *GuestConn) executeStreamTask(ctx context.Context, cmd *exec.Cmd) error {
	var stderrBuf bytes.Buffer
	cmd.Stderr = &stderrBuf

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return c.sendACK(false, err.Error())
	}

	if err := cmd.Start(); err != nil {
		return c.sendACK(false, err.Error())
	}
	defer stdout.Close()

	if err := c.sendACK(true, ""); err != nil {
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
				if err := c.conn.Send(protocol.MsgStreamTaskData, buf[:n]); err != nil {
					ferr = err
					_ = stdout.Close()
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					if ctx.Err() == context.DeadlineExceeded {
						ferr = context.DeadlineExceeded
					} else {
						ferr = err
					}
				}
				break
			}
		}
	}()

	err = cmd.Wait()
	wg.Wait()

	var errStr string
	switch {
	case ferr != nil:
		errStr = ferr.Error()
	case err != nil:
		errStr = err.Error()
	}
	stderr := strings.TrimSpace(stderrBuf.String())
	if stderr != "" {
		errStr = fmt.Sprintf("%s (stderr: %s)", errStr, stderr)
	}

	return c.conn.SendJSON(protocol.MsgStreamTaskEnd, protocol.StreamTaskEnd{Error: errStr})
}

func (c *GuestConn) Recv() (*protocol.Message, error) { return c.conn.Recv() }
func (c *GuestConn) Close() error                     { return c.conn.Close() }
