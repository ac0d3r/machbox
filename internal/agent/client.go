package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// DialFunc opens one vsock connection to the guest agent.
type DialFunc func(ctx context.Context) (net.Conn, error)

// Client is the host-side session over a single vsock connection.
type Client struct {
	conn *conn
}

// Dial opens one vsock and completes the guest→host handshake.
func Dial(ctx context.Context, dial DialFunc) (*Client, GuestInfo, error) {
	nc, err := dial(ctx)
	if err != nil {
		return nil, GuestInfo{}, err
	}
	c := &Client{conn: wrapConn(nc)}

	var info GuestInfo
	if err := c.conn.recvJSON(msgGuestInfo, &info); err != nil {
		_ = c.Close()
		return nil, GuestInfo{}, err
	}
	if err := c.conn.sendJSON(msgACK, ack{OK: true}); err != nil {
		_ = c.Close()
		return nil, GuestInfo{}, err
	}
	return c, info, nil
}

// WaitReady dials until handshake succeeds or ctx is cancelled.
func WaitReady(ctx context.Context, dial DialFunc, interval time.Duration) (*Client, GuestInfo, error) {
	var last error
	for {
		c, info, err := Dial(ctx, dial)
		if err == nil {
			LogGuest(info)
			return c, info, nil
		}
		last = err
		logrus.Debugf("guest agent not ready: %v", err)
		select {
		case <-ctx.Done():
			return nil, GuestInfo{}, fmt.Errorf("%w (last: %v)", ctx.Err(), last)
		case <-time.After(interval):
		}
	}
}

func (c *Client) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	return err
}

// SetWorkdir tells the guest where to store files and mount the share.
func (c *Client) SetWorkdir(_ context.Context) (workpath, sharepath string, err error) {
	wd := WorkDir{
		WorkPath:  fmt.Sprintf("/tmp/machbox_w%s", strconv.FormatInt(time.Now().UnixNano(), 36)),
		SharePath: "/tmp/machbox_s",
	}
	if err := c.conn.sendJSON(msgSetWorkDir, wd); err != nil {
		return "", "", fmt.Errorf("set workdir: %w", err)
	}
	var a ack
	if err := c.conn.recvJSON(msgACK, &a); err != nil {
		return "", "", fmt.Errorf("set workdir: %w", err)
	}
	if !a.OK {
		return "", "", fmt.Errorf("set workdir: %s", a.Error)
	}
	return wd.WorkPath, wd.SharePath, nil
}

// RunTask runs a non-streaming task and returns trimmed stdout.
func (c *Client) RunTask(_ context.Context, task *Task) (string, error) {
	task.Stream = false
	if err := c.conn.sendJSON(msgTask, task); err != nil {
		return "", err
	}
	var res TaskResult
	if err := c.conn.recvJSON(msgTaskResult, &res); err != nil {
		return "", err
	}
	if !res.OK {
		return "", fmt.Errorf("run task failed: %s", res.Error)
	}
	return strings.TrimSpace(res.Output), nil
}

// RunStreamTask runs a streaming task; the reader yields stdout until EOF.
func (c *Client) RunStreamTask(_ context.Context, task *Task) (io.ReadCloser, error) {
	task.Stream = true
	if err := c.conn.sendJSON(msgTask, task); err != nil {
		return nil, err
	}
	var a ack
	if err := c.conn.recvJSON(msgACK, &a); err != nil {
		return nil, err
	}
	if !a.OK {
		return nil, fmt.Errorf("task rejected: %s", a.Error)
	}

	r, w := io.Pipe()
	go func() {
		defer w.Close()
		for {
			msg, err := c.conn.recv()
			if err != nil {
				_ = w.CloseWithError(err)
				return
			}
			switch msg.Type {
			case msgStreamTaskData:
				if _, err := w.Write(msg.Payload); err != nil {
					return
				}
			case msgStreamTaskEnd:
				var end streamTaskEnd
				if err := json.Unmarshal(msg.Payload, &end); err != nil {
					_ = w.CloseWithError(err)
					return
				}
				if end.Error != "" && end.Error != context.DeadlineExceeded.Error() {
					_ = w.CloseWithError(errors.New(end.Error))
				}
				return
			default:
				_ = w.CloseWithError(fmt.Errorf("unexpected stream message type %d", msg.Type))
				return
			}
		}
	}()
	return r, nil
}

// LogGuest logs a successful guest handshake.
func LogGuest(info GuestInfo) {
	logrus.Infof("guest connected: %s %s (%s), host=%s user=%s agent=%q sip_disabled=%v",
		info.OSName, info.OSVersion, info.BuildVersion,
		info.Hostname, info.Username, info.AgentVersion, info.SIPDisabled)
	if info.Username != "root" {
		logrus.Warnf("guest agent running as non-root user: %s", info.Username)
	}
	if !info.SIPDisabled {
		logrus.Warnln("guest SIP is still enabled; EndpointSecurity.framework features may not work correctly")
	}
}
