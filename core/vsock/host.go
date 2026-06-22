package vsock

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

	"github.com/ac0d3r/machbox/core/vsock/protocol"

	"github.com/sirupsen/logrus"
)

type HostConn struct {
	conn *protocol.Conn
}

func HostConnWrap(nc net.Conn) *HostConn {
	return &HostConn{conn: protocol.Wrap(nc)}
}

func (c *HostConn) GuestHandshake() (info protocol.GuestInfo, err error) {
	if err = c.conn.RecvJSON(protocol.MsgGuestInfo, &info); err != nil {
		return
	}
	if err = c.conn.SendJSON(protocol.MsgACK, protocol.ACK{OK: true}); err != nil {
		return
	}

	logrus.Infof("guest connected: host=%s user=%s os=%s sip=%v",
		info.Hostname, info.Username, info.OSVersion, !info.SIPDisabled)
	if info.Username != "root" {
		logrus.Warnf("guest agent running as non-root user: %s", info.Username)
	}
	if !info.SIPDisabled {
		logrus.Warnln("guest SIP is still enabled; EndpointSecurity.framework features may not work correctly")
	}
	return
}

func (c *HostConn) SetWorkdir() (workpath, sharepath string, err error) {
	workdir := protocol.WorkDir{
		WorkPath:  fmt.Sprintf("/tmp/machbox_w%s", strconv.FormatInt(time.Now().UnixNano(), 36)),
		SharePath: "/tmp/machbox_s",
	}

	if err := c.conn.SendJSON(protocol.MsgSetWorkDir, workdir); err != nil {
		return "", "", fmt.Errorf("failed to set workdir: %w", err)
	}

	return workdir.WorkPath, workdir.SharePath, nil
}

func (c *HostConn) RunTask(task *protocol.Task) (string, error) {
	if err := c.conn.SendJSON(protocol.MsgTask, task); err != nil {
		return "", err
	}
	var res protocol.TaskResult
	if err := c.conn.RecvJSON(protocol.MsgTaskResult, &res); err != nil {
		return "", err
	}
	if !res.OK {
		return "", fmt.Errorf("run task failed: %s", res.Error)
	}

	return strings.TrimSpace(res.Output), nil
}

func (c *HostConn) RunStreamTask(task *protocol.Task) (io.ReadCloser, error) {
	task.Stream = true
	if err := c.conn.SendJSON(protocol.MsgTask, task); err != nil {
		return nil, err
	}

	var ack protocol.ACK
	if err := c.conn.RecvJSON(protocol.MsgACK, &ack); err != nil {
		return nil, err
	}
	if !ack.OK {
		return nil, fmt.Errorf("task rejected: %s", ack.Error)
	}

	r, w := io.Pipe()
	go func() {
		defer w.Close()

		for {
			msg, err := c.conn.Recv()
			if err != nil {
				w.CloseWithError(err)
				return
			}

			switch msg.Type {
			case protocol.MsgStreamTaskData:
				if _, err := w.Write(msg.Payload); err != nil {
					return
				}
			case protocol.MsgStreamTaskEnd:
				var end protocol.StreamTaskEnd
				if err := json.Unmarshal(msg.Payload, &end); err != nil {
					w.CloseWithError(err)
					return
				}
				if end.Error != "" {
					if end.Error == context.DeadlineExceeded.Error() {
						return
					}
					w.CloseWithError(errors.New(end.Error))
				}
				return
			}
		}
	}()

	return r, nil
}

func (c *HostConn) SendSessionEnd(keepRunning bool) {
	if keepRunning {
		if err := c.conn.SendJSON(protocol.MsgSessionEnd, protocol.SessionEnd{KeepRunning: keepRunning}); err != nil {
			logrus.Errorf("failed to send session end: %v", err)
		}
	}
}

func (c *HostConn) Close() error { return c.conn.Close() }
