package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// AgentVersion is the host↔guest agent revision shared by both sides.
// Kept in this package (not guest-agent) so host and guest can import the
// same constant without a circular dependency. Bump when the API changes
// incompatibly; unchanged values do not require reinstalling
// machbox-guest.pkg or re-importing the baseline.
const AgentVersion = "3"

// baseURL is the authority used for requests; the transport ignores it and
// always dials the guest over vsock.
const baseURL = "http://machbox-guest"

var (
	// ErrNotFound is returned when the guest has no such file.
	ErrNotFound = errors.New("not found")
	// ErrTaskTimedOut is returned by CopyTask when the task hit its timeout.
	ErrTaskTimedOut = errors.New("task timed out")
)

// DialFunc opens one vsock connection to the guest agent.
type DialFunc func(ctx context.Context) (net.Conn, error)

// CompatibleAgent reports whether a guest agent is usable with this host.
func CompatibleAgent(version string) error {
	if version == "" {
		return fmt.Errorf("guest agent did not report agent_version; reinstall machbox-guest.pkg")
	}
	if version != AgentVersion {
		return fmt.Errorf("guest agent version %q incompatible with host agent %q; reinstall machbox-guest.pkg",
			version, AgentVersion)
	}
	return nil
}

// Client talks to the guest agent's HTTP API over vsock. It is safe for
// concurrent use; each in-flight request uses its own connection.
type Client struct {
	hc *http.Client
}

// NewClient returns a client that dials the guest with dial.
func NewClient(dial DialFunc) *Client {
	return &Client{hc: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: 2,
	}}}
}

// Close drops idle connections to the guest.
func (c *Client) Close() error {
	if c != nil && c.hc != nil {
		c.hc.CloseIdleConnections()
	}
	return nil
}

// Probe asks the guest for its info over a fresh connection that is closed
// afterwards, so it observes the agent currently listening (e.g. after a
// reinstall) rather than a kept-alive connection to a previous one.
func Probe(ctx context.Context, dial DialFunc) (GuestInfo, error) {
	c := NewClient(dial)
	defer c.Close()
	return c.Info(ctx)
}

// WaitReady polls the guest until its agent answers or ctx is cancelled.
func WaitReady(ctx context.Context, dial DialFunc, interval time.Duration) (*Client, GuestInfo, error) {
	c := NewClient(dial)
	var last error
	for {
		info, err := c.Info(ctx)
		if err == nil {
			LogGuest(info)
			return c, info, nil
		}
		last = err
		logrus.Debugf("guest agent not ready: %v", err)
		select {
		case <-ctx.Done():
			_ = c.Close()
			return nil, GuestInfo{}, fmt.Errorf("%w (last: %w)", ctx.Err(), last)
		case <-time.After(interval):
		}
	}
}

// Info returns the guest's description.
func (c *Client) Info(ctx context.Context) (GuestInfo, error) {
	var info GuestInfo
	if err := c.doJSON(ctx, http.MethodGet, pathInfo, nil, &info); err != nil {
		return GuestInfo{}, fmt.Errorf("guest info: %w", err)
	}
	return info, nil
}

// SetWorkdir tells the guest where to store files and mount the share.
func (c *Client) SetWorkdir(ctx context.Context) (WorkDir, error) {
	tmpID := strconv.FormatInt(time.Now().UnixNano(), 36)
	wd := WorkDir{
		WorkPath:  fmt.Sprintf("/tmp/machbox_w%s", tmpID),
		SharePath: fmt.Sprintf("/tmp/machbox_s%s", tmpID),
	}
	if err := c.doJSON(ctx, http.MethodPost, pathWorkDir, wd, nil); err != nil {
		return WorkDir{}, fmt.Errorf("set workdir: %w", err)
	}
	return wd, nil
}

// RunTask runs a task to completion and returns its trimmed stdout.
// Cancelling ctx kills the task in the guest.
func (c *Client) RunTask(ctx context.Context, task *Task) (string, error) {
	var res TaskResult
	if err := c.doJSON(ctx, http.MethodPost, pathExec, task, &res); err != nil {
		return "", fmt.Errorf("run task: %w", err)
	}
	if !res.OK {
		return "", fmt.Errorf("run task failed: %s", res.Error)
	}
	return strings.TrimSpace(res.Output), nil
}

// RunStreamTask starts a task and returns its stdout as it is produced.
// Reaching the task timeout is a normal end (the reader returns io.EOF with
// everything collected); any other failure is returned by Read at the end.
// Closing the reader or cancelling ctx kills the task in the guest.
func (c *Client) RunStreamTask(ctx context.Context, task *Task) (io.ReadCloser, error) {
	resp, err := c.do(ctx, http.MethodPost, pathExecStream, task) //nolint:bodyclose // owned by streamReader; the caller closes it
	if err != nil {
		return nil, fmt.Errorf("start stream task: %w", err)
	}
	return &streamReader{resp: resp}, nil
}

// CopyTask runs a task to completion, copying its stdout to w as it is
// produced. Unlike RunStreamTask, reaching the timeout is an error
// (ErrTaskTimedOut); output written before it is kept. Cancelling ctx kills
// the task in the guest.
func (c *Client) CopyTask(ctx context.Context, task *Task, w io.Writer) error {
	resp, err := c.do(ctx, http.MethodPost, pathExecStream, task)
	if err != nil {
		return fmt.Errorf("start task: %w", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("task output: %w", err)
	}
	t := resp.Trailer
	if t.Get(trailerTaskTimedOut) == "true" {
		return ErrTaskTimedOut
	}
	if msg := t.Get(trailerTaskError); msg != "" {
		return fmt.Errorf("task failed: %s", msg)
	}
	return nil
}

// OpenFile returns the contents of the regular file name (relative) inside
// the guest directory root. A missing file is reported as ErrNotFound.
func (c *Client) OpenFile(ctx context.Context, root, name string) (io.ReadCloser, error) {
	q := url.Values{"root": {root}, "path": {name}}
	resp, err := c.do(ctx, http.MethodGet, pathFiles+"?"+q.Encode(), nil) //nolint:bodyclose // returned to the caller
	if err != nil {
		return nil, fmt.Errorf("open guest file %s: %w", name, err)
	}
	return resp.Body, nil
}

type streamReader struct {
	resp *http.Response
}

func (r *streamReader) Read(p []byte) (int, error) {
	n, err := r.resp.Body.Read(p)
	if errors.Is(err, io.EOF) {
		// Trailers are only populated once the body is fully read.
		t := r.resp.Trailer
		if msg := t.Get(trailerTaskError); msg != "" && t.Get(trailerTaskTimedOut) != "true" {
			return n, fmt.Errorf("stream task failed: %s", msg)
		}
	}
	return n, err
}

func (r *streamReader) Close() error { return r.resp.Body.Close() }

func (c *Client) doJSON(ctx context.Context, method, path string, in, out any) error {
	resp, err := c.do(ctx, method, path, in)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

// do sends a request and returns a 2xx response; other statuses become errors.
func (c *Client) do(ctx context.Context, method, path string, in any) (*http.Response, error) {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer resp.Body.Close()
	msg := resp.Status
	var ae apiError
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxRequestBody)).Decode(&ae); err == nil && ae.Error != "" {
		msg = ae.Error
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("guest agent: %s: %w", msg, ErrNotFound)
	}
	return nil, fmt.Errorf("guest agent: %s", msg)
}

// LogGuest logs a successful guest handshake.
func LogGuest(info GuestInfo) {
	logrus.Infof("guest connected: %s %s (%s), host=%s user=%s agent_version=%q sip_disabled=%v",
		info.OSName, info.OSVersion, info.BuildVersion,
		info.Hostname, info.Username, info.AgentVersion, info.SIPDisabled)
	if info.Username != "root" {
		logrus.Warnf("guest agent running as non-root user: %s", info.Username)
	}
	if !info.SIPDisabled {
		logrus.Warnln("guest SIP is still enabled; EndpointSecurity.framework features may not work correctly")
	}
}
