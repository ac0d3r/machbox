package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// upgradeSSH is the protocol POST /v1/ssh switches the connection to:
	// the bytes of a TCP connection to the guest's sshd.
	upgradeSSH = "machbox-ssh"
	// defaultSSHAddr is the guest's sshd (Remote Login).
	defaultSSHAddr = "127.0.0.1:22"
	sshDialTimeout = 10 * time.Second
)

// handleSSH connects the request's connection to the guest's sshd, so the
// host reaches it over vsock without a guest network (machbox run --attach).
// The host asks with an HTTP upgrade; after the 101 the connection carries
// the SSH stream both ways until either side closes.
func (s *Server) handleSSH(w http.ResponseWriter, r *http.Request) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), upgradeSSH) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("want Upgrade: %s", upgradeSSH))
		return
	}
	addr := s.SSHAddr
	if addr == "" {
		addr = defaultSSHAddr
	}
	d := net.Dialer{Timeout: sshDialTimeout}
	sshd, err := d.DialContext(r.Context(), "tcp", addr)
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("connect to sshd (is Remote Login on?): %w", err))
		return
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		_ = sshd.Close()
		writeError(w, http.StatusInternalServerError, fmt.Errorf("hijack: %w", err))
		return
	}
	// No request or header deadline may outlive the upgrade.
	_ = conn.SetDeadline(time.Time{})
	_, err = brw.WriteString("HTTP/1.1 101 Switching Protocols\r\n" +
		"Connection: Upgrade\r\nUpgrade: " + upgradeSSH + "\r\n\r\n")
	if err == nil {
		err = brw.Flush()
	}
	if err != nil {
		_ = sshd.Close()
		_ = conn.Close()
		return
	}

	// Close both when the agent stops; a hijacked connection outlives the
	// HTTP server otherwise.
	stop := context.AfterFunc(r.Context(), func() {
		_ = sshd.Close()
		_ = conn.Close()
	})
	defer stop()
	// Read through brw: it may hold bytes the host sent after the request.
	Splice(rwc{Reader: brw.Reader, Conn: conn}, sshd)
}

// rwc reads through a buffered reader and does the rest on the connection.
type rwc struct {
	io.Reader
	net.Conn
}

func (c rwc) Read(p []byte) (int, error) { return c.Reader.Read(p) }

// DialSSH opens a byte stream to the guest's sshd through the agent. The
// caller closes it; ctx only bounds opening it.
func (c *Client) DialSSH(ctx context.Context) (io.ReadWriteCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+pathSSH, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", upgradeSSH)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("open ssh stream: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		return nil, fmt.Errorf("open ssh stream: %w", responseError(resp))
	}
	stream, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		_ = resp.Body.Close()
		return nil, errors.New("open ssh stream: the response body is not writable")
	}
	return stream, nil
}

// Splice copies a and b into each other until both directions end, then
// closes both. When one direction ends, the side that was written to is
// half-closed if it can be (TCP, unix sockets), so the other direction can
// finish; otherwise both are closed at once.
func Splice(a, b io.ReadWriteCloser) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = a.Close()
			_ = b.Close()
		})
	}
	defer closeBoth()

	var wg sync.WaitGroup
	pipe := func(dst, src io.ReadWriteCloser) {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && cw.CloseWrite() == nil {
			return
		}
		closeBoth()
	}
	wg.Add(2)
	go pipe(a, b)
	go pipe(b, a)
	wg.Wait()
}
