package agent

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// startSSHAgent serves the agent API on loopback TCP with /v1/ssh pointed
// at sshAddr. stop stops the agent.
func startSSHAgent(t *testing.T, sshAddr string) (c *Client, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- (&Server{SSHAddr: sshAddr}).Serve(ctx, ln) }()
	var stopped bool
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	}
	t.Cleanup(stop)
	c = NewClient(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
	return c, stop
}

// fakeSSHD accepts one connection, sends a banner like sshd does before
// reading anything, then echoes lines. It reports when the connection ends.
func fakeSSHD(t *testing.T) (addr string, ended <-chan struct{}) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := io.WriteString(conn, "SSH-2.0-fake\r\n"); err != nil {
			return
		}
		_, _ = io.Copy(conn, conn)
	}()
	return ln.Addr().String(), ch
}

func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not end", what)
	}
}

func TestDialSSH(t *testing.T) {
	addr, ended := fakeSSHD(t)
	c, _ := startSSHAgent(t, addr)

	// Cancelling ctx once the stream is open leaves it open.
	ctx, cancel := context.WithCancel(context.Background())
	s, err := c.DialSSH(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(s)
	if banner, err := r.ReadString('\n'); err != nil || banner != "SSH-2.0-fake\r\n" {
		t.Fatalf("banner = %q, %v", banner, err)
	}
	if _, err := io.WriteString(s, "ping\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := r.ReadString('\n'); err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, ended, "sshd connection after the host closed the stream")
}

func TestDialSSHWithoutSSHD(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // nothing listens there now
	c, _ := startSSHAgent(t, addr)

	_, err = c.DialSSH(context.Background())
	if err == nil || !strings.Contains(err.Error(), "Remote Login") {
		t.Fatalf("err = %v; want one naming Remote Login", err)
	}
}

func TestSSHNeedsUpgrade(t *testing.T) {
	addr, _ := fakeSSHD(t)
	c, _ := startSSHAgent(t, addr)
	err := c.doJSON(context.Background(), "POST", pathSSH, struct{}{}, nil)
	if err == nil || !strings.Contains(err.Error(), "Upgrade") {
		t.Fatalf("err = %v; want a request without Upgrade refused", err)
	}
}

func TestAgentStopClosesSSH(t *testing.T) {
	addr, ended := fakeSSHD(t)
	c, stop := startSSHAgent(t, addr)
	s, err := c.DialSSH(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := bufio.NewReader(s).ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	stop()
	waitClosed(t, ended, "sshd connection after the agent stopped")
	read := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, s)
		read <- err
	}()
	select {
	case <-read:
	case <-time.After(5 * time.Second):
		t.Fatal("the host stream stayed open after the agent stopped")
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	s := <-accepted
	if s == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	return c, s
}

// A side that stops sending is half-closed, so the other direction still
// delivers its answer.
func TestSpliceHalfClose(t *testing.T) {
	client, a := tcpPair(t)
	b, server := tcpPair(t)
	spliced := make(chan struct{})
	go func() { Splice(a, b); close(spliced) }()

	if _, err := io.WriteString(client, "request"); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(server)
	if err != nil || string(got) != "request" {
		t.Fatalf("server read %q, %v", got, err)
	}
	if _, err := io.WriteString(server, "answer"); err != nil {
		t.Fatal(err)
	}
	_ = server.Close()
	got, err = io.ReadAll(client)
	if err != nil || string(got) != "answer" {
		t.Fatalf("client read %q, %v", got, err)
	}
	waitClosed(t, spliced, "Splice")
}

// Without half-close, the first direction to end closes both sides.
func TestSpliceClosesBoth(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	spliced := make(chan struct{})
	go func() { Splice(a2, b1); close(spliced) }()

	_ = a1.Close()
	waitClosed(t, spliced, "Splice")
	if _, err := b2.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("other side read err = %v; want it closed", err)
	}
}
