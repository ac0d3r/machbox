package vsock

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"

	"golang.org/x/sys/unix"
)

// oneConnListener hands out a single connection, then blocks until closed.
type oneConnListener struct {
	c    chan net.Conn
	done chan struct{}
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.c:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *oneConnListener) Close() error   { close(l.done); return nil }
func (l *oneConnListener) Addr() net.Addr { return addr{} }

// The agent's connections are *os.File-backed like these; net/http must
// keep serving requests on a kept-alive connection after the first one.
func TestKeepAliveRequestsOverFileConn(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if err := unix.SetNonblock(fd, true); err != nil {
			t.Fatal(err)
		}
	}
	server := &conn{File: os.NewFile(uintptr(fds[0]), "vsock")}
	client, err := net.FileConn(os.NewFile(uintptr(fds[1]), "client"))
	if err != nil {
		t.Fatal(err)
	}

	ln := &oneConnListener{c: make(chan net.Conn, 1), done: make(chan struct{})}
	ln.c <- server
	srv := &agent.Server{Info: func() (agent.GuestInfo, error) { return agent.GuestInfo{}, nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx, ln) }()

	// machbox's own client does not keep connections alive; a default
	// one does, which is what exposed the bug.
	used := false
	hc := &http.Client{Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			if used {
				t.Error("client dialed twice; the connection was not kept alive")
			}
			used = true
			return client, nil
		},
	}}

	resp, err := hc.Get("http://guest/v1/info")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	for i := range 2 {
		resp, err := hc.Post("http://guest/v1/exec", "application/json", strings.NewReader(`{"command":"echo","args":["ok"]}`))
		if err != nil {
			t.Fatal(err)
		}
		var res agent.TaskResult
		err = json.NewDecoder(resp.Body).Decode(&res)
		_ = resp.Body.Close()
		if err != nil || !res.OK || res.Output != "ok\n" {
			t.Fatalf("task %d on the kept-alive connection: %+v, %v", i+1, res, err)
		}
	}
}
