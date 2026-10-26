// Package vsock is the guest-side AF_VSOCK listener used by machbox-guest.
//
// The host cannot dial AF_VSOCK directly; it uses Virtualization.framework
// via pkg/vm.VMInstance.ConnectVsock instead. Port number lives in
// internal/agent.DefaultVsockPort.
//
// Sockets are non-blocking and wrapped in *os.File, so they are driven by the
// Go netpoller: connections support deadlines (needed by net/http), and
// closing the listener unblocks a pending Accept.
package vsock

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type addr struct{ port uint32 }

func (a addr) Network() string { return "vsock" }
func (a addr) String() string  { return fmt.Sprintf("%d", a.port) }

type conn struct {
	*os.File
	localPort  uint32
	remotePort uint32
}

func (c *conn) LocalAddr() net.Addr  { return addr{c.localPort} }
func (c *conn) RemoteAddr() net.Addr { return addr{c.remotePort} }

// Read and Write return errors as *net.OpError. net/http only recognizes a
// deadline error as a net.Error; the *PathError from *os.File lacks
// Temporary, and net/http would then cancel the context of every later
// request on the kept-alive connection.
func (c *conn) Read(b []byte) (int, error) {
	n, err := c.File.Read(b)
	return n, c.opError("read", err)
}

func (c *conn) Write(b []byte) (int, error) {
	n, err := c.File.Write(b)
	return n, c.opError("write", err)
}

func (c *conn) opError(op string, err error) error {
	if err == nil || errors.Is(err, io.EOF) {
		return err
	}
	return &net.OpError{Op: op, Net: "vsock", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
}

// *os.File provides Close and the deadline methods.
var _ net.Conn = (*conn)(nil)

type listener struct {
	f    *os.File
	rc   syscall.RawConn
	port uint32
}

// Listen binds AF_VSOCK on port (VMADDR_CID_ANY) and accepts host connections.
func Listen(port uint32) (net.Listener, error) {
	fd, err := socket()
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}

	f := os.NewFile(uintptr(fd), "vsock-listener")
	rc, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &listener{f: f, rc: rc, port: port}, nil
}

func socket() (int, error) {
	// Hold ForkLock so the fd cannot leak into a concurrently forked child
	// before it is marked close-on-exec.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("socket: %w", err)
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return -1, fmt.Errorf("set nonblock: %w", err)
	}
	return fd, nil
}

func (l *listener) Accept() (net.Conn, error) {
	var (
		nfd  int
		peer unix.Sockaddr
		aerr error
	)
	err := l.rc.Read(func(fd uintptr) bool {
		// ForkLock is held only for the non-blocking accept itself; waiting
		// for readiness happens in the netpoller without it.
		syscall.ForkLock.RLock()
		nfd, peer, aerr = unix.Accept(int(fd))
		if aerr == nil {
			unix.CloseOnExec(nfd)
		}
		syscall.ForkLock.RUnlock()
		// false: not ready yet, wait for the listener to become readable.
		return !errors.Is(aerr, unix.EAGAIN) && !errors.Is(aerr, unix.EINTR)
	})
	if err != nil {
		if errors.Is(err, os.ErrClosed) {
			return nil, net.ErrClosed
		}
		return nil, err
	}
	if aerr != nil {
		return nil, fmt.Errorf("accept: %w", aerr)
	}

	vm, ok := peer.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(nfd)
		return nil, fmt.Errorf("peer is not SockaddrVM: %T", peer)
	}
	// Darwin inherits O_NONBLOCK from the listening socket; set it
	// explicitly so os.NewFile registers the fd with the netpoller.
	if err := unix.SetNonblock(nfd, true); err != nil {
		_ = unix.Close(nfd)
		return nil, err
	}
	return &conn{
		File:       os.NewFile(uintptr(nfd), "vsock"),
		localPort:  l.port,
		remotePort: vm.Port,
	}, nil
}

func (l *listener) Addr() net.Addr { return addr{l.port} }

func (l *listener) Close() error { return l.f.Close() }
