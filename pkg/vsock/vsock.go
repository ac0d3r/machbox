// Package vsock provides a macOS guest-side AF_VSOCK listener.
// The host dials via Virtualization.framework (pkg/vm.ConnectVsock).
package vsock

import (
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultPort is the well-known virtio-vsock port for machbox guest-agent.
const DefaultPort uint32 = 12345

type addr struct{ port uint32 }

func (a addr) Network() string { return "vsock" }
func (a addr) String() string  { return fmt.Sprintf("%d", a.port) }

type conn struct {
	fd         int
	localPort  uint32
	remotePort uint32
}

func (c *conn) Read(b []byte) (int, error) {
	n, err := unix.Read(c.fd, b)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (c *conn) Write(b []byte) (int, error) {
	return unix.Write(c.fd, b)
}

func (c *conn) Close() error {
	if c.fd < 0 {
		return nil
	}
	err := unix.Close(c.fd)
	c.fd = -1
	return err
}

func (c *conn) LocalAddr() net.Addr             { return addr{c.localPort} }
func (c *conn) RemoteAddr() net.Addr            { return addr{c.remotePort} }
func (c *conn) SetDeadline(time.Time) error     { return nil }
func (c *conn) SetReadDeadline(time.Time) error { return nil }
func (c *conn) SetWriteDeadline(time.Time) error {
	return nil
}

type listener struct {
	fd   int
	port uint32
}

// Listen binds AF_VSOCK on port (VMADDR_CID_ANY) and accepts host connections.
func Listen(port uint32) (net.Listener, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: port}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}
	if err := unix.Listen(fd, unix.SOMAXCONN); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("listen: %w", err)
	}
	// Nonblocking listen fd so Accept can Poll without holding ForkLock.
	// Holding ForkLock across a blocking Accept deadlocks later exec/fork
	// (e.g. scutil from collectGuestInfo).
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("set nonblock: %w", err)
	}
	return &listener{fd: fd, port: port}, nil
}

func (l *listener) Accept() (net.Conn, error) {
	nfd, err := accept(l.fd)
	if err != nil {
		return nil, err
	}
	// Darwin inherits O_NONBLOCK from the listen socket; clear it so
	// handshake reads block until the peer sends.
	if err := unix.SetNonblock(nfd, false); err != nil {
		_ = unix.Close(nfd)
		return nil, err
	}

	peer, err := unix.Getpeername(nfd)
	if err != nil {
		_ = unix.Close(nfd)
		return nil, fmt.Errorf("getpeername: %w", err)
	}
	vm, ok := peer.(*unix.SockaddrVM)
	if !ok {
		_ = unix.Close(nfd)
		return nil, fmt.Errorf("peer is not SockaddrVM: %T", peer)
	}
	return &conn{
		fd:         nfd,
		localPort:  l.port,
		remotePort: vm.Port,
	}, nil
}

// accept waits until fd is readable, then accepts. ForkLock is held only
// around Accept+CloseOnExec, never across the wait.
func accept(fd int) (int, error) {
	for {
		if err := waitReadable(fd); err != nil {
			return -1, err
		}
		syscall.ForkLock.RLock()
		nfd, _, err := unix.Accept(fd)
		if err == nil {
			unix.CloseOnExec(nfd)
		}
		syscall.ForkLock.RUnlock()
		if err == unix.EINTR || err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			continue
		}
		if err != nil {
			return -1, err
		}
		return nfd, nil
	}
}

func waitReadable(fd int) error {
	if fd < 0 {
		return net.ErrClosed
	}
	for {
		fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		_, err := unix.Poll(fds, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		re := fds[0].Revents
		if re&unix.POLLIN != 0 {
			return nil
		}
		if re&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
			return net.ErrClosed
		}
	}
}

func (l *listener) Addr() net.Addr { return addr{l.port} }

func (l *listener) Close() error {
	if l.fd < 0 {
		return nil
	}
	err := unix.Close(l.fd)
	l.fd = -1
	return err
}
