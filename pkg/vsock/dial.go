package vsock

import (
	"errors"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

const (
	afVSOCK       = 40
	vmaddrCIDHost = 2
	vsockPort     = 12345
)

// sockaddrVM matches struct sockaddr_vm from <sys/vsock.h> on macOS.
type sockaddrVM struct {
	Len      uint8
	Family   uint8
	Reserved uint16
	Port     uint32
	CID      uint32
}

// vsockAddr implements net.Addr for virtio-vsock.
type vsockAddr struct {
	cid  uint32
	port uint32
}

func (a vsockAddr) Network() string { return "vsock" }
func (a vsockAddr) String() string  { return fmt.Sprintf("%d:%d", a.cid, a.port) }

// vsockConn wraps a raw fd into net.Conn.
type vsockConn struct {
	fd   int
	addr vsockAddr
}

func (c *vsockConn) Read(b []byte) (int, error) { return syscall.Read(c.fd, b) }
func (c *vsockConn) Write(b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, err := syscall.Write(c.fd, b)
		if n > 0 {
			total += n
			b = b[n:]
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
func (c *vsockConn) Close() error                       { return syscall.Close(c.fd) }
func (c *vsockConn) LocalAddr() net.Addr                { return nil }
func (c *vsockConn) RemoteAddr() net.Addr               { return c.addr }
func (c *vsockConn) SetDeadline(t time.Time) error      { return nil }
func (c *vsockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *vsockConn) SetWriteDeadline(t time.Time) error { return nil }

func dialVsock(port uint32) (net.Conn, error) {
	fd, err := syscall.Socket(afVSOCK, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	if fd < 0 {
		return nil, errors.New("socket: invalid fd")
	}

	addr := sockaddrVM{
		Len:    uint8(unsafe.Sizeof(sockaddrVM{})),
		Family: afVSOCK,
		Port:   port,
		CID:    vmaddrCIDHost,
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		// #nosec G103 -- required for syscall.Syscall with sockaddr_vm.
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Sizeof(addr)),
	)
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("connect: %w", errno)
	}

	return &vsockConn{fd: fd, addr: vsockAddr{cid: vmaddrCIDHost, port: port}}, nil
}

func Dial() (net.Conn, error) {
	return dialVsock(vsockPort)
}
