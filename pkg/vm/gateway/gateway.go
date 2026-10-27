// Package gateway runs a user-mode network (gvisor-tap-vsock) on the host for
// a VM attached through a file-handle network device. The guest gets DHCP,
// DNS and outbound connections to public addresses only; see policy.
package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	subnet     = "192.168.127.0/24"
	gatewayIP  = "192.168.127.1"
	gatewayMAC = "5a:94:ef:e4:0c:dd"
	mtu        = 1500

	// vz wants SO_RCVBUF at least twice SO_SNDBUF, ideally four times.
	sndBuf = 1 << 20
	rcvBuf = 4 << 20

	// maxRefusedLogged bounds the destinations logged (and remembered) when
	// the guest scans.
	maxRefusedLogged = 64
)

// Gateway relays frames between the VM and the network stack, dropping
// those the policy refuses and capturing all of them.
//
//	VM ── vm|guest ── relay ── relay|stack ── virtual network
type Gateway struct {
	vn    *virtualnetwork.VirtualNetwork
	vm    *os.File
	guest net.Conn
	relay net.Conn
	stack net.Conn
	pcap  *pcapWriter
	wg    sync.WaitGroup

	stopSwitch context.CancelFunc
	switchDone chan struct{}
}

// Start creates the gateway. capture, if not empty, receives every frame
// the guest sends or receives as pcap, refused ones included.
func Start(capture string) (g *Gateway, err error) {
	g = &Gateway{}
	defer func() {
		if err != nil {
			_ = g.Close()
		}
	}()

	if g.vn, err = virtualnetwork.New(&types.Configuration{
		MTU:               mtu,
		Subnet:            subnet,
		GatewayIP:         gatewayIP,
		GatewayMacAddress: gatewayMAC,
		Protocol:          types.VfkitProtocol,
	}); err != nil {
		return nil, fmt.Errorf("create virtual network: %w", err)
	}
	if capture != "" {
		if g.pcap, err = newPcapWriter(capture); err != nil {
			return nil, fmt.Errorf("create capture: %w", err)
		}
	}

	var guest, stack *os.File
	if g.vm, guest, err = socketpair(); err != nil {
		return nil, err
	}
	g.guest, err = fileConn(guest)
	if err != nil {
		return nil, err
	}
	relay, stack, err := socketpair()
	if err != nil {
		return nil, err
	}
	if g.relay, err = fileConn(relay); err != nil {
		_ = stack.Close()
		return nil, err
	}
	if g.stack, err = fileConn(stack); err != nil {
		return nil, err
	}

	p := &policy{gateway: netip.MustParseAddr(gatewayIP)}
	ctx, cancel := context.WithCancel(context.Background())
	g.stopSwitch, g.switchDone = cancel, make(chan struct{})
	go func() {
		defer close(g.switchDone)
		// The switch logs its own read errors, so Close stops it through ctx.
		if err := g.vn.AcceptVfkit(ctx, g.stack); err != nil && !errors.Is(err, net.ErrClosed) {
			logrus.Warnf("network gateway: %v", err)
		}
	}()
	g.wg.Add(2)
	go func() {
		defer g.wg.Done()
		g.forward(g.guest, g.relay, p)
	}()
	go func() {
		defer g.wg.Done()
		g.forward(g.relay, g.guest, nil)
	}()
	return g, nil
}

// forward copies frames from src to dst until src is closed. Frames from
// the guest go through p; refused ones are only captured.
func (g *Gateway) forward(src, dst net.Conn, p *policy) {
	refused := map[netip.Addr]struct{}{}
	buf := make([]byte, 1<<16)
	for {
		n, err := src.Read(buf)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				logrus.Warnf("network gateway: %v", err)
			}
			return
		}
		frame := buf[:n]
		g.pcap.write(frame)
		if p != nil {
			if ok, dst := p.allow(frame); !ok {
				// Multicast and broadcast are the OS's own LAN chatter (mDNS, IGMP), not connections.
				_, seen := refused[dst]
				if !seen && dst.IsValid() && !dst.IsMulticast() && dst != broadcast && len(refused) < maxRefusedLogged {
					refused[dst] = struct{}{}
					if len(refused) < maxRefusedLogged {
						logrus.Infof("network gateway: refused guest traffic to %s", dst)
					} else {
						logrus.Infof("network gateway: refused guest traffic to %s; not logging further destinations", dst)
					}
				}
				continue
			}
		}
		// A full receiver drops the frame, like a busy link.
		_, _ = dst.Write(frame)
	}
}

// VMFile returns the VM end of the link, for config.Network.File. It stays
// open until Close.
func (g *Gateway) VMFile() *os.File { return g.vm }

// Close stops the gateway and flushes the capture. The VM must be stopped
// first.
func (g *Gateway) Close() error {
	if g.stopSwitch != nil {
		// The switch checks ctx only between reads: wake it with a frame for
		// the gateway whose EtherType (local experimental) its stack drops.
		g.stopSwitch()
		wake := make([]byte, 14)
		mac, _ := net.ParseMAC(gatewayMAC)
		copy(wake, mac)
		wake[6] = 0x02
		wake[12], wake[13] = 0x88, 0xb5
		if _, err := g.relay.Write(wake); err == nil {
			<-g.switchDone
		}
	}
	for _, c := range []net.Conn{g.guest, g.relay, g.stack} {
		if c != nil {
			_ = c.Close()
		}
	}
	if g.switchDone != nil {
		<-g.switchDone
	}
	g.wg.Wait()
	if g.vm != nil {
		_ = g.vm.Close()
	}
	err := g.pcap.Close()
	if g.vn != nil {
		err = errors.Join(err, g.vn.Close())
	}
	return err
}

func socketpair() (*os.File, *os.File, error) {
	// macOS has no SOCK_CLOEXEC; hold ForkLock so no child inherits them.
	syscall.ForkLock.RLock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, fmt.Errorf("socketpair: %w", err)
	}
	for _, fd := range fds {
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
		_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvBuf)
	}
	return os.NewFile(uintptr(fds[0]), "gateway"), os.NewFile(uintptr(fds[1]), "gateway"), nil
}

// fileConn wraps f as a net.Conn and closes f.
func fileConn(f *os.File) (net.Conn, error) {
	defer f.Close()
	c, err := net.FileConn(f)
	if err != nil {
		return nil, fmt.Errorf("gateway socket: %w", err)
	}
	return c, nil
}
