package gateway

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeARP  = 0x0806

	protoTCP = 6
	protoUDP = 17

	hostAddrsTTL = 5 * time.Second
)

var (
	broadcast   = netip.AddrFrom4([4]byte{255, 255, 255, 255})
	thisNetwork = netip.MustParsePrefix("0.0.0.0/8") // 0.0.0.0 reaches the host's loopback
)

// policy decides which guest frames reach the gateway's stack. The stack's
// forwarders dial whatever address a frame is for, so a dropped frame is a
// connection never made.
type policy struct {
	gateway netip.Addr
	// interfaceAddrs lists the host's addresses; net.InterfaceAddrs if nil.
	interfaceAddrs func() ([]net.Addr, error)

	hostAddrs map[netip.Addr]struct{}
	refreshed time.Time
}

// allow reports whether frame, sent by the guest, may enter the stack. It
// returns the destination for logging when it does not.
func (p *policy) allow(frame []byte) (bool, netip.Addr) {
	if len(frame) < 14 {
		return false, netip.Addr{}
	}
	switch binary.BigEndian.Uint16(frame[12:14]) {
	case etherTypeARP:
		return true, netip.Addr{}
	case etherTypeIPv4:
		return p.allowIPv4(frame[14:])
	default:
		// The stack only speaks IPv4, so IPv6 never leaves anyway.
		return false, netip.Addr{}
	}
}

func (p *policy) allowIPv4(pkt []byte) (bool, netip.Addr) {
	if len(pkt) < 20 {
		return false, netip.Addr{}
	}
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if dst != p.gateway && dst != broadcast {
		return !p.blocked(dst), dst
	}

	// Only the gateway's own DHCP and DNS: anything else for these
	// addresses would be dialed on the host's network.
	ihl := int(pkt[0]&0x0f) * 4
	firstFragment := binary.BigEndian.Uint16(pkt[6:8])&0x1fff == 0
	if ihl < 20 || len(pkt) < ihl+4 || !firstFragment {
		return false, dst
	}
	port := binary.BigEndian.Uint16(pkt[ihl+2 : ihl+4])
	switch pkt[9] {
	case protoUDP:
		return port == 67 || (port == 53 && dst == p.gateway), dst
	case protoTCP:
		return port == 53 && dst == p.gateway, dst
	}
	return false, dst
}

// blocked reports whether the guest must not reach ip: private, loopback,
// link-local, multicast and the host's own addresses.
func (p *policy) blocked(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() || thisNetwork.Contains(ip) || ip == broadcast {
		return true
	}
	return p.isHostAddr(ip)
}

func (p *policy) isHostAddr(ip netip.Addr) bool {
	if time.Since(p.refreshed) > hostAddrsTTL {
		p.refreshHostAddrs()
	}
	_, ok := p.hostAddrs[ip]
	return ok
}

func (p *policy) refreshHostAddrs() {
	list := p.interfaceAddrs
	if list == nil {
		list = net.InterfaceAddrs
	}
	addrs, err := list()
	if err != nil {
		return // keep the last known set
	}
	p.hostAddrs = make(map[netip.Addr]struct{}, len(addrs))
	for _, a := range addrs {
		if pfx, err := netip.ParsePrefix(a.String()); err == nil {
			p.hostAddrs[pfx.Addr().Unmap()] = struct{}{}
		}
	}
	p.refreshed = time.Now()
}
