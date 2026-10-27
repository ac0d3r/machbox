package gateway

import (
	"net"
	"net/netip"
	"testing"
)

func ipv4Frame(proto byte, dst string, port uint16) []byte {
	f := make([]byte, 14+20+4)
	f[12], f[13] = 0x08, 0x00
	ip := f[14:]
	ip[0] = 0x45
	ip[9] = proto
	copy(ip[16:20], netip.MustParseAddr(dst).AsSlice())
	ip[22], ip[23] = byte(port>>8), byte(port)
	return f
}

func TestPolicyAllow(t *testing.T) {
	p := &policy{
		gateway: netip.MustParseAddr(gatewayIP),
		interfaceAddrs: func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.7"), Mask: net.CIDRMask(24, 32)}}, nil
		},
	}
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	ipv6 := make([]byte, 54)
	ipv6[12], ipv6[13] = 0x86, 0xdd

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"arp", arp, true},
		{"ipv6", ipv6, false},
		{"public tcp", ipv4Frame(protoTCP, "93.184.215.14", 443), true},
		{"public udp", ipv4Frame(protoUDP, "1.1.1.1", 53), true},
		{"dhcp broadcast", ipv4Frame(protoUDP, "255.255.255.255", 67), true},
		{"dhcp gateway", ipv4Frame(protoUDP, gatewayIP, 67), true},
		{"dns gateway udp", ipv4Frame(protoUDP, gatewayIP, 53), true},
		{"dns gateway tcp", ipv4Frame(protoTCP, gatewayIP, 53), true},
		{"gateway other port", ipv4Frame(protoTCP, gatewayIP, 22), false},
		{"broadcast other port", ipv4Frame(protoUDP, "255.255.255.255", 137), false},
		{"10/8", ipv4Frame(protoTCP, "10.1.2.3", 80), false},
		{"172.16/12", ipv4Frame(protoTCP, "172.31.0.1", 80), false},
		{"192.168/16", ipv4Frame(protoTCP, "192.168.1.1", 80), false},
		{"guest subnet", ipv4Frame(protoTCP, "192.168.127.2", 80), false},
		{"loopback", ipv4Frame(protoTCP, "127.0.0.1", 80), false},
		{"this network", ipv4Frame(protoTCP, "0.0.0.0", 80), false},
		{"link-local", ipv4Frame(protoTCP, "169.254.169.254", 80), false},
		{"multicast", ipv4Frame(protoUDP, "224.0.0.251", 5353), false},
		{"host address", ipv4Frame(protoTCP, "203.0.113.7", 22), false},
		{"host's neighbour", ipv4Frame(protoTCP, "203.0.113.8", 22), true},
	}
	for _, tt := range tests {
		if got, _ := p.allow(tt.frame); got != tt.want {
			t.Errorf("%s: allow = %v, want %v", tt.name, got, tt.want)
		}
	}

	for _, ip := range []string{"::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:10.0.0.1"} {
		if !p.blocked(netip.MustParseAddr(ip)) {
			t.Errorf("blocked(%s) = false", ip)
		}
	}
}
