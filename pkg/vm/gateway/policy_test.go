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
	newPolicy := func(egress Egress) *policy {
		return &policy{
			gateway: netip.MustParseAddr(gatewayIP),
			egress:  egress,
			interfaceAddrs: func() ([]net.Addr, error) {
				return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.7"), Mask: net.CIDRMask(24, 32)}}, nil
			},
		}
	}
	all, public, none := newPolicy(EgressAll), newPolicy(EgressPublic), newPolicy(EgressNone)
	arp := make([]byte, 42)
	arp[12], arp[13] = 0x08, 0x06
	ipv6 := make([]byte, 54)
	ipv6[12], ipv6[13] = 0x86, 0xdd

	tests := []struct {
		name              string
		frame             []byte
		all, public, none bool
	}{
		{"arp", arp, true, true, true},
		{"ipv6", ipv6, false, false, false},
		{"public tcp", ipv4Frame(protoTCP, "93.184.215.14", 443), true, true, false},
		{"public udp", ipv4Frame(protoUDP, "1.1.1.1", 53), true, true, false},
		{"dhcp broadcast", ipv4Frame(protoUDP, "255.255.255.255", 67), true, true, true},
		{"dhcp gateway", ipv4Frame(protoUDP, gatewayIP, 67), true, true, true},
		{"dns gateway udp", ipv4Frame(protoUDP, gatewayIP, 53), true, true, true},
		{"dns gateway tcp", ipv4Frame(protoTCP, gatewayIP, 53), true, true, true},
		{"gateway other port", ipv4Frame(protoTCP, gatewayIP, 22), false, false, false},
		{"broadcast other port", ipv4Frame(protoUDP, "255.255.255.255", 137), false, false, false},
		{"10/8", ipv4Frame(protoTCP, "10.1.2.3", 80), true, false, false},
		{"172.16/12", ipv4Frame(protoTCP, "172.31.0.1", 80), true, false, false},
		{"192.168/16", ipv4Frame(protoTCP, "192.168.1.1", 80), true, false, false},
		{"guest subnet", ipv4Frame(protoTCP, "192.168.127.2", 80), true, false, false},
		{"loopback", ipv4Frame(protoTCP, "127.0.0.1", 80), false, false, false},
		{"this network", ipv4Frame(protoTCP, "0.0.0.0", 80), false, false, false},
		{"link-local", ipv4Frame(protoTCP, "169.254.169.254", 80), true, false, false},
		{"cgnat", ipv4Frame(protoTCP, "100.100.100.100", 53), true, false, false},
		{"cgnat edge", ipv4Frame(protoTCP, "100.127.255.254", 80), true, false, false},
		{"above cgnat", ipv4Frame(protoTCP, "100.128.0.1", 80), true, true, false},
		{"multicast", ipv4Frame(protoUDP, "224.0.0.251", 5353), false, false, false},
		{"host address", ipv4Frame(protoTCP, "203.0.113.7", 22), false, false, false},
		{"host's neighbour", ipv4Frame(protoTCP, "203.0.113.8", 22), true, true, false},
	}
	for _, tt := range tests {
		if got, _ := all.allow(tt.frame); got != tt.all {
			t.Errorf("egress all %s: allow = %v, want %v", tt.name, got, tt.all)
		}
		if got, _ := public.allow(tt.frame); got != tt.public {
			t.Errorf("egress public %s: allow = %v, want %v", tt.name, got, tt.public)
		}
		if got, _ := none.allow(tt.frame); got != tt.none {
			t.Errorf("egress none %s: allow = %v, want %v", tt.name, got, tt.none)
		}
	}

	proxy := newPolicy(EgressNone)
	proxy.proxy = true
	for _, tt := range []struct {
		frame []byte
		want  bool
	}{
		{ipv4Frame(protoTCP, gatewayIP, 80), true},
		{ipv4Frame(protoTCP, gatewayIP, 443), false},
		{ipv4Frame(protoUDP, gatewayIP, 80), false},
		{ipv4Frame(protoTCP, "255.255.255.255", 80), false},
	} {
		if got, dst := proxy.allow(tt.frame); got != tt.want {
			t.Errorf("with proxy: allow %s = %v, want %v", dst, got, tt.want)
		}
	}
	if got, _ := public.allow(ipv4Frame(protoTCP, gatewayIP, 80)); got {
		t.Error("gateway port 80 allowed without a proxy")
	}

	for _, ip := range []string{"::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:10.0.0.1"} {
		if !public.blocked(netip.MustParseAddr(ip)) {
			t.Errorf("egress public blocked(%s) = false", ip)
		}
	}
	for _, ip := range []string{"::1", "ff02::1", "::ffff:127.0.0.1"} {
		if !all.blocked(netip.MustParseAddr(ip)) {
			t.Errorf("egress all blocked(%s) = false", ip)
		}
	}
}
