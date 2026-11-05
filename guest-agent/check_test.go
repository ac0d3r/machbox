package main

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
)

func TestDecodeKCPassword(t *testing.T) {
	// "secret" as sysadminctl writes it: NUL-terminated, padded to a
	// multiple of 12 bytes.
	plain := append([]byte("secret\x00"), make([]byte, 5)...)
	enc := make([]byte, len(plain))
	for i, b := range plain {
		enc[i] = b ^ kcpasswordKey[i%len(kcpasswordKey)]
	}
	if got := decodeKCPassword(enc); got != "secret" {
		t.Errorf("decoded %q", got)
	}
}

func TestSIPDisabled(t *testing.T) {
	if !sipDisabled("System Integrity Protection status: disabled.\n") {
		t.Error("disabled not parsed")
	}
	if sipDisabled("System Integrity Protection status: enabled.\n") {
		t.Error("enabled parsed as disabled")
	}
}

func TestReachableIPv4(t *testing.T) {
	var addrs []net.Addr
	for _, s := range []string{"127.0.0.1/8", "169.254.3.4/16", "fe80::1/64", "2001:db8::5/64", "192.168.64.5/24", "10.0.0.2/8"} {
		p := netip.MustParsePrefix(s)
		addrs = append(addrs, &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())})
	}
	if got := fmt.Sprint(reachableIPv4(addrs)); got != "[192.168.64.5 10.0.0.2]" {
		t.Errorf("reachableIPv4 = %s", got)
	}
}
