package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
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

func TestSaveCheck(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "check.json")
	want := agent.CheckReport{AgentVersion: agent.AgentVersion, Features: []string{agent.FeatureFullDiskAccess}}
	for range 2 { // the second replaces the first
		if err := saveCheck(file, want); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var got agent.CheckReport
	if err := json.Unmarshal(data, &got); err != nil || !slices.Equal(got.Features, want.Features) {
		t.Errorf("saved %s (%v)", data, err)
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o644 {
		t.Errorf("mode %v, want 0644 for Setup to read", info.Mode().Perm())
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("left %d files, want only the report", len(entries))
	}
}
