package filebase

import "testing"

func TestSniffZIPAndXAR(t *testing.T) {
	if sn := sniffHeader([]byte{'P', 'K', 0x03, 0x04}); sn.Kind != kindZIP {
		t.Fatalf("zip: got %v", sn.Kind)
	}
	if sn := sniffHeader([]byte("xar!\x00\x00")); sn.Kind != kindXAR {
		t.Fatalf("xar: got %v", sn.Kind)
	}
	if !sniffDMGTrailer([]byte("koly" + string(make([]byte, 508)))) {
		t.Fatal("expected dmg trailer")
	}
}
