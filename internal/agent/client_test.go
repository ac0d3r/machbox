package agent

import "testing"

func TestCompatibleProtocol(t *testing.T) {
	if err := CompatibleProtocol(ProtocolVersion); err != nil {
		t.Fatalf("matching protocol: %v", err)
	}
	if CompatibleProtocol("") == nil {
		t.Fatal("empty protocol should fail")
	}
	if CompatibleProtocol(ProtocolVersion + ".x") == nil {
		t.Fatal("mismatched protocol should fail")
	}
}
