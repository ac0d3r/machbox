package agent

import "testing"

func TestCompatibleAgent(t *testing.T) {
	if err := CompatibleAgent(AgentVersion); err != nil {
		t.Fatalf("matching agent version: %v", err)
	}
	if CompatibleAgent("") == nil {
		t.Fatal("empty agent version should fail")
	}
	if CompatibleAgent(AgentVersion+".x") == nil {
		t.Fatal("mismatched agent version should fail")
	}
}
