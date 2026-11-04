package vm

import (
	"slices"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
)

func TestCheckFeatures(t *testing.T) {
	got := checkFeatures(&agent.CheckReport{
		SIPDisabled: true,
		Features:    []string{"autologin", "fda", "brew", "agent", "rosetta"},
	})
	want := []string{"agent", "autologin", "rosetta", "sip-disabled"}
	if !slices.Equal(got, want) {
		t.Errorf("features = %v, want %v", got, want)
	}

	// SIP follows the report, not a stale feature.
	got = checkFeatures(&agent.CheckReport{Features: []string{"sip-disabled"}})
	if !slices.Equal(got, []string{"agent"}) {
		t.Errorf("features = %v, want [agent]", got)
	}
}
