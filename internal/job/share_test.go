package job

import (
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
)

// The share always holds the plugin, so access is checked with or without
// file inputs.
func TestCheckShareAccess(t *testing.T) {
	for _, tc := range []struct {
		name    string
		vm      *db.VM
		refused bool
	}{
		{"SIP on, no access", &db.VM{Name: "sip-on", Features: []string{agent.FeatureAgent}}, true},
		{"SIP off", &db.VM{Features: []string{agent.FeatureSIPDisabled}}, false},
		{"full disk access", &db.VM{Features: []string{agent.FeatureFullDiskAccess}}, false},
	} {
		err := checkShareAccess(tc.vm)
		if (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, refused %v", tc.name, err, tc.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "Full Disk Access") {
			t.Errorf("%s: unhelpful error %q", tc.name, err)
		}
	}
}
