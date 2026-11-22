package job

import (
	"strings"
	"testing"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/plugin"
)

func TestCheckShareAccess(t *testing.T) {
	wf := &plugin.Workflow{Inputs: plugin.Inputs{
		{Name: "sample", Type: plugin.InputFile},
		{Name: "password", Type: plugin.InputString},
	}}
	sipOn := &db.VM{Name: "sip-on", Features: []string{agent.FeatureAgent}}
	for _, tc := range []struct {
		name    string
		vm      *db.VM
		inputs  map[string]string
		refused bool
	}{
		{"file input, SIP on, no access", sipOn, map[string]string{"sample": "/x"}, true},
		{"no file given", sipOn, map[string]string{"password": "p"}, false},
		{"SIP off", &db.VM{Features: []string{agent.FeatureSIPDisabled}}, map[string]string{"sample": "/x"}, false},
		{"full disk access", &db.VM{Features: []string{agent.FeatureFullDiskAccess}}, map[string]string{"sample": "/x"}, false},
	} {
		err := checkShareAccess(tc.vm, wf, tc.inputs)
		if (err != nil) != tc.refused {
			t.Errorf("%s: err = %v, refused %v", tc.name, err, tc.refused)
		}
		if err != nil && !strings.Contains(err.Error(), "Full Disk Access") {
			t.Errorf("%s: unhelpful error %q", tc.name, err)
		}
	}
}
