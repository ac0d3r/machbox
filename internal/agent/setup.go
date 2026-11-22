package agent

import (
	"context"
	"fmt"
	"net/http"
	"slices"
)

// AgentPath is where Machbox Setup installs the agent in the guest.
const AgentPath = "/usr/local/libexec/machbox-guest"

// Features a baseline can have. The agent itself is one; the rest are what
// the agent's check finds in the guest.
const (
	FeatureAgent     = "agent"
	FeatureAutologin = "autologin"
	FeatureRosetta   = "rosetta"
	FeatureCLT       = "clt"
	FeatureSSH       = "ssh"
	// FeatureFullDiskAccess: the agent may read anything TCC guards, the
	// share included. Implied with SIP off.
	FeatureFullDiskAccess = "full-disk-access"
	FeatureSIPDisabled    = "sip-disabled"
)

// Features is every known feature, in display order.
var Features = []string{
	FeatureAgent, FeatureAutologin, FeatureRosetta, FeatureCLT, FeatureSSH, FeatureFullDiskAccess, FeatureSIPDisabled,
}

// KnownFeature reports whether name is in Features.
func KnownFeature(name string) bool {
	return slices.Contains(Features, name)
}

// WithSIP returns features with sip-disabled set to match sipDisabled, as
// the live guest reports it.
func WithSIP(features []string, sipDisabled bool) []string {
	out := slices.DeleteFunc(slices.Clone(features), func(f string) bool { return f == FeatureSIPDisabled })
	if sipDisabled {
		out = append(out, FeatureSIPDisabled)
	}
	return out
}

// CheckFile is where the agent leaves its last CheckReport for Machbox
// Setup, which cannot run the check itself: TCC would judge Full Disk Access
// by Setup's grant, not the agent's.
const CheckFile = "/var/run/dev.machbox.guest.check.json"

// CheckReport is what the agent's check finds (GET /v1/check, CheckFile).
type CheckReport struct {
	AgentVersion  string `json:"agent_version"`
	ConsoleUser   string `json:"console_user,omitempty"`
	AutoLoginUser string `json:"autologin_user,omitempty"`
	FileVault     bool   `json:"filevault"`
	SIPDisabled   bool   `json:"sip_disabled"`
	// Features is what is in place, out of Features less agent.
	Features []string `json:"features"`
}

// Check has the agent check the guest, in its own process: what it can
// read is what runs can.
func (c *Client) Check(ctx context.Context) (CheckReport, error) {
	var r CheckReport
	if err := c.doJSON(ctx, http.MethodGet, pathCheck, nil, &r); err != nil {
		return r, fmt.Errorf("guest check: %w", err)
	}
	return r, nil
}
