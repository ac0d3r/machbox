package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
)

// AgentPath is where Machbox Setup installs the agent in the guest.
const AgentPath = "/usr/local/libexec/machbox-guest"

// Features a baseline can have. The agent itself is one; the rest are what
// `machbox-guest check` finds in the guest.
const (
	FeatureAgent       = "agent"
	FeatureAutologin   = "autologin"
	FeatureRosetta     = "rosetta"
	FeatureCLT         = "clt"
	FeatureSSH         = "ssh"
	FeatureSIPDisabled = "sip-disabled"
)

// Features is every known feature, in display order.
var Features = []string{
	FeatureAgent, FeatureAutologin, FeatureRosetta, FeatureCLT, FeatureSSH, FeatureSIPDisabled,
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

// CheckReport is the output of `machbox-guest check`.
type CheckReport struct {
	AgentVersion  string `json:"agent_version"`
	ConsoleUser   string `json:"console_user,omitempty"`
	AutoLoginUser string `json:"autologin_user,omitempty"`
	FileVault     bool   `json:"filevault"`
	SIPDisabled   bool   `json:"sip_disabled"`
	// Features is what is in place, out of Features less agent.
	Features []string `json:"features"`
}

// Check runs `machbox-guest check` as a task.
func (c *Client) Check(ctx context.Context) (CheckReport, error) {
	var r CheckReport
	out, err := c.RunTask(ctx, &Task{Command: AgentPath, Args: []string{"check"}})
	if err != nil {
		return r, fmt.Errorf("guest check: %w", err)
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		return r, fmt.Errorf("guest check: %w", err)
	}
	return r, nil
}
