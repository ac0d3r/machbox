package plugin

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/ac0d3r/machbox/internal/agent"
)

// SIPState is the System Integrity Protection state a plugin needs.
type SIPState string

const (
	SIPAny      SIPState = ""
	SIPDisabled SIPState = "disabled"
	SIPEnabled  SIPState = "enabled"
)

// Requires constrains the guest a plugin runs in.
type Requires struct {
	// MacOS is a comma-separated list of version constraints, e.g.
	// ">=14.0" or ">=14, <16".
	MacOS string   `yaml:"macos"`
	SIP   SIPState `yaml:"sip"`
	// Features the baseline must have (agent.Features), e.g. [rosetta, clt].
	Features []string `yaml:"features"`
}

func (r Requires) validate() error {
	if _, err := parseConstraints(r.MacOS); err != nil {
		return fmt.Errorf("macos: %w", err)
	}
	switch r.SIP {
	case SIPAny, SIPDisabled, SIPEnabled:
	default:
		return fmt.Errorf("sip: unknown state %q (disabled, enabled)", r.SIP)
	}
	for _, f := range r.Features {
		if !agent.KnownFeature(f) {
			return fmt.Errorf("features: unknown feature %q (%s)", f, strings.Join(agent.Features, ", "))
		}
	}
	return nil
}

// CheckOS reports whether a guest running osVersion satisfies the macOS
// constraint.
func (r Requires) CheckOS(osVersion string) error {
	cs, err := parseConstraints(r.MacOS)
	if err != nil {
		return err
	}
	for _, c := range cs {
		ok, err := c.match(osVersion)
		if err != nil {
			return fmt.Errorf("guest macOS version: %w", err)
		}
		if !ok {
			return fmt.Errorf("guest macOS %s does not satisfy %s", osVersion, r.MacOS)
		}
	}
	return nil
}

// Check verifies a guest against all requirements. Baseline records carry
// all of them, so this works before boot; after boot it confirms them.
func (r Requires) Check(osVersion string, features []string) error {
	if err := r.CheckOS(osVersion); err != nil {
		return err
	}
	sipDisabled := slices.Contains(features, agent.FeatureSIPDisabled)
	switch {
	case r.SIP == SIPDisabled && !sipDisabled:
		return errors.New("guest SIP is enabled; plugin requires it disabled")
	case r.SIP == SIPEnabled && sipDisabled:
		return errors.New("guest SIP is disabled; plugin requires it enabled")
	}
	var missing []string
	for _, f := range r.Features {
		if !slices.Contains(features, f) {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("guest lacks %s; add it with: machbox vm setup", strings.Join(missing, ", "))
	}
	return nil
}

// String describes the requirements, e.g. "macOS >=14.0, SIP disabled".
func (r Requires) String() string {
	var parts []string
	if r.MacOS != "" {
		parts = append(parts, "macOS "+r.MacOS)
	}
	if r.SIP != SIPAny {
		parts = append(parts, "SIP "+string(r.SIP))
	}
	if len(r.Features) > 0 {
		parts = append(parts, "features "+strings.Join(r.Features, ", "))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

type constraint struct {
	op      string
	version []int
}

var constraintOps = []string{">=", "<=", "==", ">", "<"} // two-char operators first

func parseConstraints(s string) ([]constraint, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var cs []constraint
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		var c constraint
		for _, op := range constraintOps {
			if strings.HasPrefix(part, op) {
				c.op = op
				break
			}
		}
		if c.op == "" {
			return nil, fmt.Errorf("constraint %q needs an operator (%s)", part, strings.Join(constraintOps, " "))
		}
		v, err := parseVersion(strings.TrimSpace(part[len(c.op):]))
		if err != nil {
			return nil, err
		}
		c.version = v
		cs = append(cs, c)
	}
	return cs, nil
}

func (c constraint) match(version string) (bool, error) {
	v, err := parseVersion(version)
	if err != nil {
		return false, err
	}
	cmp := compareVersions(v, c.version)
	switch c.op {
	case ">=":
		return cmp >= 0, nil
	case "<=":
		return cmp <= 0, nil
	case ">":
		return cmp > 0, nil
	case "<":
		return cmp < 0, nil
	default:
		return cmp == 0, nil
	}
}

func parseVersion(s string) ([]int, error) {
	if s == "" {
		return nil, errors.New("empty version")
	}
	parts := strings.Split(s, ".")
	v := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("invalid version %q", s)
		}
		v[i] = n
	}
	return v, nil
}

// compareVersions compares dotted versions; missing components count as 0.
func compareVersions(a, b []int) int {
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
