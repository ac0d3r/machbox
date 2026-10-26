package plugin

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
}

func (r Requires) validate() error {
	if _, err := parseConstraints(r.MacOS); err != nil {
		return fmt.Errorf("macos: %w", err)
	}
	switch r.SIP {
	case SIPAny, SIPDisabled, SIPEnabled:
		return nil
	}
	return fmt.Errorf("sip: unknown state %q (disabled, enabled)", r.SIP)
}

// CheckOS reports whether a guest running osVersion satisfies the macOS
// constraint. Baseline records carry the version, so this works before boot.
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

// Check verifies a running guest against all requirements.
func (r Requires) Check(osVersion string, sipDisabled bool) error {
	if err := r.CheckOS(osVersion); err != nil {
		return err
	}
	switch {
	case r.SIP == SIPDisabled && !sipDisabled:
		return errors.New("guest SIP is enabled; plugin requires it disabled")
	case r.SIP == SIPEnabled && sipDisabled:
		return errors.New("guest SIP is disabled; plugin requires it enabled")
	}
	return nil
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
