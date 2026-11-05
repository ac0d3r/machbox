package main

import (
	"crypto/pbkdf2"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"

	"howett.net/plist"
)

// runCheck prints what is in place in this guest as an agent.CheckReport.
func runCheck() int {
	r := agent.CheckReport{
		AgentVersion:  agent.AgentVersion,
		ConsoleUser:   consoleUser(),
		AutoLoginUser: autoLoginUser(),
		FileVault:     fileVaultOn(),
		Features:      []string{},
	}
	if csr, err := runTrim(exec.Command("/usr/bin/csrutil", "status")); err == nil {
		r.SIPDisabled = sipDisabled(csr)
	}
	for _, c := range []struct {
		feature string
		ok      bool
	}{
		{agent.FeatureAutologin, r.AutoLoginUser != ""},
		{agent.FeatureRosetta, succeeds("/usr/sbin/pkgutil", "--pkg-info", "com.apple.pkg.RosettaUpdateAuto")},
		{agent.FeatureCLT, succeeds("/usr/bin/xcode-select", "-p")},
		{agent.FeatureSSH, sshListening()},
	} {
		if c.ok {
			r.Features = append(r.Features, c.feature)
		}
	}
	r.Features = agent.WithSIP(r.Features, r.SIPDisabled)
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// autoLoginUser returns the user macOS logs in at boot. As root, also
// requires that /etc/kcpassword holds that user's current password: after a
// password change the setting stays, but the login fails. Others cannot read
// the file and get the setting alone.
func autoLoginUser() string {
	name, _ := runTrim(exec.Command("/usr/bin/defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"))
	if name == "" || os.Geteuid() != 0 {
		return name
	}
	data, err := os.ReadFile(kcpasswordPath)
	if err != nil {
		return ""
	}
	// Compared in process: a password on a command line (dscl -authonly)
	// is visible to every process in the guest.
	ok, err := passwordMatches(name, decodeKCPassword(data))
	if err != nil {
		// A user not in the local node, or a record without a PBKDF2 hash:
		// the setting and kcpassword are all there is to go by.
		fmt.Fprintf(os.Stderr, "check automatic login password: %v\n", err)
		return name
	}
	if !ok {
		return ""
	}
	return name
}

// localUsersDir holds the local node's user records, readable by root only.
const localUsersDir = "/var/db/dslocal/nodes/Default/users"

// passwordMatches reports whether password is user's, checked against the
// SALTED-SHA512-PBKDF2 hash in their local record.
func passwordMatches(user, password string) (bool, error) {
	if user == "" || user != filepath.Base(user) || strings.HasPrefix(user, ".") {
		return false, fmt.Errorf("invalid user name %q", user)
	}
	// #nosec G304 -- user is a single path element, checked above, in a root-only directory
	data, err := os.ReadFile(filepath.Join(localUsersDir, user+".plist"))
	if err != nil {
		return false, err
	}
	return shadowHashMatches(data, password)
}

// shadowHashMatches checks password against a user record (a plist whose
// ShadowHashData holds a plist of hashes).
func shadowHashMatches(record []byte, password string) (bool, error) {
	var rec struct {
		ShadowHashData [][]byte `plist:"ShadowHashData"`
	}
	if _, err := plist.Unmarshal(record, &rec); err != nil {
		return false, fmt.Errorf("user record: %w", err)
	}
	if len(rec.ShadowHashData) == 0 {
		return false, errors.New("user record has no ShadowHashData")
	}
	var hashes struct {
		PBKDF2 *struct {
			Entropy    []byte `plist:"entropy"`
			Iterations int    `plist:"iterations"`
			Salt       []byte `plist:"salt"`
		} `plist:"SALTED-SHA512-PBKDF2"`
	}
	if _, err := plist.Unmarshal(rec.ShadowHashData[0], &hashes); err != nil {
		return false, fmt.Errorf("ShadowHashData: %w", err)
	}
	h := hashes.PBKDF2
	if h == nil || len(h.Entropy) == 0 || len(h.Salt) == 0 || h.Iterations <= 0 {
		return false, errors.New("no SALTED-SHA512-PBKDF2 hash")
	}
	key, err := pbkdf2.Key(sha512.New, password, h.Salt, h.Iterations, len(h.Entropy))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(key, h.Entropy) == 1, nil
}

const kcpasswordPath = "/etc/kcpassword"

// kcpasswordKey is the fixed key loginwindow XORs the password with.
var kcpasswordKey = []byte{0x7d, 0x89, 0x52, 0x23, 0xd2, 0xbc, 0xdd, 0xea, 0xa3, 0xb9, 0x1f}

// decodeKCPassword undoes the XOR; the password ends at the first NUL, and
// padding follows it.
func decodeKCPassword(data []byte) string {
	out := make([]byte, 0, len(data))
	for i, b := range data {
		c := b ^ kcpasswordKey[i%len(kcpasswordKey)]
		if c == 0 {
			break
		}
		out = append(out, c)
	}
	return string(out)
}

func fileVaultOn() bool {
	// fdesetup exits non-zero when FileVault is off; stdout still answers.
	out, _ := exec.Command("/usr/bin/fdesetup", "isactive").Output()
	return strings.TrimSpace(string(out)) == "true"
}

func sshListening() bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:22", 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func succeeds(name string, args ...string) bool {
	return exec.Command(name, args...).Run() == nil // #nosec G204 -- fixed commands
}
