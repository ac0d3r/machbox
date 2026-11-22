package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
)

// check reports what is in place in this guest, and leaves the report in
// agent.CheckFile for Machbox Setup.
func check() (agent.CheckReport, error) {
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
		{agent.FeatureFullDiskAccess, fullDiskAccess()},
	} {
		if c.ok {
			r.Features = append(r.Features, c.feature)
		}
	}
	r.Features = agent.WithSIP(r.Features, r.SIPDisabled)
	if err := saveCheck(agent.CheckFile, r); err != nil {
		fmt.Fprintf(os.Stderr, "save check: %v\n", err)
	}
	return r, nil
}

// saveCheck replaces file, which Setup may be reading.
func saveCheck(file string, r agent.CheckReport) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".machbox-check.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil { // #nosec G302 -- Setup runs as the user
		return err
	}
	return os.Rename(tmp.Name(), file)
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
	// #nosec G204 -- dscl takes the password only as an argument.
	if exec.Command("/usr/bin/dscl", "/Search", "-authonly", name, decodeKCPassword(data)).Run() != nil {
		return ""
	}
	return name
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

// fullDiskAccess reports whether the agent may read what only Full Disk
// Access opens, as the share needs with SIP on. A grant reaches a running
// agent only once it restarts.
func fullDiskAccess() bool {
	f, err := os.Open("/Library/Application Support/com.apple.TCC/TCC.db")
	if err != nil {
		return false
	}
	defer f.Close()
	_, err = f.Read(make([]byte, 1))
	return err == nil
}
