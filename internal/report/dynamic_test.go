package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func eventsToJSONL(events []DynamicEvent) *bytes.Buffer {
	var buf bytes.Buffer
	for _, ev := range events {
		b, _ := json.Marshal(ev)
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return &buf
}

func collectPIDs(node *ProcessTreeNode, out map[int32]struct{}) {
	if node == nil {
		return
	}
	out[node.PID] = struct{}{}
	for _, c := range node.Children {
		collectPIDs(c, out)
	}
}

func TestSanitizePath(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"/private/tmp/machbox_dj0csm4okui0/Calisto", "$WORKDIR/Calisto"},
		{"/tmp/machbox_dj0csm4okui0/dynamictool", "$WORKDIR/dynamictool"},
		{"pid=345 path=/private/tmp/machbox_dj0e0qfx197s/Calisto", "pid=345 path=$WORKDIR/Calisto"},
		{"/usr/lib/dyld", "/usr/lib/dyld"},
		{"addr=8599568384 size=28672 prot=1", "addr=8599568384 size=28672 prot=1"},
	}
	for _, c := range cases {
		got := workdirRegex.ReplaceAllString(c.input, sanitizedPath)
		if got != c.expected {
			t.Errorf("sanitizeString(%q) = %q, want %q", c.input, got, c.expected)
		}
	}
}

func TestParseAndBuildTreeExecUpdatesXPCProxyRootPath(t *testing.T) {
	ppid := int32(1)
	pid := int32(1234)
	appPath := "/Applications/Test.app/Contents/MacOS/Test"

	events := []DynamicEvent{
		{
			Type:    "open",
			PID:     pid,
			PPID:    &ppid,
			Process: "/usr/libexec/xpcproxy",
			Target:  "/Applications/Test.app",
		},
		{
			Type:    "exec",
			PID:     pid,
			PPID:    &ppid,
			Process: "/usr/libexec/xpcproxy",
			Target:  appPath,
			Object: &EventObject{
				Kind: "process",
				Path: appPath,
				PID:  &pid,
				PPID: &ppid,
			},
		},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), appPath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("parseAndBuildTree returned nil")
	}
	if tree.Path != appPath {
		t.Fatalf("root path = %q, want %q", tree.Path, appPath)
	}
}

func TestDynamicRiskScoresInjectionPatternAsMalicious(t *testing.T) {
	eventTypes := map[string]int{
		"remote_thread_create": 1,
		"mprotect":             1,
		"get_task":             1,
	}
	risk := evaluateDynamicRisk(nil, eventTypes, nil)

	if risk.score < 70 {
		t.Fatalf("risk score = %d, want >= 70", risk.score)
	}
	if got := risk.verdict(); got != "malicious" {
		t.Fatalf("verdict = %q, want malicious", got)
	}
}

func TestDynamicRiskKeepsLowSignalActivityClean(t *testing.T) {
	eventTypes := map[string]int{
		"open":        20,
		"xpc_connect": 10,
		"exit":        1,
	}
	risk := evaluateDynamicRisk(nil, eventTypes, nil)

	if risk.score >= 35 {
		t.Fatalf("risk score = %d, want < 35", risk.score)
	}
	if got := risk.verdict(); got != "clean" {
		t.Fatalf("verdict = %q, want clean", got)
	}
}

func TestDynamicRiskShellAndExternalNetworkIsSuspiciousNotMalicious(t *testing.T) {
	eventTypes := map[string]int{
		"exec":        1,
		"tcp_connect": 1,
	}
	behavior := &BehaviorSummary{
		HasShellExecution:  true,
		HasExternalNetwork: true,
		CommandsExecuted:   []string{"/bin/bash"},
		NetworkConnections: []string{"1.2.3.4:80"},
	}
	risk := evaluateDynamicRisk(nil, eventTypes, behavior)

	if risk.score < 35 || risk.score >= 70 {
		t.Fatalf("risk score = %d, want in [35, 70)", risk.score)
	}
	if got := risk.verdict(); got != "suspicious" {
		t.Fatalf("verdict = %q, want suspicious", got)
	}
}

func TestDynamicRiskPersistenceWithExternalNetworkElevates(t *testing.T) {
	eventTypes := map[string]int{
		"btm_launch_item_add": 1,
		"tcp_connect":         1,
	}
	behavior := &BehaviorSummary{
		HasExternalNetwork: true,
		PersistenceItems:   []string{"/Library/LaunchAgents/com.example.plist"},
		NetworkConnections: []string{"8.8.8.8:443"},
	}
	risk := evaluateDynamicRisk(nil, eventTypes, behavior)

	if risk.score < 35 {
		t.Fatalf("risk score = %d, want >= 35", risk.score)
	}
	if got := risk.verdict(); got != "suspicious" && got != "malicious" {
		t.Fatalf("verdict = %q, want suspicious or malicious", got)
	}
}

func TestDynamicRiskPrivilegeSignalsNotDoubleCounted(t *testing.T) {
	eventTypes := map[string]int{
		"seteuid": 3,
		"setuid":  2,
		"open":    1,
	}
	behavior := &BehaviorSummary{PrivilegeEscalation: true}
	risk := evaluateDynamicRisk(nil, eventTypes, behavior)

	// Privilege category is capped at 30; no stacking of seteuid+setuid+flag.
	if risk.score > 30 {
		t.Fatalf("risk score = %d, want <= 30 (privilege cap only)", risk.score)
	}
	privFactors := 0
	for _, f := range risk.factors {
		if strings.Contains(f, "uid") || strings.Contains(f, "privilege") {
			privFactors++
		}
	}
	if privFactors != 1 {
		t.Fatalf("privilege factors = %d (%v), want exactly 1", privFactors, risk.factors)
	}
}

func TestDynamicRiskRWXWithCodeSignatureInvalidation(t *testing.T) {
	pid := int32(100)
	tree := &ProcessTreeNode{
		PID: pid,
		Events: []DynamicEvent{
			{Type: "mprotect", PID: pid, Metadata: map[string]string{"protection": "7"}},
		},
	}
	eventTypes := map[string]int{
		"mprotect":       1,
		"cs_invalidated": 1,
	}
	risk := evaluateDynamicRisk(tree, eventTypes, nil)

	// injection: RWX(15)+cs(15)=30 + combo(20) = 50 → suspicious
	if risk.score < 35 {
		t.Fatalf("risk score = %d, want >= 35", risk.score)
	}
	found := false
	for _, f := range risk.factors {
		if f == "RWX memory with code signature invalidation" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing RWX+cs combo factor, got %v", risk.factors)
	}
	// Category should surface both signals, not only the first.
	hasRWX, hasCS := false, false
	for _, f := range risk.factors {
		if f == "RWX memory protection change" {
			hasRWX = true
		}
		if f == "code signature invalidated" {
			hasCS = true
		}
	}
	if !hasRWX || !hasCS {
		t.Fatalf("want both category factors, got %v", risk.factors)
	}
}

func TestDynamicRiskLaunchAgentWriteNotDoubleCountedInFilesystem(t *testing.T) {
	plist := "/Library/LaunchAgents/com.example.plist"
	eventTypes := map[string]int{
		"btm_launch_item_add": 1,
		"open":                1,
	}
	behavior := &BehaviorSummary{
		HasSensitiveWrite: true,
		FilesWritten:      []string{plist},
		PersistenceItems:  []string{plist},
	}
	risk := evaluateDynamicRisk(nil, eventTypes, behavior)

	for _, f := range risk.factors {
		if f == "write to sensitive location" {
			t.Fatalf("LaunchAgent write should not also score as filesystem sensitive write, factors=%v", risk.factors)
		}
	}
	// persistence: BTM(35)+launch path(10)=45 + LaunchAgent combo(15) = 60
	if risk.score < 50 || risk.score >= 70 {
		t.Fatalf("risk score = %d, want roughly persistence+combo without filesystem stack", risk.score)
	}
}

func TestParseAndBuildTreeRemovesNoise(t *testing.T) {
	ppid := int32(1)
	sample := int32(100)
	child := int32(101)
	noise := int32(200)

	events := []DynamicEvent{
		{Type: "open", PID: sample, PPID: &ppid, Process: "/tmp/machbox_test/dynamictool"},
		{Type: "exec", PID: child, PPID: &sample, Process: "/bin/sh"},
		{Type: "open", PID: noise, PPID: &ppid, Process: "/usr/libexec/dasd"},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "$WORKDIR/dynamictool")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected tree, got nil")
	}

	pids := make(map[int32]struct{})
	collectPIDs(tree, pids)

	if _, ok := pids[sample]; !ok {
		t.Error("expected sample PID in tree")
	}
	if _, ok := pids[child]; !ok {
		t.Error("expected child PID in tree")
	}
	if _, ok := pids[noise]; ok {
		t.Error("noise PID should be filtered out")
	}
}

func TestParseAndBuildTreeFiltersBySamplePath(t *testing.T) {
	ppid := int32(1)
	sample := int32(100)
	child := int32(101)
	noise := int32(200)

	events := []DynamicEvent{
		{Type: "open", PID: sample, PPID: &ppid, Process: "/tmp/samples/malware"},
		{Type: "exec", PID: child, PPID: &sample, Process: "/bin/sh"},
		{Type: "open", PID: noise, PPID: &ppid, Process: "/usr/libexec/dasd"},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "/tmp/samples/malware")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected tree, got nil")
	}

	pids := make(map[int32]struct{})
	collectPIDs(tree, pids)

	if _, ok := pids[sample]; !ok {
		t.Error("expected sample PID in tree")
	}
	if _, ok := pids[child]; !ok {
		t.Error("expected child PID in tree")
	}
	if _, ok := pids[noise]; ok {
		t.Error("noise PID should be filtered out")
	}
}

func TestParseAndBuildTreeWithExecObjectTarget(t *testing.T) {
	ppid := int32(1)
	pid := int32(1234)
	appPath := "/Applications/Test.app/Contents/MacOS/Test"

	events := []DynamicEvent{
		{
			Type:    "open",
			PID:     pid,
			PPID:    &ppid,
			Process: "/usr/libexec/xpcproxy",
		},
		{
			Type:    "exec",
			PID:     pid,
			PPID:    &ppid,
			Process: "/usr/libexec/xpcproxy",
			Object: &EventObject{
				Kind: "process",
				Path: appPath,
				PID:  &pid,
				PPID: &ppid,
			},
		},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), appPath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected tree, got nil")
	}
	if tree.Path != appPath {
		t.Fatalf("root path = %q, want %q", tree.Path, appPath)
	}
}

func TestParseAndBuildTreeSampleLaunchMarker(t *testing.T) {
	ppid := int32(1)
	root := int32(100)
	child := int32(101)
	noise := int32(200)
	samplePath := "/tmp/samples/malware"

	events := []DynamicEvent{
		{Type: "machbox_launch", PID: root, PIDVersion: 5, Target: samplePath},
		{Type: "open", PID: root, PPID: &ppid, Process: samplePath, PIDVersion: 5},
		{Type: "exec", PID: child, PPID: &root, Process: "/bin/sh", PIDVersion: 6},
		{Type: "open", PID: noise, PPID: &ppid, Process: "/usr/libexec/dasd", PIDVersion: 1},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), samplePath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected tree, got nil")
	}

	pids := make(map[int32]struct{})
	collectPIDs(tree, pids)

	if _, ok := pids[root]; !ok {
		t.Error("expected root PID in tree")
	}
	if _, ok := pids[child]; !ok {
		t.Error("expected child PID in tree")
	}
	if _, ok := pids[noise]; ok {
		t.Error("noise PID should be filtered out")
	}
}

func TestPathMatchesSample(t *testing.T) {
	cases := []struct {
		path    string
		sample  string
		matches bool
	}{
		{"/tmp/samples/malware", "/tmp/samples/malware", true},
		{"/private/tmp/samples/malware", "/tmp/samples/malware", true},
		{"/tmp/samples/malware", "malware", true},
		{"/tmp/samples/malware.app/Contents/MacOS/malware", "malware", true},
		{"/tmp/malware-scanner/malware", "malware", true},
		{"/tmp/malwarefoo", "malware", false},
		{"/tmp/samples/other", "malware", false},
		{"", "malware", false},
		{"/tmp/samples/malware", "", false},
	}

	for _, c := range cases {
		got := pathMatchesSample(c.path, c.sample)
		if got != c.matches {
			t.Errorf("pathMatchesSample(%q, %q) = %v, want %v", c.path, c.sample, got, c.matches)
		}
	}
}

func TestBehaviorSummaryCollectsNetworkFileAndCommand(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	childPID := int32(101)

	events := []DynamicEvent{
		{Type: "dnet_tcp_connect", PID: pid, PPID: &ppid, Process: "sample",
			Metadata: map[string]string{"remote": "8.8.8.8:443"}},
		{Type: "dnet_bind", PID: pid, PPID: &ppid, Process: "sample",
			Metadata: map[string]string{"local": "0.0.0.0:8080"}},
		{Type: "open", PID: pid, PPID: &ppid, Process: "sample", Target: "/Library/LaunchAgents/com.example.plist",
			Metadata: map[string]string{"flags": "W"}},
		{Type: "exec", PID: childPID, PPID: &pid, Process: "/bin/sh", Target: "/bin/sh",
			Object: &EventObject{Kind: "process", Path: "/bin/sh"}},
		{Type: "btm_launch_item_add", PID: pid, PPID: &ppid, Process: "sample", Target: "/Library/LaunchAgents/com.example.plist"},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if tree == nil {
		t.Fatal("expected tree, got nil")
	}

	summary := summarize(tree, 0)
	bs := summary.BehaviorSummary
	if bs == nil {
		t.Fatal("expected behavior summary")
	}

	if !bs.HasExternalNetwork {
		t.Error("expected external network connection")
	}
	if !bs.HasBindAllInterfaces {
		t.Error("expected bind on all interfaces")
	}
	if !bs.HasListenSocket {
		t.Error("expected listen socket")
	}
	if !bs.HasShellExecution {
		t.Error("expected shell execution")
	}
	if !bs.HasSensitiveWrite {
		t.Error("expected sensitive write")
	}
	if len(bs.NetworkConnections) == 0 || bs.NetworkConnections[0] != "8.8.8.8:443" {
		t.Errorf("unexpected network connections: %v", bs.NetworkConnections)
	}
	if len(bs.CommandsExecuted) == 0 || bs.CommandsExecuted[0] != "/bin/sh" {
		t.Errorf("unexpected commands executed: %v", bs.CommandsExecuted)
	}
	if len(bs.PersistenceItems) == 0 {
		t.Errorf("expected persistence items, got %v", bs.PersistenceItems)
	}
}

func TestBehaviorSummaryShellAndExternalNetworkIsSuspicious(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	childPID := int32(101)

	events := []DynamicEvent{
		{Type: "dnet_tcp_connect", PID: pid, PPID: &ppid, Process: "sample",
			Metadata: map[string]string{"remote": "1.2.3.4:80"}},
		{Type: "exec", PID: childPID, PPID: &pid, Process: "/bin/bash", Target: "/bin/bash",
			Object: &EventObject{Kind: "process", Path: "/bin/bash"}},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	summary := summarize(tree, 0)

	if summary.Verdict != "suspicious" && summary.Verdict != "malicious" {
		t.Fatalf("verdict = %q, want suspicious or malicious", summary.Verdict)
	}
	if summary.RiskScore < 35 {
		t.Fatalf("risk score = %d, want >= 35", summary.RiskScore)
	}
}

func TestBehaviorSummaryCloneAndUDPAndNumericOpenFlags(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	dest := "/Library/LaunchAgents/com.cloned.plist"

	events := []DynamicEvent{
		{
			Type: "clone", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/tmp/src -> " + dest,
			Object: &EventObject{Kind: "file", Path: dest},
			Metadata: map[string]string{
				"source":      "/tmp/src",
				"destination": dest,
			},
		},
		{
			Type: "dnet_udp_send", PID: pid, PPID: &ppid, Process: "sample",
			Target:   "9.9.9.9:53",
			Metadata: map[string]string{"remote": "9.9.9.9:53", "family": "inet4"},
		},
		{
			Type: "open", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/etc/hosts",
			Object: &EventObject{Kind: "file", Path: "/etc/hosts"},
			// ES fflag uses FREAD(1)|FWRITE(2); 2 = write-only open.
			Metadata: map[string]string{"fflag": "2", "access": "write"},
		},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	bs := summarize(tree, 0).BehaviorSummary
	if bs == nil {
		t.Fatal("expected behavior summary")
	}
	if !bs.HasSensitiveWrite {
		t.Error("expected sensitive write from clone/open")
	}
	if len(bs.FilesWritten) == 0 || bs.FilesWritten[0] != dest {
		t.Errorf("FilesWritten = %v, want destination path %q first", bs.FilesWritten, dest)
	}
	if !bs.HasExternalNetwork {
		t.Error("expected external network from udp_send")
	}
	if len(bs.NetworkConnections) == 0 || bs.NetworkConnections[0] != "9.9.9.9:53" {
		t.Errorf("NetworkConnections = %v, want 9.9.9.9:53", bs.NetworkConnections)
	}
	foundHosts := false
	for _, p := range bs.FilesWritten {
		if p == "/etc/hosts" {
			foundHosts = true
			break
		}
	}
	if !foundHosts {
		t.Errorf("expected /etc/hosts write from numeric fflag open, got %v", bs.FilesWritten)
	}
}

func TestBehaviorSummaryReadOnlyOpenNotCountedAsWrite(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)

	events := []DynamicEvent{
		{
			Type: "open", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/private/etc/hosts",
			Object: &EventObject{Kind: "file", Path: "/private/etc/hosts"},
			// FREAD=1 — previously misparsed as O_WRONLY and flooded FilesWritten.
			Metadata: map[string]string{"fflag": "1", "access": "read"},
		},
		{
			Type: "close", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/private/etc/hosts",
			Object:   &EventObject{Kind: "file", Path: "/private/etc/hosts"},
			Metadata: map[string]string{"modified": "0"},
		},
		{
			Type: "open", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/System/Volumes/Preboot/Cryptexes/OS",
			Object:   &EventObject{Kind: "file", Path: "/System/Volumes/Preboot/Cryptexes/OS"},
			Metadata: map[string]string{"fflag": "1", "access": "read"},
		},
		{
			Type: "close", PID: pid, PPID: &ppid, Process: "sample",
			Target: "/dev/null",
			Object:   &EventObject{Kind: "file", Path: "/dev/null"},
			Metadata: map[string]string{"modified": "true"},
		},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	bs := summarize(tree, 0).BehaviorSummary
	if bs.HasSensitiveWrite {
		t.Fatalf("read-only opens must not set HasSensitiveWrite, FilesWritten=%v", bs.FilesWritten)
	}
	for _, p := range bs.FilesWritten {
		if p == "/private/etc/hosts" || p == "/System/Volumes/Preboot/Cryptexes/OS" {
			t.Fatalf("read-only path %q must not be in FilesWritten=%v", p, bs.FilesWritten)
		}
	}
	foundNull := false
	for _, p := range bs.FilesWritten {
		if p == "/dev/null" {
			foundNull = true
		}
	}
	if !foundNull {
		t.Fatalf("close.modified=true should count as write, FilesWritten=%v", bs.FilesWritten)
	}
}

func TestBehaviorSummarySensitiveFileWriteIncreasesRisk(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)

	events := []DynamicEvent{
		{Type: "open", PID: pid, PPID: &ppid, Process: "sample", Target: "/etc/paths",
			Metadata: map[string]string{"flags": "W"}},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	summary := summarize(tree, 0)

	if !summary.BehaviorSummary.HasSensitiveWrite {
		t.Error("expected sensitive write flag")
	}
	found := false
	for _, f := range summary.RiskFactors {
		if f == "write to sensitive location" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'write to sensitive location' risk factor, got %v", summary.RiskFactors)
	}
}

func TestBehaviorSummaryFiltersSelfLaunch(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	childPID := int32(101)
	samplePath := "/tmp/machbox_test/malware"

	events := []DynamicEvent{
		// Self-launch of the sample: should be ignored.
		{
			Type: "exec", PID: pid, PPID: &ppid, Process: samplePath,
			Object:   &EventObject{Kind: "process", Path: samplePath},
			Metadata: map[string]string{"argv": samplePath + "\x00--flag"},
		},
		// Child shell: should be kept.
		{
			Type: "exec", PID: childPID, PPID: &pid, Process: samplePath,
			Object:   &EventObject{Kind: "process", Path: "/bin/sh"},
			Metadata: map[string]string{"argv": "/bin/sh\x00-c\x00echo hi"},
		},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), samplePath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	summary := summarize(tree, 0)
	bs := summary.BehaviorSummary

	for _, cmd := range bs.CommandsExecuted {
		if cmd == samplePath {
			t.Errorf("self-launch command %q should be filtered out", cmd)
		}
	}
	if len(bs.CommandsExecuted) != 1 || bs.CommandsExecuted[0] != "/bin/sh" {
		t.Errorf("expected only /bin/sh in CommandsExecuted, got %v", bs.CommandsExecuted)
	}
	if len(bs.CommandLines) != 1 || bs.CommandLines[0] != "/bin/sh -c echo hi" {
		t.Errorf("expected command line '/bin/sh -c echo hi', got %v", bs.CommandLines)
	}
}

func TestParseAndBuildTreeMovesUIPCConnectToNetworks(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	events := []DynamicEvent{
		{Type: "exec", PID: pid, PPID: &ppid, Process: "sample",
			Object: &EventObject{Kind: "process", Path: "sample"}},
		{Type: "uipc_connect", PID: pid, PPID: &ppid, Process: "sample",
			Target:   "/private/var/run/mDNSResponder",
			Metadata: map[string]string{"domain": "1"}},
		{Type: "dnet_socket", PID: pid, PPID: &ppid, Process: "sample",
			Metadata: map[string]string{"family": "unix", "direction": "create"}},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), "sample")
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	if len(tree.Networks) != 2 {
		t.Fatalf("Networks = %d, want 2 (uipc + dnet_socket)", len(tree.Networks))
	}
	types := map[string]bool{}
	for _, ev := range tree.Networks {
		types[ev.Type] = true
	}
	if !types["unix_connect"] {
		t.Fatalf("expected unix_connect in Networks, got %v", tree.Networks)
	}
	if !types["socket"] {
		t.Fatalf("expected socket in Networks, got %v", tree.Networks)
	}
	for _, ev := range tree.Events {
		if ev.Type == "uipc_connect" || ev.Type == "unix_connect" {
			t.Fatalf("unix connect should not remain in Events: %v", ev)
		}
	}
}

func TestBehaviorSummaryCollectsHostnameAndSwVers(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	shellPID := int32(101)
	hostPID := int32(102)
	swVersPID := int32(103)
	samplePath := "/tmp/machbox_test/malware"

	events := []DynamicEvent{
		{Type: "exec", PID: pid, PPID: &ppid, Process: samplePath,
			Object: &EventObject{Kind: "process", Path: samplePath}},
		{Type: "fork", PID: shellPID, PPID: &pid, Process: samplePath,
			Object: &EventObject{Kind: "process", Path: samplePath, PID: &shellPID, PPID: &pid}},
		{Type: "exec", PID: shellPID, PPID: &pid, Process: samplePath,
			Object:   &EventObject{Kind: "process", Path: "/bin/sh", PID: &shellPID, PPID: &pid},
			Metadata: map[string]string{"argv": "/bin/sh\x00-c\x00hostname;sw_vers"}},
		{Type: "exec", PID: hostPID, PPID: &shellPID, Process: "/bin/sh",
			Object:   &EventObject{Kind: "process", Path: "/bin/hostname", PID: &hostPID, PPID: &shellPID},
			Metadata: map[string]string{"argv": "/bin/hostname\x00"}},
		{Type: "exec", PID: swVersPID, PPID: &shellPID, Process: "/bin/sh",
			Object:   &EventObject{Kind: "process", Path: "/usr/bin/sw_vers", PID: &swVersPID, PPID: &shellPID},
			Metadata: map[string]string{"argv": "/usr/bin/sw_vers\x00"}},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), samplePath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	summary := summarize(tree, 0)
	bs := summary.BehaviorSummary

	for _, want := range []string{"/bin/sh", "/bin/hostname", "/usr/bin/sw_vers"} {
		found := false
		for _, cmd := range bs.CommandsExecuted {
			if cmd == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing %q in CommandsExecuted=%v", want, bs.CommandsExecuted)
		}
	}
}

func TestEventCommandLineExtractsArgv(t *testing.T) {
	ev := DynamicEvent{
		Type: "exec",
		Metadata: map[string]string{
			"argv": "/bin/bash\x00-c\x00echo hello\x00",
		},
	}
	got := eventCommandLine(&ev)
	want := "/bin/bash -c echo hello"
	if got != want {
		t.Errorf("eventCommandLine() = %q, want %q", got, want)
	}
}

func TestBehaviorSummaryDetectsLaunchctlPersistence(t *testing.T) {
	ppid := int32(1)
	pid := int32(100)
	childPID := int32(101)
	samplePath := "/tmp/machbox_test/malware"
	plistPath := "/Library/LaunchDaemons/com.apple.qtop.plist"

	events := []DynamicEvent{
		{Type: "exec", PID: pid, PPID: &ppid, Process: samplePath,
			Object: &EventObject{Kind: "process", Path: samplePath}},
		{Type: "exec", PID: childPID, PPID: &pid, Process: samplePath,
			Object:   &EventObject{Kind: "process", Path: "/bin/launchctl"},
			Metadata: map[string]string{"argv": "/bin/launchctl\x00load\x00-F\x00" + plistPath + "\x00"}},
	}

	tree, _, err := parseAndBuildTree(eventsToJSONL(events), samplePath)
	if err != nil {
		t.Fatalf("parseAndBuildTree error: %v", err)
	}
	summary := summarize(tree, 0)
	bs := summary.BehaviorSummary

	if !bs.HasLaunchctlPersistence {
		t.Error("expected launchctl persistence flag")
	}
	if summary.PersistenceCount != 1 {
		t.Errorf("expected persistence_count=1, got %d", summary.PersistenceCount)
	}
	found := false
	for _, p := range bs.PersistenceItems {
		if p == plistPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected plist path in persistence items, got %v", bs.PersistenceItems)
	}

	riskFactorFound := false
	for _, f := range summary.RiskFactors {
		if f == "launchctl load/bootstrap persistence" {
			riskFactorFound = true
			break
		}
	}
	if !riskFactorFound {
		t.Errorf("expected launchctl persistence risk factor, got %v", summary.RiskFactors)
	}
}

func TestDeduplicateCommandLinesKeepsWrapper(t *testing.T) {
	input := []string{
		"sh -c ( ( which sudo );echo exitcode:$? ) 2\u003e\u00261",
		"which sudo",
		"sh -c ( ps -p 1 -o comm= ) 2\u003e\u00261",
		"ps -p 1 -o comm=",
		"sh -c ( sudo /bin/bash -c 'PATH=/usr/local/bin/:/usr/bin:/bin:/usr/sbin:/sbin; (qtop \u003e/dev/null 2\u003e\u00261 \u0026); exit' ) 2\u003e\u00261",
		"sudo /bin/bash -c PATH=/usr/local/bin/:/usr/bin:/bin:/usr/sbin:/sbin; (qtop \u003e/dev/null 2\u003e\u00261 \u0026); exit",
		"/bin/bash -c PATH=/usr/local/bin/:/usr/bin:/bin:/usr/sbin:/sbin; (qtop \u003e/dev/null 2\u003e\u00261 \u0026); exit",
		"sh -c ( ( echo $HOME,$PATH,$SHELL );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( ( sudo mkdir -p /usr/local/bin );echo exitcode:$? ) 2\u003e\u00261",
		"sudo mkdir -p /usr/local/bin",
		"mkdir -p /usr/local/bin",
		"sh -c ( sudo launchctl start com.apple.qtop ) 2\u003e\u00261",
		"sudo launchctl start com.apple.qtop",
		"launchctl start com.apple.qtop",
		"sh -c ( sudo launchctl load -F /Library/LaunchDaemons/com.apple.qtop.plist ) 2\u003e\u00261",
		"sudo launchctl load -F /Library/LaunchDaemons/com.apple.qtop.plist",
		"launchctl load -F /Library/LaunchDaemons/com.apple.qtop.plist",
		"sh -c ( ( whoami );echo exitcode:$? ) 2\u003e\u00261",
		"whoami",
		"sh -c ( dscl -plist . -readall /Users RecordName UniqueID UserShell NFSHomeDirectory ) 2\u003e\u00261",
		"dscl -plist . -readall /Users RecordName UniqueID UserShell NFSHomeDirectory",
		"sh -c ( ( sudo chown root /usr/local/bin/qtop );echo exitcode:$? ) 2\u003e\u00261",
		"sudo chown root /usr/local/bin/qtop",
		"chown root /usr/local/bin/qtop",
		"sh -c ( ( sudo test -d /usr/local/bin );echo exitcode:$? ) 2\u003e\u00261",
		"sudo test -d /usr/local/bin",
		"test -d /usr/local/bin",
		"sh -c ( ps ax -o uid,pid,command ) 2\u003e\u00261",
		"ps ax -o uid,pid,command",
		"sh -c open https://google.com/",
		"open https://google.com/",
	}
	got := deduplicateCommandLines(input)
	want := []string{
		"sh -c ( ( which sudo );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( ps -p 1 -o comm= ) 2\u003e\u00261",
		"sh -c ( sudo /bin/bash -c 'PATH=/usr/local/bin/:/usr/bin:/bin:/usr/sbin:/sbin; (qtop \u003e/dev/null 2\u003e\u00261 \u0026); exit' ) 2\u003e\u00261",
		"sh -c ( ( echo $HOME,$PATH,$SHELL );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( ( sudo mkdir -p /usr/local/bin );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( sudo launchctl start com.apple.qtop ) 2\u003e\u00261",
		"sh -c ( sudo launchctl load -F /Library/LaunchDaemons/com.apple.qtop.plist ) 2\u003e\u00261",
		"sh -c ( ( whoami );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( dscl -plist . -readall /Users RecordName UniqueID UserShell NFSHomeDirectory ) 2\u003e\u00261",
		"sh -c ( ( sudo chown root /usr/local/bin/qtop );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( ( sudo test -d /usr/local/bin );echo exitcode:$? ) 2\u003e\u00261",
		"sh -c ( ps ax -o uid,pid,command ) 2\u003e\u00261",
		"sh -c open https://google.com/",
	}

	if len(got) != len(want) {
		t.Fatalf("deduplicateCommandLines() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
