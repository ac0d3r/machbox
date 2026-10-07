package report

import (
	"regexp"
	"strings"
)

func summarize(tree *ProcessTreeNode, parseErrors int) DynamicSummary {
	s := DynamicSummary{
		ParseErrors:     parseErrors,
		BehaviorSummary: &BehaviorSummary{},
	}
	// eventTypes is kept only for internal risk heuristics; it is not serialized.
	eventTypes := make(map[string]int)
	samplePaths := extractSamplePaths(tree)
	if tree != nil {
		collectTreeStats(tree, &s, eventTypes, samplePaths)
	}
	if behavior := s.BehaviorSummary; behavior != nil {
		behavior.CommandLines = deduplicateCommandLines(behavior.CommandLines)
	}

	risk := evaluateDynamicRisk(tree, eventTypes, s.BehaviorSummary)
	s.RiskScore = risk.score
	s.RiskFactors = risk.factors
	s.Verdict = risk.verdict()
	return s
}

// deduplicateCommandLines removes command lines that are duplicates after
// stripping common wrappers (sh -c, sudo, bash -c) and shell noise. The first
// occurrence in event order is kept for each group so the timeline is preserved.
func deduplicateCommandLines(lines []string) []string {
	if len(lines) <= 1 {
		return lines
	}

	seen := make(map[string]struct{})
	var result []string
	for _, line := range lines {
		core := commandLineCore(line)
		key := core
		if key == "" {
			key = line
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, line)
	}
	return result
}

var trailingRedirectionRegex = regexp.MustCompile(`\s+(?:2>&1|>/dev/null\s+2>&1|2>/dev/null|>/dev/null)\s*$`)

// shellNoiseRegex strips trailing wrapper fragments like ";echo exitcode:$?".
var shellNoiseRegex = regexp.MustCompile(`;\s*echo\s+[^;]*$`)

// commandLineCore strips common wrappers and shell noise so that commands like
//
//	sh -c ( sudo /bin/bash -c '...' ) 2>&1
//	sudo /bin/bash -c ...
//	/bin/bash -c ...
//
// all collapse to the same inner command.
func commandLineCore(line string) string {
	prev := ""
	for prev != line {
		prev = line
		line = strings.TrimSpace(line)
		line = stripOneCommandWrapper(line)
		line = strings.TrimSpace(line)
		line = trailingRedirectionRegex.ReplaceAllString(line, "")
		line = strings.TrimSpace(line)
		line = stripOuterParens(line)
		line = strings.TrimSpace(line)
		line = shellNoiseRegex.ReplaceAllString(line, "")
		line = strings.TrimSpace(line)
		line = stripOuterQuotes(line)
		line = strings.TrimSpace(line)
	}
	return line
}

func stripOneCommandWrapper(line string) string {
	line = strings.TrimSpace(line)

	for _, sh := range shellBasenames {
		prefix := sh + " -c"
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
		suffix := "/" + sh + " -c"
		if idx := strings.Index(line, suffix); idx >= 0 {
			return strings.TrimSpace(line[idx+len(suffix):])
		}
	}
	if strings.HasPrefix(line, "sudo ") {
		return strings.TrimSpace(line[len("sudo "):])
	}
	if strings.HasPrefix(line, "env ") {
		rest := strings.TrimSpace(line[len("env "):])
		parts := strings.Fields(rest)
		i := 0
		for i < len(parts) && strings.Contains(parts[i], "=") {
			i++
		}
		return strings.TrimSpace(strings.Join(parts[i:], " "))
	}
	return line
}

func stripOuterParens(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "(") && strings.HasSuffix(line, ")") {
		return strings.TrimSpace(line[1 : len(line)-1])
	}
	return line
}

func stripOuterQuotes(line string) string {
	line = strings.TrimSpace(line)
	if len(line) < 2 {
		return line
	}
	if (line[0] == '\'' && line[len(line)-1] == '\'') ||
		(line[0] == '"' && line[len(line)-1] == '"') {
		return strings.TrimSpace(line[1 : len(line)-1])
	}
	return line
}

func extractSamplePaths(tree *ProcessTreeNode) []string {
	if tree == nil {
		return nil
	}
	// Synthetic root container: its children are the actual sample roots.
	if tree.PID == 0 && tree.Path == "<root>" {
		var paths []string
		for _, child := range tree.Children {
			if child.Path != "" {
				paths = append(paths, child.Path)
			}
		}
		return paths
	}
	if tree.Path != "" {
		return []string{tree.Path}
	}
	return nil
}

func isSamplePath(path string, samplePaths []string) bool {
	for _, p := range samplePaths {
		if pathMatchesSample(path, p) {
			return true
		}
	}
	return false
}

func collectTreeStats(node *ProcessTreeNode, s *DynamicSummary, eventTypes map[string]int, samplePaths []string) {
	if node == nil {
		return
	}

	behavior := s.BehaviorSummary

	for i := range node.Events {
		ev := &node.Events[i]
		eventTypes[ev.Type]++

		collectFileBehavior(ev, behavior)
		collectProcessBehavior(ev, behavior, samplePaths)
		collectLaunchctlPersistence(ev, s, behavior)

		switch ev.Type {
		case "btm_launch_item_add", "btm_launch_item_remove", "setextattr":
			notePersistence(s, behavior, eventTargetPath(ev))
		case "seteuid", "setegid", "setreuid", "setregid", "setuid", "setgid":
			s.PrivilegeChanges++
			behavior.PrivilegeEscalation = true
		case "cs_invalidated":
			s.CodeSigInvalidations++
		case "remote_thread_create", "get_task":
			noteInjection(s, behavior, eventTargetPath(ev))
		}
	}

	for i := range node.Networks {
		ev := &node.Networks[i]
		eventTypes[ev.Type]++
		collectNetworkBehavior(ev, behavior)
	}

	if len(node.Children) > 0 {
		behavior.ChildProcesses += len(node.Children)
	}

	for _, child := range node.Children {
		collectTreeStats(child, s, eventTypes, samplePaths)
	}
}

func collectFileBehavior(ev *DynamicEvent, behavior *BehaviorSummary) {
	switch ev.Type {
	case "write", "pwrite", "truncate", "creat", "clone", "copyfile":
		noteFileWrite(behavior, eventFilePath(ev))
	case "open":
		// Only count opens that requested write (FWRITE). Read-only opens of
		// sensitive paths must not appear under FilesWritten.
		if openEventHasWriteIntent(ev) {
			noteFileWrite(behavior, eventFilePath(ev))
		}
	case "close":
		// ES often delivers open+close without a separate write event; modified
		// on close is the reliable confirmation that content changed.
		if closeEventWasModified(ev) {
			noteFileWrite(behavior, eventFilePath(ev))
		}
	case "unlink", "rename":
		path := eventMetadata(ev, "source")
		if path == "" {
			path = eventFilePath(ev)
		}
		noteFileDelete(behavior, path)
	case "chmod", "chown", "setmode", "setattr", "setextattr":
		path := eventFilePath(ev)
		if path == "" {
			return
		}
		behavior.FilesModifiedPerms = appendUnique(behavior.FilesModifiedPerms, path)
		if isSensitivePath(path) || ev.Type == "setextattr" {
			behavior.HasSensitiveChmod = true
		}
	}
}

func collectProcessBehavior(ev *DynamicEvent, behavior *BehaviorSummary, samplePaths []string) {
	if !isProcessLifecycleEvent(ev.Type) {
		return
	}
	cmd := eventCommandPath(ev)
	if cmd == "" || isSamplePath(cmd, samplePaths) {
		return
	}
	behavior.CommandsExecuted = appendUnique(behavior.CommandsExecuted, cmd)
	if line := eventCommandLine(ev); line != "" {
		behavior.CommandLines = appendUnique(behavior.CommandLines, line)
	}
	if isShellPath(cmd) {
		behavior.HasShellExecution = true
	}
	if isScriptPath(cmd) {
		behavior.HasScriptExecution = true
	}
}

func collectLaunchctlPersistence(ev *DynamicEvent, s *DynamicSummary, behavior *BehaviorSummary) {
	if !isProcessLifecycleEvent(ev.Type) {
		return
	}
	cmd := eventCommandPath(ev)
	if !isLaunchctlCommand(cmd) {
		return
	}
	parts := splitNullArgv(eventMetadata(ev, "argv"))
	if len(parts) < 2 {
		return
	}
	switch parts[1] {
	case "load", "loadw", "bootstrap", "enable":
	default:
		return
	}
	plistPath := extractLaunchctlPlistPath(parts)
	if plistPath == "" {
		return
	}
	notePersistence(s, behavior, plistPath)
	behavior.HasLaunchctlPersistence = true
}

func isLaunchctlCommand(cmd string) bool {
	return cmd == "launchctl" || strings.HasSuffix(cmd, "/launchctl")
}

func extractLaunchctlPlistPath(argv []string) string {
	for _, arg := range argv {
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}
		if strings.HasSuffix(arg, ".plist") ||
			strings.Contains(arg, "/LaunchAgents") ||
			strings.Contains(arg, "/LaunchDaemons") {
			return arg
		}
	}
	return ""
}

func collectNetworkBehavior(ev *DynamicEvent, behavior *BehaviorSummary) {
	switch ev.Type {
	case "tcp_connect", "udp_connect", "udp_send", "msg_send",
		"tcp_accept", "udp_recv", "msg_recv":
		remote := eventNetworkRemote(ev)
		if remote != "" {
			behavior.NetworkConnections = appendUnique(behavior.NetworkConnections, remote)
		}
		if isExternalEndpoint(remote) {
			behavior.HasExternalNetwork = true
		}
		if ev.Type == "tcp_accept" {
			behavior.HasListenSocket = true
		}
	case "bind":
		behavior.HasListenSocket = true
		if isBindAllLocal(eventMetadata(ev, "local")) {
			behavior.HasBindAllInterfaces = true
		}
	}
}

type dynamicRisk struct {
	score       int
	factors     []string
	factorSet   map[string]struct{}
	hasActivity bool
}

func (r dynamicRisk) verdict() string {
	if r.score >= 70 {
		return "malicious"
	}
	if r.score >= 35 {
		return "suspicious"
	}
	if r.score > 0 || r.hasActivity {
		return "clean"
	}
	return "unknown"
}

func (r *dynamicRisk) add(points int, factor string) {
	if points <= 0 {
		return
	}
	r.score += points
	if r.score > 100 {
		r.score = 100
	}
	r.noteFactor(factor)
}

func (r *dynamicRisk) noteFactor(factor string) {
	if factor == "" {
		return
	}
	if r.factorSet == nil {
		r.factorSet = make(map[string]struct{})
	}
	if _, ok := r.factorSet[factor]; ok {
		return
	}
	r.factorSet[factor] = struct{}{}
	r.factors = append(r.factors, factor)
}

func (r *dynamicRisk) addCategory(points, maxPoints int, factors ...string) {
	if points <= 0 {
		return
	}
	if points > maxPoints {
		points = maxPoints
	}
	r.score += points
	if r.score > 100 {
		r.score = 100
	}
	for _, f := range factors {
		r.noteFactor(f)
	}
}

func evaluateDynamicRisk(tree *ProcessTreeNode, eventTypes map[string]int, behavior *BehaviorSummary) dynamicRisk {
	risk := dynamicRisk{hasActivity: hasBehavioralActivity(eventTypes)}
	if !risk.hasActivity {
		return risk
	}

	mprotectPts, mprotectDesc, hasRWX := analyzeMprotectBase(tree, eventTypes)

	scoreKernel(&risk, eventTypes)
	scoreInjection(&risk, tree, eventTypes, behavior, mprotectPts, mprotectDesc)
	scorePersistence(&risk, eventTypes, behavior)
	scorePrivilege(&risk, eventTypes, behavior)
	scoreNetwork(&risk, eventTypes, behavior)
	scoreExecution(&risk, behavior)
	scoreFilesystem(&risk, eventTypes, behavior)
	scoreAccessRecon(&risk, tree, eventTypes)
	scoreCombos(&risk, eventTypes, behavior, hasRWX)

	return risk
}

func scoreKernel(risk *dynamicRisk, eventTypes map[string]int) {
	if eventTypes["kextload"] > 0 || eventTypes["kextunload"] > 0 {
		risk.addCategory(85, 85, "kernel extension load/unload")
	}
}

func scoreInjection(risk *dynamicRisk, tree *ProcessTreeNode, eventTypes map[string]int, behavior *BehaviorSummary, mprotectPts int, mprotectDesc string) {
	raw := 0
	var factors []string

	if eventTypes["remote_thread_create"] > 0 {
		raw += 40
		factors = append(factors, "remote thread creation")
	}
	if eventTypes["trace"] > 0 {
		raw += 15
		factors = append(factors, "process tracing")
	}
	if eventTypes["cs_invalidated"] > 0 {
		raw += 15
		factors = append(factors, "code signature invalidated")
	}

	if pts, desc := analyzeGetTaskEvents(tree, eventTypes); pts > 0 {
		raw += pts
		factors = append(factors, desc)
	}
	if mprotectPts > 0 {
		raw += mprotectPts
		factors = append(factors, mprotectDesc)
	}
	if behavior != nil && len(behavior.InjectionTargets) > 0 {
		raw += 8
		factors = append(factors, "injection targeting specific processes")
	}

	risk.addCategory(raw, 60, factors...)
}

func scorePersistence(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	raw := 0
	var factors []string

	hasBTM := eventTypes["btm_launch_item_add"] > 0 || eventTypes["btm_launch_item_remove"] > 0
	hasLaunchctl := behavior != nil && behavior.HasLaunchctlPersistence
	hasItems := behavior != nil && len(behavior.PersistenceItems) > 0

	// Take the strongest persistence signal; don't stack BTM + launchctl + items.
	switch {
	case hasBTM:
		raw = 35
		factors = append(factors, "background/login item modification")
	case hasLaunchctl:
		raw = 30
		factors = append(factors, "launchctl load/bootstrap persistence")
	case hasItems:
		raw = 20
		factors = append(factors, "persistence item paths observed")
	}

	if eventTypes["setextattr"] > 0 {
		raw += 5
		factors = append(factors, "extended attribute modification")
	}
	if hasSensitiveLaunchPersistence(behavior) {
		raw += 10
		factors = append(factors, "LaunchAgent/Daemon path persistence")
	}

	risk.addCategory(raw, 50, factors...)
}

func scorePrivilege(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	raw := 0
	var factors []string

	switch {
	case eventTypes["seteuid"] > 0 || eventTypes["setegid"] > 0 ||
		eventTypes["setreuid"] > 0 || eventTypes["setregid"] > 0:
		raw = 20
		factors = append(factors, "effective uid/gid change")
	case eventTypes["setuid"] > 0 || eventTypes["setgid"] > 0:
		raw = 15
		factors = append(factors, "uid/gid change")
	case behavior != nil && behavior.PrivilegeEscalation:
		raw = 15
		factors = append(factors, "privilege escalation behavior")
	}

	risk.addCategory(raw, 30, factors...)
}

func scoreNetwork(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	raw := 0
	var factors []string

	external := behavior != nil && behavior.HasExternalNetwork
	bindAll := behavior != nil && behavior.HasBindAllInterfaces
	listen := behavior != nil && behavior.HasListenSocket

	if external {
		raw += 25
		factors = append(factors, "external network connection")
	}
	if bindAll {
		raw += 18
		factors = append(factors, "bind on all interfaces (0.0.0.0/::)")
	}
	if listen && !bindAll {
		raw += 10
		factors = append(factors, "network socket listen")
	}

	// Only score generic socket noise when behavior did not already capture intent.
	if !external {
		if eventTypes["tcp_connect"] > 0 {
			raw += 8
			factors = append(factors, "TCP network connection")
		} else if eventTypes["udp_send"] > 0 || eventTypes["udp_connect"] > 0 {
			raw += 6
			factors = append(factors, "UDP network activity")
		}
	}
	if !listen && eventTypes["tcp_accept"] > 0 {
		raw += 8
		factors = append(factors, "accepted inbound TCP connection")
	}
	if eventTypes["unix_connect"] > 0 {
		raw += 2
	}
	if eventTypes["socket"] > 5 && !external && !listen {
		raw += 4
	}

	risk.addCategory(raw, 40, factors...)
}

func scoreExecution(risk *dynamicRisk, behavior *BehaviorSummary) {
	if behavior == nil {
		return
	}
	raw := 0
	var factors []string
	if behavior.HasShellExecution {
		raw += 18
		factors = append(factors, "shell execution")
	}
	if behavior.HasScriptExecution {
		raw += 8
		factors = append(factors, "script execution")
	}
	if len(behavior.CommandsExecuted) > 3 {
		raw += 8
		factors = append(factors, "multiple distinct commands executed")
	}
	risk.addCategory(raw, 35, factors...)
}

func scoreFilesystem(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	raw := 0
	var factors []string

	if eventTypes["mount"] > 0 || eventTypes["remount"] > 0 {
		raw += 20
		factors = append(factors, "filesystem mount/remount")
	}
	if eventTypes["link"] > 0 {
		raw += 10
		factors = append(factors, "hard link creation")
	}
	if behavior != nil {
		// LaunchAgent/Daemon writes are scored under persistence — don't also
		// count them as generic sensitive filesystem writes.
		if hasNonLaunchSensitiveWrite(behavior) {
			raw += 18
			factors = append(factors, "write to sensitive location")
		}
		if behavior.HasSensitiveDelete {
			raw += 12
			factors = append(factors, "delete sensitive file")
		}
		if behavior.HasSensitiveChmod {
			raw += 10
			factors = append(factors, "permission change on sensitive path")
		}
	}
	// Demote bare deletion volume — only matters at high volume without sensitive delete.
	if eventTypes["unlink"] > 20 && (behavior == nil || !behavior.HasSensitiveDelete) {
		raw += 8
		factors = append(factors, "high-volume file deletion")
	}

	risk.addCategory(raw, 35, factors...)
}

func scoreAccessRecon(risk *dynamicRisk, tree *ProcessTreeNode, eventTypes map[string]int) {
	raw := 0
	var factors []string

	if eventTypes["proc_suspend_resume"] > 0 {
		raw += 15
		factors = append(factors, "process suspend/resume control")
	}
	switch {
	case eventTypes["proc_check"] > 20:
		raw += 12
		factors = append(factors, "high-volume process permission checks")
	case eventTypes["proc_check"] > 5:
		raw += 6
		factors = append(factors, "repeated process permission checks")
	}
	if eventTypes["signal"] > 3 {
		raw += 6
		factors = append(factors, "multiple process signals")
	}
	if pts, desc := analyzeXPCConnect(tree, eventTypes); pts > 0 {
		raw += pts
		factors = append(factors, desc)
	}
	if eventTypes["iokit_open"] > 0 {
		raw += 6
		factors = append(factors, "IOKit user client access")
	}

	risk.addCategory(raw, 25, factors...)
}

func scoreCombos(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary, hasRWX bool) {
	hasRemoteThread := eventTypes["remote_thread_create"] > 0
	hasTask := eventTypes["get_task"]+eventTypes["get_task_read"]+eventTypes["get_task_inspect"] > 0
	hasMprotect := eventTypes["mprotect"] > 0

	if hasRemoteThread && (hasMprotect || hasTask) {
		risk.add(25, "injection chain: remote thread with task/memory access")
	}
	if hasRWX && eventTypes["cs_invalidated"] > 0 {
		risk.add(20, "RWX memory with code signature invalidation")
	}

	hasBTM := eventTypes["btm_launch_item_add"] > 0 || eventTypes["btm_launch_item_remove"] > 0
	hasPersistence := hasBTM ||
		(behavior != nil && (behavior.HasLaunchctlPersistence || len(behavior.PersistenceItems) > 0))
	external := behavior != nil && behavior.HasExternalNetwork

	if hasPersistence && external {
		risk.add(15, "persistence with external network")
	}
	if behavior != nil && behavior.HasShellExecution && external {
		risk.add(15, "shell execution with external network")
	}
	if hasSensitiveLaunchPersistence(behavior) &&
		(hasBTM || (behavior != nil && behavior.HasLaunchctlPersistence)) {
		risk.add(15, "LaunchAgent/Daemon write with install persistence")
	}
}

func isLaunchPersistencePath(path string) bool {
	return strings.Contains(path, "/LaunchAgents") || strings.Contains(path, "/LaunchDaemons")
}

func hasSensitiveLaunchPersistence(behavior *BehaviorSummary) bool {
	if behavior == nil {
		return false
	}
	for _, p := range behavior.PersistenceItems {
		if isLaunchPersistencePath(p) {
			return true
		}
	}
	if behavior.HasSensitiveWrite {
		for _, p := range behavior.FilesWritten {
			if isLaunchPersistencePath(p) {
				return true
			}
		}
	}
	return false
}

// hasNonLaunchSensitiveWrite is true when sensitive writes include paths outside
// LaunchAgents/Daemons (those belong to the persistence category).
func hasNonLaunchSensitiveWrite(behavior *BehaviorSummary) bool {
	if behavior == nil || !behavior.HasSensitiveWrite {
		return false
	}
	sawSensitive := false
	for _, p := range behavior.FilesWritten {
		if !isSensitivePath(p) {
			continue
		}
		sawSensitive = true
		if !isLaunchPersistencePath(p) {
			return true
		}
	}
	// Flag set but no enumerable paths — keep scoring to avoid under-counting.
	return !sawSensitive
}

func analyzeGetTaskEvents(tree *ProcessTreeNode, eventTypes map[string]int) (score int, description string) {
	// get_task_name only queries the process name — ignore for scoring.
	total := eventTypes["get_task"] + eventTypes["get_task_read"] + eventTypes["get_task_inspect"]
	if total == 0 {
		return 0, ""
	}

	uniqueTargets := make(map[string]struct{})
	systemTargets := 0

	walkTree(tree, func(ev DynamicEvent) {
		if ev.Type != "get_task" && ev.Type != "get_task_read" && ev.Type != "get_task_inspect" {
			return
		}
		target := ev.Target
		if target == "" && ev.Object != nil {
			target = ev.Object.Path
		}
		if target != "" {
			uniqueTargets[target] = struct{}{}
			if isSystemProcessTarget(target) {
				systemTargets++
			}
		}
	})

	if systemTargets > 0 {
		return 25, "task access targeting system processes"
	}
	if len(uniqueTargets) > 5 {
		return 18, "task access across many distinct processes"
	}
	if total > 10 {
		return 12, "high-volume task access"
	}
	return 5, "task access"
}

// analyzeMprotectBase returns a standalone mprotect score without combo stacking.
// Combos are applied separately in scoreCombos.
func analyzeMprotectBase(tree *ProcessTreeNode, eventTypes map[string]int) (score int, description string, hasRWX bool) {
	if eventTypes["mprotect"] == 0 {
		return 0, "", false
	}

	walkTree(tree, func(ev DynamicEvent) {
		if ev.Type != "mprotect" {
			return
		}
		if prot, ok := ev.Metadata["protection"]; ok && prot == "7" {
			hasRWX = true
		}
	})

	if hasRWX {
		return 15, "RWX memory protection change", true
	}
	return 5, "memory protection change", false
}

func analyzeXPCConnect(tree *ProcessTreeNode, eventTypes map[string]int) (score int, description string) {
	if eventTypes["xpc_connect"] == 0 {
		return 0, ""
	}

	nonApple := 0
	walkTree(tree, func(ev DynamicEvent) {
		if ev.Type != "xpc_connect" {
			return
		}
		service := ""
		if ev.Object != nil {
			service = ev.Object.Name
		}
		if service == "" {
			service = ev.Target
		}
		if service != "" && !strings.HasPrefix(service, "com.apple.") {
			nonApple++
		}
	})

	if nonApple > 5 {
		return 12, "multiple non-Apple XPC service connections"
	}
	if nonApple > 0 {
		return 6, "non-Apple XPC service connection"
	}
	return 0, ""
}

func hasBehavioralActivity(eventTypes map[string]int) bool {
	for t, count := range eventTypes {
		if t != "exit" && count > 0 {
			return true
		}
	}
	return false
}

func isSystemProcessTarget(target string) bool {
	for _, p := range []string{
		"kernel_task",
		"launchd",
		"/System/Library/",
		"/usr/sbin/",
		"/sbin/",
		"/usr/libexec/",
	} {
		if strings.Contains(target, p) {
			return true
		}
	}
	return false
}
