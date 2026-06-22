package report

import (
	"path/filepath"
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

	// Shell wrappers, with optional leading path like /bin/bash -c or bash -c.
	shells := []string{"sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "fish"}
	for _, sh := range shells {
		prefix := sh + " -c"
		if strings.HasPrefix(line, prefix) {
			return strings.TrimSpace(line[len(prefix):])
		}
		// /bin/bash -c, /usr/local/bin/zsh -c, etc.
		suffix := "/" + sh + " -c"
		if idx := strings.Index(line, suffix); idx >= 0 {
			return strings.TrimSpace(line[idx+len(suffix):])
		}
	}
	if strings.HasPrefix(line, "sudo ") {
		return strings.TrimSpace(line[len("sudo "):])
	}
	// env FOO=bar ... cmd
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
		if path == p {
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

		// Collect file-system behavior.
		collectFileBehavior(ev, behavior)

		// Collect command execution behavior (skip self-launch).
		collectProcessBehavior(ev, behavior, samplePaths)

		// launchctl load/bootstrap is a common persistence mechanism.
		collectLaunchctlPersistence(ev, s, behavior)

		switch ev.Type {
		case "btm_launch_item_add", "btm_launch_item_remove", "setextattr":
			s.PersistenceCount++
			if path := eventTargetPath(ev); path != "" {
				s.PersistencePaths = appendUnique(s.PersistencePaths, path)
				behavior.PersistenceItems = appendUnique(behavior.PersistenceItems, path)
			}
		case "seteuid", "setegid", "setreuid", "setregid", "setuid", "setgid":
			s.PrivilegeChanges++
			behavior.PrivilegeEscalation = true
		case "cs_invalidated":
			s.CodeSigInvalidations++
		case "remote_thread_create", "get_task":
			// 真正的代码注入能力：远程线程创建或获取完整任务端口
			s.InjectionCount++
			if target := eventTargetPath(ev); target != "" {
				s.InjectedTargets = appendUnique(s.InjectedTargets, target)
				behavior.InjectionTargets = appendUnique(behavior.InjectionTargets, target)
			}
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
	path := eventFilePath(ev)
	if path == "" {
		return
	}

	switch ev.Type {
	case "write", "pwrite", "truncate", "creat":
		behavior.FilesWritten = appendUnique(behavior.FilesWritten, path)
		if isSensitivePath(path) {
			behavior.HasSensitiveWrite = true
		}
	case "open":
		// Treat opens with write intent as writes when we can infer it.
		if hasWriteIntent(ev.Metadata["flags"]) {
			behavior.FilesWritten = appendUnique(behavior.FilesWritten, path)
			if isSensitivePath(path) {
				behavior.HasSensitiveWrite = true
			}
		}
	case "unlink", "rename":
		behavior.FilesDeleted = appendUnique(behavior.FilesDeleted, path)
		if isSensitivePath(path) {
			behavior.HasSensitiveDelete = true
		}
	case "chmod", "chown", "setmode", "setattr", "setextattr":
		behavior.FilesModifiedPerms = appendUnique(behavior.FilesModifiedPerms, path)
		if isSensitivePath(path) || ev.Type == "setextattr" {
			behavior.HasSensitiveChmod = true
		}
	}
}

func hasWriteIntent(flags string) bool {
	flags = strings.ToUpper(flags)
	return strings.Contains(flags, "W") ||
		strings.Contains(flags, "WRONLY") ||
		strings.Contains(flags, "RDWR") ||
		strings.Contains(flags, "CREAT") ||
		strings.Contains(flags, "TRUNC")
}

func collectProcessBehavior(ev *DynamicEvent, behavior *BehaviorSummary, samplePaths []string) {
	if ev.Type != "exec" && ev.Type != "posix_spawn" && ev.Type != "fork" {
		return
	}
	cmd := eventCommandPath(ev)
	if cmd == "" {
		return
	}
	// Filter out the sample launching itself; this is usually the first exec/spawn event.
	if isSamplePath(cmd, samplePaths) {
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
	if ev.Type != "exec" && ev.Type != "posix_spawn" && ev.Type != "fork" {
		return
	}
	cmd := eventCommandPath(ev)
	if !isLaunchctlCommand(cmd) {
		return
	}
	argv := ev.Metadata["argv"]
	if argv == "" {
		return
	}
	parts := strings.Split(argv, "\x00")
	if len(parts) < 2 {
		return
	}
	// Drop trailing empty part caused by a terminating null byte.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}

	subcommand := parts[1]
	if subcommand != "load" && subcommand != "loadw" && subcommand != "bootstrap" && subcommand != "enable" {
		return
	}

	plistPath := extractLaunchctlPlistPath(parts)
	if plistPath == "" {
		return
	}

	s.PersistenceCount++
	s.PersistencePaths = appendUnique(s.PersistencePaths, plistPath)
	behavior.PersistenceItems = appendUnique(behavior.PersistenceItems, plistPath)
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
	case "tcp_connect", "udp_connect":
		remote := eventNetworkRemote(ev)
		if remote != "" {
			behavior.NetworkConnections = appendUnique(behavior.NetworkConnections, remote)
		}
		if isExternalEndpoint(remote) {
			behavior.HasExternalNetwork = true
		}
	case "bind":
		behavior.HasListenSocket = true
		local := ev.Metadata["local"]
		if strings.HasPrefix(local, "0.0.0.0") || strings.HasPrefix(local, "[::]") {
			behavior.HasBindAllInterfaces = true
		}
	}
}

func eventTargetPath(ev *DynamicEvent) string {
	if ev.Target != "" {
		return ev.Target
	}
	if ev.Object != nil {
		if ev.Object.Path != "" {
			return ev.Object.Path
		}
		if ev.Object.Name != "" {
			return ev.Object.Name
		}
	}
	return ""
}

func eventFilePath(ev *DynamicEvent) string {
	if ev.Type == "exec" || ev.Type == "posix_spawn" || ev.Type == "fork" {
		return ""
	}
	return eventTargetPath(ev)
}

func eventCommandPath(ev *DynamicEvent) string {
	if ev.Object != nil && ev.Object.Path != "" {
		return ev.Object.Path
	}
	if ev.Target != "" {
		return ev.Target
	}
	return ev.Process
}

func eventCommandLine(ev *DynamicEvent) string {
	// dynamictool stores argv as a null-separated string under the "argv" metadata key.
	argv := ev.Metadata["argv"]
	if argv == "" {
		return ""
	}
	parts := strings.Split(argv, "\x00")
	// Drop trailing empty part caused by a terminating null byte.
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func eventNetworkRemote(ev *DynamicEvent) string {
	for _, key := range []string{"remote", "dest", "dst", "peer"} {
		if v := ev.Metadata[key]; v != "" {
			return v
		}
	}
	if ev.Target != "" {
		return ev.Target
	}
	if ev.Object != nil && ev.Object.Name != "" {
		return ev.Object.Name
	}
	return ""
}

func isShellPath(path string) bool {
	base := filepath.Base(path)
	shells := map[string]struct{}{
		"sh": {}, "bash": {}, "zsh": {}, "csh": {}, "tcsh": {},
		"ksh": {}, "dash": {}, "fish": {}, "rbash": {}, "rzsh": {},
	}
	_, ok := shells[base]
	return ok
}

func isScriptPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".sh" || ext == ".py" || ext == ".pl" || ext == ".rb" ||
		ext == ".php" || ext == ".js" || ext == ".applescript" || ext == ".scpt"
}

func isSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	sensitive := []string{
		"/System/",
		"/usr/bin/",
		"/usr/sbin/",
		"/bin/",
		"/sbin/",
		"/etc/",
		"/Library/LaunchAgents",
		"/Library/LaunchDaemons",
		"/Library/StartupItems",
		"/Library/Preferences/LoginWindow",
		"~/Library/LaunchAgents",
		"/Users/*/Library/LaunchAgents",
		"/Users/*/Library/LaunchDaemons",
		".bash_profile", ".bashrc", ".zshrc", ".zprofile",
		".profile", ".login", ".logout",
		"/private/etc/",
	}
	for _, p := range sensitive {
		if strings.Contains(path, p) {
			return true
		}
	}
	return false
}

func isExternalEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}
	// Strip port and brackets for IPv6.
	host := endpoint
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")

	// Local-only addresses are not external.
	localPrefixes := []string{"127.", "10.", "192.168.", "172."}
	for _, p := range localPrefixes {
		if strings.HasPrefix(host, p) {
			return false
		}
	}
	if host == "localhost" || host == "::1" || host == "0.0.0.0" {
		return false
	}

	// Heuristic: if it looks like an IP or has a port, treat as external.
	return strings.Contains(endpoint, ".") || strings.Contains(endpoint, ":")
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

type dynamicRisk struct {
	score       int
	factors     []string
	hasActivity bool
}

func (r dynamicRisk) verdict() string {
	if r.score >= 70 {
		return "malicious"
	}
	if r.score >= 35 {
		return "suspicious"
	}
	if r.score > 0 {
		return "clean"
	}
	if r.hasActivity {
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
	if factor != "" {
		r.factors = append(r.factors, factor)
	}
}

func evaluateDynamicRisk(tree *ProcessTreeNode, eventTypes map[string]int, behavior *BehaviorSummary) dynamicRisk {
	risk := dynamicRisk{hasActivity: hasBehavioralActivity(eventTypes)}

	if !risk.hasActivity {
		return risk
	}

	// Kernel extension activity is rare and high impact on modern macOS.
	if eventTypes["kextload"] > 0 || eventTypes["kextunload"] > 0 {
		risk.add(85, "kernel extension load/unload")
	}

	addCodeInjectionRisk(&risk, tree, eventTypes, behavior)
	addPersistenceRisk(&risk, eventTypes, behavior)
	addPrivilegeRisk(&risk, eventTypes, behavior)
	addProcessAccessRisk(&risk, eventTypes)
	addFilesystemRisk(&risk, eventTypes, behavior)
	addIPCAndReconRisk(&risk, tree, eventTypes)
	if tree != nil {
		addNetworkRisk(&risk, tree.Networks, eventTypes, behavior)
		addCommandExecutionRisk(&risk, behavior)
	}

	return risk
}

func addCodeInjectionRisk(risk *dynamicRisk, tree *ProcessTreeNode, eventTypes map[string]int, behavior *BehaviorSummary) {
	getTaskScore, getTaskFactor := analyzeGetTaskEvents(tree, eventTypes)
	mprotectScore, mprotectFactor := analyzeMprotectEvents(tree, eventTypes)

	if eventTypes["remote_thread_create"] > 0 {
		risk.add(45, "remote thread creation")
	}
	if eventTypes["trace"] > 0 {
		risk.add(25, "process tracing")
	}
	if eventTypes["cs_invalidated"] > 0 {
		risk.add(20, "code signature invalidated")
	}
	if mprotectScore > 0 {
		risk.add(mprotectScore, mprotectFactor)
	}
	if getTaskScore > 0 {
		risk.add(getTaskScore, getTaskFactor)
	}
	if eventTypes["remote_thread_create"] > 0 && eventTypes["mprotect"] > 0 {
		risk.add(20, "remote thread combined with memory protection changes")
	}

	if behavior != nil && len(behavior.InjectionTargets) > 0 {
		risk.add(10, "injection targeting specific processes")
	}
}

func addPersistenceRisk(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	if eventTypes["btm_launch_item_add"] > 0 || eventTypes["btm_launch_item_remove"] > 0 {
		risk.add(35, "background/login item modification")
	}
	if eventTypes["setextattr"] > 0 {
		risk.add(10, "extended attribute modification")
	}

	if behavior != nil && len(behavior.PersistenceItems) > 0 {
		risk.add(10, "persistence item paths observed")
	}

	if behavior != nil && behavior.HasLaunchctlPersistence {
		risk.add(30, "launchctl load/bootstrap persistence")
	}
}

func addPrivilegeRisk(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	if eventTypes["seteuid"] > 0 || eventTypes["setegid"] > 0 ||
		eventTypes["setreuid"] > 0 || eventTypes["setregid"] > 0 {
		risk.add(20, "effective uid/gid change")
	}
	if eventTypes["setuid"] > 0 || eventTypes["setgid"] > 0 {
		risk.add(15, "uid/gid change")
	}

	if behavior != nil && behavior.PrivilegeEscalation {
		risk.add(10, "privilege escalation behavior")
	}
}

func addProcessAccessRisk(risk *dynamicRisk, eventTypes map[string]int) {
	if eventTypes["proc_suspend_resume"] > 0 {
		risk.add(20, "process suspend/resume control")
	}
	if eventTypes["signal"] > 3 {
		risk.add(15, "multiple process signals")
	} else if eventTypes["signal"] > 0 {
		risk.add(5, "process signal")
	}

	procChecks := eventTypes["proc_check"]
	switch {
	case procChecks > 20:
		risk.add(25, "high-volume process permission checks")
	case procChecks > 5:
		risk.add(15, "repeated process permission checks")
	case procChecks > 0:
		risk.add(3, "process permission check")
	}

	if eventTypes["get_task"]+eventTypes["get_task_read"]+eventTypes["get_task_inspect"] > 0 &&
		eventTypes["remote_thread_create"] > 0 {
		risk.add(25, "task port access combined with remote thread creation")
	}
}

func addFilesystemRisk(risk *dynamicRisk, eventTypes map[string]int, behavior *BehaviorSummary) {
	if eventTypes["link"] > 0 {
		risk.add(15, "hard link creation")
	}
	if eventTypes["mount"] > 0 || eventTypes["remount"] > 0 {
		risk.add(25, "filesystem mount/remount")
	}

	if behavior != nil {
		if behavior.HasSensitiveWrite {
			risk.add(20, "write to sensitive location")
		}
		if behavior.HasSensitiveDelete {
			risk.add(15, "delete sensitive file")
		}
		if behavior.HasSensitiveChmod {
			risk.add(15, "permission change on sensitive path")
		}
	}

	// Keep volume-based deletion scoring as a secondary signal.
	if eventTypes["unlink"] > 20 {
		risk.add(15, "high-volume file deletion")
	} else if eventTypes["unlink"] > 0 {
		risk.add(3, "file deletion")
	}
}

func addCommandExecutionRisk(risk *dynamicRisk, behavior *BehaviorSummary) {
	if behavior == nil {
		return
	}
	if behavior.HasShellExecution {
		risk.add(20, "shell execution")
	}
	if behavior.HasScriptExecution {
		risk.add(10, "script execution")
	}
	if len(behavior.CommandsExecuted) > 3 {
		risk.add(10, "multiple distinct commands executed")
	}
}

func addIPCAndReconRisk(risk *dynamicRisk, tree *ProcessTreeNode, eventTypes map[string]int) {
	xpcScore, xpcFactor := analyzeXPCConnect(tree, eventTypes)
	if xpcScore > 0 {
		risk.add(xpcScore, xpcFactor)
	}
	if eventTypes["iokit_open"] > 0 {
		risk.add(10, "IOKit user client access")
	}
}

func addNetworkRisk(risk *dynamicRisk, networkEvents []DynamicEvent, eventTypes map[string]int, behavior *BehaviorSummary) {
	if len(networkEvents) == 0 {
		return
	}

	if behavior != nil && behavior.HasExternalNetwork {
		risk.add(20, "external network connection")
	}
	if behavior != nil && behavior.HasBindAllInterfaces {
		risk.add(18, "bind on all interfaces (0.0.0.0/::)")
	}
	if behavior != nil && behavior.HasListenSocket {
		risk.add(10, "network socket listen")
	}

	if eventTypes["tcp_connect"] > 0 {
		risk.add(10, "TCP network connection")
	}
	if eventTypes["unix_connect"] > 0 {
		risk.add(3, "Unix domain socket connection")
	}
	if eventTypes["socket"] > 5 {
		risk.add(10, "high volume socket creation")
	} else if eventTypes["socket"] > 0 {
		risk.add(2, "socket creation")
	}
	if eventTypes["msg_send"] > 0 || eventTypes["msg_recv"] > 0 {
		risk.add(3, "network message activity")
	}

	// --- bind scoring (legacy count-based fallback) ---
	if eventTypes["bind"] > 0 {
		if eventTypes["bind"] > 1 {
			risk.add(3, "multiple socket binds")
		} else {
			risk.add(5, "socket bind")
		}

		for _, ev := range networkEvents {
			if ev.Type != "bind" {
				continue
			}
			local := ev.Metadata["local"]
			if local == "" {
				continue
			}
			// local format: "0.0.0.0:8080" or "[::]:80" or unix path
			if strings.HasPrefix(local, "0.0.0.0") || strings.HasPrefix(local, "[::]") {
				risk.add(5, "bind on all interfaces (0.0.0.0/::)")
			}
		}
	}
}

func analyzeGetTaskEvents(tree *ProcessTreeNode, eventTypes map[string]int) (score int, description string) {
	// get_task_name 仅查询进程名，风险极低，不计入评分
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
		return 45, "task access targeting system processes"
	}
	if len(uniqueTargets) > 5 {
		return 30, "task access across many distinct processes"
	}
	if total > 10 {
		return 20, "high-volume task access"
	}
	return 5, "task access"
}

func analyzeMprotectEvents(tree *ProcessTreeNode, eventTypes map[string]int) (score int, description string) {
	if eventTypes["mprotect"] == 0 {
		return 0, ""
	}

	hasRWX := false
	walkTree(tree, func(ev DynamicEvent) {
		if ev.Type != "mprotect" {
			return
		}
		if prot, ok := ev.Metadata["protection"]; ok && prot == "7" {
			hasRWX = true
		}
	})

	// mprotect + exec + cs_invalidated = shellcode injection pattern
	if eventTypes["exec"] > 0 && eventTypes["cs_invalidated"] > 0 {
		if hasRWX {
			return 55, "RWX memory with exec and code signature invalidation"
		}
		return 35, "memory protection changes with exec and code signature invalidation"
	}

	// mprotect + remote_thread_create = code injection
	if eventTypes["remote_thread_create"] > 0 {
		if hasRWX {
			return 50, "RWX memory with remote thread creation"
		}
		return 30, "memory protection changes with remote thread creation"
	}

	// mprotect + exec alone: often JIT/dyld, low score
	if eventTypes["exec"] > 0 {
		if hasRWX {
			return 20, "RWX memory after exec"
		}
		return 8, "memory protection changes after exec"
	}

	// mprotect + repeated proc_check = anti-analysis unpacking
	if eventTypes["proc_check"] > 3 {
		if hasRWX {
			return 30, "RWX memory with repeated process checks"
		}
		return 15, "memory protection changes with repeated process checks"
	}

	return 3, "memory protection change"
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
		return 20, "multiple non-Apple XPC service connections"
	}
	if nonApple > 0 {
		return 10, "non-Apple XPC service connection"
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
	systemPaths := []string{
		"kernel_task",
		"launchd",
		"/System/Library/",
		"/usr/sbin/",
		"/sbin/",
		"/usr/libexec/",
	}
	for _, p := range systemPaths {
		if strings.Contains(target, p) {
			return true
		}
	}
	return false
}
