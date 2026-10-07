package report

import (
	"path/filepath"
	"strconv"
	"strings"
)

var shellBasenames = []string{
	"sh", "bash", "zsh", "csh", "tcsh", "ksh", "dash", "fish", "rbash", "rzsh",
}

func normalizePath(path string) string {
	switch {
	case strings.HasPrefix(path, "/private/var/"):
		return "/var/" + strings.TrimPrefix(path, "/private/var/")
	case strings.HasPrefix(path, "/private/tmp/"):
		return "/tmp/" + strings.TrimPrefix(path, "/private/tmp/")
	default:
		return path
	}
}

// pathMatchesSample reports whether path refers to the sample executable.
// Avoids strings.Contains which falsely matches when a dirname contains the
// sample basename. For .app bundles, inner Contents/MacOS paths also match.
func pathMatchesSample(path, samplePath string) bool {
	path = normalizePath(path)
	samplePath = normalizePath(samplePath)
	if path == "" || samplePath == "" {
		return false
	}
	if path == samplePath {
		return true
	}
	if strings.HasSuffix(samplePath, ".app") {
		if strings.HasPrefix(path, samplePath+string(filepath.Separator)) {
			return true
		}
	}
	if strings.HasSuffix(path, samplePath) {
		prefix := path[:len(path)-len(samplePath)]
		if prefix == "" || strings.HasSuffix(prefix, string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func isProcessLifecycleEvent(typ string) bool {
	return typ == "exec" || typ == "posix_spawn" || typ == "fork"
}

func eventMetadata(ev *DynamicEvent, key string) string {
	if ev.Metadata == nil {
		return ""
	}
	return ev.Metadata[key]
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
	if isProcessLifecycleEvent(ev.Type) {
		return ""
	}
	// Prefer structured paths: Target is often "src -> dst" for clone/copy/rename.
	if ev.Object != nil && ev.Object.Path != "" {
		return ev.Object.Path
	}
	if dest := eventMetadata(ev, "destination"); dest != "" {
		return dest
	}
	if path := eventMetadata(ev, "path"); path != "" {
		return path
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

func splitNullArgv(argv string) []string {
	if argv == "" {
		return nil
	}
	parts := strings.Split(argv, "\x00")
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func eventCommandLine(ev *DynamicEvent) string {
	parts := splitNullArgv(eventMetadata(ev, "argv"))
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

func eventNetworkRemote(ev *DynamicEvent) string {
	for _, key := range []string{"remote", "dest", "dst", "peer"} {
		if v := eventMetadata(ev, key); v != "" {
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

func isBindAllLocal(local string) bool {
	return strings.HasPrefix(local, "0.0.0.0") || strings.HasPrefix(local, "[::]")
}

func isShellPath(path string) bool {
	base := filepath.Base(path)
	for _, sh := range shellBasenames {
		if base == sh {
			return true
		}
	}
	return false
}

func isScriptPath(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".sh", ".py", ".pl", ".rb", ".php", ".js", ".applescript", ".scpt":
		return true
	default:
		return false
	}
}

func isSensitivePath(path string) bool {
	if path == "" {
		return false
	}
	for _, p := range []string{
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
	} {
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
	host := endpoint
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")

	for _, p := range []string{"127.", "10.", "192.168.", "172."} {
		if strings.HasPrefix(host, p) {
			return false
		}
	}
	if host == "localhost" || host == "::1" || host == "0.0.0.0" {
		return false
	}
	return strings.Contains(endpoint, ".") || strings.Contains(endpoint, ":")
}

// darwinFWrite is FWRITE from <sys/fcntl.h> / <sys/file.h>.
// Endpoint Security es_event_open_t.fflag uses FREAD(1)|FWRITE(2), NOT open(2) O_*.
const darwinFWrite = 0x2

// openEventHasWriteIntent reports whether an open event requested write access.
// Prefer metadata.access from dynamictool (already FWRITE-based); fall back to
// fflag as FREAD/FWRITE bits, then legacy textual flags ("W", "RDWR", …).
func openEventHasWriteIntent(ev *DynamicEvent) bool {
	if access := eventMetadata(ev, "access"); access != "" {
		return strings.EqualFold(access, "write")
	}
	if fflag := eventMetadata(ev, "fflag"); fflag != "" {
		if n, err := strconv.Atoi(fflag); err == nil {
			return n&darwinFWrite != 0
		}
	}
	return hasWriteIntent(eventMetadata(ev, "flags"))
}

func closeEventWasModified(ev *DynamicEvent) bool {
	mod := eventMetadata(ev, "modified")
	return mod == "1" || strings.EqualFold(mod, "true")
}

func hasWriteIntent(flags string) bool {
	if flags == "" {
		return false
	}
	flags = strings.ToUpper(flags)
	return strings.Contains(flags, "W") ||
		strings.Contains(flags, "WRONLY") ||
		strings.Contains(flags, "RDWR") ||
		strings.Contains(flags, "CREAT") ||
		strings.Contains(flags, "TRUNC")
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func notePersistence(s *DynamicSummary, behavior *BehaviorSummary, path string) {
	if path == "" {
		return
	}
	s.PersistenceCount++
	s.PersistencePaths = appendUnique(s.PersistencePaths, path)
	if behavior != nil {
		behavior.PersistenceItems = appendUnique(behavior.PersistenceItems, path)
	}
}

func noteInjection(s *DynamicSummary, behavior *BehaviorSummary, target string) {
	s.InjectionCount++
	if target == "" {
		return
	}
	s.InjectedTargets = appendUnique(s.InjectedTargets, target)
	if behavior != nil {
		behavior.InjectionTargets = appendUnique(behavior.InjectionTargets, target)
	}
}

func noteFileWrite(behavior *BehaviorSummary, path string) {
	if behavior == nil || path == "" {
		return
	}
	behavior.FilesWritten = appendUnique(behavior.FilesWritten, path)
	if isSensitivePath(path) {
		behavior.HasSensitiveWrite = true
	}
}

func noteFileDelete(behavior *BehaviorSummary, path string) {
	if behavior == nil || path == "" {
		return
	}
	behavior.FilesDeleted = appendUnique(behavior.FilesDeleted, path)
	if isSensitivePath(path) {
		behavior.HasSensitiveDelete = true
	}
}
