package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type DynamicEvent struct {
	Timestamp   time.Time         `json:"ts"`
	Type        string            `json:"type"`
	PID         int32             `json:"pid"`
	PIDVersion  int32             `json:"pidversion,omitempty"`
	PPID        *int32            `json:"ppid,omitempty"`
	PPIDVersion int32             `json:"ppidversion,omitempty"`
	Process     string            `json:"process,omitempty"`
	Target      string            `json:"target,omitempty"`
	Subject     *ProcessIdentity  `json:"subject,omitempty"`
	Object      *EventObject      `json:"object,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

type ProcessIdentity struct {
	PID         int32  `json:"pid"`
	PIDVersion  int32  `json:"pidversion,omitempty"`
	PPID        int32  `json:"ppid,omitempty"`
	PPIDVersion int32  `json:"ppidversion,omitempty"`
	Path        string `json:"path,omitempty"`
}

type EventObject struct {
	Kind        string `json:"kind"`
	Path        string `json:"path,omitempty"`
	PID         *int32 `json:"pid,omitempty"`
	PIDVersion  int32  `json:"pidversion,omitempty"`
	PPID        *int32 `json:"ppid,omitempty"`
	PPIDVersion int32  `json:"ppidversion,omitempty"`
	Name        string `json:"name,omitempty"`
}

type ProcessTreeNode struct {
	PID      int32              `json:"pid"`
	PPID     int32              `json:"ppid,omitempty"`
	Path     string             `json:"path,omitempty"`
	Children []*ProcessTreeNode `json:"children,omitempty"`
	Events   []DynamicEvent     `json:"events,omitempty"`
	Networks []DynamicEvent     `json:"networks,omitempty"`
}

func walkTree(node *ProcessTreeNode, fn func(DynamicEvent)) {
	if node == nil {
		return
	}
	for i := range node.Events {
		fn(node.Events[i])
	}
	for _, child := range node.Children {
		walkTree(child, fn)
	}
}

type DynamicSummary struct {
	ParseErrors int      `json:"parse_errors"`
	RiskScore   int      `json:"risk_score"`
	RiskFactors []string `json:"risk_factors,omitempty"`
	Verdict     string   `json:"verdict"`

	// Key security indicators
	PersistenceCount     int `json:"persistence_count"`
	PrivilegeChanges     int `json:"privilege_changes"`
	CodeSigInvalidations int `json:"code_sig_invalidations"`
	InjectionCount       int `json:"injection_count"`

	// Specific paths / targets (deduplicated)
	PersistencePaths []string `json:"persistence_paths,omitempty"`
	InjectedTargets  []string `json:"injected_targets,omitempty"`

	// BehaviorSummary surfaces qualitative malicious behaviors rather than raw counts.
	BehaviorSummary *BehaviorSummary `json:"behavior_summary,omitempty"`
}

// BehaviorSummary captures the presence and scope of security-relevant behaviors.
// It is intended to be more useful for reporting than aggregate event counts.
type BehaviorSummary struct {
	// Network behavior
	NetworkConnections   []string `json:"network_connections,omitempty"`
	HasExternalNetwork   bool     `json:"has_external_network"`
	HasBindAllInterfaces bool     `json:"has_bind_all_interfaces"`
	HasListenSocket      bool     `json:"has_listen_socket"`

	// File behavior
	FilesWritten       []string `json:"files_written,omitempty"`
	FilesDeleted       []string `json:"files_deleted,omitempty"`
	FilesModifiedPerms []string `json:"files_modified_perms,omitempty"`
	HasSensitiveWrite  bool     `json:"has_sensitive_write"`
	HasSensitiveDelete bool     `json:"has_sensitive_delete"`
	HasSensitiveChmod  bool     `json:"has_sensitive_chmod"`

	// Process / command execution behavior
	CommandsExecuted   []string `json:"commands_executed,omitempty"`
	CommandLines       []string `json:"command_lines,omitempty"`
	HasShellExecution  bool     `json:"has_shell_execution"`
	HasScriptExecution bool     `json:"has_script_execution"`
	ChildProcesses     int      `json:"child_processes"`

	// Persistence behavior
	PersistenceItems        []string `json:"persistence_items,omitempty"`
	HasLaunchctlPersistence bool     `json:"has_launchctl_persistence"`

	// Privilege behavior
	PrivilegeEscalation bool `json:"privilege_escalation"`

	// Injection behavior
	InjectionTargets []string `json:"injection_targets,omitempty"`
}

type DynamicReport struct {
	ProcessTree *ProcessTreeNode `json:"process_tree,omitempty"`
	Summary     DynamicSummary   `json:"summary"`
}

type launchMarker struct {
	pid  int32
	path string
}

type procInfo struct {
	pid           int32
	ppid          int32
	path          string
	events        []DynamicEvent
	networkEvents []DynamicEvent
}

// parseAndBuildTree streams JSONL events and directly builds a filtered process
// tree.  It avoids materialising the full event slice in memory.
func parseAndBuildTree(r io.Reader, samplePath string) (*ProcessTreeNode, int, error) {
	samplePath = workdirRegex.ReplaceAllString(samplePath, sanitizedPath)

	infos := make(map[int32]*procInfo)
	parseErrors := 0
	var marker *launchMarker

	// ------------------------------------------------------------------
	// Phase 1 – Stream parse: group events by PID into procInfo buckets.
	// Network events (dnet_*) are stripped of prefix and collected
	// separately so they don't pollute the process tree.
	// ------------------------------------------------------------------
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		sanitized := workdirRegex.ReplaceAll(line, []byte(sanitizedPath))

		var ev DynamicEvent
		if err := json.Unmarshal(sanitized, &ev); err != nil {
			parseErrors++
			continue
		}

		// A synthetic marker emitted by the launcher tells us the authoritative
		// root PID/path.  When present we trust it over path-based heuristics.
		// Ignore malformed markers (pid == 0) and keep the first valid one.
		if ev.Type == "machbox_launch" && ev.PID > 0 && marker == nil {
			marker = &launchMarker{
				pid:  ev.PID,
				path: ev.Target,
			}
			continue
		}

		info, exists := infos[ev.PID]
		if !exists {
			ppid := int32(0)
			if ev.PPID != nil {
				ppid = *ev.PPID
			}
			path := ev.Process
			if (ev.Type == "exec" || ev.Type == "fork") && ev.Object != nil && ev.Object.Path != "" {
				path = ev.Object.Path
			}
			info = &procInfo{
				pid:  ev.PID,
				ppid: ppid,
				path: path,
			}
			infos[ev.PID] = info
		} else if (ev.Type == "exec" || ev.Type == "fork") && ev.Object != nil && ev.Object.Path != "" {
			info.path = ev.Object.Path
			if ev.PPID != nil {
				info.ppid = *ev.PPID
			}
		}

		// Strip dnet_ prefix and collect network events separately.
		if strings.HasPrefix(ev.Type, "dnet_") {
			ev.Type = strings.TrimPrefix(ev.Type, "dnet_")
			info.networkEvents = append(info.networkEvents, ev)
			continue
		}

		info.events = append(info.events, ev)

		// For exec events the target process may be a new PID we have not seen yet.
		if ev.Type == "exec" && ev.Object != nil && ev.Object.PID != nil {
			targetPID := *ev.Object.PID
			if _, ok := infos[targetPID]; !ok {
				targetPPID := int32(0)
				if ev.Object.PPID != nil {
					targetPPID = *ev.Object.PPID
				}
				infos[targetPID] = &procInfo{
					pid:  targetPID,
					ppid: targetPPID,
					path: ev.Object.Path,
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, fmt.Errorf("scan jsonl: %w", err)
	}

	// ------------------------------------------------------------------
	// Phase 2 – Trim pre-sample events and identify seed PIDs in one pass.
	//
	// Prefer an explicit machbox_launch marker.  Otherwise fall back to
	// path-based seeding using exact/suffix matching (avoiding the overly
	// permissive strings.Contains).
	// ------------------------------------------------------------------
	seeds := make(map[int32]struct{})
	if marker != nil {
		seeds[marker.pid] = struct{}{}
		// Even with an authoritative marker, the PID may have existed before
		// the sample launched (e.g. a reused process or ES buffering). Trim
		// pre-sample events by finding the last exec/fork into the sample binary.
		if info, ok := infos[marker.pid]; ok {
			if cutoff := findSampleExecCutoff(marker.pid, info.events, samplePath); cutoff >= 0 {
				info.events = info.events[cutoff:]
			}
		}
	}
	// Fallback: when no marker is present, seed by path matching and trim
	// each matching PID to the point where it exec'd/forked the sample.
	for pid, info := range infos {
		if _, alreadySeed := seeds[pid]; alreadySeed {
			continue
		}
		if !pathMatchesSample(info.path, samplePath) {
			continue
		}
		seeds[pid] = struct{}{}
		if cutoff := findSampleExecCutoff(pid, info.events, samplePath); cutoff >= 0 {
			info.events = info.events[cutoff:]
		}
	}

	// ------------------------------------------------------------------
	// Phase 3 – Build children map and collect all PIDs reachable from seeds.
	// ------------------------------------------------------------------
	children := make(map[int32][]int32)
	for pid, info := range infos {
		if info.ppid != 0 {
			children[info.ppid] = append(children[info.ppid], pid)
		}
	}

	related := make(map[int32]struct{})
	var collect func(pid int32)
	collect = func(pid int32) {
		if _, ok := related[pid]; ok {
			return
		}
		related[pid] = struct{}{}
		for _, child := range children[pid] {
			collect(child)
		}
	}
	for pid := range seeds {
		collect(pid)
	}

	// ------------------------------------------------------------------
	// Phase 4 – Materialise ProcessTreeNode only for related PIDs.
	// ------------------------------------------------------------------
	nodes := make(map[int32]*ProcessTreeNode, len(related))
	for pid := range related {
		info := infos[pid]
		nodes[pid] = &ProcessTreeNode{
			PID:      pid,
			PPID:     info.ppid,
			Path:     info.path,
			Events:   info.events,
			Networks: info.networkEvents,
		}
	}

	var roots []*ProcessTreeNode
	for pid := range related {
		info := infos[pid]
		if info.ppid == 0 {
			roots = append(roots, nodes[pid])
		} else if parent, ok := nodes[info.ppid]; ok {
			parent.Children = append(parent.Children, nodes[pid])
		} else {
			// Parent not observed or not related; treat as root.
			roots = append(roots, nodes[pid])
		}
	}

	if len(roots) == 0 {
		return nil, parseErrors, nil
	}
	if len(roots) == 1 {
		return roots[0], parseErrors, nil
	}

	// Multiple roots usually means parent links were broken (e.g. a parent
	// exited before we observed it, or PID reuse).  Use an explicit synthetic
	// container so the UI can render it intentionally instead of looking like
	// a real process with an empty path.
	return &ProcessTreeNode{
		PID:      0,
		Path:     "<root>",
		Children: roots,
	}, parseErrors, nil
}

// findSampleExecCutoff returns the index of the last exec/fork event that
// transitions the process into the sample binary. Events before this index are
// considered pre-sample activity for that PID.
func findSampleExecCutoff(pid int32, events []DynamicEvent, samplePath string) int {
	logrus.Debugf("[cutoff-debug] pid=%d samplePath=%q eventCount=%d", pid, samplePath, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		ev := events[i]
		if ev.Type != "exec" && ev.Type != "fork" {
			continue
		}
		// Prefer Object.Path (the new process identity), but fall back to
		// Target/Process because some emitters populate only Target.
		path := ""
		if ev.Object != nil {
			path = ev.Object.Path
		}
		if path == "" && ev.Target != "" {
			path = ev.Target
		}
		if path == "" {
			path = ev.Process
		}
		matched := path != "" && pathMatchesSample(path, samplePath)
		logrus.Debugf("[cutoff-debug] pid=%d idx=%d type=%s objPath=%q target=%q process=%q chosen=%q matched=%v", pid, i, ev.Type, ev.Object.Path, ev.Target, ev.Process, path, matched)
		if matched {
			logrus.Debugf("[cutoff-debug] pid=%d cutoff=%d", pid, i)
			return i
		}
	}

	logrus.Debugf("[cutoff-debug] pid=%d no cutoff found", pid)
	return -1
}

// pathMatchesSample reports whether path refers to the sample executable.
// It avoids strings.Contains which can falsely match when the workdir name
// happens to contain the sample basename.
//
// For app bundles (.app), paths inside the bundle (e.g. Contents/MacOS/...)
// are also considered a match because the launcher passes the bundle path
// while exec events carry the inner executable path.
func pathMatchesSample(path, samplePath string) bool {
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
