package agent

// DefaultVsockPort is the virtio-vsock port the guest agent listens on.
// Host dials the same port via Virtualization.framework.
const DefaultVsockPort uint32 = 12345

// ShareTag is the virtiofs tag of the host directory shared with the guest.
const ShareTag = "machbox"

// HTTP API served by the guest agent over vsock.
const (
	pathInfo       = "/v1/info"
	pathWorkDir    = "/v1/workdir"
	pathExec       = "/v1/exec"
	pathExecStream = "/v1/exec/stream"

	// Trailers sent after the stdout body of a streaming task.
	trailerTaskError    = "X-Task-Error"
	trailerTaskTimedOut = "X-Task-Timed-Out"
)

// GuestInfo describes the guest; returned by GET /v1/info.
type GuestInfo struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	BuildVersion string `json:"build_version"`
	// AgentVersion is the guest agent revision used for host compatibility checks.
	AgentVersion string `json:"agent_version"`
	SIPDisabled  bool   `json:"sip_disabled"`
}

// WorkDir tells the guest where to store files and run tasks.
type WorkDir struct {
	SharePath string `json:"share_path"`
	WorkPath  string `json:"work_path"`
}

// Task describes a command to execute inside the guest.
type Task struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	WorkDir string   `json:"work_dir,omitempty"`
	Timeout int      `json:"timeout,omitempty"` // seconds; default 60
}

// TaskResult is returned for a finished non-streaming Task. A task that ran
// but failed (non-zero exit, timeout) is OK=false with Error set; protocol
// errors are reported as HTTP errors instead.
type TaskResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}

type apiError struct {
	Error string `json:"error"`
}
