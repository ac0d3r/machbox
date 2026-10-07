package agent

// DefaultVsockPort is the virtio-vsock port the guest agent listens on.
// Host dials the same port via Virtualization.framework.
const DefaultVsockPort uint32 = 12345

// GuestInfo is sent by the guest during handshake.
type GuestInfo struct {
	Hostname     string `json:"hostname"`
	Username     string `json:"username"`
	OSName       string `json:"os_name"`
	OSVersion    string `json:"os_version"`
	BuildVersion string `json:"build_version"`
	// AgentVersion is the protocol revision used for host compatibility checks.
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
	Stream  bool     `json:"stream,omitempty"`
}

// TaskResult is returned for a finished non-streaming Task.
type TaskResult struct {
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	Output string `json:"output,omitempty"`
}
