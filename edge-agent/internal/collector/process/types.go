// Package process defines process telemetry data types and collector implementation.
package process

// ExecData contains the category-specific payload for process.exec events.
type ExecData struct {
	Filename string   `json:"filename"`
	Argv     []string `json:"argv,omitempty"`
	Envp     []string `json:"envp,omitempty"` // Only if environment collection is enabled.
	RetCode  int32    `json:"ret_code,omitempty"`
}

// ForkData contains the category-specific payload for process.fork events.
type ForkData struct {
	ChildPID       int32  `json:"child_pid"`
	ChildTID       int32  `json:"child_tid,omitempty"`
	ChildComm      string `json:"child_comm,omitempty"`
	ChildEntityID  string `json:"child_entity_id,omitempty"`
	CloneFlags     uint64 `json:"clone_flags,omitempty"`
	CloneFlagsDesc string `json:"clone_flags_desc,omitempty"`
}

// ExitData contains the category-specific payload for process.exit events.
type ExitData struct {
	ExitCode   int32  `json:"exit_code"`
	Signal     int32  `json:"signal,omitempty"`
	SignalDesc string `json:"signal_desc,omitempty"`
	Duration   uint64 `json:"duration_ns,omitempty"` // Process lifetime in nanoseconds.
}

// SnapshotData contains the category-specific payload for process.snapshot events.
type SnapshotData struct {
	State        string   `json:"state"`         // R, S, D, Z, T, etc.
	StateDesc    string   `json:"state_desc"`     // "running", "sleeping", etc.
	Threads      int      `json:"threads"`
	VmSizeKB     uint64   `json:"vm_size_kb,omitempty"`
	VmRSSKB      uint64   `json:"vm_rss_kb,omitempty"`
	OpenFDs      int      `json:"open_fds,omitempty"`
	Cmdline      []string `json:"cmdline,omitempty"`
	CgroupPath   string   `json:"cgroup_path,omitempty"`
	SessionID    int32    `json:"session_id,omitempty"`
	TTY          string   `json:"tty,omitempty"`
}
