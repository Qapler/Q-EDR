// Package envelope defines the common event envelope for all Q-EDR telemetry records.
//
// Every telemetry record, regardless of category (process, network, IPC, filesystem),
// shares this envelope structure. The envelope provides self-describing metadata
// including schema version, timestamps, host identity, collection source, and actor
// process information. Category-specific data is carried in the Data field.
package envelope

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

const (
	// SchemaVersion is the current version of the event envelope schema.
	SchemaVersion = "1.0.0"

	// CollectorName identifies this collector in output records.
	CollectorName = "q-edr-linux-collector"

	// CollectorVersion is the current version of the collector.
	CollectorVersion = "0.1.0"

	// Collection modes.
	CollectionModeEvent    = "event"    // Observed as it occurred (eBPF, tracepoint).
	CollectionModeSnapshot = "snapshot" // State at a point in time (/proc, /sys).
)

// Event is the common envelope for all Q-EDR telemetry records.
// Each record is a self-describing JSON object that identifies its type,
// origin, timing, and category-specific payload.
type Event struct {
	// SchemaVersion identifies the envelope schema version for forward compatibility.
	SchemaVersion string `json:"schema_version"`

	// EventID is a globally unique identifier for this specific record.
	EventID string `json:"event_id"`

	// EventType identifies the telemetry event category and operation,
	// e.g. "process.exec", "network.connect", "filesystem.open".
	EventType string `json:"event_type"`

	// EventTime is when the event actually occurred (kernel timestamp converted to UTC).
	// Nil if only the collector's observation time is available.
	EventTime *time.Time `json:"event_time,omitempty"`

	// ObservedTime is when the collector received or processed the event (always set).
	ObservedTime time.Time `json:"observed_time"`

	// CollectionMode distinguishes event-driven ("event") from point-in-time ("snapshot") records.
	CollectionMode string `json:"collection_mode"`

	// Host identifies the machine that produced this record.
	Host HostInfo `json:"host"`

	// Source describes how this record was collected.
	Source SourceInfo `json:"source"`

	// Actor is the process associated with this event (nil for host-level events).
	Actor *ActorInfo `json:"actor,omitempty"`

	// Data contains category-specific telemetry fields.
	// The concrete type depends on EventType.
	Data interface{} `json:"data"`

	// Quality reports collection quality metrics relevant to this record.
	Quality *QualityInfo `json:"quality,omitempty"`
}

// HostInfo identifies the host machine.
type HostInfo struct {
	HostID        string `json:"host_id"`
	Hostname      string `json:"hostname"`
	BootID        string `json:"boot_id"`
	OS            string `json:"os"`
	Architecture  string `json:"architecture"`
	KernelRelease string `json:"kernel_release"`
}

// SourceInfo describes the collection mechanism.
type SourceInfo struct {
	Collector        string `json:"collector"`
	CollectorVersion string `json:"collector_version"`
	Mechanism        string `json:"mechanism"` // "ebpf", "tracepoint", "proc", "netlink", "sysfs"
	Probe            string `json:"probe,omitempty"`
}

// ActorInfo identifies the process associated with an event.
type ActorInfo struct {
	PID             int32          `json:"pid"`
	TID             int32          `json:"tid,omitempty"`
	PPID            int32          `json:"ppid,omitempty"`
	UID             uint32         `json:"uid"`
	GID             uint32         `json:"gid"`
	EUID            *uint32        `json:"euid,omitempty"`
	EGID            *uint32        `json:"egid,omitempty"`
	Comm            string         `json:"comm"`
	Exe             string         `json:"exe,omitempty"`
	Cmdline         []string       `json:"cmdline,omitempty"`
	ProcessStartNS  uint64         `json:"process_start_time_ns,omitempty"`
	ProcessEntityID string         `json:"process_entity_id"`
	ParentComm      string         `json:"parent_comm,omitempty"`
	ParentExe       string         `json:"parent_exe,omitempty"`
	ParentEntityID  string         `json:"parent_entity_id,omitempty"`
	NamespaceIDs    *NamespaceInfo `json:"namespace_ids,omitempty"`
	CgroupPath      string         `json:"cgroup_path,omitempty"`
}

// NamespaceInfo contains Linux namespace identifiers.
type NamespaceInfo struct {
	PID    uint32 `json:"pid_ns,omitempty"`
	MNT    uint32 `json:"mnt_ns,omitempty"`
	NET    uint32 `json:"net_ns,omitempty"`
	User   uint32 `json:"user_ns,omitempty"`
	IPC    uint32 `json:"ipc_ns,omitempty"`
	UTS    uint32 `json:"uts_ns,omitempty"`
	Cgroup uint32 `json:"cgroup_ns,omitempty"`
}

// QualityInfo reports data quality and collection health for this record.
type QualityInfo struct {
	EventsDropped    uint64 `json:"events_dropped,omitempty"`
	Incomplete       bool   `json:"incomplete,omitempty"`
	IncompleteReason string `json:"incomplete_reason,omitempty"`
	// TimestampSource documents the origin of the event timestamp:
	// "kernel_monotonic" - converted from kernel monotonic clock
	// "collector_wall" - collector's wall clock (fallback)
	// "proc_stat" - from /proc/[pid]/stat start time
	TimestampSource string `json:"timestamp_source,omitempty"`
}

// NewEvent creates a new Event with a generated ID and observed timestamp.
func NewEvent(eventType, collectionMode string, host HostInfo, source SourceInfo, data interface{}) *Event {
	now := time.Now().UTC()
	return &Event{
		SchemaVersion:  SchemaVersion,
		EventID:        uuid.New().String(),
		EventType:      eventType,
		ObservedTime:   now,
		CollectionMode: collectionMode,
		Host:           host,
		Source:         source,
		Data:           data,
	}
}

// SetEventTime sets the actual event occurrence time.
func (e *Event) SetEventTime(t time.Time) {
	utc := t.UTC()
	e.EventTime = &utc
}

// SetActor sets the actor process information for this event.
func (e *Event) SetActor(actor *ActorInfo) {
	e.Actor = actor
}

// SetQuality sets quality/coverage metadata for this event.
func (e *Event) SetQuality(quality *QualityInfo) {
	e.Quality = quality
}

// Marshal serializes the event to JSON bytes.
func (e *Event) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// NewSource creates a SourceInfo for the Q-EDR collector.
func NewSource(mechanism, probe string) SourceInfo {
	return SourceInfo{
		Collector:        CollectorName,
		CollectorVersion: CollectorVersion,
		Mechanism:        mechanism,
		Probe:            probe,
	}
}
