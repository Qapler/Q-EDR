// Package metrics provides thread-safe counters for tracking collection quality.
package metrics

import (
	"encoding/json"
	"sync/atomic"
)

// Counters tracks per-category event and drop counts.
type Counters struct {
	ProcessEvents     atomic.Uint64
	ProcessDrops      atomic.Uint64
	NetworkEvents     atomic.Uint64
	NetworkDrops      atomic.Uint64
	IPCEvents         atomic.Uint64
	IPCDrops          atomic.Uint64
	FilesystemEvents  atomic.Uint64
	FilesystemDrops   atomic.Uint64
	SnapshotEvents    atomic.Uint64
	TotalWritten      atomic.Uint64
	TotalDropped      atomic.Uint64
	TotalErrors       atomic.Uint64
	KernelDrops       atomic.Uint64 // Ring/perf buffer drops reported by kernel.
}

// NewCounters creates a new Counters instance.
func NewCounters() *Counters {
	return &Counters{}
}

// RecordEvent increments the event counter for the given category.
func (c *Counters) RecordEvent(category string) {
	switch category {
	case "process":
		c.ProcessEvents.Add(1)
	case "network":
		c.NetworkEvents.Add(1)
	case "ipc":
		c.IPCEvents.Add(1)
	case "filesystem":
		c.FilesystemEvents.Add(1)
	case "snapshot":
		c.SnapshotEvents.Add(1)
	}
	c.TotalWritten.Add(1)
}

// RecordDrop increments the drop counter for the given category.
func (c *Counters) RecordDrop(category string) {
	switch category {
	case "process":
		c.ProcessDrops.Add(1)
	case "network":
		c.NetworkDrops.Add(1)
	case "ipc":
		c.IPCDrops.Add(1)
	case "filesystem":
		c.FilesystemDrops.Add(1)
	}
	c.TotalDropped.Add(1)
}

// RecordError increments the total error counter.
func (c *Counters) RecordError() {
	c.TotalErrors.Add(1)
}

// RecordKernelDrop records events dropped by the kernel ring/perf buffer.
func (c *Counters) RecordKernelDrop(count uint64) {
	c.KernelDrops.Add(count)
	c.TotalDropped.Add(count)
}

// Snapshot returns a JSON-serializable snapshot of current counter values.
type Snapshot struct {
	ProcessEvents    uint64 `json:"process_events"`
	ProcessDrops     uint64 `json:"process_drops"`
	NetworkEvents    uint64 `json:"network_events"`
	NetworkDrops     uint64 `json:"network_drops"`
	IPCEvents        uint64 `json:"ipc_events"`
	IPCDrops         uint64 `json:"ipc_drops"`
	FilesystemEvents uint64 `json:"filesystem_events"`
	FilesystemDrops  uint64 `json:"filesystem_drops"`
	SnapshotEvents   uint64 `json:"snapshot_events"`
	TotalWritten     uint64 `json:"total_written"`
	TotalDropped     uint64 `json:"total_dropped"`
	TotalErrors      uint64 `json:"total_errors"`
	KernelDrops      uint64 `json:"kernel_drops"`
}

// TakeSnapshot returns a point-in-time copy of all counters.
func (c *Counters) TakeSnapshot() Snapshot {
	return Snapshot{
		ProcessEvents:    c.ProcessEvents.Load(),
		ProcessDrops:     c.ProcessDrops.Load(),
		NetworkEvents:    c.NetworkEvents.Load(),
		NetworkDrops:     c.NetworkDrops.Load(),
		IPCEvents:        c.IPCEvents.Load(),
		IPCDrops:         c.IPCDrops.Load(),
		FilesystemEvents: c.FilesystemEvents.Load(),
		FilesystemDrops:  c.FilesystemDrops.Load(),
		SnapshotEvents:   c.SnapshotEvents.Load(),
		TotalWritten:     c.TotalWritten.Load(),
		TotalDropped:     c.TotalDropped.Load(),
		TotalErrors:      c.TotalErrors.Load(),
		KernelDrops:      c.KernelDrops.Load(),
	}
}

// MarshalJSON returns the snapshot as JSON.
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type Alias Snapshot // Prevent infinite recursion.
	return json.Marshal(Alias(s))
}

// String returns a human-readable summary.
func (s Snapshot) String() string {
	b, _ := json.MarshalIndent(s, "", "  ")
	return string(b)
}
