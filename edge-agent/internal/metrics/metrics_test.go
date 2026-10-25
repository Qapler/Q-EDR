package metrics

import (
	"strings"
	"testing"
)

func TestCounters(t *testing.T) {
	c := NewCounters()

	c.RecordEvent("process")
	c.RecordEvent("network")
	c.RecordEvent("ipc")
	c.RecordEvent("filesystem")
	c.RecordEvent("snapshot")

	c.RecordDrop("process")
	c.RecordDrop("network")
	c.RecordDrop("ipc")
	c.RecordDrop("filesystem")

	c.RecordError()
	c.RecordKernelDrop(5)

	snap := c.TakeSnapshot()

	if snap.ProcessEvents != 1 || snap.NetworkEvents != 1 || snap.IPCEvents != 1 || snap.FilesystemEvents != 1 || snap.SnapshotEvents != 1 {
		t.Errorf("unexpected event counts in snapshot: %+v", snap)
	}

	if snap.ProcessDrops != 1 || snap.NetworkDrops != 1 || snap.IPCDrops != 1 || snap.FilesystemDrops != 1 {
		t.Errorf("unexpected drop counts in snapshot: %+v", snap)
	}

	if snap.TotalWritten != 5 {
		t.Errorf("expected 5 total written, got %d", snap.TotalWritten)
	}

	// 4 category drops + 5 kernel drops = 9 total dropped
	if snap.TotalDropped != 9 {
		t.Errorf("expected 9 total dropped, got %d", snap.TotalDropped)
	}

	if snap.TotalErrors != 1 {
		t.Errorf("expected 1 total error, got %d", snap.TotalErrors)
	}

	if snap.KernelDrops != 5 {
		t.Errorf("expected 5 kernel drops, got %d", snap.KernelDrops)
	}

	str := snap.String()
	if !strings.Contains(str, "process_events") {
		t.Errorf("expected String() to contain process_events, got: %s", str)
	}
}
