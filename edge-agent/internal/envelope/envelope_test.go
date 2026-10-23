package envelope

import (
	"encoding/json"
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	host := HostInfo{
		HostID:        "test-host-id",
		Hostname:      "test-host",
		BootID:        "test-boot-id",
		OS:            "linux",
		Architecture:  "amd64",
		KernelRelease: "5.15.0-generic",
	}
	source := NewSource("ebpf", "sched_process_exec")

	data := map[string]string{"test": "data"}
	evt := NewEvent("process.exec", CollectionModeEvent, host, source, data)

	if evt.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", evt.SchemaVersion, SchemaVersion)
	}
	if evt.EventID == "" {
		t.Error("event_id should not be empty")
	}
	if evt.EventType != "process.exec" {
		t.Errorf("event_type = %q, want %q", evt.EventType, "process.exec")
	}
	if evt.CollectionMode != CollectionModeEvent {
		t.Errorf("collection_mode = %q, want %q", evt.CollectionMode, CollectionModeEvent)
	}
	if evt.EventTime != nil {
		t.Error("event_time should be nil before SetEventTime")
	}
	if evt.ObservedTime.IsZero() {
		t.Error("observed_time should not be zero")
	}
	if evt.Actor != nil {
		t.Error("actor should be nil by default")
	}
	if evt.Quality != nil {
		t.Error("quality should be nil by default")
	}
}

func TestSetEventTime(t *testing.T) {
	host := HostInfo{}
	source := NewSource("ebpf", "test")
	evt := NewEvent("test.event", CollectionModeEvent, host, source, nil)

	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.FixedZone("IST", 5*3600+30*60))
	evt.SetEventTime(now)

	if evt.EventTime == nil {
		t.Fatal("event_time should be set")
	}
	// Should be converted to UTC.
	if evt.EventTime.Location() != time.UTC {
		t.Errorf("event_time should be UTC, got %v", evt.EventTime.Location())
	}
}

func TestSetActor(t *testing.T) {
	host := HostInfo{}
	source := NewSource("ebpf", "test")
	evt := NewEvent("test.event", CollectionModeEvent, host, source, nil)

	actor := &ActorInfo{
		PID:             1234,
		UID:             1000,
		GID:             1000,
		Comm:            "test-process",
		ProcessEntityID: "entity-123",
	}
	evt.SetActor(actor)

	if evt.Actor == nil {
		t.Fatal("actor should be set")
	}
	if evt.Actor.PID != 1234 {
		t.Errorf("actor.pid = %d, want 1234", evt.Actor.PID)
	}
}

func TestMarshal(t *testing.T) {
	host := HostInfo{
		HostID:        "host-1",
		Hostname:      "linux-lab-01",
		BootID:        "boot-abc",
		OS:            "linux",
		Architecture:  "amd64",
		KernelRelease: "5.15.0",
	}
	source := NewSource("ebpf", "sched_process_exec")
	data := map[string]interface{}{
		"filename": "/usr/bin/ls",
	}

	evt := NewEvent("process.exec", CollectionModeEvent, host, source, data)
	eventTime := time.Date(2026, 10, 23, 10, 0, 0, 0, time.UTC)
	evt.SetEventTime(eventTime)
	evt.SetActor(&ActorInfo{
		PID:             42,
		UID:             0,
		GID:             0,
		Comm:            "ls",
		Exe:             "/usr/bin/ls",
		ProcessEntityID: "entity-42",
	})

	b, err := evt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("Marshal() produced invalid JSON: %v", err)
	}

	// Check required fields exist.
	requiredFields := []string{
		"schema_version", "event_id", "event_type",
		"observed_time", "collection_mode", "host", "source", "data",
	}
	for _, field := range requiredFields {
		if _, ok := parsed[field]; !ok {
			t.Errorf("missing required field %q in marshaled JSON", field)
		}
	}

	// Check event_time is present (we set it).
	if _, ok := parsed["event_time"]; !ok {
		t.Error("event_time should be present after SetEventTime")
	}

	// Check actor is present (we set it).
	if _, ok := parsed["actor"]; !ok {
		t.Error("actor should be present after SetActor")
	}
}

func TestMarshalOmitsNilFields(t *testing.T) {
	host := HostInfo{HostID: "h1", Hostname: "h", BootID: "b", OS: "linux", Architecture: "amd64", KernelRelease: "5.15"}
	source := NewSource("proc", "")
	evt := NewEvent("process.snapshot", CollectionModeSnapshot, host, source, map[string]string{})

	b, err := evt.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	// event_time, actor, quality should be omitted when nil.
	for _, field := range []string{"event_time", "actor", "quality"} {
		if _, ok := parsed[field]; ok {
			t.Errorf("field %q should be omitted when nil", field)
		}
	}
}

func TestNewSource(t *testing.T) {
	src := NewSource("ebpf", "sched_process_exec")
	if src.Collector != CollectorName {
		t.Errorf("collector = %q, want %q", src.Collector, CollectorName)
	}
	if src.CollectorVersion != CollectorVersion {
		t.Errorf("collector_version = %q, want %q", src.CollectorVersion, CollectorVersion)
	}
	if src.Mechanism != "ebpf" {
		t.Errorf("mechanism = %q, want %q", src.Mechanism, "ebpf")
	}
	if src.Probe != "sched_process_exec" {
		t.Errorf("probe = %q, want %q", src.Probe, "sched_process_exec")
	}
}

func TestEventIDUniqueness(t *testing.T) {
	host := HostInfo{}
	source := NewSource("test", "")
	seen := make(map[string]bool)

	for i := 0; i < 1000; i++ {
		evt := NewEvent("test", CollectionModeEvent, host, source, nil)
		if seen[evt.EventID] {
			t.Fatalf("duplicate event_id after %d events: %s", i, evt.EventID)
		}
		seen[evt.EventID] = true
	}
}
