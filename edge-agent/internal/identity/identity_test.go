package identity

import (
	"testing"
)

func TestGenerateProcessEntityID(t *testing.T) {
	id := GenerateProcessEntityID("abc-boot-id", 1234, 999999999)
	if id == "" {
		t.Fatal("entity ID should not be empty")
	}
	if len(id) != 32 {
		t.Errorf("entity ID length = %d, want 32 hex chars", len(id))
	}
}

func TestDeterministic(t *testing.T) {
	id1 := GenerateProcessEntityID("boot-1", 100, 5000000)
	id2 := GenerateProcessEntityID("boot-1", 100, 5000000)
	if id1 != id2 {
		t.Errorf("same inputs should produce same ID: %q != %q", id1, id2)
	}
}

func TestDifferentBootID(t *testing.T) {
	id1 := GenerateProcessEntityID("boot-1", 100, 5000000)
	id2 := GenerateProcessEntityID("boot-2", 100, 5000000)
	if id1 == id2 {
		t.Error("different boot IDs should produce different entity IDs")
	}
}

func TestDifferentPID(t *testing.T) {
	id1 := GenerateProcessEntityID("boot-1", 100, 5000000)
	id2 := GenerateProcessEntityID("boot-1", 101, 5000000)
	if id1 == id2 {
		t.Error("different PIDs should produce different entity IDs")
	}
}

func TestDifferentStartTime(t *testing.T) {
	// Same PID but different start time = PID was reused.
	id1 := GenerateProcessEntityID("boot-1", 100, 5000000)
	id2 := GenerateProcessEntityID("boot-1", 100, 6000000)
	if id1 == id2 {
		t.Error("different start times (PID reuse) should produce different entity IDs")
	}
}

func TestParentEntityID(t *testing.T) {
	// Parent entity ID uses the same algorithm.
	id1 := GenerateProcessEntityID("boot-1", 50, 1000000)
	id2 := GenerateParentEntityID("boot-1", 50, 1000000)
	if id1 != id2 {
		t.Error("GenerateParentEntityID should produce the same result as GenerateProcessEntityID")
	}
}
