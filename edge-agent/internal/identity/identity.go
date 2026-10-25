// Package identity provides unique process identification that accounts for PID reuse.
//
// On Linux, PIDs are recycled. A PID alone does not uniquely identify a process instance.
// This package generates a process entity ID from the combination of:
//   - Host boot ID (changes on reboot, so PIDs across boots are distinguished)
//   - PID
//   - Process start time in nanoseconds (from /proc/[pid]/stat or kernel event)
//
// The entity ID is a deterministic SHA-256 hash (truncated to 32 hex chars) that
// uniquely identifies a specific process instance across time and reboots.
package identity

import (
	"crypto/sha256"
	"fmt"
)

// GenerateProcessEntityID produces a deterministic, unique process identifier
// from boot_id, pid, and process start time (nanoseconds).
//
// The same inputs always produce the same entity ID, allowing correlation
// between event-driven telemetry and /proc enrichment data.
func GenerateProcessEntityID(bootID string, pid int32, startTimeNS uint64) string {
	input := fmt.Sprintf("%s:%d:%d", bootID, pid, startTimeNS)
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%x", hash[:16]) // 32 hex chars = 128 bits
}

// GenerateParentEntityID is a convenience wrapper that generates an entity ID
// for a parent process. It uses the same algorithm as GenerateProcessEntityID.
func GenerateParentEntityID(bootID string, ppid int32, parentStartTimeNS uint64) string {
	return GenerateProcessEntityID(bootID, ppid, parentStartTimeNS)
}
