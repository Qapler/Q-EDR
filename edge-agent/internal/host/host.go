// Package host collects host-level metadata for inclusion in telemetry records.
//
// Host information is collected once at startup and cached for the lifetime
// of the collector process. Fields that are unavailable on the current platform
// are left empty with a documented reason.
package host

import (
	"os"
	"runtime"
	"strings"

	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
)

// Collect gathers host metadata. Platform-specific details are filled in by
// the host_linux.go or host_other.go implementations.
func Collect() envelope.HostInfo {
	hostname, _ := os.Hostname()
	info := envelope.HostInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Architecture: runtime.GOARCH,
	}
	fillPlatformInfo(&info)
	return info
}

// readFileString reads a file and returns its trimmed contents.
func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
