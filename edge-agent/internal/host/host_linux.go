//go:build linux

package host

import (
	"crypto/sha256"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
)

// BootTimeOffsetNS returns the wall-clock time of boot in nanoseconds since the
// Unix epoch, such that wall = offset + bpf_ktime_get_boot_ns(). It is derived
// from CLOCK_REALTIME - CLOCK_BOOTTIME, which (unlike btime in /proc/stat) has
// sub-second precision.
func BootTimeOffsetNS() uint64 {
	var rt, bt unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_REALTIME, &rt)
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &bt)
	return uint64(rt.Nano() - bt.Nano())
}

func fillPlatformInfo(info *envelope.HostInfo) {
	// Boot ID from /proc/sys/kernel/random/boot_id.
	info.BootID = readFileString("/proc/sys/kernel/random/boot_id")

	// Kernel release from uname.
	var utsname syscall.Utsname
	if err := syscall.Uname(&utsname); err == nil {
		info.KernelRelease = utsToString(utsname.Release)
	}

	// Host ID: deterministic hash of machine-id + boot_id for correlation.
	machineID := readFileString("/etc/machine-id")
	if machineID == "" {
		machineID = readFileString("/var/lib/dbus/machine-id")
	}
	if machineID != "" {
		hash := sha256.Sum256([]byte(machineID))
		info.HostID = fmt.Sprintf("%x", hash[:16])
	} else {
		info.HostID = "unknown"
	}
}

// utsToString converts a [65]int8 (from syscall.Utsname) to a Go string.
func utsToString(arr [65]int8) string {
	var buf []byte
	for _, b := range arr {
		if b == 0 {
			break
		}
		buf = append(buf, byte(b))
	}
	return string(buf)
}
