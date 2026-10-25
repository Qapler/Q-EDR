//go:build !linux

package host

import (
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
)

func fillPlatformInfo(info *envelope.HostInfo) {
	info.HostID = "non-linux-host"
	info.BootID = "unavailable"
	info.KernelRelease = "unavailable"
}
