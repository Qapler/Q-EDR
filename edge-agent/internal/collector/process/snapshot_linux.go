//go:build linux

package process

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Qapler/Q-EDR/edge-agent/internal/config"
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
	"github.com/Qapler/Q-EDR/edge-agent/internal/host"
	"github.com/Qapler/Q-EDR/edge-agent/internal/identity"
)

// Snapshot performs a point-in-time scan of /proc to enumerate running processes.
func (c *Collector) Snapshot(ctx context.Context, events chan<- *envelope.Event) error {
	hostInfo := host.Collect()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return fmt.Errorf("read /proc: %w", err)
	}

	count := 0
	for _, entry := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		// Only process numeric directory entries (PIDs).
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		evt := scanProcess(pid, hostInfo, c.cfg)
		if evt == nil {
			continue
		}

		select {
		case events <- evt:
			count++
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	log.Printf("[process] snapshot: enumerated %d processes", count)
	return nil
}

// scanProcess reads /proc/[pid]/* to build a process.snapshot event.
func scanProcess(pid int, hostInfo envelope.HostInfo, cfg *config.Config) *envelope.Event {
	procDir := fmt.Sprintf("/proc/%d", pid)

	// Read /proc/[pid]/stat for basic info.
	statData, err := os.ReadFile(filepath.Join(procDir, "stat"))
	if err != nil {
		return nil // Process may have exited.
	}

	stat := parseProcStat(string(statData))
	if stat == nil {
		return nil
	}

	// Read exe symlink.
	exe, _ := os.Readlink(filepath.Join(procDir, "exe"))

	// Read cmdline.
	var cmdline []string
	if !cfg.RedactCmdline {
		cmdlineData, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err == nil && len(cmdlineData) > 0 {
			parts := strings.Split(strings.TrimRight(string(cmdlineData), "\x00"), "\x00")
			cmdline = parts
		}
	}

	// Read status for supplementary info.
	status := readProcStatus(procDir)

	// Build snapshot data.
	data := SnapshotData{
		State:     stat.state,
		StateDesc: stateDescription(stat.state),
		Threads:   stat.numThreads,
		VmSizeKB:  status.vmSizeKB,
		VmRSSKB:   status.vmRSSKB,
		Cmdline:   cmdline,
		SessionID: int32(stat.session),
	}

	// Read open FDs count.
	fdEntries, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err == nil {
		data.OpenFDs = len(fdEntries)
	}

	// Read cgroup.
	cgroupData, err := os.ReadFile(filepath.Join(procDir, "cgroup"))
	if err == nil {
		// Use the first line's cgroup path.
		lines := strings.Split(strings.TrimSpace(string(cgroupData)), "\n")
		if len(lines) > 0 {
			parts := strings.SplitN(lines[0], ":", 3)
			if len(parts) == 3 {
				data.CgroupPath = parts[2]
			}
		}
	}

	source := envelope.NewSource("proc", "/proc/[pid]/*")
	evt := envelope.NewEvent("process.snapshot", envelope.CollectionModeSnapshot, hostInfo, source, data)

	entityID := identity.GenerateProcessEntityID(hostInfo.BootID, int32(pid), stat.startTimeTicks)

	uid := status.uid
	gid := status.gid
	actor := &envelope.ActorInfo{
		PID:             int32(pid),
		PPID:            int32(stat.ppid),
		UID:             uid,
		GID:             gid,
		Comm:            stat.comm,
		Exe:             exe,
		Cmdline:         cmdline,
		ProcessStartNS:  stat.startTimeTicks,
		ProcessEntityID: entityID,
		CgroupPath:      data.CgroupPath,
	}
	evt.SetActor(actor)
	evt.SetQuality(&envelope.QualityInfo{TimestampSource: "proc_stat"})

	return evt
}

// procStat holds parsed /proc/[pid]/stat fields.
type procStat struct {
	pid             int
	comm            string
	state           string
	ppid            int
	session         int
	numThreads      int
	startTimeTicks  uint64
}

// parseProcStat parses /proc/[pid]/stat content.
func parseProcStat(data string) *procStat {
	// Format: pid (comm) state ppid pgrp session tty_nr ...
	// The comm field can contain spaces and parentheses, so we find the last ')'.
	lastParen := strings.LastIndex(data, ")")
	if lastParen < 0 {
		return nil
	}
	firstParen := strings.Index(data, "(")
	if firstParen < 0 {
		return nil
	}

	stat := &procStat{}

	// PID is before '('
	fmt.Sscanf(data[:firstParen], "%d", &stat.pid)

	// Comm is between '(' and ')'
	stat.comm = data[firstParen+1 : lastParen]

	// Fields after ')'
	rest := strings.TrimSpace(data[lastParen+1:])
	fields := strings.Fields(rest)
	if len(fields) < 20 {
		return nil
	}

	stat.state = fields[0]
	stat.ppid, _ = strconv.Atoi(fields[1])
	stat.session, _ = strconv.Atoi(fields[3])
	stat.numThreads, _ = strconv.Atoi(fields[17])
	starttime, _ := strconv.ParseUint(fields[19], 10, 64)
	stat.startTimeTicks = starttime

	return stat
}

// procStatus holds parsed /proc/[pid]/status fields.
type procStatus struct {
	uid      uint32
	gid      uint32
	vmSizeKB uint64
	vmRSSKB  uint64
}

func readProcStatus(procDir string) procStatus {
	var status procStatus
	f, err := os.Open(filepath.Join(procDir, "status"))
	if err != nil {
		return status
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		switch {
		case strings.HasPrefix(line, "Uid:"):
			fmt.Sscanf(line, "Uid:\t%d", &status.uid)
		case strings.HasPrefix(line, "Gid:"):
			fmt.Sscanf(line, "Gid:\t%d", &status.gid)
		case strings.HasPrefix(line, "VmSize:"):
			fmt.Sscanf(line, "VmSize:\t%d", &status.vmSizeKB)
		case strings.HasPrefix(line, "VmRSS:"):
			fmt.Sscanf(line, "VmRSS:\t%d", &status.vmRSSKB)
		}
	}
	return status
}

func stateDescription(state string) string {
	switch state {
	case "R":
		return "running"
	case "S":
		return "sleeping"
	case "D":
		return "disk_sleep"
	case "Z":
		return "zombie"
	case "T":
		return "stopped"
	case "t":
		return "tracing_stop"
	case "X", "x":
		return "dead"
	case "K":
		return "wakekill"
	case "W":
		return "waking"
	case "P":
		return "parked"
	case "I":
		return "idle"
	default:
		return "unknown"
	}
}
