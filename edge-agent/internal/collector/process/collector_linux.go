//go:build linux

// Package process implements process telemetry collection using eBPF tracepoints
// and /proc enrichment.
//
// Event-driven collection (eBPF):
//   - sched/sched_process_exec → process.exec
//   - sched/sched_process_fork → process.fork
//   - sched/sched_process_exit → process.exit
//
// Snapshot collection (/proc):
//   - /proc/[pid]/stat, status, cmdline, exe → process.snapshot
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64,arm64 -type process_exec_event -type process_fork_event -type process_exit_event processProbe ../../../bpf/process.bpf.c -- -I../../../bpf
package process

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/Qapler/Q-EDR/edge-agent/internal/config"
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
	"github.com/Qapler/Q-EDR/edge-agent/internal/host"
	"github.com/Qapler/Q-EDR/edge-agent/internal/identity"
	"github.com/Qapler/Q-EDR/edge-agent/internal/metrics"
)

// eBPF event type constants - must match common.h
const (
	eventProcessExec = 1
	eventProcessFork = 2
	eventProcessExit = 3

	maxCommLen     = 16
	maxFilenameLen = 256
	maxArgvLen     = 256
)

// Raw C struct equivalents for binary decoding from ring buffer.
// These must match the structs defined in bpf/common.h exactly.

type eventHeader struct {
	EventType   uint32
	PID         uint32
	TID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	TimestampNS uint64
	CgroupID    uint64
	Comm        [maxCommLen]byte
	StartTimeNS       uint64 // group_leader->start_boottime
	ParentStartTimeNS uint64 // real_parent->start_boottime
}

type processExecEventRaw struct {
	Hdr      eventHeader
	Filename [maxFilenameLen]byte
	Argv     [maxArgvLen]byte
	ArgvLen  uint32
	RetCode  int32
}

type processForkEventRaw struct {
	Hdr        eventHeader
	ChildPID   uint32
	ChildTID   uint32
	CloneFlags uint64
	ChildComm  [maxCommLen]byte
	ChildStartTimeNS uint64
}

type processExitEventRaw struct {
	Hdr         eventHeader
	ExitCode    int32
	Signal      int32
	StartTimeNS uint64
}

// Collector implements the process telemetry collector.
type Collector struct {
	cfg       *config.Config
	hostInfo  envelope.HostInfo
	counters  *metrics.Counters
	links     []link.Link
	reader    *ringbuf.Reader
	bootTimeNS uint64 // Boot time offset for timestamp conversion.
}

// New creates a new process telemetry collector.
func New(cfg *config.Config, counters *metrics.Counters) *Collector {
	return &Collector{
		cfg:      cfg,
		hostInfo: host.Collect(),
		counters: counters,
	}
}

func (c *Collector) Name() string { return "process" }

func (c *Collector) Start(ctx context.Context, events chan<- *envelope.Event) error {
	// Calculate boot time offset for timestamp conversion.
	c.bootTimeNS = host.BootTimeOffsetNS()

	// Load the eBPF objects.
	spec, err := loadProcessProbe()
	if err != nil {
		return fmt.Errorf("load process eBPF spec: %w", err)
	}

	var objs processProbeObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("load process eBPF objects: %w", err)
	}

	// Attach tracepoints.
	tpExec, err := link.Tracepoint("sched", "sched_process_exec", objs.TracepointSchedProcessExec, nil)
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach sched_process_exec: %w", err)
	}
	c.links = append(c.links, tpExec)

	tpFork, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: objs.RawTracepointSchedProcessFork,
	})
	if err != nil {
		log.Printf("[process] warning: could not attach sched_process_fork: %v", err)
	} else {
		c.links = append(c.links, tpFork)
	}

	tpExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TracepointSchedProcessExit, nil)
	if err != nil {
		log.Printf("[process] warning: could not attach sched_process_exit: %v", err)
	} else {
		c.links = append(c.links, tpExit)
	}

	// Open ring buffer reader.
	c.reader, err = ringbuf.NewReader(objs.ProcessEvents)
	if err != nil {
		c.Stop()
		return fmt.Errorf("open process ring buffer: %w", err)
	}

	log.Printf("[process] eBPF probes attached, reading events...")

	// Read events until context is cancelled.
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			c.counters.RecordDrop("process")
			continue
		}

		evt := c.parseEvent(record.RawSample)
		if evt != nil {
			select {
			case events <- evt:
			case <-ctx.Done():
				return nil
			}
		}
	}
}

func (c *Collector) Stop() error {
	if c.reader != nil {
		c.reader.Close()
	}
	for _, l := range c.links {
		l.Close()
	}
	return nil
}

// parseEvent converts raw ring buffer bytes into an envelope.Event.
func (c *Collector) parseEvent(raw []byte) *envelope.Event {
	if len(raw) < int(unsafe.Sizeof(eventHeader{})) {
		return nil
	}

	// Peek at event type from the first 4 bytes.
	eventType := binary.LittleEndian.Uint32(raw[:4])

	switch eventType {
	case eventProcessExec:
		return c.parseExecEvent(raw)
	case eventProcessFork:
		return c.parseForkEvent(raw)
	case eventProcessExit:
		return c.parseExitEvent(raw)
	default:
		return nil
	}
}

func (c *Collector) parseExecEvent(raw []byte) *envelope.Event {
	var re processExecEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		log.Printf("[process] exec decode error: %v", err)
		return nil
	}

	data := ExecData{
		Filename: cstring(re.Filename[:]),
		RetCode:  re.RetCode,
	}

	if !c.cfg.RedactCmdline && re.ArgvLen > 0 {
		data.Argv = parseArgv(re.Argv[:re.ArgvLen])
	}

	source := envelope.NewSource("ebpf", "sched_process_exec")
	evt := envelope.NewEvent("process.exec", envelope.CollectionModeEvent, c.hostInfo, source, data)

	eventTime := c.kernelTSToWallClock(re.Hdr.TimestampNS)
	evt.SetEventTime(eventTime)

	actor := c.headerToActor(&re.Hdr)
	evt.SetActor(actor)
	evt.SetQuality(&envelope.QualityInfo{TimestampSource: "kernel_boot_ns"})

	return evt
}

func (c *Collector) parseForkEvent(raw []byte) *envelope.Event {
	var re processForkEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil
	}

	childEntityID := identity.GenerateProcessEntityID(c.hostInfo.BootID, int32(re.ChildPID),
		identity.NormalizeStartTimeNS(re.ChildStartTimeNS))
	data := ForkData{
		ChildPID:      int32(re.ChildPID),
		ChildTID:      int32(re.ChildTID),
		ChildComm:     cstring(re.ChildComm[:]),
		ChildEntityID: childEntityID,
		CloneFlags:    re.CloneFlags,
	}

	source := envelope.NewSource("ebpf", "sched_process_fork")
	evt := envelope.NewEvent("process.fork", envelope.CollectionModeEvent, c.hostInfo, source, data)
	evt.SetEventTime(c.kernelTSToWallClock(re.Hdr.TimestampNS))
	evt.SetActor(c.headerToActor(&re.Hdr))
	evt.SetQuality(&envelope.QualityInfo{TimestampSource: "kernel_boot_ns"})

	return evt
}

func (c *Collector) parseExitEvent(raw []byte) *envelope.Event {
	var re processExitEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil
	}

	data := ExitData{
		ExitCode: re.ExitCode,
		Signal:   re.Signal,
	}

	source := envelope.NewSource("ebpf", "sched_process_exit")
	evt := envelope.NewEvent("process.exit", envelope.CollectionModeEvent, c.hostInfo, source, data)
	evt.SetEventTime(c.kernelTSToWallClock(re.Hdr.TimestampNS))
	evt.SetActor(c.headerToActor(&re.Hdr))
	evt.SetQuality(&envelope.QualityInfo{TimestampSource: "kernel_boot_ns"})

	return evt
}

// headerToActor converts an eBPF event header to an ActorInfo.
func (c *Collector) headerToActor(hdr *eventHeader) *envelope.ActorInfo {
	comm := cstring(hdr.Comm[:])

	// Try to enrich from /proc.
	exe := readProcExe(int(hdr.PID))
	ppid := hdr.PPID
	if ppid == 0 {
		ppid = readProcPPID(int(hdr.PID))
	}

	var cmdline []string
	if !c.cfg.RedactCmdline {
		cmdline = readProcCmdline(int(hdr.PID))
	}

	startNS := identity.NormalizeStartTimeNS(hdr.StartTimeNS)
	entityID := identity.GenerateProcessEntityID(c.hostInfo.BootID, int32(hdr.PID), startNS)
	var parentEntityID string
	if hdr.PPID > 0 {
		parentEntityID = identity.GenerateParentEntityID(c.hostInfo.BootID, int32(hdr.PPID),
			identity.NormalizeStartTimeNS(hdr.ParentStartTimeNS))
	}

	return &envelope.ActorInfo{
		PID:             int32(hdr.PID),
		TID:             int32(hdr.TID),
		PPID:            int32(ppid),
		UID:             hdr.UID,
		GID:             hdr.GID,
		Comm:            comm,
		Exe:             exe,
		Cmdline:         cmdline,
		ProcessStartNS:  startNS,
		ProcessEntityID: entityID,
		ParentEntityID:  parentEntityID,
	}
}

// kernelTSToWallClock converts a kernel boot-ns timestamp to wall-clock UTC.
func (c *Collector) kernelTSToWallClock(bootNS uint64) time.Time {
	// Boot time is the wall-clock time when the system booted.
	// kernel timestamp = time since boot in nanoseconds.
	wallNS := c.bootTimeNS + bootNS
	return time.Unix(0, int64(wallNS)).UTC()
}

// /proc helpers.

func readProcExe(pid int) string {
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return exe
}

func readProcPPID(pid int) uint32 {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PPid:") {
			var ppid uint32
			fmt.Sscanf(line, "PPid:\t%d", &ppid)
			return ppid
		}
	}
	return 0
}

func readProcCmdline(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(data) == 0 {
		return nil
	}
	// cmdline is null-separated.
	parts := bytes.Split(bytes.TrimRight(data, "\x00"), []byte{0})
	result := make([]string, len(parts))
	for i, p := range parts {
		result[i] = string(p)
	}
	return result
}

// cstring extracts a null-terminated C string from a byte slice.
func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}

// parseArgv splits null-separated argv bytes into a string slice.
func parseArgv(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	parts := bytes.Split(bytes.TrimRight(b, "\x00"), []byte{0})
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) > 0 {
			result = append(result, string(p))
		}
	}
	return result
}
