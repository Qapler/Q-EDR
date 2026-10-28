//go:build linux && amd64

// Package filesystem implements filesystem telemetry collection using eBPF syscall tracepoints.
//
// The probes dispatch on x86_64 syscall numbers and registers, so this collector
// is built for linux/amd64 only; other targets get the stub in collector_other.go.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type fs_event fsProbe ../../../bpf/filesystem.bpf.c -- -I../../../bpf
package filesystem

import (
	"bufio"
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

const (
	eventFSOpen   = 30
	eventFSWrite  = 31
	eventFSRename = 32
	eventFSUnlink = 33
	eventFSMkdir  = 34
	eventFSChmod  = 35
	eventFSChown  = 36

	maxCommLen = 16
	maxPathLen = 256

	// Linux flags
	oCreat      = 0100
	atRemovedir = 0x200
)

type eventHeader struct {
	EventType         uint32
	PID               uint32
	TID               uint32
	PPID              uint32
	UID               uint32
	GID               uint32
	TimestampNS       uint64
	CgroupID          uint64
	Comm              [maxCommLen]byte
	StartTimeNS       uint64 // group_leader->start_boottime
	ParentStartTimeNS uint64 // real_parent->start_boottime
}

type fsEventRaw struct {
	Hdr     eventHeader
	Path    [maxPathLen]byte
	Path2   [maxPathLen]byte
	DirFD   int32
	DirFD2  int32
	Flags   int32
	Mode    uint32
	FD      int32
	RetCode int32
	Count   uint64
	Written int64
	OwnerID int32
	GroupID int32
}

// Collector implements the filesystem telemetry collector.
type Collector struct {
	cfg        *config.Config
	hostInfo   envelope.HostInfo
	counters   *metrics.Counters
	links      []link.Link
	reader     *ringbuf.Reader
	bootTimeNS uint64
}

// New creates a new filesystem collector.
func New(cfg *config.Config, counters *metrics.Counters) *Collector {
	return &Collector{
		cfg:      cfg,
		hostInfo: host.Collect(),
		counters: counters,
	}
}

func (c *Collector) Name() string { return "filesystem" }

func (c *Collector) Start(ctx context.Context, events chan<- *envelope.Event) error {
	c.bootTimeNS = host.BootTimeOffsetNS()

	spec, err := loadFsProbe()
	if err != nil {
		return fmt.Errorf("load filesystem eBPF spec: %w", err)
	}

	var objs fsProbeObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("load filesystem eBPF objects: %w", err)
	}

	// Raw syscall tracepoints; the BPF side dispatches on the syscall number.
	attachRawTracepoint := func(name string, prog *ebpf.Program) {
		tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: prog})
		if err != nil {
			log.Printf("[filesystem] warning: could not attach raw_tracepoint/%s: %v", name, err)
		} else {
			c.links = append(c.links, tp)
		}
	}

	attachRawTracepoint("sys_enter", objs.RawTracepointSysEnter)
	attachRawTracepoint("sys_exit", objs.RawTracepointSysExit)

	c.reader, err = ringbuf.NewReader(objs.FsEvents)
	if err != nil {
		c.Stop()
		return fmt.Errorf("open filesystem ring buffer: %w", err)
	}

	log.Printf("[filesystem] eBPF probes attached, reading events...")

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
			c.counters.RecordDrop("filesystem")
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

func (c *Collector) parseEvent(raw []byte) *envelope.Event {
	if len(raw) < int(unsafe.Sizeof(eventHeader{})) {
		return nil
	}

	var rawEvt fsEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rawEvt); err != nil {
		return nil
	}

	comm := cString(rawEvt.Hdr.Comm[:])
	startNS := identity.NormalizeStartTimeNS(rawEvt.Hdr.StartTimeNS)
	entityID := identity.GenerateProcessEntityID(c.hostInfo.BootID, int32(rawEvt.Hdr.PID), startNS)
	parentEntityID := ""
	if rawEvt.Hdr.PPID > 0 {
		parentEntityID = identity.GenerateParentEntityID(c.hostInfo.BootID, int32(rawEvt.Hdr.PPID),
			identity.NormalizeStartTimeNS(rawEvt.Hdr.ParentStartTimeNS))
	}

	actor := &envelope.ActorInfo{
		PID:             int32(rawEvt.Hdr.PID),
		TID:             int32(rawEvt.Hdr.TID),
		PPID:            int32(rawEvt.Hdr.PPID),
		ParentEntityID:  parentEntityID,
		Comm:            comm,
		UID:             rawEvt.Hdr.UID,
		GID:             rawEvt.Hdr.GID,
		ProcessStartNS:  startNS,
		ProcessEntityID: entityID,
	}

	path1 := cString(rawEvt.Path[:])
	path2 := cString(rawEvt.Path2[:])

	var (
		eventType string
		payload   any
	)

	switch rawEvt.Hdr.EventType {
	case eventFSOpen:
		if rawEvt.Flags&oCreat != 0 {
			eventType = "filesystem.create"
		} else {
			eventType = "filesystem.open"
		}
		payload = OpenData{
			Path:      path1,
			Flags:     rawEvt.Flags,
			FlagsDesc: formatOpenFlags(rawEvt.Flags),
			Mode:      rawEvt.Mode,
			FD:        rawEvt.FD,
			RetCode:   rawEvt.RetCode,
			DirFD:     rawEvt.DirFD,
		}

	case eventFSWrite:
		eventType = "filesystem.write"
		payload = WriteData{
			FD:      rawEvt.FD,
			Count:   rawEvt.Count,
			Written: rawEvt.Written,
			RetCode: rawEvt.RetCode,
		}

	case eventFSRename:
		eventType = "filesystem.rename"
		payload = RenameData{
			OldPath:  path1,
			NewPath:  path2,
			OldDirFD: rawEvt.DirFD,
			NewDirFD: rawEvt.DirFD2,
			Flags:    rawEvt.Flags,
			RetCode:  rawEvt.RetCode,
		}

	case eventFSUnlink:
		eventType = "filesystem.unlink"
		payload = UnlinkData{
			Path:    path1,
			DirFD:   rawEvt.DirFD,
			Flags:   rawEvt.Flags,
			IsDir:   (rawEvt.Flags & atRemovedir) != 0,
			RetCode: rawEvt.RetCode,
		}

	case eventFSMkdir:
		eventType = "filesystem.mkdir"
		payload = MkdirData{
			Path:    path1,
			DirFD:   rawEvt.DirFD,
			Mode:    rawEvt.Mode,
			RetCode: rawEvt.RetCode,
		}

	case eventFSChmod:
		eventType = "filesystem.chmod"
		payload = ChmodData{
			Path:    path1,
			DirFD:   rawEvt.DirFD,
			Mode:    rawEvt.Mode,
			RetCode: rawEvt.RetCode,
		}

	case eventFSChown:
		eventType = "filesystem.chown"
		payload = ChownData{
			Path:    path1,
			DirFD:   rawEvt.DirFD,
			OwnerID: rawEvt.OwnerID,
			GroupID: rawEvt.GroupID,
			RetCode: rawEvt.RetCode,
		}

	default:
		return nil
	}

	source := envelope.NewSource("ebpf", eventType)
	evt := envelope.NewEvent(eventType, envelope.CollectionModeEvent, c.hostInfo, source, payload)
	evt.SetEventTime(c.ktimeToWallTime(rawEvt.Hdr.TimestampNS))
	evt.SetActor(actor)
	evt.SetQuality(&envelope.QualityInfo{TimestampSource: "kernel_boot_ns"})

	return evt
}

// Snapshot enumerates mounted filesystems from /proc/mounts.
func (c *Collector) Snapshot(ctx context.Context, events chan<- *envelope.Event) error {
	log.Printf("[filesystem] starting mount snapshot...")
	file, err := os.Open("/proc/mounts")
	if err != nil {
		return fmt.Errorf("open /proc/mounts: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}

		source := envelope.NewSource("proc", "/proc/mounts")
		evt := envelope.NewEvent(
			"filesystem.snapshot",
			envelope.CollectionModeSnapshot,
			c.hostInfo,
			source,
			MountSnapshotData{
				Device:     fields[0],
				MountPoint: fields[1],
				FSType:     fields[2],
				Options:    fields[3],
			},
		)
		evt.SetActor(&envelope.ActorInfo{ProcessEntityID: "system", Comm: "kernel"})
		select {
		case events <- evt:
		case <-ctx.Done():
			return nil
		}
	}
	log.Printf("[filesystem] mount snapshot completed")
	return nil
}

func (c *Collector) ktimeToWallTime(ktimeNS uint64) time.Time {
	wallNS := c.bootTimeNS + ktimeNS
	return time.Unix(0, int64(wallNS)).UTC()
}

func cString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

func formatOpenFlags(flg int32) string {
	var parts []string
	switch flg & 3 {
	case 0:
		parts = append(parts, "O_RDONLY")
	case 1:
		parts = append(parts, "O_WRONLY")
	case 2:
		parts = append(parts, "O_RDWR")
	}
	if flg&0100 != 0 {
		parts = append(parts, "O_CREAT")
	}
	if flg&0200 != 0 {
		parts = append(parts, "O_EXCL")
	}
	if flg&01000 != 0 {
		parts = append(parts, "O_TRUNC")
	}
	if flg&02000 != 0 {
		parts = append(parts, "O_APPEND")
	}
	return strings.Join(parts, "|")
}
