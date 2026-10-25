//go:build linux

// Package ipc implements IPC telemetry collection using eBPF syscall tracepoints.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type ipc_event ipcProbe ../../bpf/ipc.bpf.c -- -I../../bpf
package ipc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
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
	eventIPCPipe       = 20
	eventIPCSocketpair = 21
	eventIPCShmget     = 22
	eventIPCShmat      = 23
	eventIPCMsgget     = 24
	eventIPCMsgsnd     = 25
	eventIPCMsgrcv     = 26
	eventIPCSemget     = 27
	eventIPCSemop      = 28

	maxCommLen = 16
)

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
}

type ipcEventRaw struct {
	Hdr      eventHeader
	FD0      int32
	FD1      int32
	Key      int32
	IPCID    int32
	Size     uint64
	MsgType  int64
	NSems    int32
	NSops    int32
	Flags    int32
	RetCode  int32
	Family   uint16
	SockType uint16
	Protocol int32
}

// Collector implements the IPC telemetry collector.
type Collector struct {
	cfg        *config.Config
	hostInfo   envelope.HostInfo
	counters   *metrics.Counters
	links      []link.Link
	reader     *ringbuf.Reader
	bootTimeNS uint64
}

// New creates a new IPC collector.
func New(cfg *config.Config, counters *metrics.Counters) *Collector {
	return &Collector{
		cfg:      cfg,
		hostInfo: host.Collect(),
		counters: counters,
	}
}

func (c *Collector) Name() string { return "ipc" }

func (c *Collector) Start(ctx context.Context, events chan<- *envelope.Event) error {
	c.bootTimeNS = getBootTimeOffsetNS()

	spec, err := loadIpcProbe()
	if err != nil {
		return fmt.Errorf("load ipc eBPF spec: %w", err)
	}

	var objs ipcProbeObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("load ipc eBPF objects: %w", err)
	}

	// Attach tracepoints
	attachTracepoint := func(group, name string, prog *ebpf.Program) {
		tp, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			log.Printf("[ipc] warning: could not attach %s/%s: %v", group, name, err)
		} else {
			c.links = append(c.links, tp)
		}
	}

	attachTracepoint("syscalls", "sys_enter_pipe2", objs.TracepointSyscallsSysEnterPipe2)
	attachTracepoint("syscalls", "sys_exit_pipe2", objs.TracepointSyscallsSysExitPipe2)
	attachTracepoint("syscalls", "sys_enter_socketpair", objs.TracepointSyscallsSysEnterSocketpair)
	attachTracepoint("syscalls", "sys_exit_socketpair", objs.TracepointSyscallsSysExitSocketpair)
	attachTracepoint("syscalls", "sys_enter_shmget", objs.TracepointSyscallsSysEnterShmget)
	attachTracepoint("syscalls", "sys_enter_msgget", objs.TracepointSyscallsSysEnterMsgget)
	attachTracepoint("syscalls", "sys_enter_msgsnd", objs.TracepointSyscallsSysEnterMsgsnd)
	attachTracepoint("syscalls", "sys_enter_semget", objs.TracepointSyscallsSysEnterSemget)
	attachTracepoint("syscalls", "sys_enter_semop", objs.TracepointSyscallsSysEnterSemop)

	// Open ring buffer reader
	c.reader, err = ringbuf.NewReader(objs.IpcEvents)
	if err != nil {
		c.Stop()
		return fmt.Errorf("open ipc ring buffer: %w", err)
	}

	log.Printf("[ipc] eBPF probes attached, reading events...")

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
			c.counters.RecordDrop("ipc")
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

	var rawEvt ipcEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &rawEvt); err != nil {
		return nil
	}

	comm := cString(rawEvt.Hdr.Comm[:])
	entityID := identity.GenerateProcessEntityID(c.hostInfo.BootID, int32(rawEvt.Hdr.PID), rawEvt.Hdr.TimestampNS)
	parentEntityID := ""
	if rawEvt.Hdr.PPID > 0 {
		parentEntityID = identity.GenerateParentEntityID(c.hostInfo.BootID, int32(rawEvt.Hdr.PPID), 0)
	}

	actor := &envelope.ActorInfo{
		PID:             int32(rawEvt.Hdr.PID),
		TID:             int32(rawEvt.Hdr.TID),
		PPID:            int32(rawEvt.Hdr.PPID),
		ParentEntityID:  parentEntityID,
		Comm:            comm,
		UID:             rawEvt.Hdr.UID,
		GID:             rawEvt.Hdr.GID,
		ProcessStartNS:  rawEvt.Hdr.TimestampNS,
		ProcessEntityID: entityID,
	}

	var (
		eventType string
		payload   any
	)

	switch rawEvt.Hdr.EventType {
	case eventIPCPipe:
		eventType = "ipc.pipe_create"
		payload = PipeCreateData{
			ReadFD:  rawEvt.FD0,
			WriteFD: rawEvt.FD1,
			Flags:   rawEvt.Flags,
			RetCode: rawEvt.RetCode,
		}

	case eventIPCSocketpair:
		eventType = "ipc.socketpair_create"
		payload = SocketPairData{
			Family:   "unix",
			Type:     sockTypeToString(rawEvt.SockType),
			Protocol: rawEvt.Protocol,
			FD0:      rawEvt.FD0,
			FD1:      rawEvt.FD1,
			RetCode:  rawEvt.RetCode,
		}

	case eventIPCShmget:
		eventType = "ipc.shm_get"
		payload = ShmGetData{
			Key:      rawEvt.Key,
			ShmID:    rawEvt.IPCID,
			Size:     rawEvt.Size,
			ShmFlg:   rawEvt.Flags,
			FlagDesc: formatIPCFlags(rawEvt.Flags),
			RetCode:  rawEvt.RetCode,
		}

	case eventIPCMsgget:
		eventType = "ipc.msg_get"
		payload = MsgGetData{
			Key:      rawEvt.Key,
			MsgID:    rawEvt.IPCID,
			MsgFlg:   rawEvt.Flags,
			FlagDesc: formatIPCFlags(rawEvt.Flags),
			RetCode:  rawEvt.RetCode,
		}

	case eventIPCMsgsnd:
		eventType = "ipc.msg_send"
		payload = MsgSendData{
			MsgID:   rawEvt.IPCID,
			MsgType: rawEvt.MsgType,
			MsgSize: rawEvt.Size,
			MsgFlg:  rawEvt.Flags,
			RetCode: rawEvt.RetCode,
		}

	case eventIPCSemget:
		eventType = "ipc.sem_get"
		payload = SemGetData{
			Key:      rawEvt.Key,
			SemID:    rawEvt.IPCID,
			NSems:    rawEvt.NSems,
			SemFlg:   rawEvt.Flags,
			FlagDesc: formatIPCFlags(rawEvt.Flags),
			RetCode:  rawEvt.RetCode,
		}

	case eventIPCSemop:
		eventType = "ipc.sem_op"
		payload = SemOpData{
			SemID:   rawEvt.IPCID,
			NSops:   rawEvt.NSops,
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

// Snapshot enumerates current System V IPC resources from /proc/sysvipc/.
func (c *Collector) Snapshot(ctx context.Context, events chan<- *envelope.Event) error {
	log.Printf("[ipc] starting IPC snapshot...")
	c.snapshotSHM(ctx, events)
	c.snapshotMSG(ctx, events)
	c.snapshotSEM(ctx, events)
	log.Printf("[ipc] IPC snapshot completed")
	return nil
}

func (c *Collector) snapshotSHM(ctx context.Context, events chan<- *envelope.Event) {
	file, err := os.Open("/proc/sysvipc/shm")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false // Skip header
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		key, _ := strconv.ParseInt(fields[0], 10, 32)
		shmid, _ := strconv.ParseInt(fields[1], 10, 32)
		perms, _ := strconv.ParseUint(fields[2], 8, 32)
		size, _ := strconv.ParseUint(fields[3], 10, 64)
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		nattch, _ := strconv.ParseInt(fields[9], 10, 32)
		atime, _ := strconv.ParseInt(fields[10], 10, 64)

		source := envelope.NewSource("proc", "/proc/sysvipc/shm")
		evt := envelope.NewEvent(
			"ipc.snapshot",
			envelope.CollectionModeSnapshot,
			c.hostInfo,
			source,
			IPCSnapshotData{
				ResourceType: "shm",
				Key:          int32(key),
				ID:           int32(shmid),
				OwnerUID:     uint32(uid),
				Permissions:  uint32(perms),
				Size:         size,
				LastOpTime:   atime,
				NumAttach:    int32(nattch),
			},
		)
		evt.SetActor(&envelope.ActorInfo{ProcessEntityID: "system", Comm: "kernel"})
		select {
		case events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) snapshotMSG(ctx context.Context, events chan<- *envelope.Event) {
	file, err := os.Open("/proc/sysvipc/msg")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 14 {
			continue
		}

		key, _ := strconv.ParseInt(fields[0], 10, 32)
		msgid, _ := strconv.ParseInt(fields[1], 10, 32)
		perms, _ := strconv.ParseUint(fields[2], 8, 32)
		uid, _ := strconv.ParseUint(fields[7], 10, 32)
		stime, _ := strconv.ParseInt(fields[11], 10, 64)

		source := envelope.NewSource("proc", "/proc/sysvipc/msg")
		evt := envelope.NewEvent(
			"ipc.snapshot",
			envelope.CollectionModeSnapshot,
			c.hostInfo,
			source,
			IPCSnapshotData{
				ResourceType: "msg",
				Key:          int32(key),
				ID:           int32(msgid),
				OwnerUID:     uint32(uid),
				Permissions:  uint32(perms),
				LastOpTime:   stime,
			},
		)
		evt.SetActor(&envelope.ActorInfo{ProcessEntityID: "system", Comm: "kernel"})
		select {
		case events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) snapshotSEM(ctx context.Context, events chan<- *envelope.Event) {
	file, err := os.Open("/proc/sysvipc/sem")
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}

		key, _ := strconv.ParseInt(fields[0], 10, 32)
		semid, _ := strconv.ParseInt(fields[1], 10, 32)
		perms, _ := strconv.ParseUint(fields[2], 8, 32)
		nsems, _ := strconv.ParseInt(fields[3], 10, 32)
		uid, _ := strconv.ParseUint(fields[4], 10, 32)
		otime, _ := strconv.ParseInt(fields[8], 10, 64)

		source := envelope.NewSource("proc", "/proc/sysvipc/sem")
		evt := envelope.NewEvent(
			"ipc.snapshot",
			envelope.CollectionModeSnapshot,
			c.hostInfo,
			source,
			IPCSnapshotData{
				ResourceType: "sem",
				Key:          int32(key),
				ID:           int32(semid),
				OwnerUID:     uint32(uid),
				Permissions:  uint32(perms),
				Size:         uint64(nsems),
				LastOpTime:   otime,
			},
		)
		evt.SetActor(&envelope.ActorInfo{ProcessEntityID: "system", Comm: "kernel"})
		select {
		case events <- evt:
		case <-ctx.Done():
			return
		}
	}
}

func (c *Collector) ktimeToWallTime(ktimeNS uint64) time.Time {
	wallNS := c.bootTimeNS + ktimeNS
	return time.Unix(0, int64(wallNS)).UTC()
}

func getBootTimeOffsetNS() uint64 {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return uint64(time.Now().UnixNano())
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			var btime uint64
			fmt.Sscanf(line, "btime %d", &btime)
			return btime * 1_000_000_000
		}
	}
	return uint64(time.Now().UnixNano())
}

func cString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx < 0 {
		return string(b)
	}
	return string(b[:idx])
}

func sockTypeToString(st uint16) string {
	switch st & 0xf {
	case 1:
		return "stream"
	case 2:
		return "dgram"
	case 5:
		return "seqpacket"
	default:
		return fmt.Sprintf("type_%d", st)
	}
}

func formatIPCFlags(flg int32) string {
	var parts []string
	if flg&01000 != 0 {
		parts = append(parts, "IPC_CREAT")
	}
	if flg&02000 != 0 {
		parts = append(parts, "IPC_EXCL")
	}
	if len(parts) == 0 {
		return fmt.Sprintf("0%o", flg&0777)
	}
	return strings.Join(parts, "|")
}
