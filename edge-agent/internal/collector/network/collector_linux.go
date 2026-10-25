//go:build linux

// Package network implements network telemetry collection using eBPF and /proc/net.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -type network_event networkProbe ../../bpf/network.bpf.c -- -I../../bpf
package network

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
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
	eventNetConnect = 10
	eventNetAccept  = 11
	eventNetBind    = 12
	eventNetClose   = 13

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

type networkEventRaw struct {
	Hdr      eventHeader
	Family   uint16
	Protocol uint16
	Sport    uint16
	Dport    uint16
	Saddr    [4]uint32
	Daddr    [4]uint32
	RetCode  int32
	SocketFD int32
	OldState int32
	NewState int32
	Backlog  int32
}

type Collector struct {
	cfg        *config.Config
	hostInfo   envelope.HostInfo
	counters   *metrics.Counters
	links      []link.Link
	reader     *ringbuf.Reader
	bootTimeNS uint64
}

func New(cfg *config.Config, counters *metrics.Counters) *Collector {
	return &Collector{
		cfg:      cfg,
		hostInfo: host.Collect(),
		counters: counters,
	}
}

func (c *Collector) Name() string { return "network" }

func (c *Collector) Start(ctx context.Context, events chan<- *envelope.Event) error {
	c.bootTimeNS = getBootTimeOffsetNS()

	spec, err := loadNetworkProbe()
	if err != nil {
		return fmt.Errorf("load network eBPF spec: %w", err)
	}

	var objs networkProbeObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{}); err != nil {
		return fmt.Errorf("load network eBPF objects: %w", err)
	}

	// Attach inet_sock_set_state tracepoint.
	tpState, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TracepointSockInetSockSetState, nil)
	if err != nil {
		log.Printf("[network] warning: could not attach inet_sock_set_state: %v", err)
	} else {
		c.links = append(c.links, tpState)
	}

	// Attach bind tracepoints.
	tpBindEnter, err := link.Tracepoint("syscalls", "sys_enter_bind", objs.TracepointSyscallsSysEnterBind, nil)
	if err != nil {
		log.Printf("[network] warning: could not attach sys_enter_bind: %v", err)
	} else {
		c.links = append(c.links, tpBindEnter)
	}

	tpBindExit, err := link.Tracepoint("syscalls", "sys_exit_bind", objs.TracepointSyscallsSysExitBind, nil)
	if err != nil {
		log.Printf("[network] warning: could not attach sys_exit_bind: %v", err)
	} else {
		c.links = append(c.links, tpBindExit)
	}

	c.reader, err = ringbuf.NewReader(objs.NetworkEvents)
	if err != nil {
		c.Stop()
		return fmt.Errorf("open network ring buffer: %w", err)
	}

	log.Printf("[network] eBPF probes attached, reading events...")

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
			c.counters.RecordDrop("network")
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
	if len(raw) < int(unsafe.Sizeof(networkEventRaw{})) {
		return nil
	}

	var re networkEventRaw
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &re); err != nil {
		return nil
	}

	family := familyString(re.Family)
	proto := protocolString(re.Protocol)

	var eventType string
	var data interface{}

	switch re.Hdr.EventType {
	case eventNetConnect:
		eventType = "network.connect"
		data = ConnectData{
			Family:     family,
			Protocol:   proto,
			Direction:  "outbound",
			LocalAddr:  addrToString(re.Saddr, re.Family),
			LocalPort:  re.Sport,
			RemoteAddr: addrToString(re.Daddr, re.Family),
			RemotePort: re.Dport,
			RetCode:    re.RetCode,
			SocketFD:   re.SocketFD,
		}
	case eventNetAccept:
		eventType = "network.accept"
		data = AcceptData{
			Family:     family,
			Protocol:   proto,
			Direction:  "inbound",
			LocalAddr:  addrToString(re.Saddr, re.Family),
			LocalPort:  re.Sport,
			RemoteAddr: addrToString(re.Daddr, re.Family),
			RemotePort: re.Dport,
			NewFD:      re.SocketFD,
		}
	case eventNetBind:
		eventType = "network.bind"
		data = BindData{
			Family:   family,
			Protocol: proto,
			Addr:     addrToString(re.Saddr, re.Family),
			Port:     re.Sport,
			RetCode:  re.RetCode,
			SocketFD: re.SocketFD,
		}
	case eventNetClose:
		eventType = "network.close"
		data = CloseData{
			Family:     family,
			Protocol:   proto,
			LocalAddr:  addrToString(re.Saddr, re.Family),
			LocalPort:  re.Sport,
			RemoteAddr: addrToString(re.Daddr, re.Family),
			RemotePort: re.Dport,
			OldState:   tcpStateString(re.OldState),
			NewState:   tcpStateString(re.NewState),
		}
	default:
		return nil
	}

	source := envelope.NewSource("ebpf", eventType)
	evt := envelope.NewEvent(eventType, envelope.CollectionModeEvent, c.hostInfo, source, data)
	evt.SetEventTime(c.kernelTSToWallClock(re.Hdr.TimestampNS))

	comm := cstring(re.Hdr.Comm[:])
	entityID := identity.GenerateProcessEntityID(c.hostInfo.BootID, int32(re.Hdr.PID), re.Hdr.TimestampNS)
	evt.SetActor(&envelope.ActorInfo{
		PID:             int32(re.Hdr.PID),
		TID:             int32(re.Hdr.TID),
		UID:             re.Hdr.UID,
		GID:             re.Hdr.GID,
		Comm:            comm,
		ProcessEntityID: entityID,
	})

	return evt
}

// Snapshot reads /proc/net/tcp and /proc/net/udp for socket inventory.
func (c *Collector) Snapshot(ctx context.Context, events chan<- *envelope.Event) error {
	hostInfo := host.Collect()
	count := 0

	for _, proto := range []struct {
		file     string
		protocol string
		family   string
	}{
		{"/proc/net/tcp", "tcp", "ipv4"},
		{"/proc/net/udp", "udp", "ipv4"},
		{"/proc/net/tcp6", "tcp", "ipv6"},
		{"/proc/net/udp6", "udp", "ipv6"},
	} {
		data, err := os.ReadFile(proto.file)
		if err != nil {
			continue
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for i, line := range lines {
			if i == 0 {
				continue // Skip header.
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}

			snap := parseProcNetLine(line, proto.protocol, proto.family)
			if snap == nil {
				continue
			}

			source := envelope.NewSource("proc", proto.file)
			evt := envelope.NewEvent("network.snapshot", envelope.CollectionModeSnapshot, hostInfo, source, snap)
			select {
			case events <- evt:
				count++
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	log.Printf("[network] snapshot: enumerated %d sockets", count)
	return nil
}

func parseProcNetLine(line, protocol, family string) *SocketSnapshotData {
	fields := strings.Fields(line)
	if len(fields) < 10 {
		return nil
	}

	localParts := strings.SplitN(fields[1], ":", 2)
	remoteParts := strings.SplitN(fields[2], ":", 2)
	if len(localParts) != 2 || len(remoteParts) != 2 {
		return nil
	}

	return &SocketSnapshotData{
		Family:     family,
		Protocol:   protocol,
		State:      fields[3],
		LocalAddr:  localParts[0],
		LocalPort:  hexToPort(localParts[1]),
		RemoteAddr: remoteParts[0],
		RemotePort: hexToPort(remoteParts[1]),
	}
}

func hexToPort(hex string) uint16 {
	var port uint16
	fmt.Sscanf(hex, "%X", &port)
	return port
}

func (c *Collector) kernelTSToWallClock(bootNS uint64) time.Time {
	wallNS := c.bootTimeNS + bootNS
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

func familyString(f uint16) string {
	switch f {
	case 2:
		return "ipv4"
	case 10:
		return "ipv6"
	case 1:
		return "unix"
	default:
		return fmt.Sprintf("af_%d", f)
	}
}

func protocolString(p uint16) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("proto_%d", p)
	}
}

func addrToString(addr [4]uint32, family uint16) string {
	switch family {
	case 2: // AF_INET
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, addr[0])
		return ip.String()
	case 10: // AF_INET6
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(ip[i*4:], addr[i])
		}
		return ip.String()
	default:
		return ""
	}
}

func tcpStateString(state int32) string {
	names := map[int32]string{
		1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV",
		4: "FIN_WAIT1", 5: "FIN_WAIT2", 6: "TIME_WAIT",
		7: "CLOSE", 8: "CLOSE_WAIT", 9: "LAST_ACK",
		10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
	}
	if name, ok := names[state]; ok {
		return name
	}
	return fmt.Sprintf("STATE_%d", state)
}

func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return string(b)
	}
	return string(b[:i])
}
