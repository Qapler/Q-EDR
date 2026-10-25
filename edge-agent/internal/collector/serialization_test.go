package collector_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/filesystem"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/ipc"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/network"
	"github.com/Qapler/Q-EDR/edge-agent/internal/collector/process"
	"github.com/Qapler/Q-EDR/edge-agent/internal/envelope"
)

func TestAllEventsSerialization(t *testing.T) {
	hostInfo := envelope.HostInfo{
		HostID:        "host-123",
		Hostname:      "test-box",
		BootID:        "boot-456",
		OS:            "linux",
		Architecture:  "x86_64",
		KernelRelease: "6.8.0-generic",
	}

	testCases := []struct {
		eventType string
		mode      string
		mechanism string
		probe     string
		data      any
	}{
		// Process
		{
			eventType: "process.exec",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sched_process_exec",
			data: process.ExecData{
				Filename: "/bin/bash",
				Argv:     []string{"/bin/bash", "-c", "whoami"},
				RetCode:  0,
			},
		},
		{
			eventType: "process.fork",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sched_process_fork",
			data: process.ForkData{
				ChildPID:      1235,
				ChildTID:      1235,
				ChildComm:     "bash",
				ChildEntityID: "child-entity-001",
				CloneFlags:    0x1200011,
			},
		},
		{
			eventType: "process.exit",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sched_process_exit",
			data: process.ExitData{
				ExitCode: 0,
				Signal:   0,
			},
		},
		{
			eventType: "process.snapshot",
			mode:      envelope.CollectionModeSnapshot,
			mechanism: "proc",
			probe:     "/proc/[pid]",
			data: process.SnapshotData{
				State:     "S",
				StateDesc: "sleeping",
				Threads:   1,
				VmSizeKB:  10240,
				VmRSSKB:   2048,
				OpenFDs:   4,
				Cmdline:   []string{"/sbin/init"},
			},
		},

		// Network
		{
			eventType: "network.connect",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "inet_sock_set_state",
			data: network.ConnectData{
				Family:     "ipv4",
				Protocol:   "tcp",
				Direction:  "outbound",
				LocalAddr:  "10.0.0.5",
				LocalPort:  45234,
				RemoteAddr: "93.184.216.34",
				RemotePort: 443,
				SocketFD:   3,
			},
		},
		{
			eventType: "network.accept",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "inet_sock_set_state",
			data: network.AcceptData{
				Family:     "ipv4",
				Protocol:   "tcp",
				Direction:  "inbound",
				LocalAddr:  "0.0.0.0",
				LocalPort:  8080,
				RemoteAddr: "192.168.1.100",
				RemotePort: 54122,
				NewFD:      4,
			},
		},
		{
			eventType: "network.bind",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_bind",
			data: network.BindData{
				Family:   "ipv4",
				Protocol: "tcp",
				Addr:     "0.0.0.0",
				Port:     8080,
				SocketFD: 3,
			},
		},
		{
			eventType: "network.close",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "inet_sock_set_state",
			data: network.CloseData{
				Family:     "ipv4",
				Protocol:   "tcp",
				LocalAddr:  "10.0.0.5",
				LocalPort:  45234,
				RemoteAddr: "93.184.216.34",
				RemotePort: 443,
				OldState:   "ESTABLISHED",
				NewState:   "CLOSE",
			},
		},
		{
			eventType: "network.snapshot",
			mode:      envelope.CollectionModeSnapshot,
			mechanism: "proc",
			probe:     "/proc/net/tcp",
			data: network.SocketSnapshotData{
				Family:     "ipv4",
				Protocol:   "tcp",
				LocalAddr:  "127.0.0.1",
				LocalPort:  53,
				RemoteAddr: "0.0.0.0",
				RemotePort: 0,
				State:      "LISTEN",
				Inode:      12345,
			},
		},

		// IPC
		{
			eventType: "ipc.pipe_create",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_exit_pipe2",
			data: ipc.PipeCreateData{
				ReadFD:  3,
				WriteFD: 4,
				Flags:   0,
			},
		},
		{
			eventType: "ipc.socketpair_create",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_exit_socketpair",
			data: ipc.SocketPairData{
				Family:   "unix",
				Type:     "stream",
				Protocol: 0,
				FD0:      5,
				FD1:      6,
			},
		},
		{
			eventType: "ipc.shm_get",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_shmget",
			data: ipc.ShmGetData{
				Key:      1234,
				ShmID:    1,
				Size:     4096,
				ShmFlg:   0666,
				FlagDesc: "0666",
			},
		},
		{
			eventType: "ipc.msg_send",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_msgsnd",
			data: ipc.MsgSendData{
				MsgID:   2,
				MsgType: 1,
				MsgSize: 128,
			},
		},
		{
			eventType: "ipc.sem_op",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_semop",
			data: ipc.SemOpData{
				SemID: 3,
				NSops: 1,
			},
		},
		{
			eventType: "ipc.snapshot",
			mode:      envelope.CollectionModeSnapshot,
			mechanism: "proc",
			probe:     "/proc/sysvipc/shm",
			data: ipc.IPCSnapshotData{
				ResourceType: "shm",
				Key:          1234,
				ID:           1,
				OwnerUID:     1000,
				Permissions:  0666,
				Size:         4096,
			},
		},

		// Filesystem
		{
			eventType: "filesystem.open",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_openat",
			data: filesystem.OpenData{
				Path:      "/etc/passwd",
				Flags:     0,
				FlagsDesc: "O_RDONLY",
				FD:        3,
			},
		},
		{
			eventType: "filesystem.create",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_openat",
			data: filesystem.OpenData{
				Path:      "/tmp/test.txt",
				Flags:     0102,
				FlagsDesc: "O_RDWR|O_CREAT",
				Mode:      0644,
				FD:        4,
			},
		},
		{
			eventType: "filesystem.write",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_write",
			data: filesystem.WriteData{
				FD:      4,
				Count:   1024,
				Written: 1024,
			},
		},
		{
			eventType: "filesystem.rename",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_renameat2",
			data: filesystem.RenameData{
				OldPath: "/tmp/old.txt",
				NewPath: "/tmp/new.txt",
			},
		},
		{
			eventType: "filesystem.unlink",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_unlinkat",
			data: filesystem.UnlinkData{
				Path:  "/tmp/test.txt",
				IsDir: false,
			},
		},
		{
			eventType: "filesystem.mkdir",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_mkdirat",
			data: filesystem.MkdirData{
				Path: "/tmp/mydir",
				Mode: 0755,
			},
		},
		{
			eventType: "filesystem.chmod",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_fchmodat",
			data: filesystem.ChmodData{
				Path: "/tmp/script.sh",
				Mode: 0755,
			},
		},
		{
			eventType: "filesystem.chown",
			mode:      envelope.CollectionModeEvent,
			mechanism: "ebpf",
			probe:     "sys_enter_fchownat",
			data: filesystem.ChownData{
				Path:    "/tmp/script.sh",
				OwnerID: 1000,
				GroupID: 1000,
			},
		},
		{
			eventType: "filesystem.snapshot",
			mode:      envelope.CollectionModeSnapshot,
			mechanism: "proc",
			probe:     "/proc/mounts",
			data: filesystem.MountSnapshotData{
				Device:     "/dev/sda1",
				MountPoint: "/",
				FSType:     "ext4",
				Options:    "rw,relatime",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.eventType, func(t *testing.T) {
			source := envelope.NewSource(tc.mechanism, tc.probe)
			evt := envelope.NewEvent(tc.eventType, tc.mode, hostInfo, source, tc.data)
			evt.SetEventTime(time.Now().UTC())
			evt.SetActor(&envelope.ActorInfo{
				PID:             100,
				TID:             100,
				PPID:            1,
				UID:             1000,
				GID:             1000,
				Comm:            "test-proc",
				ProcessEntityID: "test-entity-001",
			})
			evt.SetQuality(&envelope.QualityInfo{TimestampSource: "test"})

			bytes, err := evt.Marshal()
			if err != nil {
				t.Fatalf("failed to marshal %s: %v", tc.eventType, err)
			}

			var roundTrip map[string]interface{}
			if err := json.Unmarshal(bytes, &roundTrip); err != nil {
				t.Fatalf("failed to unmarshal JSON for %s: %v", tc.eventType, err)
			}

			if roundTrip["schema_version"] != envelope.SchemaVersion {
				t.Errorf("wrong schema_version: %v", roundTrip["schema_version"])
			}
			if roundTrip["event_type"] != tc.eventType {
				t.Errorf("wrong event_type: got %v, want %v", roundTrip["event_type"], tc.eventType)
			}
			if roundTrip["collection_mode"] != tc.mode {
				t.Errorf("wrong collection_mode: got %v, want %v", roundTrip["collection_mode"], tc.mode)
			}
			if roundTrip["data"] == nil {
				t.Errorf("data payload is nil for %s", tc.eventType)
			}
		})
	}
}
