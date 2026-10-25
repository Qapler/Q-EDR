# Q-EDR Collector: Capability & Compatibility Matrix

> **Collector Version:** 0.1.0  
> **Target OS:** Linux (x86_64, aarch64)  
> **Minimum Kernel:** Linux 5.10+ (Recommended: 5.15+)  

---

## 1. Category Implementation Status

| Domain | Event Type | Mechanism | Hook / Tracepoint | Status | Notes |
|---|---|---|---|---|---|
| **Process** | `process.exec` | eBPF | `tracepoint/sched/sched_process_exec` | **Complete** | Captures binary, argv, retcode |
| | `process.fork` | eBPF | `tracepoint/sched/sched_process_fork` | **Complete** | Child PID, TID, clone flags |
| | `process.exit` | eBPF | `tracepoint/sched/sched_process_exit` | **Complete** | Exit code, terminating signal |
| | `process.snapshot` | `/proc` | `/proc/[pid]/stat,status,cmdline` | **Complete** | Full process table scan |
| **Network** | `network.connect` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | Outbound TCP state transitions |
| | `network.accept` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | Inbound TCP accepted sockets |
| | `network.bind` | eBPF | `tracepoint/syscalls/sys_enter_bind` | **Complete** | Local address/port binding |
| | `network.close` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | TCP close transitions |
| | `network.snapshot` | `/proc` | `/proc/net/tcp`, `/proc/net/udp` | **Complete** | Listening & established sockets |
| **IPC** | `ipc.pipe_create` | eBPF | `tracepoint/syscalls/sys_exit_pipe2` | **Complete** | Anonymous pipes |
| | `ipc.socketpair_create` | eBPF | `tracepoint/syscalls/sys_exit_socketpair` | **Complete** | UNIX domain socket pairs |
| | `ipc.shm_get` | eBPF | `tracepoint/syscalls/sys_enter_shmget` | **Complete** | System V shared memory |
| | `ipc.msg_send` | eBPF | `tracepoint/syscalls/sys_enter_msgsnd` | **Complete** | System V message queue send |
| | `ipc.sem_op` | eBPF | `tracepoint/syscalls/sys_enter_semop` | **Complete** | System V semaphore operations |
| | `ipc.snapshot` | `/proc` | `/proc/sysvipc/shm,msg,sem` | **Complete** | System V active resources |
| **Filesystem** | `filesystem.open` | eBPF | `tracepoint/syscalls/sys_enter_openat` | **Complete** | Target path, flags, mode, FD |
| | `filesystem.create` | eBPF | `tracepoint/syscalls/sys_enter_openat` | **Complete** | Auto-detected via `O_CREAT` |
| | `filesystem.write` | eBPF | `tracepoint/syscalls/sys_enter_write` | **Complete** | Metadata only (bytes written) |
| | `filesystem.rename` | eBPF | `tracepoint/syscalls/sys_enter_renameat2`| **Complete** | Source path and destination path |
| | `filesystem.unlink` | eBPF | `tracepoint/syscalls/sys_enter_unlinkat` | **Complete** | File & directory deletion |
| | `filesystem.mkdir` | eBPF | `tracepoint/syscalls/sys_enter_mkdirat` | **Complete** | Directory creation with mode |
| | `filesystem.chmod` | eBPF | `tracepoint/syscalls/sys_enter_fchmodat` | **Complete** | Permission changes |
| | `filesystem.chown` | eBPF | `tracepoint/syscalls/sys_enter_fchownat`  | **Complete** | Owner / group modifications |
| | `filesystem.snapshot` | `/proc` | `/proc/mounts` | **Complete** | Mount point inventory |

---

## 2. Linux Distribution & Kernel Support

| Distribution | Supported Versions | Kernel Version | eBPF Status | Validation Method |
|---|---|---|---|---|
| **Ubuntu** | 22.04 LTS (Jammy) | 5.15+ | Fully Supported | Direct / Docker VM |
| | 24.04 LTS (Noble) | 6.8+ | Fully Supported | Direct / Docker VM |
| **Debian** | 12 (Bookworm) | 6.1+ | Fully Supported | Tested |
| **RHEL / Rocky / Alma** | 9.x | 5.14+ | Fully Supported | Tested |
| | 8.x | 4.18+ (backported) | Partial | Ring buffer requires $\ge 5.8$ |
| **Fedora** | 39, 40+ | 6.5+ | Fully Supported | Tested |
| **Alpine Linux** | 3.19+ (musl) | 6.6+ | Fully Supported | Static Go binary |

---

## 3. Required Privileges & Capabilities

The collector requires elevated capabilities to load BPF programs and attach tracepoints:

1. **Root Execution (Standard):** Run as `root` (or `sudo ./collector`).
2. **Fine-Grained Capabilities (Least Privilege):**
   * `CAP_BPF` (kernel $\ge 5.8$): Load and verify eBPF programs, create BPF maps.
   * `CAP_PERFMON` (kernel $\ge 5.8$): Read tracepoints and perf events.
   * `CAP_SYS_PTRACE`: Read `/proc/[pid]/exe` and `/proc/[pid]/cmdline` of processes owned by other users.
   * `CAP_NET_ADMIN` (optional): Deep netlink socket diagnostics.

---

## 4. Known Limitations & Mitigation

1. **macOS / Windows Execution:**
   * macOS and Windows lack the Linux eBPF subsystem. The codebase compiles cleanly on Darwin using Go build tags (`//go:build !linux`), providing mock stubs so development, schema generation, and tests run locally. Full execution requires Linux.
2. **Filesystem Write Event Volume:**
   * High write volume can stress user-space buffers. Mitigated by collecting **metadata only** (byte counts and FDs, never payload bytes) and filtering by path prefix if configured.
3. **Short-Lived Process /proc Race:**
   * If a process executes and exits within milliseconds (e.g. `/bin/true`), the eBPF event captures its execution, but a subsequent `/proc/[pid]/cmdline` read may return EOF. Mitigated by capturing initial `argv` in kernel eBPF memory.
