# Q-EDR Collector: Capability & Compatibility Matrix

> **Collector Version:** 0.1.0  
> **Target OS:** Linux (x86_64, aarch64)  
> **Minimum Kernel:** Linux 5.10+ (Recommended: 5.15+)  

---

## 1. Category Implementation Status

| Domain | Event Type | Mechanism | Hook / Tracepoint | Status | Notes |
|---|---|---|---|---|---|
| **Process** | `process.exec` | eBPF | `tracepoint/sched/sched_process_exec` | **Complete** | Captures binary, argv, retcode |
| | `process.fork` | eBPF | `raw_tracepoint/sched_process_fork` | **Complete** | Child PID, TID, comm, entity ID (new processes only; threads skipped; clone flags not captured) |
| | `process.exit` | eBPF | `tracepoint/sched/sched_process_exit` | **Complete** | Exit code, terminating signal (from `task->exit_code` via CO-RE) |
| | `process.snapshot` | `/proc` | `/proc/[pid]/stat,status,cmdline` | **Complete** | Full process table scan |
| **Network** | `network.connect` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | Outbound TCP; actor recorded at `connect()` time |
| | `network.accept` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | Inbound TCP; actor is best-effort (transition runs in softirq) |
| | `network.bind` | eBPF | `tracepoint/syscalls/sys_enter_bind` | **Complete** | Local address/port binding |
| | `network.close` | eBPF | `tracepoint/sock/inet_sock_set_state` | **Complete** | One event per socket on transition to `TCP_CLOSE` |
| | `network.snapshot` | `/proc` | `/proc/net/tcp`, `/proc/net/udp` | **Complete** | Listening & established sockets |
| **IPC** | `ipc.pipe_create` | eBPF | `tracepoint/syscalls/sys_exit_pipe2` | **Complete** | Anonymous pipes |
| | `ipc.socketpair_create` | eBPF | `tracepoint/syscalls/sys_exit_socketpair` | **Complete** | UNIX domain socket pairs |
| | `ipc.shm_get` | eBPF | `tracepoint/syscalls/sys_enter_shmget` | **Complete** | System V shared memory |
| | `ipc.msg_send` | eBPF | `tracepoint/syscalls/sys_enter_msgsnd` | **Complete** | System V message queue send |
| | `ipc.sem_op` | eBPF | `tracepoint/syscalls/sys_enter_semop`, `sys_enter_semtimedop` | **Complete** | System V semaphore operations (glibc `semop()` uses `semtimedop`) |
| | `ipc.snapshot` | `/proc` | `/proc/sysvipc/shm,msg,sem` | **Complete** | System V active resources |
| **Filesystem** | `filesystem.open` | eBPF | `raw_tracepoint/sys_enter` + `sys_exit` | **Complete** | `open`, `creat`, `openat`, `openat2`; path, flags, mode, FD |
| | `filesystem.create` | eBPF | `raw_tracepoint/sys_enter` + `sys_exit` | **Complete** | Auto-detected via `O_CREAT` |
| | `filesystem.write` | eBPF | `raw_tracepoint/sys_enter` + `sys_exit` | **Complete** | Metadata only (bytes written) |
| | `filesystem.rename` | eBPF | `raw_tracepoint/sys_enter` | **Complete** | `rename`, `renameat`, `renameat2` |
| | `filesystem.unlink` | eBPF | `raw_tracepoint/sys_enter` | **Complete** | `unlink`, `rmdir`, `unlinkat` |
| | `filesystem.mkdir` | eBPF | `raw_tracepoint/sys_enter` | **Complete** | `mkdir`, `mkdirat` with mode |
| | `filesystem.chmod` | eBPF | `raw_tracepoint/sys_enter` | **Complete** | `chmod`, `fchmodat`, `fchmodat2` |
| | `filesystem.chown` | eBPF | `raw_tracepoint/sys_enter` | **Complete** | `chown`, `lchown`, `fchownat` |
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
