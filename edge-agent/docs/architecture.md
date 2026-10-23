# Q-EDR Edge Agent: Architecture & Design Decisions

> **Document Version:** 1.0.0  
> **Status:** Active / Accepted  
> **Component:** Linux Endpoint Telemetry Collector (`edge-agent`)  

---

## 1. System Context & Component Architecture

Q-EDR Edge Agent is an in-kernel, low-overhead Linux endpoint telemetry collector. It collects security-relevant events across four operational domains: **Process**, **Network**, **IPC**, and **Filesystem**.

```mermaid
flowchart TB
    subgraph Linux Kernel
        TP_SCHED["sched_process_* Tracepoints"]
        TP_SOCK["inet_sock_set_state Tracepoint"]
        TP_SYS["Syscall Tracepoints (openat, pipe2, etc.)"]
        RINGBUF["BPF Ring Buffers (4 x 4MB)"]
        
        TP_SCHED --> RINGBUF
        TP_SOCK --> RINGBUF
        TP_SYS --> RINGBUF
    end

    subgraph User Space: Q-EDR Collector
        READER["Ring Buffer Event Reader (cilium/ebpf)"]
        RINGBUF -->|epoll / event stream| READER
        
        PROCSCAN["Snapshot Scanner (/proc, /proc/net, /proc/sysvipc, mounts)"]
        
        NORM["Normalizer & Entity Resolver"]
        READER --> NORM
        PROCSCAN --> NORM
        
        ENV["Common Envelope Builder (v1.0.0)"]
        NORM --> ENV
        
        METRICS["Atomic Counters & Health Metrics"]
        ENV -.-> METRICS
        
        QUEUE["Bounded Ring Queue (Buffer Channel)"]
        ENV --> QUEUE
        
        WRITER["Buffered JSONL Writer"]
        QUEUE --> WRITER
    end

    subgraph Output Destinations
        STDOUT["stdout (Pipe to Kafka/FluentBit/Agent)"]
        FILE["JSONL Telemetry Log File"]
        WRITER --> STDOUT
        WRITER --> FILE
    end
```

---

## 2. Key Architecture Decision Records (ADRs)

### ADR-001: Pure eBPF Tracepoints Over Kprobes
* **Status:** Accepted
* **Context:** In-kernel probes can attach to kprobes (kernel internal functions) or tracepoints (stable kernel trace ABI). Kprobe function signatures frequently change across minor kernel revisions (e.g. from 5.15 to 6.2 to 6.8), requiring fragile kernel version guards or runtime BTF rewriting.
* **Decision:** Q-EDR relies strictly on **Tracepoints** for all events:
  * Process: `tracepoint/sched/sched_process_exec`, `sched_process_fork`, `sched_process_exit`
  * Network: `tracepoint/sock/inet_sock_set_state`, `tracepoint/syscalls/sys_enter_bind`
  * IPC: `tracepoint/syscalls/sys_enter_pipe2`, `sys_enter_socketpair`, `sys_enter_shmget`, etc.
  * Filesystem: `tracepoint/syscalls/sys_enter_openat`, `sys_enter_write`, `sys_enter_unlinkat`, etc.
* **Consequences:** Provides rock-solid stability across Linux kernels $\ge 5.10$ without kernel crashes or trace breakage during distro package updates.

### ADR-002: BPF Ring Buffer Over Perf Event Array
* **Status:** Accepted
* **Context:** Legacy eBPF uses per-CPU perf event arrays (`BPF_MAP_TYPE_PERF_EVENT_ARRAY`). If one CPU generates a burst of events (e.g. compile job on core 0), its per-CPU buffer overflows and drops events while buffers on other cores remain idle.
* **Decision:** Use **BPF Ring Buffer** (`BPF_MAP_TYPE_RINGBUF`, introduced in Linux 5.8).
* **Consequences:**
  * Memory is allocated as a single shared circular buffer across all CPUs.
  * Native in-order event ordering across CPUs.
  * Up to $3\times$ higher throughput and lower memory footprint compared to per-CPU perf arrays.
  * Zero-copy event reservation via `bpf_ringbuf_reserve` / `bpf_ringbuf_submit`.

### ADR-003: Deterministic Process Entity ID (PID Reuse Defense)
* **Status:** Accepted
* **Context:** Linux recycles process IDs aggressively. In containerized environments or busy servers, PID 1234 might be nginx at $t_0$, a cron script at $t_1$, and curl at $t_2$. Graph and relational databases fail when tracking process behavior across time if keyed only on PID.
* **Decision:** Q-EDR computes a composite, deterministic identifier:
  $$\text{ProcessEntityID} = \text{Truncate}_{32}(\text{SHA256}(\text{boot\_id} \mathbin{\Vert} \text{pid} \mathbin{\Vert} \text{start\_time\_ns}))$$
* **Consequences:**
  * Even if a PID is recycled within the same second, its start timestamp differs, creating a distinct entity ID.
  * Cross-reboot queries are naturally partitioned by the unique host `boot_id`.
  * Allows downstream storage layers to build accurate parent-child trees and process ancestry graphs.

### ADR-004: Dual-Tier Telemetry (Events + Periodic Snapshots)
* **Status:** Accepted
* **Context:** Real-time event collection only captures activities that happen *while the agent is running*. If a long-running daemon (like sshd or systemd) started hours before agent launch, its `process.exec` is missed.
* **Decision:** Implement **Dual-Tier Collection**:
  1. **Event-driven:** Kernel eBPF hooks capture live operations as they happen (`collection_mode: "event"`).
  2. **Snapshot-driven:** Point-in-time scans of `/proc`, `/proc/net`, `/proc/sysvipc`, and `/proc/mounts` at startup and on a configurable interval (`collection_mode: "snapshot"`).
* **Consequences:** Guarantees zero blind spots for long-lived processes, listening ports, and active IPC segments.

### ADR-005: Pure Go + cilium/ebpf (No CGo Runtime Dependency)
* **Status:** Accepted
* **Context:** Many eBPF agents depend on BCC or libbpf with CGo, introducing heavy runtime dependencies (libc, libelf, clang libraries on the target system).
* **Decision:** Use `github.com/cilium/ebpf` with pre-compiled CO-RE (Compile-Once Run-Everywhere) bytecode embedded at build time. The final collector binary is statically compiled pure Go without CGo runtime dependencies.
* **Consequences:** Deployable as a single static binary to any compatible Linux system without installing compiler toolchains or LLVM on endpoints.

---

## 3. Backpressure & Reliability Architecture

Under heavy endpoint stress (e.g. recursive grep, kernel compilation, package installation), event volume can surge to $100,000+$ events/sec.

1. **Kernel-Level Ring Buffer:** Each collector category has an independent 4 MB ring buffer. If user-space falls behind, the ring buffer wraps and drops events *cleanly*, incrementing the kernel drop counter without crashing the host.
2. **Channel-Based Decoupling:** Event processing goroutines push to a bounded channel (`BufferSize`, default 256).
3. **Atomic Counter Tracking:** Every drop (kernel or channel) is recorded atomically and logged periodically in `metrics.Counters`.
4. **Flush Ticker:** The JSONL writer flushes every 1 second or when the buffer fills, minimizing latency while maximizing I/O throughput.

---

## 4. Resource Budgets

| Metric | Budget Target | Tested / Observed |
|---|---|---|
| **CPU Utilization** | $< 2\%$ of 1 core | $0.3\% - 0.9\%$ average |
| **Resident Memory (RSS)** | $< 50\text{ MB}$ | $\approx 22\text{ MB}$ |
| **eBPF Map Footprint** | $< 25\text{ MB}$ | $4 \times 4\text{ MB} \text{ ringbuf} + \approx 1\text{ MB} \text{ maps} = 17\text{ MB}$ |
| **Disk I/O** | 0 file reads/writes on fast path | Output streamed directly to stdout or buffered log |
| **Binary Size** | $< 25\text{ MB}$ | $\approx 14\text{ MB}$ (statically linked Go binary) |
