# Q-EDR Linux Endpoint Telemetry Collector (`edge-agent`)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://golang.org)
[![eBPF Engine](https://img.shields.io/badge/eBPF-cilium%2Febpf-orange?style=flat)](https://github.com/cilium/ebpf)
[![License](https://img.shields.io/badge/License-GPLv2%20%2F%20BSD--3--Clause-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-green.svg)]()

> High-performance, low-overhead Linux endpoint telemetry collector built on pure eBPF tracepoints and `/proc` state snapshots. Emits standardized, database-independent telemetry envelopes formatted as JSON Lines (JSONL).

---

## 1. Project Context

Q-EDR is an open-source endpoint detection and response system for Linux consisting of five core components:

1. **Linux Endpoint Telemetry Collector (`edge-agent`)** *(This Component)*: In-kernel eBPF observation, `/proc` inventory, and standardized schema normalization.
2. **Edge Agent Engine**: Local telemetry correlation and low-latency anomaly detection.
3. **Cloud & Multi-Agent Analysis**: Distributed graph construction and alert clustering.
4. **LLM Evidence Explanation**: Automated root-cause narration and threat intelligence mapping.
5. **Orchestration & Infrastructure**: Scalable fleet deployment and policy management.

This component collects raw kernel and subsystem activity and normalizes it into a **database-independent data contract** ready for relational, analytical, graph, or document storage tiers.

---

## 2. Telemetry Coverage

The collector implements real-time eBPF event tracking and point-in-time state snapshots across **four operational categories**:

| Category | Real-Time Events (eBPF) | Periodic / Startup Snapshot (`/proc`) |
|---|---|---|
| **Process** | `process.exec`, `process.fork`, `process.exit` | `process.snapshot` (full process inventory, threads, RSS, state) |
| **Network** | `network.connect`, `network.accept`, `network.bind`, `network.close` | `network.snapshot` (listening ports, active sockets, inodes) |
| **IPC** | `ipc.pipe_create`, `ipc.socketpair_create`, `ipc.shm_get`, `ipc.msg_send`, `ipc.sem_op` | `ipc.snapshot` (SysV SHM, message queues, semaphores) |
| **Filesystem** | `filesystem.open`, `filesystem.create`, `filesystem.write` *(metadata only)*, `filesystem.rename`, `filesystem.unlink`, `filesystem.mkdir`, `filesystem.chmod`, `filesystem.chown` | `filesystem.snapshot` (active filesystem mounts) |

---

## 3. Data Contract & Envelope Model

Every record emitted is a self-contained JSON Line adhering to the **Q-EDR Common Envelope (v1.0.0)**:

```json
{
  "schema_version": "1.0.0",
  "event_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "event_type": "process.exec",
  "event_time": "2026-10-23T15:04:05.123456Z",
  "observed_time": "2026-10-23T15:04:05.124000Z",
  "collection_mode": "event",
  "host": {
    "host_id": "c128c773-8ff4-44b2-a4f6-8c6f11223344",
    "hostname": "prod-web-01",
    "boot_id": "d98341e2-b112-4011-9a7f-382947192837",
    "os": "linux",
    "architecture": "x86_64",
    "kernel_release": "6.8.0-40-generic"
  },
  "source": {
    "collector": "q-edr-linux-collector",
    "collector_version": "0.1.0",
    "mechanism": "ebpf",
    "probe": "sched_process_exec"
  },
  "actor": {
    "pid": 14521,
    "tid": 14521,
    "ppid": 14500,
    "uid": 1000,
    "gid": 1000,
    "comm": "curl",
    "exe": "/usr/bin/curl",
    "cmdline": ["curl", "-s", "https://example.com/api/v1/health"],
    "process_start_time_ns": 1729695845123456000,
    "process_entity_id": "4f9a7218b0e123fa4891b2c3d4e5f6a7",
    "parent_entity_id": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"
  },
  "data": {
    "filename": "/usr/bin/curl",
    "argv": ["curl", "-s", "https://example.com/api/v1/health"],
    "ret_code": 0
  },
  "quality": {
    "timestamp_source": "kernel_boot_ns"
  }
}
```

### PID Reuse Defense: Process Entity ID
To avoid attribution flaws when the Linux kernel recycles PIDs, the collector calculates a 128-bit deterministic entity identifier for every process:
$$\text{ProcessEntityID} = \text{Truncate}_{32}(\text{SHA256}(\text{boot\_id} \mathbin{\Vert} \text{pid} \mathbin{\Vert} \text{start\_time\_ns}))$$

---

## 4. Building & Running

### Requirements
* **Compilation:** Go 1.22+ (Compiles on macOS, Linux, or Windows).
* **Execution:** Linux Kernel $\ge 5.10$ with root or `CAP_BPF` + `CAP_PERFMON` privileges.

### Build Targets

```bash
# Build for host OS
make build

# Cross-compile standalone static Linux binary (amd64)
make build-linux

# Cross-compile standalone static Linux binary (arm64)
make build-linux-arm64

# Run all unit and serialization tests
make test
```

### Running the Collector

```bash
# Run with stdout output (default)
sudo ./bin/q-edr-collector-linux-amd64

# Stream events to a JSONL log file
sudo ./bin/q-edr-collector-linux-amd64 -output=/var/log/q-edr/events.jsonl

# Selectively enable specific categories and set snapshot interval
sudo ./bin/q-edr-collector-linux-amd64 \
  -process=true \
  -network=true \
  -ipc=true \
  -filesystem=false \
  -snapshot-interval=30s
```

### Command-Line Flags

| Flag | Default | Description |
|---|---|---|
| `-output` | `"-"` | Output destination: `"-"` for stdout, or file path. |
| `-process` | `true` | Enable/disable process telemetry. |
| `-network` | `true` | Enable/disable network telemetry. |
| `-ipc` | `true` | Enable/disable IPC telemetry. |
| `-filesystem` | `true` | Enable/disable filesystem telemetry. |
| `-snapshot-interval`| `60s` | Frequency of periodic state inventory scans (`0` to disable). |
| `-snapshot-on-startup` | `true` | Perform initial inventory snapshot at startup. |
| `-redact-cmdline` | `false` | Redact command line arguments for privacy compliance. |
| `-buffer-size` | `256` | Event queue channel buffer depth. |
| `-log-level` | `"info"` | Diagnostic log level (`debug`, `info`, `warn`, `error`). Always routed to `stderr`. |
| `-version` | | Display version information and exit. |

---

## 5. Repository Layout

```
edge-agent/
├── cmd/collector/main.go          # CLI entry point, signal handling, pipeline assembly
├── internal/
│   ├── collector/                 # Collector interface & manager
│   │   ├── process/               # Process collector (eBPF + /proc)
│   │   ├── network/               # Network collector (eBPF + /proc/net)
│   │   ├── ipc/                   # IPC collector (eBPF + /proc/sysvipc)
│   │   └── filesystem/            # Filesystem collector (eBPF + /proc/mounts)
│   ├── config/                    # CLI flags & validation
│   ├── envelope/                  # Common event envelope & JSON marshaling
│   ├── host/                      # Host identity (/etc/machine-id, boot_id)
│   ├── identity/                  # Process entity ID generator
│   ├── metrics/                   # Atomic drop counters & quality statistics
│   └── output/                    # Buffered JSONL writer
├── bpf/                           # eBPF C probe source code
│   ├── headers/                   # Vendored Linux & BPF helper headers
│   ├── common.h                   # Shared C struct binary ABI definitions
│   ├── process.bpf.c              # Sched tracepoint probes
│   ├── network.bpf.c              # Socket state transition & bind probes
│   ├── ipc.bpf.c                  # Syscall tracepoints for pipe, socketpair, SysV
│   └── filesystem.bpf.c           # Syscall tracepoints for openat, write, rename
├── schemas/                       # Formal JSON Schemas (Draft-07)
│   ├── envelope.schema.json       # Envelope schema
│   ├── process.schema.json        # Process payload schema
│   ├── network.schema.json        # Network payload schema
│   ├── ipc.schema.json            # IPC payload schema
│   └── filesystem.schema.json     # Filesystem payload schema
├── docs/                          # Architecture & contract documentation
│   ├── event-contract.md          # Complete data contract for storage developers
│   ├── architecture.md            # Architecture Decision Records (ADRs)
│   └── capability-matrix.md       # Kernel & feature compatibility matrix
├── examples/
│   └── sample-events.jsonl        # Verified synthetic example records
├── Makefile                       # Cross-compilation & test automation
└── go.mod                         # Go module dependencies
```

---

## 6. Detailed Documentation

* [Telemetry Data Contract (for Database & Storage Teams)](file:///Users/abhinav/Desktop/Q-EDR/edge-agent/docs/event-contract.md)
* [Architecture Decision Records & Design Choices](file:///Users/abhinav/Desktop/Q-EDR/edge-agent/docs/architecture.md)
* [Kernel & Capability Matrix](file:///Users/abhinav/Desktop/Q-EDR/edge-agent/docs/capability-matrix.md)
