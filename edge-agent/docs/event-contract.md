# Q-EDR Telemetry Data Contract & Event Specification

> **Version:** 1.0.0  
> **Status:** Standard  
> **Target Audience:** Database & Storage Engineers, Detection Engineers, Analytics Developers  

---

## 1. Overview & Contract Philosophy

This document defines the formal, **storage-agnostic data contract** emitted by the Q-EDR Linux Endpoint Telemetry Collector (`edge-agent`).

The collector produces a continuous stream of structured records formatted as **JSON Lines (JSONL)**. To support arbitrary storage architectures—including relational databases (PostgreSQL, SQLite), analytical columnar engines (ClickHouse, DuckDB), graph databases (Neo4j, Memgraph), or document stores (OpenSearch, MongoDB)—the data contract adheres to five foundational design principles:

1. **Self-Describing Envelope:** Every event shares an identical, strict root envelope containing event metadata, host identity, provenance, and actor process context.
2. **Explicit Event Typing:** Events use a two-level hierarchical dot-notation (`category.operation`, e.g., `process.exec`, `network.connect`).
3. **Decoupled Telemetry Payload:** Category-specific details reside exclusively in the `data` sub-object, keeping envelope parsing uniform.
4. **PID Reuse Immunity:** Every process is assigned a globally unique, deterministic `process_entity_id` derived from the boot UUID, PID, and process start time.
5. **Dual Timestamping:** Every record captures both when the kernel executed the operation (`event_time`) and when user-space processed it (`observed_time`).

---

## 2. Common Event Envelope Specification

Every JSON line emitted adheres to the following root contract:

```json
{
  "schema_version": "1.0.0",
  "event_id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
  "event_type": "process.exec",
  "event_time": "2026-10-23T15:04:05.123456Z",
  "observed_time": "2026-10-23T15:04:05.124000Z",
  "collection_mode": "event",
  "host": { ... },
  "source": { ... },
  "actor": { ... },
  "data": { ... },
  "quality": { ... }
}
```

### 2.1 Envelope Field Descriptions

| Field | Type | Required | Description | Database Mapping Hint |
|---|---|---|---|---|
| `schema_version` | String | Yes | SemVer of the event contract format (e.g. `"1.0.0"`). | Constant column or partition filter. |
| `event_id` | String (UUID) | Yes | Globally unique UUIDv4 identifying this record instance. | Primary Key in RDBMS / Document ID. |
| `event_type` | String | Yes | Category and action (e.g., `process.exec`). | Partition key / Indexed enum column. |
| `event_time` | String (ISO 8601) | Optional | UTC wall-clock time when the event occurred in the kernel. `null` only for static snapshots where kernel time is unavailable. | Time-series partition key, B-tree index. |
| `observed_time` | String (ISO 8601) | Yes | UTC wall-clock time when collector processed the event. | Secondary time index / ingestion lag tracking. |
| `collection_mode` | String | Yes | `"event"` (real-time eBPF) or `"snapshot"` (point-in-time /proc scan). | Filter flag / Partition dimension. |
| `host` | Object | Yes | Persistent machine and OS metadata. | Foreign Key to `hosts` table. |
| `source` | Object | Yes | Collector identity and probe mechanism. | Diagnostics and pipeline auditing. |
| `actor` | Object | Optional | Subject process initiating the action. `null` for system-wide background tasks. | Foreign Key to `processes` table / Graph `(Process)` node. |
| `data` | Object | Yes | Category-specific payload (see Section 4). | Typed JSONB column, normalized child table, or graph edge properties. |
| `quality` | Object | Optional | Reliability metrics, dropped counter, truncation reason. | Health auditing. |

---

## 3. Core Entities & Identity Model

### 3.1 Host Identity (`host`)

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `host_id` | String | Yes | Machine identity (from `/etc/machine-id` or D-Bus). | `"c128c773-8ff4-44b2-a4f6-8c6f11223344"` |
| `hostname` | String | Yes | Hostname at event time. | `"prod-web-01"` |
| `boot_id` | String (UUID) | Yes | Kernel boot UUID (`/proc/sys/kernel/random/boot_id`). Changes on reboot. | `"d98341e2-b112-4011-9a7f-382947192837"` |
| `os` | String | Yes | Operating system identifier. | `"linux"` |
| `architecture` | String | Yes | Hardware CPU architecture. | `"x86_64"`, `"aarch64"` |
| `kernel_release` | String | Yes | Linux kernel release string (`uname -r`). | `"6.8.0-40-generic"` |

### 3.2 Process Entity Identity (`actor`)

Linux PIDs are recycled by the kernel (maximum PID is typically 32,768 or 4,194,304). Relying on PID alone causes critical misattribution in long-running storage. Q-EDR resolves this by generating a deterministic **Process Entity ID**:

$$\text{ProcessEntityID} = \text{Truncate}_{32}(\text{SHA256}(\text{boot\_id} \mathbin{\Vert} \text{pid} \mathbin{\Vert} \text{start\_time\_ns}))$$

| Field | Type | Required | Description | Example |
|---|---|---|---|---|
| `pid` | Integer | Yes | OS Process ID in root namespace. | `14521` |
| `tid` | Integer | Optional | OS Thread ID. | `14521` |
| `ppid` | Integer | Optional | Parent Process ID. | `14500` |
| `uid` | Integer | Yes | Real User ID. | `1000` |
| `gid` | Integer | Yes | Real Group ID. | `1000` |
| `euid` | Integer | Optional | Effective User ID (when setuid invoked). | `0` |
| `egid` | Integer | Optional | Effective Group ID. | `0` |
| `comm` | String | Yes | Short comm name from `task_struct` ($\le 16$ chars). | `"curl"` |
| `exe` | String | Optional | Absolute executable path from `/proc/[pid]/exe`. | `"/usr/bin/curl"` |
| `cmdline` | Array[String] | Optional | Command-line arguments. | `["curl", "-s", "https://api.internal/"]` |
| `process_start_time_ns` | Integer | Optional | Start timestamp in nanoseconds since boot. | `1729695845123456000` |
| `process_entity_id` | String | Yes | Deterministic unique instance identifier. | `"4f9a7218b0e123fa4891b2c3d4e5f6a7"` |
| `parent_comm` | String | Optional | Short name of parent process. | `"bash"` |
| `parent_entity_id` | String | Optional | Deterministic unique parent identifier. | `"1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"` |
| `cgroup_path` | String | Optional | Relative cgroup path (v1 or v2). | `"/user.slice/user-1000.slice"` |

---

## 4. Telemetry Event Taxonomy & Payloads

### 4.1 Process Telemetry (`process.*`)

#### `process.exec`
Triggered when a thread executes a new program via `execve` / `execveat`. Hook: `sched/sched_process_exec`.
* Payload (`data`):
  * `filename` (string, required): Binary path provided to execve.
  * `argv` (array of strings, optional): Command line arguments.
  * `envp` (array of strings, optional): Environment variables (if enabled).
  * `ret_code` (integer, optional): System call return code (0 = success).

#### `process.fork`
Triggered when a process creates a child via `clone`, `clone3`, `fork`, or `vfork`. Hook: `sched/sched_process_fork`.
* Payload (`data`):
  * `child_pid` (integer, required): PID of newly created child.
  * `child_tid` (integer, optional): TID of newly created thread.
  * `child_comm` (string, optional): Short name of the child.
  * `child_entity_id` (string, required): Unique Entity ID for child.
  * `clone_flags` (integer, optional): Bitmask of clone flags.
  * `clone_flags_desc` (string, optional): Human-readable clone flags (`"CLONE_VM|CLONE_FS"`).

#### `process.exit`
Triggered when a task terminates. Hook: `sched/sched_process_exit`.
* Payload (`data`):
  * `exit_code` (integer, required): Process exit code.
  * `signal` (integer, optional): Terminating signal number (0 if clean exit).
  * `signal_desc` (string, optional): Signal name (e.g. `"SIGTERM"`, `"SIGKILL"`).
  * `duration_ns` (integer, optional): Total process lifespan in nanoseconds.

#### `process.snapshot`
Point-in-time inventory of a running process from `/proc/[pid]/`.
* Payload (`data`):
  * `state` (string, required): Single letter state code (`"R"`, `"S"`, `"D"`, `"Z"`, `"T"`).
  * `state_desc` (string, required): Full description (`"running"`, `"sleeping"`, `"zombie"`).
  * `threads` (integer, required): Active thread count.
  * `vm_size_kb` (integer, optional): Virtual memory size in KiB.
  * `vm_rss_kb` (integer, optional): Resident set size in KiB.
  * `open_fds` (integer, optional): Total open file descriptors count.
  * `cmdline` (array of strings, optional): Command line arguments.
  * `cgroup_path` (string, optional): Control group path.

---

### 4.2 Network Telemetry (`network.*`)

#### `network.connect`
Outbound TCP/UDP connection initiation. Hook: `sock/inet_sock_set_state` (SYN_SENT) or `syscalls/sys_enter_connect`.
* Payload (`data`):
  * `family` (string, required): `"ipv4"` or `"ipv6"`.
  * `protocol` (string, required): `"tcp"` or `"udp"`.
  * `direction` (string, required): `"outbound"`.
  * `local_addr` (string, required): Local IP address.
  * `local_port` (integer, required): Local port.
  * `remote_addr` (string, required): Destination IP address.
  * `remote_port` (integer, required): Destination port.
  * `socket_fd` (integer, optional): Socket file descriptor.
  * `ret_code` (integer, optional): Return code.

#### `network.accept`
Inbound TCP connection accepted by listening socket. Hook: `sock/inet_sock_set_state` (ESTABLISHED on passive socket).
* Payload (`data`):
  * `family` (string, required): `"ipv4"` or `"ipv6"`.
  * `protocol` (string, required): `"tcp"`.
  * `direction` (string, required): `"inbound"`.
  * `local_addr` (string, required): Local listening IP.
  * `local_port` (integer, required): Listening port.
  * `remote_addr` (string, required): Remote client IP.
  * `remote_port` (integer, required): Remote client port.
  * `new_fd` (integer, optional): Newly allocated socket FD for connection.

#### `network.bind`
Socket bound to a local address/port. Hook: `syscalls/sys_enter_bind`.
* Payload (`data`):
  * `family` (string, required): `"ipv4"`, `"ipv6"`, or `"unix"`.
  * `protocol` (string, required): `"tcp"` or `"udp"`.
  * `addr` (string, required): Address bound to (`"0.0.0.0"`, `"::"`, etc.).
  * `port` (integer, required): Port bound.
  * `socket_fd` (integer, optional): Bound socket FD.

#### `network.close`
Socket closed / connection terminated. Hook: `sock/inet_sock_set_state` transition to `TCP_CLOSE`.
* Payload (`data`):
  * `family` (string, required): `"ipv4"` or `"ipv6"`.
  * `protocol` (string, required): `"tcp"` or `"udp"`.
  * `local_addr` (string, required): Local IP.
  * `local_port` (integer, required): Local port.
  * `remote_addr` (string, required): Remote IP.
  * `remote_port` (integer, required): Remote port.
  * `old_state` (string, required): Previous TCP state (`"ESTABLISHED"`, `"CLOSE_WAIT"`).
  * `new_state` (string, required): `"CLOSE"`.

#### `network.snapshot`
Snapshot of active listening and established sockets from `/proc/net/tcp` and `/proc/net/udp`.
* Payload (`data`):
  * `family` (string, required): `"ipv4"` or `"ipv6"`.
  * `protocol` (string, required): `"tcp"` or `"udp"`.
  * `local_addr` (string, required): Local IP.
  * `local_port` (integer, required): Local port.
  * `remote_addr` (string, optional): Remote IP (`"0.0.0.0"` for listeners).
  * `remote_port` (integer, optional): Remote port (`0` for listeners).
  * `state` (string, required): `"LISTEN"`, `"ESTABLISHED"`, etc.
  * `inode` (integer, optional): Socket inode.

---

### 4.3 IPC Telemetry (`ipc.*`)

#### `ipc.pipe_create`
Creation of anonymous pipe. Hook: `syscalls/sys_exit_pipe2`.
* Payload (`data`):
  * `read_fd` (integer, required): Read file descriptor.
  * `write_fd` (integer, required): Write file descriptor.
  * `flags` (integer, optional): Creation flags (`O_CLOEXEC`, `O_NONBLOCK`).

#### `ipc.socketpair_create`
Creation of connected UNIX domain socket pair. Hook: `syscalls/sys_exit_socketpair`.
* Payload (`data`):
  * `family` (string, required): `"unix"`.
  * `type` (string, required): `"stream"`, `"dgram"`, or `"seqpacket"`.
  * `protocol` (integer, required): Protocol number.
  * `fd0` (integer, required): First socket FD.
  * `fd1` (integer, required): Second socket FD.

#### `ipc.shm_get`
System V shared memory allocation or access. Hook: `syscalls/sys_enter_shmget`.
* Payload (`data`):
  * `key` (integer, required): IPC key.
  * `shm_id` (integer, required): Shared memory ID.
  * `size` (integer, required): Memory size in bytes.
  * `shm_flg` (integer, required): Permission and creation flags.
  * `flag_desc` (string, optional): Decoded flags (`"IPC_CREAT|0666"`).

#### `ipc.msg_send`
Message sent to System V message queue. Hook: `syscalls/sys_enter_msgsnd`.
* Payload (`data`):
  * `msg_id` (integer, required): Message queue identifier.
  * `msg_type` (integer, required): Message type value.
  * `msg_size` (integer, required): Payload size in bytes.

#### `ipc.sem_op`
Operations executed on System V semaphores. Hook: `syscalls/sys_enter_semop`.
* Payload (`data`):
  * `sem_id` (integer, required): Semaphore set ID.
  * `nsops` (integer, required): Number of semaphore operations.

#### `ipc.snapshot`
Snapshot of active System V IPC resources from `/proc/sysvipc/shm`, `/proc/sysvipc/msg`, `/proc/sysvipc/sem`.
* Payload (`data`):
  * `resource_type` (string, required): `"shm"`, `"msg"`, or `"sem"`.
  * `key` (integer, required): IPC key.
  * `id` (integer, required): Resource ID.
  * `owner_uid` (integer, required): Owning User ID.
  * `permissions` (integer, required): Octal permissions.
  * `size` (integer, optional): Size in bytes (for SHM) or number of sems.
  * `num_attach` (integer, optional): Attached processes (SHM only).

---

### 4.4 Filesystem Telemetry (`filesystem.*`)

#### `filesystem.open` & `filesystem.create`
File opened for reading, writing, or creation via `openat`. Hook: `syscalls/sys_enter_openat` and exit.
* Payload (`data`):
  * `path` (string, optional): Resolved target file path.
  * `path_error` (string, optional): Set if path resolution failed in kernel.
  * `flags` (integer, required): Access mode and status flags.
  * `flags_desc` (string, optional): Human-readable flags (`"O_RDONLY"`, `"O_WRONLY|O_CREAT"`).
  * `mode` (integer, optional): Permission mode on creation.
  * `fd` (integer, optional): Assigned file descriptor.
  * `dir_fd` (integer, optional): Working directory FD (`AT_FDCWD` or directory FD).

#### `filesystem.write`
Data written to file descriptor. Hook: `syscalls/sys_enter_write` and exit. (Captures **metadata only**, never payload content).
* Payload (`data`):
  * `fd` (integer, required): File descriptor written to.
  * `count` (integer, required): Number of bytes requested to write.
  * `written` (integer, required): Number of bytes actually written (or negative errno).

#### `filesystem.rename`
File or directory renamed/moved. Hook: `syscalls/sys_enter_renameat2`.
* Payload (`data`):
  * `old_path` (string, required): Source path.
  * `new_path` (string, required): Target path.
  * `flags` (integer, optional): Rename flags (e.g. `RENAME_NOREPLACE`, `RENAME_EXCHANGE`).

#### `filesystem.unlink`
File or directory unlinked/deleted. Hook: `syscalls/sys_enter_unlinkat`.
* Payload (`data`):
  * `path` (string, required): Target path.
  * `is_dir` (boolean, required): `true` if directory removal (`AT_REMOVEDIR`), `false` for files.

#### `filesystem.mkdir`
Directory created. Hook: `syscalls/sys_enter_mkdirat`.
* Payload (`data`):
  * `path` (string, required): Created directory path.
  * `mode` (integer, required): Permissions mode.

#### `filesystem.chmod` & `filesystem.chown`
Metadata permission or ownership modifications. Hooks: `syscalls/sys_enter_fchmodat`, `sys_enter_fchownat`.
* `filesystem.chmod` Payload: `path` (string), `mode` (integer).
* `filesystem.chown` Payload: `path` (string), `owner_id` (integer), `group_id` (integer).

#### `filesystem.snapshot`
Snapshot of active mounts from `/proc/mounts`.
* Payload (`data`):
  * `device` (string, required): Source device or virtual filesystem name.
  * `mount_point` (string, required): Mount target path.
  * `fs_type` (string, required): Filesystem type (`"ext4"`, `"xfs"`, `"overlay"`, `"tmpfs"`).
  * `options` (string, optional): Mount options string (`"rw,relatime"`).

---

## 5. Storage Layer Mapping Recommendations

This section provides concrete guidance for the teammate implementing the database and storage tier.

### 5.1 Relational Storage (PostgreSQL / SQLite)

* **Normalized Table Design:**
  * `hosts (host_id PK, hostname, boot_id, os, arch, kernel_release, first_seen, last_seen)`
  * `processes (process_entity_id PK, host_id FK, pid, ppid, parent_entity_id, uid, gid, comm, exe, start_time, exit_time)`
  * `events (event_id PK, event_type, event_time, observed_time, collection_mode, host_id FK, process_entity_id FK, data JSONB)`
* **Indexes:**
  * B-Tree index on `(host_id, event_time)` for host timeline queries.
  * B-Tree index on `(process_entity_id, event_time)` for process lifecycle reconstruction.
  * GIN index on `data` in PostgreSQL for flexible JSON querying (e.g. `data->>'remote_addr'`).

### 5.2 Graph Storage (Neo4j / Memgraph)

* **Nodes:**
  * `(:Host {host_id, hostname, boot_id})`
  * `(:Process {entity_id, pid, comm, exe, start_time})`
  * `(:Socket {addr, port, protocol})`
  * `(:File {path, inode})`
* **Edges:**
  * `(:Process)-[:SPAWNED {timestamp, clone_flags}]->(:Process)`
  * `(:Process)-[:EXECUTED {timestamp, argv}]->(:File)`
  * `(:Process)-[:CONNECTED_TO {timestamp, local_port, remote_port}]->(:Socket)`
  * `(:Process)-[:MODIFIED {timestamp, operation}]->(:File)`

### 5.3 Columnar / Analytical Storage (ClickHouse / DuckDB)

* **Partitioning & Sorting:**
  * Partition by `toYYYYMM(event_time)` or `toDate(event_time)`.
  * Order by `(host_id, event_type, event_time, actor.process_entity_id)`.
* **Field Extraction:**
  * Flatten high-cardinality fields (`data.remote_addr`, `data.remote_port`, `data.path`, `actor.comm`) into dedicated typed columns for $10\times$ compression and vector search speed.

---

## 6. Schema Versioning & Evolution

1. **Semantic Versioning:** The `schema_version` field follows SemVer (`MAJOR.MINOR.PATCH`).
   * **PATCH:** Backward-compatible bug fixes or clarifications.
   * **MINOR:** New optional fields added to `envelope` or `data`. Consumers must ignore unknown fields.
   * **MAJOR:** Breaking changes (field removals, type alterations, restructuring).
2. **Forward Compatibility Rule:** Storage and ingestion consumers **must** be written to tolerate additional, unrecognized fields in JSON payloads without raising deserialization errors.
