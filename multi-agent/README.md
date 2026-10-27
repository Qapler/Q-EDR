# Q-EDR Graph-Native Threat Detection Engine

A production-grade, graph-native rule-based threat detection engine designed for Endpoint Detection and Response (EDR) and security operations. It directly queries a Neo4j graph threat model to detect advanced persistent threats (APTs), lateral movement, privilege escalation, credential access, ransomware, and command & control activity.

---

## 🌟 Key Features

- **Direct Graph Threat Model Analysis**: Rules execute high-performance Cypher queries across multi-hop relationships (`SPAWNED`, `CONNECTED_TO`, `ACCESSED`, `AUTHENTICATED_TO`, `WRITES`, `CREATED`).
- **69 Production Detection Rules**: Aligned with all 10 core MITRE ATT&CK enterprise tactics.
- **Enterprise Alert Pipeline**:
  - Time-windowed alert deduplication (configurable window, default 300s).
  - Rule suppression lists (silence benign noisy scripts without code changes).
  - Contextual entity enrichment (IPs, SIDs, hostnames, MITRE technique URLs).
  - Append-only JSONL file storage (`alerts.jsonl`) + optional Neo4j alert node persistence.
- **High Concurrency & Resilience**:
  - Configurable thread-pool parallel rule execution.
  - Per-rule timeout enforcement (prevents slow or runaway queries from stalling the engine).
  - Connection pooling with automatic reconnection and retry logic.
- **Full Observability Stack**:
  - Structured JSON logging with context (`timestamp`, `level`, `rule_id`, `severity`, `elapsed_ms`).
  - Prometheus metrics (rules executed, rules matched, alerts generated, scan duration, rule errors) with thread-safe in-process fallback.
  - Composite Health Check with HTTP daemon (`/health`, `/ready`, `/metrics`).
- **Offline Simulation Mode**: Run, test, and demonstrate live detections without needing an active Neo4j cluster running.

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THREAT DETECTION ENGINE                         │
│                                                                        │
│  ┌──────────────┐     ┌────────────────┐     ┌──────────────────────┐  │
│  │   Neo4j DB   │────▶│ ThreatDetector │────▶│     AlertManager     │  │
│  │ (Graph Model)│     │ (Parallel Loop)│     │(Dedup/Enrich/Persist)│  │
│  └──────────────┘     └────────────────┘     └──────────────────────┘  │
│         ▲                     ▲                         │              │
│         │                     │                         ▼              │
│  ┌──────────────┐     ┌────────────────┐     ┌──────────────────────┐  │
│  │ GraphSeeder  │     │  RuleRegistry  │     │   alerts.jsonl /     │  │
│  │ (12 Scenarios│     │  (69 Rules)    │     │   Neo4j Alert Nodes  │  │
│  └──────────────┘     └────────────────┘     └──────────────────────┘  │
│                               ▲                         │              │
│                               │                         ▼              │
│                       ┌────────────────┐     ┌──────────────────────┐  │
│                       │ EngineMetrics  │◀────│     HealthCheck      │  │
│                       │  (Prometheus)  │     │(HTTP :8001 /health)  │  │
│                       └────────────────┘     └──────────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Rule Catalog (69 Rules Across 10 Categories)

| Category | Count | Severities | Key MITRE Techniques Detected |
|---|---|---|---|
| **Lateral Movement** | 8 | CRITICAL / HIGH | Pass-the-Hash (T1550.002), RDP Lateral Movement (T1021.001), SMB Admin Shares (T1021.002), WMI Remote Exec (T1047), SSH Key Hopping (T1021.004), PsExec (T1569.002), DCOM (T1021.003), Remote Tasks (T1053.005) |
| **Privilege Escalation** | 7 | CRITICAL / HIGH | Sudo Abuse (T1548.003), Token Impersonation (T1134.001), Memory Injection (T1055), SUID Exploitation (T1548.001), Service Binary Replacement (T1574.010), Unquoted Service Paths (T1574.009), PrintSpooler (T1068) |
| **Persistence** | 8 | CRITICAL / HIGH | Suspicious Scheduled Tasks (T1053.005), Registry Run Keys (T1547.001), Web Shell Creation (T1505.003), Startup Folder Items (T1547.001), Backdoor Admin Accounts (T1098), Cron Jobs (T1053.003), BITS Jobs (T1197), DLL Sideloading (T1574.002) |
| **Credential Access** | 8 | CRITICAL / HIGH | LSASS Memory Dumping (T1003.001), Kerberoasting (T1558.003), Password Spraying (T1110.003), Brute Force (T1110.001), Credential Stuffing (T1110.004), SAM Database Access (T1003.002), Keylogging APIs (T1056.001), NTDS.dit Active Directory Dump (T1003.003) |
| **Defense Evasion** | 7 | CRITICAL / HIGH | Event Log Clearing (T1070.001), Timestomping (T1070.006), Process Masquerading (T1036.005), AMSI Bypass (T1562.001), Mass Artifact Deletion (T1070), Obfuscated Commands (T1027), Windows Firewall Disable (T1562.004) |
| **Discovery** | 6 | HIGH / MEDIUM | Network Port Scanning (T1046), Account Discovery (T1087.002), System Info Enumeration (T1082), Network Share Enumeration (T1135), Active Directory LDAP Recon (T1018), Internal Subnet Scanning (T1046) |
| **Exfiltration** | 6 | CRITICAL / HIGH | Large Outbound Data Transfer (T1048), DNS Tunneling Exfiltration (T1048.001), Exfiltration over C2 (T1041), Suspicious HTTPS POST (T1048.002), Cloud Storage Uploads (T1567.002), Archive & Immediate Transfer (T1560.001) |
| **Execution** | 7 | CRITICAL / HIGH | PowerShell Encoded Commands (T1059.001), Living-off-the-Land (LOLBins) (T1218), WMI Process Spawning (T1047), Office Macro Shell Spawns (T1204.002), Multi-Stage Interpreters (T1059.005), .NET Assembly Injection (T1620), rundll32 Abuse (T1218.011) |
| **Command & Control** | 6 | HIGH / MEDIUM | Periodic Beaconing (T1071.001), Domain Fronting (T1090.004), C2 over DNS (T1071.004), Proxy Tunneling (T1090.001), Non-Standard Port Protocols (T1571), Encrypted Channel to Untrusted Domain (T1573) |
| **Impact** | 6 | CRITICAL / HIGH / MED | Ransomware File Encryption (T1486), Shadow Copy Deletion (T1490), Critical Service Termination (T1489), Mass File Deletion / Wiper (T1485), Master Boot Record / Disk Wipe (T1561.001), Web Server Defacement (T1491.001) |

---

## 🚀 Quickstart & CLI Commands

The engine includes a full CLI entry point in `main.py`:

### 1. List All Detection Rules
```bash
python main.py rules
```
Filter by category or severity:
```bash
python main.py rules --category credential_access
python main.py rules --severity CRITICAL
```

### 2. Run a One-Off Detection Scan
Run against your configured Neo4j database:
```bash
python main.py scan
```
Run in dry-run mode (does not persist alerts):
```bash
python main.py scan --dry-run
```
Run against offline simulated attack graph:
```bash
python main.py scan --simulate
python main.py scan --simulate --scenario ransomware
python main.py scan --simulate --scenario lateral_movement
```

### 3. Run the Automated Test Suite
Executes all 48 unit and integration tests:
```bash
python main.py test
```
Or directly via unittest:
```bash
python -m unittest discover -s threat_engine/tests
```

### 4. Check Health & Observability
```bash
python main.py health
python main.py health --simulate
```

### 5. Start Continuous Detection Daemon
Runs continuous background scans every 60s and hosts the HTTP health server on `:8001`:
```bash
python main.py start --interval 60 --health-port 8001
```

### 6. Apply Graph Database Schema
Creates all uniqueness constraints and secondary indexes in Neo4j:
```bash
python main.py schema
```

### 7. Seed Synthetic Attack Graph Data
Seeds realistic attack paths into Neo4j for detection validation:
```bash
python main.py seed --clear
```

---

## ⚙️ Configuration Reference

Settings can be specified via environment variables or `.env`:

| Environment Variable | Default | Description |
|---|---|---|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j Bolt connection URI |
| `NEO4J_USERNAME` | `neo4j` | Database username |
| `NEO4J_PASSWORD` | `password` | Database password |
| `NEO4J_DATABASE` | `neo4j` | Target database name |
| `NEO4J_POOL_SIZE` | `50` | Maximum connection pool size |
| `SCAN_INTERVAL_SECONDS` | `60` | Background scan interval in seconds |
| `RULE_TIMEOUT_SECONDS` | `30` | Per-rule wall-clock timeout |
| `MAX_WORKERS` | `10` | Parallel thread pool worker count |
| `ALERT_DEDUP_WINDOW_SECONDS` | `300` | Alert deduplication window in seconds |
| `ALERT_OUTPUT_FILE` | `alerts.jsonl` | Local alert output file path |
| `HEALTH_PORT` | `8001` | HTTP Health endpoint port |
| `METRICS_PORT` | `8000` | Prometheus metrics port |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `LOG_FORMAT` | `json` | Log format: `json` or `text` |
| `DRY_RUN` | `false` | If true, evaluates rules without persisting alerts |

---

## 📊 Graph Schema Threat Model

The engine operates over the following graph model:

### Node Labels
- `Process` (`pid`, `name`, `command_line`, `path`, `username`, `integrity_level`, `timestamp`)
- `Host` (`ip`, `hostname`, `os`, `is_external`)
- `NetworkConnection` (`src_ip`, `dst_ip`, `dst_port`, `protocol`, `direction`, `bytes_sent`, `timestamp`)
- `File` (`name`, `path`, `extension`, `size_bytes`, `timestamp`)
- `User` (`username`, `sid`, `is_admin`)
- `Service` (`name`, `state`, `binary_path`)
- `RegistryKey` (`path`, `value`, `value_type`, `timestamp`)
- `DNSQuery` (`query_name`, `query_type`, `response`, `timestamp`)
- `Alert` (`alert_id`, `rule_id`, `severity`, `status`, `occurrence_count`)

### Relationships
- `(Process)-[:SPAWNED]->(Process)`
- `(Process)-[:CONNECTED_TO]->(NetworkConnection)`
- `(Host)-[:CONNECTED_TO]->(NetworkConnection)-[:CONNECTED_TO]->(Host)`
- `(Process)-[:ACCESSED]->(Process)`
- `(Process)-[:CREATED | MODIFIED | DELETED]->(File)`
- `(Process)-[:WRITES]->(RegistryKey)`
- `(Host)-[:HAS_PROCESS]->(Process)`
- `(Host)-[:OWNS]->(Service)`
- `(Host)-[:TRIGGERED]->(DNSQuery)`
