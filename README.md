# Q-EDR

An open-source, highly performant Endpoint Detection and Response (EDR) system operating autonomously on the edge and extending to cloud intelligence.

---

## Architecture Overview

Q-EDR is composed of five modular, decoupled components designed for Linux endpoint security:

1. **[Linux Endpoint Telemetry Collector (`edge-agent`)](edge-agent/)**: In-kernel eBPF probes, `/proc` inventory scanners, and schema standardization emitting JSON Lines data contracts.
2. **Edge Agent Detection Engine**: Lightweight local telemetry analysis and real-time behavioral anomaly detection.
3. **Cloud & Multi-Agent Analysis**: Distributed graph correlation and threat clustering across fleets.
4. **LLM Evidence Explanation**: Automated threat narrative generation and MITRE ATT&CK mapping.
5. **Orchestration & Infrastructure**: Automated fleet deployment, updates, and policy management.

---

## Getting Started with the Telemetry Collector

The first component—the Linux endpoint telemetry collector—is implemented in [`edge-agent/`](edge-agent/).

```bash
cd edge-agent

# Build for current OS
make build

# Cross-compile for Linux (x86_64)
make build-linux

# Run tests
make test
```

For complete documentation on the database-independent data contract, see:
* [Telemetry Data Contract](edge-agent/docs/event-contract.md)
* [Architecture Decision Records](edge-agent/docs/architecture.md)
* [Capability Matrix](edge-agent/docs/capability-matrix.md)
* [JSON Schemas](edge-agent/schemas/)
