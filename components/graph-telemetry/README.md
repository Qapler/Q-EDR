# Q-EDR Graph Telemetry

A telemetry ingestion component that validates host events, processes them in batches, and stores them in a Neo4j graph database.

## Architecture

```text
Telemetry Producer
       ↓
HTTP Consumer API
       ↓
Normalizer → Buffer → Graph Writer
                         ↓
                    Neo4j Graph DB
```

- **Consumer API:** Receives telemetry events over HTTP.
- **Normalizer:** Validates and standardizes event structures.
- **Buffer:** Queues events for batch processing.
- **Graph Writer:** Stores events and their relationships in Neo4j.

## Supported Event Examples

- Process: `process.exec`
- Filesystem: `filesystem.open`
- Network: `network.connect`
- IPC: `ipc.pipe_create`

The examples demonstrate supported event categories. Compatibility with all external edge-agent events must be verified separately.

## Project Structure

```text
graph-telemetry/
├── consumer_api.py
├── normalizer.py
├── buffer.py
├── graph_writer.py
├── config.py
├── main.py
├── schema/
├── examples/
└── tests/
```

## Requirements

- Python 3
- A reachable Neo4j database

## Setup

From the repository root:

```bash
cd components/graph-telemetry
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Configure your Neo4j credentials in `.env`. Never commit real credentials.

## Run the API

From the `components/graph-telemetry` directory:

```bash
PYTHONPATH="$PWD" python -m uvicorn consumer_api:app --host 127.0.0.1 --port 8000
```

## API Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/events` | Submit one event |
| POST | `/events/batch` | Submit a batch |
| POST | `/events/jsonl` | Submit newline-delimited JSON |

The JSONL endpoint expects `Content-Type: text/plain`.

## Testing

Run unit tests:

```bash
PYTHONPATH="$PWD" python -m pytest -q tests/
```

Check Neo4j connectivity:

```bash
python test_connection.py
```

Run the graph-writing test:

```bash
python test_graph_write.py
```

## Current Status

- HTTP ingestion pipeline implemented.
- Neo4j connectivity and graph writing tested locally.
- 12 unit tests passing.
- Four example events verified through local JSONL ingestion.

## Future Work

- Add a WebSocket receiver for live edge-agent telemetry.
- Validate compatibility with actual edge-agent events.
- Define the downstream graph/capsule output interface.

**Note:** WebSocket support is not implemented in the current version. Local test success does not guarantee compatibility with every external event type.
