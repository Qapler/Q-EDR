# Q-EDR Graph Telemetry

Ingests normalized host telemetry events into Neo4j.

## Requirements
- Python 3
- A reachable Neo4j database

## Setup

From this directory, create a virtual environment, install requirements, and configure `.env` using `.env.example`. Never commit `.env` or real credentials.

## Run the API

```bash
PYTHONPATH="$PWD" python -m uvicorn consumer_api:app --host 127.0.0.1 --port 8000
```

## Tests

```bash
PYTHONPATH="$PWD" python -m pytest -q tests/
```

## Endpoints
- `GET /health`
- `POST /events`
- `POST /events/batch`
- `POST /events/jsonl`

The JSONL endpoint accepts newline-delimited JSON with `Content-Type: text/plain`.

WebSocket support is not currently implemented.
