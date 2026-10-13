# Q-EDR DuckDB Telemetry Pipeline

## Summary
Implemented an initial telemetry ingestion pipeline using Python and DuckDB. The pipeline consumes Daniel's dummy sensor JSON output, stores structured telemetry events in a local database, and makes them available for downstream processing by Kapil's LLM agent.

## Files Added/Modified

- `components/telemetry-ingestion/schema.sql`
  - Defines the `telemetry_events` table and its columns for process, file access, and network connection events.

- `components/telemetry-ingestion/ingest.py`
  - Reads `components/dummy-sensor/telemetry.json`.
  - Parses event timestamps and inserts telemetry events into DuckDB.
  - Uses parameterized SQL and a database transaction.
  - Prints ingestion counts for verification.

- `components/telemetry-ingestion/requirements.txt`
  - Specifies DuckDB as the Python dependency.

- `.gitignore`
  - Excludes local DuckDB database files, Python virtual environments, and Python cache files.

## Technical Stack
- **Language:** Python
- **Database:** DuckDB
- **Input format:** JSON
- **Schema definition:** SQL
- **Sensor component:** Rust
- **Database driver:** Python `duckdb` package

## Data Flow
1. **Daniel — Dummy Sensor:** Generates synthetic events in `components/dummy-sensor/telemetry.json`.
2. **Jayant — Ingestion Pipeline:** Reads the JSON file and inserts the events into the `telemetry_events` table in `components/telemetry-ingestion/telemetry.duckdb`.
3. **Kapil — LLM Agent:** Reads the process event from DuckDB and supplies it to a local LLM with the prompt: "Explain this raw process event in one sentence."

## Setup and Execution

Run these commands from the Q-EDR repository root.

### 1. Generate sensor data
Rust and Cargo must be installed.

```bash
cd components/dummy-sensor
cargo run
cd ../..
```

This generates `components/dummy-sensor/telemetry.json`.

### 2. Set up Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r components/telemetry-ingestion/requirements.txt
```

### 3. Run ingestion

```bash
python components/telemetry-ingestion/ingest.py
```

This creates or opens `components/telemetry-ingestion/telemetry.duckdb`, initializes the table using `schema.sql`, and inserts the sensor events.

### 4. Verify stored events

```bash
python -c "import duckdb; c=duckdb.connect('components/telemetry-ingestion/telemetry.duckdb', read_only=True); print(c.execute('SELECT event_type, COUNT(*) FROM telemetry_events GROUP BY event_type').fetchall()); c.close()"
```

## Instructions for Kapil

- Use the same repository and database path: `components/telemetry-ingestion/telemetry.duckdb`.
- Install the Python dependency using the setup commands above.
- Connect to DuckDB with `duckdb.connect(DB_PATH, read_only=True)`.
- Query the `telemetry_events` table and select the required process event.
- Convert the selected row into a dictionary or JSON representation before passing it to the local LLM.
- Use the prompt: `Explain this raw process event in one sentence.`

**Important:** The current event type is `process_start`, not `ProcessCreate`. Kapil's SQL query must use `process_start` unless the team agrees to change the event naming convention.

The DuckDB database file is intentionally excluded from Git. If Kapil is working in a separate clone, he must generate the sensor JSON and run the ingestion script locally, or obtain the database through an agreed shared mechanism.

## Validation
- Successfully generated dummy sensor JSON using Daniel's Rust component.
- Successfully ingested three synthetic events.
- Verified one event each for `process_start`, `file_access`, and `network_connection`.

## Scope and Limitations
- Initial schema and basic ingestion only.
- No Thread Graph integration.
- No real host telemetry collection.
- Repeated ingestion currently generates new UUIDs and may create duplicate logical events; deduplication is not yet implemented.
