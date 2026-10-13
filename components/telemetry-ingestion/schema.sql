
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id UUID PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source VARCHAR NOT NULL,
    synthetic BOOLEAN NOT NULL,
    event_type VARCHAR NOT NULL,
    process_id BIGINT,
    process_name VARCHAR,
    file_path VARCHAR,
    destination_ip VARCHAR,
    destination_port INTEGER,
    ingested_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
