
import json
import uuid
from datetime import datetime
from pathlib import Path

import duckdb

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parents[1]

JSON_FILE = ROOT_DIR / "components/dummy-sensor/telemetry.json"
DB_FILE = BASE_DIR / "telemetry.duckdb"
SCHEMA_FILE = BASE_DIR / "schema.sql"


def main():
    if not JSON_FILE.exists():
        raise FileNotFoundError(f"Sensor JSON not found: {JSON_FILE}")

    with JSON_FILE.open("r", encoding="utf-8") as f:
        payload = json.load(f)

    events = payload.get("events")
    if not isinstance(events, list):
        raise ValueError("JSON must contain an events array")

    with duckdb.connect(str(DB_FILE)) as con:
        con.execute(SCHEMA_FILE.read_text(encoding="utf-8"))

        con.begin()
        try:
            for event in events:
                timestamp = datetime.fromisoformat(
                    event["timestamp"].replace("Z", "+00:00")
                )

                if timestamp.tzinfo is None:
                    raise ValueError("Event timestamp must include timezone")

                con.execute(
                    """
                    INSERT INTO telemetry_events (
                        event_id, timestamp, source, synthetic,
                        event_type, process_id, process_name,
                        file_path, destination_ip, destination_port
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        str(uuid.uuid4()),
                        timestamp,
                        event["source"],
                        event["synthetic"],
                        event["event_type"],
                        event["process_id"],
                        event["process_name"],
                        event.get("file_path"),
                        event.get("destination_ip"),
                        event.get("destination_port"),
                    ],
                )

            con.commit()
        except Exception:
            con.rollback()
            raise

        count = con.execute(
            "SELECT COUNT(*) FROM telemetry_events"
        ).fetchone()[0]

        print(f"Inserted {len(events)} sensor events.")
        print(f"Total rows in database: {count}")


if __name__ == "__main__":
    main()
