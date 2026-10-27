import json
from datetime import datetime
from typing import Any


SUPPORTED_EVENT_PREFIXES = (
    "process.",
    "filesystem.",
    "file.",
    "network.",
    "ipc.",
)


def _validate_timestamp(value: Any, field: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO timestamp string")

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Invalid timestamp in {field}") from exc

    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("Event must be a JSON object")

    required = {
        "schema_version",
        "event_id",
        "event_type",
        "observed_time",
        "collection_mode",
        "host",
        "source",
        "data",
    }

    missing = required - event.keys()
    if missing:
        raise ValueError(f"Missing required fields: {sorted(missing)}")

    if not isinstance(event["event_id"], str) or not event["event_id"].strip():
        raise ValueError("event_id must be a non-empty string")

    event_type = event["event_type"]
    if not isinstance(event_type, str) or not event_type.startswith(
        SUPPORTED_EVENT_PREFIXES
    ):
        raise ValueError(f"Unsupported event_type: {event_type!r}")

    for field in ("host", "source", "data"):
        if not isinstance(event[field], dict):
            raise ValueError(f"{field} must be a JSON object")

    actor = event.get("actor")
    if actor is not None and not isinstance(actor, dict):
        raise ValueError("actor must be an object or null")

    quality = event.get("quality")
    if quality is not None and not isinstance(quality, dict):
        raise ValueError("quality must be an object or null")

    if not event["host"].get("host_id"):
        raise ValueError("host.host_id is required")

    for field in ("event_time", "observed_time"):
        if field in event and event[field] is not None:
            _validate_timestamp(event[field], field)

    if event.get("observed_time") is None:
        raise ValueError("observed_time is required")

    # Ensure the entire event is JSON-serializable.
    # Return a copy so the caller's original object is not mutated.
    normalized = json.loads(json.dumps(event))

    # Preserve the source contract; do not rename its fields.
    normalized.setdefault("quality", {})
    return normalized


def parse_jsonl(payload: str) -> list[dict[str, Any]]:
    events = []

    for line_number, line in enumerate(payload.splitlines(), start=1):
        if not line.strip():
            continue

        try:
            event = json.loads(line)
            events.append(normalize_event(event))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(
                f"Invalid event on JSONL line {line_number}: {exc}"
            ) from exc

    return events
