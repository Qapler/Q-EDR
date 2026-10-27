import json
from pathlib import Path

import pytest

from normalizer import normalize_event, parse_jsonl


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.mark.parametrize(
    "filename",
    ["process.json", "file.json", "network.json", "ipc.json"],
)
def test_example_events_are_valid(filename):
    event = json.loads((EXAMPLES / filename).read_text())
    normalized = normalize_event(event)

    assert normalized["event_id"] == event["event_id"]
    assert normalized["event_type"] == event["event_type"]
    assert normalized["data"] == event["data"]


def test_missing_event_id_is_rejected():
    event = json.loads((EXAMPLES / "process.json").read_text())
    event.pop("event_id")

    with pytest.raises(ValueError, match="Missing required fields"):
        normalize_event(event)


def test_jsonl_parses_multiple_events():
    first = json.loads((EXAMPLES / "process.json").read_text())
    second = json.loads((EXAMPLES / "network.json").read_text())

    result = parse_jsonl(
        json.dumps(first) + "\n" + json.dumps(second) + "\n"
    )

    assert len(result) == 2


def test_invalid_jsonl_is_rejected():
    with pytest.raises(ValueError, match="line 1"):
        parse_jsonl("{invalid-json}")
