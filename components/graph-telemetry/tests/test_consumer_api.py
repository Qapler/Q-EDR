
import json
from pathlib import Path

import pytest

from normalizer import normalize_event


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def test_process_example_is_valid():
    event = json.loads((EXAMPLES / "process.json").read_text())
    normalized = normalize_event(event)

    assert normalized["event_id"] == event["event_id"]
    assert normalized["event_type"] == event["event_type"]


def test_invalid_event_is_rejected_by_normalizer():
    with pytest.raises(ValueError):
        normalize_event({"event_type": "unknown"})
