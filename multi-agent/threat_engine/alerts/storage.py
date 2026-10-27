"""
Storage backends for alerts (local append-only JSONL file and Neo4j graph storage).
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional
from .models import Alert

logger = logging.getLogger(__name__)


class AlertFileStorage:
    """Persists alerts to an append-only JSONL file."""

    def __init__(self, file_path: str = "alerts.jsonl") -> None:
        self.file_path = file_path
        # Ensure parent dir exists
        parent = os.path.dirname(file_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def append(self, alert: Alert) -> None:
        """Append an alert record to the JSONL file."""
        try:
            line = json.dumps(alert.to_dict()) + "\n"
            with open(self.file_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as exc:
            logger.error(f"Failed to write alert to file {self.file_path}: {exc}", exc_info=True)

    def read_all(self) -> List[Dict[str, Any]]:
        """Read all alert records from the JSONL file."""
        if not os.path.exists(self.file_path):
            return []
        records = []
        try:
            with open(self.file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        records.append(json.loads(line))
        except Exception as exc:
            logger.error(f"Failed to read alerts from file {self.file_path}: {exc}", exc_info=True)
        return records


class AlertGraphStorage:
    """Optionally stores Alert nodes directly in the Neo4j graph for graph correlation."""

    def __init__(self, graph_client) -> None:
        self.client = graph_client

    def save(self, alert: Alert) -> None:
        """Write an Alert node and connect it to matched entities."""
        cypher = """
        MERGE (a:Alert {alert_id: $alert_id})
        SET a.rule_id = $rule_id,
            a.rule_name = $rule_name,
            a.severity = $severity,
            a.category = $category,
            a.mitre_tactic = $mitre_tactic,
            a.mitre_technique = $mitre_technique,
            a.status = $status,
            a.match_count = $match_count,
            a.description = $description,
            a.first_seen = $first_seen,
            a.last_seen = $last_seen,
            a.occurrence_count = $occurrence_count
        """
        params = {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity.value,
            "category": alert.category.value,
            "mitre_tactic": alert.mitre.tactic if alert.mitre else None,
            "mitre_technique": alert.mitre.technique_id if alert.mitre else None,
            "status": alert.status.value,
            "match_count": alert.match_count,
            "description": alert.description,
            "first_seen": alert.first_seen.isoformat(),
            "last_seen": alert.last_seen.isoformat(),
            "occurrence_count": alert.occurrence_count,
        }
        try:
            self.client.execute_write(cypher, params)
        except Exception as exc:
            logger.warning(f"Failed to persist alert node in Neo4j: {exc}")
