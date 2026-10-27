"""
Alert data models for the Q-EDR threat detection engine.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from ..rules.base import Severity, MITRETechnique, RuleCategory, RuleMatch


class AlertStatus(str, Enum):
    """Lifecycle status of a generated threat alert."""
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class Alert:
    """
    Structured alert produced when a threat detection rule triggers.
    Enriched with MITRE ATT&CK taxonomy, entity references, and deduplication counters.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.MEDIUM
    category: RuleCategory = RuleCategory.EXECUTION
    mitre: Optional[MITRETechnique] = None
    status: AlertStatus = AlertStatus.NEW
    matches: List[RuleMatch] = field(default_factory=list)
    match_count: int = 0
    description: str = ""
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    occurrence_count: int = 1
    tags: List[str] = field(default_factory=list)
    enrichments: Dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    suppression_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert into a JSON-serializable dictionary."""
        return {
            "alert_id": self.alert_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "mitre_tactic": self.mitre.tactic if self.mitre else None,
            "mitre_technique": self.mitre.technique_id if self.mitre else None,
            "mitre_technique_name": self.mitre.technique_name if self.mitre else None,
            "mitre_url": self.mitre.url if self.mitre else None,
            "status": self.status.value,
            "match_count": self.match_count,
            "description": self.description,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "occurrence_count": self.occurrence_count,
            "tags": self.tags,
            "enrichments": self.enrichments,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "matches": [
                {
                    "node_ids": m.node_ids,
                    "properties": m.properties,
                }
                for m in self.matches
            ],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Reconstruct Alert object from dict."""
        mitre = None
        if data.get("mitre_technique"):
            mitre = MITRETechnique(
                tactic=data.get("mitre_tactic", ""),
                technique_id=data.get("mitre_technique", ""),
                technique_name=data.get("mitre_technique_name", ""),
                url=data.get("mitre_url", ""),
            )
        matches = [
            RuleMatch(node_ids=m.get("node_ids", []), properties=m.get("properties", {}))
            for m in data.get("matches", [])
        ]
        return cls(
            alert_id=data.get("alert_id", str(uuid.uuid4())),
            rule_id=data.get("rule_id", ""),
            rule_name=data.get("rule_name", ""),
            severity=Severity(data.get("severity", "MEDIUM")),
            category=RuleCategory(data.get("category", "execution")),
            mitre=mitre,
            status=AlertStatus(data.get("status", "NEW")),
            matches=matches,
            match_count=data.get("match_count", len(matches)),
            description=data.get("description", ""),
            first_seen=datetime.fromisoformat(data["first_seen"]) if "first_seen" in data else datetime.now(timezone.utc),
            last_seen=datetime.fromisoformat(data["last_seen"]) if "last_seen" in data else datetime.now(timezone.utc),
            occurrence_count=data.get("occurrence_count", 1),
            tags=data.get("tags", []),
            enrichments=data.get("enrichments", {}),
            suppressed=data.get("suppressed", False),
            suppression_reason=data.get("suppression_reason"),
        )
