"""
Abstract base classes for the threat detection rule system.
All rules inherit from Rule and implement get_cypher().
"""
from __future__ import annotations

import abc
import time
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """Alert severity levels (aligned with CVSS / NIST SP 800-61)."""
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class RuleCategory(str, Enum):
    """MITRE ATT&CK tactic-aligned rule categories."""
    LATERAL_MOVEMENT     = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE          = "persistence"
    CREDENTIAL_ACCESS    = "credential_access"
    DEFENSE_EVASION      = "defense_evasion"
    DISCOVERY            = "discovery"
    EXFILTRATION         = "exfiltration"
    EXECUTION            = "execution"
    COMMAND_CONTROL      = "command_control"
    IMPACT               = "impact"
    INITIAL_ACCESS       = "initial_access"
    RECONNAISSANCE       = "reconnaissance"


# ---------------------------------------------------------------------------
# MITRE Technique
# ---------------------------------------------------------------------------

@dataclass
class MITRETechnique:
    """Reference to a MITRE ATT&CK technique."""
    tactic:           str
    technique_id:     str
    technique_name:   str
    sub_technique_id: Optional[str] = None
    url:              str = ""

    def __post_init__(self) -> None:
        if not self.url:
            if self.sub_technique_id:
                path = f"{self.technique_id}/{self.sub_technique_id}"
            else:
                path = self.technique_id
            self.url = f"https://attack.mitre.org/techniques/{path}/"

    @property
    def full_id(self) -> str:
        if self.sub_technique_id:
            return f"{self.technique_id}.{self.sub_technique_id}"
        return self.technique_id


# ---------------------------------------------------------------------------
# Rule Match
# ---------------------------------------------------------------------------

@dataclass
class RuleMatch:
    """A single pattern match returned by a rule's Cypher query."""
    node_ids:   List[Any]       = field(default_factory=list)
    properties: Dict[str, Any]  = field(default_factory=dict)
    raw_record: Dict[str, Any]  = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rule Result
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """The outcome of executing a single rule."""
    rule_id:           str
    rule_name:         str
    severity:          Severity
    category:          RuleCategory
    mitre:             Optional[Any]     = None
    matched:           bool              = False
    matches:           List[RuleMatch]   = field(default_factory=list)
    records:           List[Any]         = field(default_factory=list)
    execution_time_ms: float             = 0.0
    error:             Optional[str]     = None
    timestamp:         datetime          = field(default_factory=lambda: datetime.now(timezone.utc))
    alert_id:          str               = field(default_factory=lambda: str(uuid.uuid4()))

    def __post_init__(self) -> None:
        if self.records and not self.matches:
            self.matches = [
                RuleMatch(properties=r if isinstance(r, dict) else {"data": r}, raw_record=r if isinstance(r, dict) else {"data": r})
                for r in self.records
            ]
        elif self.matches and not self.records:
            self.records = [m.raw_record or m.properties for m in self.matches]

    @property
    def match_count(self) -> int:
        return len(self.matches)


# ---------------------------------------------------------------------------
# Abstract Rule
# ---------------------------------------------------------------------------

class Rule(abc.ABC):
    """
    Abstract base class for all threat detection rules.

    Subclasses MUST:
    - Set class-level attributes: rule_id, rule_name, description, severity,
      category, mitre.
    - Implement get_cypher() returning a valid Cypher query.

    The query SHOULD return a field called `ids` (list of internal node IDs)
    for traceability, plus any relevant context fields.

    Cypher queries use the parameter ``$time_window`` (seconds) for time filtering.
    Return at least: ids (list), and context fields for the alert.
    """

    # --- Required class attributes ---
    rule_id:   str = ""
    rule_name: str = ""
    description: str = ""
    severity:  Severity = Severity.MEDIUM
    category:  RuleCategory = RuleCategory.EXECUTION
    mitre:     Optional[MITRETechnique] = None

    # --- Optional tuning ---
    time_window_seconds: int  = 300      # look-back window
    min_match_count:     int  = 1        # minimum rows to trigger
    enabled:             bool = True
    tags:                List[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @abc.abstractmethod
    def get_cypher(self) -> str:
        """
        Return the Cypher query for this rule.

        The query MUST use ``$time_window`` as its time-window parameter
        (in seconds), e.g.::

            WHERE p.timestamp > datetime() - duration({seconds: $time_window})

        The query SHOULD return an ``ids`` field (list of node IDs) for
        traceability, plus relevant context fields.
        """

    # ------------------------------------------------------------------
    # Optional overrides
    # ------------------------------------------------------------------

    def get_cypher_params(self) -> Dict[str, Any]:
        """Return the parameter dict to pass with the Cypher query."""
        return {"time_window": self.time_window_seconds}

    def evaluate(self, records: List[Dict[str, Any]]) -> bool:
        """
        Decide whether the returned records constitute a threat.
        Default: match if at least ``min_match_count`` rows are returned.
        Override for more complex logic.
        """
        return len(records) >= self.min_match_count

    def build_match(self, record: Dict[str, Any]) -> RuleMatch:
        """Convert a raw DB record dict into a RuleMatch."""
        return RuleMatch(
            node_ids=record.get("ids", []),
            properties={k: v for k, v in record.items() if k != "ids"},
            raw_record=record,
        )

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, graph_client) -> RuleResult:
        """
        Execute this rule against the graph and return a RuleResult.

        Args:
            graph_client: A connected GraphClient instance.

        Returns:
            RuleResult with matched=True and populated matches if a threat
            was detected, or matched=False / error set on failure.
        """
        if not self.enabled:
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                mitre=self.mitre,
                matched=False,
                error="Rule disabled",
            )

        t_start = time.monotonic()
        try:
            cypher = self.get_cypher()
            params  = self.get_cypher_params()
            if hasattr(graph_client, "execute_read"):
                records = graph_client.execute_read(cypher, params)
            elif hasattr(graph_client, "run_query"):
                records = graph_client.run_query(cypher, params)
            else:
                records = []

            elapsed_ms = round((time.monotonic() - t_start) * 1000, 2)
            matched    = self.evaluate(records)
            matches    = [self.build_match(r) for r in records] if matched else []

            if matched:
                logger.warning(
                    "THREAT DETECTED",
                    extra={
                        "rule_id":     self.rule_id,
                        "rule_name":   self.rule_name,
                        "severity":    self.severity.value,
                        "mitre":       self.mitre.full_id if self.mitre else "",
                        "match_count": len(matches),
                        "elapsed_ms":  elapsed_ms,
                    },
                )
            else:
                logger.debug(
                    "Rule clear",
                    extra={"rule_id": self.rule_id, "elapsed_ms": elapsed_ms},
                )

            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                mitre=self.mitre,
                matched=matched,
                matches=matches,
                execution_time_ms=elapsed_ms,
            )

        except Exception as exc:
            elapsed_ms = round((time.monotonic() - t_start) * 1000, 2)
            logger.error(
                "Rule execution error",
                extra={"rule_id": self.rule_id, "error": str(exc)},
                exc_info=True,
            )
            return RuleResult(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                mitre=self.mitre,
                matched=False,
                execution_time_ms=elapsed_ms,
                error=str(exc),
            )
