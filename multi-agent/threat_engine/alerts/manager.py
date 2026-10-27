"""
Alert Manager: Handles alert generation, deduplication, suppression,
enrichment, and storage.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from ..rules.base import RuleResult, Severity, RuleCategory
from .models import Alert, AlertStatus
from .storage import AlertFileStorage, AlertGraphStorage

logger = logging.getLogger(__name__)


class AlertManager:
    """
    Thread-safe manager for threat alerts.
    
    Features:
    - Time-windowed deduplication (merges matches from same rule within window)
    - Rule suppression list (silences benign or noisy rules)
    - Alert enrichment (adds contextual metadata and taxonomy)
    - Lifecycle tracking (NEW, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE)
    - In-memory cache + file storage sink
    """

    def __init__(
        self,
        dedup_window_seconds: int = 300,
        output_file: Optional[str] = "alerts.jsonl",
        graph_client: Optional[Any] = None,
    ) -> None:
        self.dedup_window_seconds = dedup_window_seconds
        self._lock = threading.RLock()
        self._alerts: Dict[str, Alert] = {}  # alert_id -> Alert
        # Key: rule_id -> most recent alert_id within dedup window
        self._recent_rule_alerts: Dict[str, str] = {}
        # Set of suppressed rule IDs
        self._suppressed_rules: Dict[str, str] = {}  # rule_id -> reason
        
        self.file_storage = AlertFileStorage(output_file) if output_file else None
        self.graph_storage = AlertGraphStorage(graph_client) if graph_client else None

    def suppress(self, rule_id: str, reason: str = "Administrator suppression") -> None:
        """Suppress future alerts from a specific rule."""
        with self._lock:
            self._suppressed_rules[rule_id] = reason
            logger.info("Rule suppressed", extra={"rule_id": rule_id, "reason": reason})

    def unsuppress(self, rule_id: str) -> None:
        """Remove a rule from the suppression list."""
        with self._lock:
            self._suppressed_rules.pop(rule_id, None)
            logger.info("Rule unsuppressed", extra={"rule_id": rule_id})

    def is_suppressed(self, rule_id: str) -> bool:
        """Check if a rule is currently suppressed."""
        with self._lock:
            return rule_id in self._suppressed_rules

    def process_rule_result(self, result: RuleResult) -> Optional[Alert]:
        """
        Process a RuleResult from the detection engine:
        - Drops non-matches and errors
        - Checks suppression
        - Deduplicates against existing recent alert for the same rule
        - Enriches new alerts
        - Emits and stores the final Alert
        """
        if not result.matched or result.error:
            return None

        with self._lock:
            # Check suppression
            if result.rule_id in self._suppressed_rules:
                reason = self._suppressed_rules[result.rule_id]
                logger.info(
                    "Alert suppressed by rule rule_id",
                    extra={"rule_id": result.rule_id, "reason": reason},
                )
                suppressed_alert = Alert(
                    rule_id=result.rule_id,
                    rule_name=result.rule_name,
                    severity=result.severity,
                    category=result.category,
                    mitre=result.mitre,
                    matches=result.matches,
                    match_count=len(result.matches),
                    suppressed=True,
                    suppression_reason=reason,
                )
                return suppressed_alert

            # Check deduplication window
            now = datetime.now(timezone.utc)
            existing_alert_id = self._recent_rule_alerts.get(result.rule_id)
            if existing_alert_id and existing_alert_id in self._alerts:
                existing = self._alerts[existing_alert_id]
                time_diff = (now - existing.last_seen).total_seconds()
                if time_diff <= self.dedup_window_seconds:
                    # Deduplicate: update existing alert
                    existing.last_seen = now
                    existing.occurrence_count += 1
                    existing.matches.extend(result.matches)
                    existing.match_count = len(existing.matches)
                    logger.debug(
                        "Deduplicated alert",
                        extra={
                            "alert_id": existing.alert_id,
                            "rule_id": result.rule_id,
                            "occurrences": existing.occurrence_count,
                        },
                    )
                    return existing

            # New Alert
            alert = Alert(
                rule_id=result.rule_id,
                rule_name=result.rule_name,
                severity=result.severity,
                category=result.category,
                mitre=result.mitre,
                status=AlertStatus.NEW,
                matches=result.matches,
                match_count=len(result.matches),
                description=f"Rule '{result.rule_name}' triggered with {len(result.matches)} pattern match(es).",
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
                tags=getattr(result, "tags", []) or [],
            )

            # Enrich alert
            self._enrich(alert)

            # Store in memory
            self._alerts[alert.alert_id] = alert
            self._recent_rule_alerts[result.rule_id] = alert.alert_id

            # Persist
            if self.file_storage:
                self.file_storage.append(alert)
            if self.graph_storage:
                self.graph_storage.save(alert)

            logger.warning(
                "ALERT CREATED",
                extra={
                    "alert_id": alert.alert_id,
                    "rule_id": alert.rule_id,
                    "severity": alert.severity.value,
                    "match_count": alert.match_count,
                },
            )
            return alert

    def _enrich(self, alert: Alert) -> None:
        """Enrich alert with metadata, environment context, and taxonomy."""
        enrichments: Dict[str, Any] = {
            "engine_version": "1.0.0",
            "taxonomy": "MITRE_ATTACK_v15",
            "environment": "production",
        }
        # Extract unique IPs and Hostnames from matches if present
        entities = set()
        for match in alert.matches:
            for k, v in match.properties.items():
                if "ip" in k or "host" in k or "user" in k or "process" in k:
                    entities.add(f"{k}:{v}")
        if entities:
            enrichments["entities"] = sorted(list(entities))[:20]
        alert.enrichments.update(enrichments)

    def acknowledge(self, alert_id: str) -> bool:
        """Set alert status to ACKNOWLEDGED."""
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].status = AlertStatus.ACKNOWLEDGED
                return True
            return False

    def resolve(self, alert_id: str) -> bool:
        """Set alert status to RESOLVED."""
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].status = AlertStatus.RESOLVED
                return True
            return False

    def mark_false_positive(self, alert_id: str) -> bool:
        """Set alert status to FALSE_POSITIVE."""
        with self._lock:
            if alert_id in self._alerts:
                self._alerts[alert_id].status = AlertStatus.FALSE_POSITIVE
                return True
            return False

    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Retrieve an alert by ID."""
        with self._lock:
            return self._alerts.get(alert_id)

    def get_active_alerts(self) -> List[Alert]:
        """Return non-suppressed alerts that are not RESOLVED or FALSE_POSITIVE."""
        with self._lock:
            return [
                a for a in self._alerts.values()
                if not a.suppressed and a.status not in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE)
            ]

    def get_alerts_by_severity(self, severity: Severity) -> List[Alert]:
        """Filter active alerts by severity."""
        with self._lock:
            return [a for a in self._alerts.values() if a.severity == severity]

    def get_stats(self) -> Dict[str, Any]:
        """Calculate alert distribution statistics."""
        with self._lock:
            total = len(self._alerts)
            by_severity: Dict[str, int] = {}
            by_category: Dict[str, int] = {}
            by_status: Dict[str, int] = {}

            for a in self._alerts.values():
                by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1
                by_category[a.category.value] = by_category.get(a.category.value, 0) + 1
                by_status[a.status.value] = by_status.get(a.status.value, 0) + 1

            return {
                "total_alerts": total,
                "active_alerts": len(self.get_active_alerts()),
                "suppressed_rules_count": len(self._suppressed_rules),
                "by_severity": by_severity,
                "by_category": by_category,
                "by_status": by_status,
            }
