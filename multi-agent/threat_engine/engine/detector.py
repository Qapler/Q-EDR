"""
threat_engine/engine/detector.py
Core threat detector — runs detection rules against the graph and emits alerts.
Supports parallel rule execution with a configurable thread pool.
"""
import logging
import time
import concurrent.futures
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from ..rules.base import Rule, RuleResult, RuleCategory
from ..rules.registry import RuleRegistry
from ..alerts.models import Alert
from ..alerts.manager import AlertManager
from ..graph.client import GraphClient
from ..observability.metrics import EngineMetrics

logger = logging.getLogger(__name__)


class ThreatDetector:
    """
    Core threat detector — runs rules against the graph and emits alerts.

    Rules are executed in parallel using a ``ThreadPoolExecutor``.
    Each rule is subject to an individual timeout so a single slow rule
    cannot block the whole scan.

    Args:
        graph_client: Abstraction over the Neo4j / graph database.
        rule_registry: Registry that holds all registered detection rules.
        alert_manager: Responsible for dedup, suppression, and persistence.
        metrics: Optional Prometheus (or fallback) metrics collector.
        max_workers: Thread-pool size for parallel rule execution.
        rule_timeout: Per-rule wall-clock timeout in seconds.
        enabled_categories: If set, only run rules from these categories.
        dry_run: Run all rules but do NOT create / persist alerts.
    """

    def __init__(
        self,
        graph_client: GraphClient,
        rule_registry: RuleRegistry,
        alert_manager: AlertManager,
        metrics: Optional[EngineMetrics] = None,
        max_workers: int = 10,
        rule_timeout: float = 30.0,
        enabled_categories: Optional[List[RuleCategory]] = None,
        dry_run: bool = False,
    ) -> None:
        self._graph = graph_client
        self._registry = rule_registry
        self._alert_manager = alert_manager
        self._metrics = metrics
        self._max_workers = max_workers
        self._rule_timeout = rule_timeout
        self._enabled_categories = enabled_categories
        self._dry_run = dry_run
        self._scan_count: int = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_rules(self) -> List[Rule]:
        """Return rules filtered by enabled categories (if configured)."""
        if self._enabled_categories:
            rules: List[Rule] = []
            for cat in self._enabled_categories:
                rules.extend(self._registry.get_by_category(cat))
            return rules
        return self._registry.get_enabled()

    def _run_single_rule(self, rule: Rule) -> RuleResult:
        """
        Execute *one* rule with an enforced timeout.

        A nested ``ThreadPoolExecutor`` with a single worker isolates
        each rule's execution so that a hung Cypher query does not
        block the outer pool indefinitely.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(rule.run, self._graph)
            try:
                return future.result(timeout=self._rule_timeout)
            except concurrent.futures.TimeoutError:
                logger.error(
                    "Rule timed out",
                    extra={"rule_id": rule.rule_id, "timeout_s": self._rule_timeout},
                )
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    category=rule.category,
                    mitre=rule.mitre,
                    matched=False,
                    error=f"Timeout after {self._rule_timeout}s",
                )
            except Exception as exc:  # pylint: disable=broad-except
                logger.exception(
                    "Unexpected error executing rule",
                    extra={"rule_id": rule.rule_id, "error": str(exc)},
                )
                return RuleResult(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    severity=rule.severity,
                    category=rule.category,
                    mitre=rule.mitre,
                    matched=False,
                    error=str(exc),
                )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_scan(self) -> Dict[str, Any]:
        """
        Run all enabled detection rules in parallel.

        Returns:
            A summary dict containing:
              - ``scan_id``: Unique identifier for this scan.
              - ``timestamp``: ISO-8601 UTC timestamp.
              - ``total_rules``: Number of rules evaluated.
              - ``matched_rules``: Number of rules that fired.
              - ``error_rules``: Number of rules that errored/timed out.
              - ``alerts_generated``: Number of new alerts created.
              - ``elapsed_seconds``: Wall-clock time of the scan.
              - ``dry_run``: Whether this was a dry-run scan.
              - ``alerts``: List of serialised alert dicts.
              - ``matched_rule_ids``: IDs of rules that matched.
              - ``error_rule_ids``: ``[(rule_id, error_msg), …]`` pairs.
        """
        scan_id = f"scan_{int(time.time())}_{self._scan_count}"
        self._scan_count += 1
        start = time.monotonic()

        rules = self._get_rules()
        results: List[RuleResult] = []
        alerts: List[Alert] = []

        logger.info(
            "Starting detection scan",
            extra={"scan_id": scan_id, "rule_count": len(rules)},
        )

        if self._metrics:
            self._metrics.scan_started()

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures: Dict[concurrent.futures.Future[RuleResult], Rule] = {
                pool.submit(self._run_single_rule, rule): rule for rule in rules
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                except Exception as exc:  # pylint: disable=broad-except
                    rule = futures[future]
                    logger.exception(
                        "Future raised unexpected exception",
                        extra={"rule_id": rule.rule_id, "error": str(exc)},
                    )
                    result = RuleResult(
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        severity=rule.severity,
                        category=rule.category,
                        mitre=rule.mitre,
                        matched=False,
                        error=str(exc),
                    )

                results.append(result)

                if self._metrics:
                    self._metrics.rule_executed(result)

                if result.matched and not result.error and not self._dry_run:
                    alert = self._alert_manager.process_rule_result(result)
                    if alert:
                        alerts.append(alert)
                        if self._metrics:
                            self._metrics.alert_generated(alert)

        elapsed = time.monotonic() - start

        matched = [r for r in results if r.matched]
        errors = [r for r in results if r.error]

        summary: Dict[str, Any] = {
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_rules": len(rules),
            "matched_rules": len(matched),
            "error_rules": len(errors),
            "alerts_generated": len(alerts),
            "elapsed_seconds": round(elapsed, 3),
            "dry_run": self._dry_run,
            "alerts": [a.to_dict() for a in alerts],
            "matched_rule_ids": [r.rule_id for r in matched],
            "error_rule_ids": [(r.rule_id, r.error) for r in errors],
        }

        if self._metrics:
            self._metrics.scan_completed(elapsed, len(matched), len(alerts))

        logger.info(
            "Detection scan complete",
            extra={
                "scan_id": scan_id,
                "matched": len(matched),
                "alerts": len(alerts),
                "elapsed_s": round(elapsed, 3),
            },
        )

        return summary
