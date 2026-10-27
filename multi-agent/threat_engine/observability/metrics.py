"""
threat_engine/observability/metrics.py
Prometheus-backed (with graceful fallback) metrics for the detection engine.
"""
import logging
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional prometheus_client import
# ---------------------------------------------------------------------------
try:
    import prometheus_client as prom  # type: ignore

    _PROMETHEUS_AVAILABLE = True
    logger.debug("prometheus_client found — using native Prometheus metrics")
except ImportError:  # pragma: no cover
    prom = None  # type: ignore
    _PROMETHEUS_AVAILABLE = False
    logger.warning(
        "prometheus_client not installed — falling back to in-process counter dict"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _label_severity(severity: Any) -> str:
    """Normalise a severity value to a lowercase string label."""
    return str(getattr(severity, "value", severity)).lower()


def _label_category(category: Any) -> str:
    """Normalise a category value to a lowercase string label."""
    return str(getattr(category, "value", category)).lower()


# ---------------------------------------------------------------------------
# EngineMetrics
# ---------------------------------------------------------------------------

class EngineMetrics:
    """
    Collects and exposes operational metrics for the detection engine.

    When ``prometheus_client`` is installed the metrics are registered
    in the default Prometheus registry and can be scraped via the
    standard ``/metrics`` endpoint (started by :class:`HealthCheck`).

    When ``prometheus_client`` is absent a thread-safe in-process counter
    dictionary is used instead; :meth:`get_stats` always returns a plain
    Python dict regardless of the backend.

    Tracked metrics
    ---------------
    * ``rules_executed_total``   — labelled by ``severity``, ``category``
    * ``rules_matched_total``    — labelled by ``severity``, ``category``
    * ``rule_execution_errors_total`` — labelled by ``rule_id``
    * ``alerts_generated_total`` — labelled by ``severity``
    * ``active_alerts_gauge``    — current number of open alerts
    * ``scan_duration_seconds``  — histogram of full-scan wall-clock time
    * ``scans_total``            — counter of completed scans
    """

    def __init__(self, namespace: str = "qedr_engine", registry: Optional[Any] = None) -> None:
        self._namespace = namespace
        self._lock = threading.Lock()

        if _PROMETHEUS_AVAILABLE:
            self._init_prometheus(registry or prom.REGISTRY)
        else:
            self._init_fallback()

    # ------------------------------------------------------------------
    # Initialisation
    # ------------------------------------------------------------------

    def _init_prometheus(self, registry: Any) -> None:
        """Create prometheus_client metric objects."""
        ns = self._namespace

        self._rules_executed = prom.Counter(
            f"{ns}_rules_executed_total",
            "Total number of rules executed",
            ["severity", "category"],
            registry=registry,
        )
        self._rules_matched = prom.Counter(
            f"{ns}_rules_matched_total",
            "Total number of rules that produced a match",
            ["severity", "category"],
            registry=registry,
        )
        self._rule_errors = prom.Counter(
            f"{ns}_rule_execution_errors_total",
            "Total rule execution errors (timeouts, exceptions)",
            ["rule_id"],
            registry=registry,
        )
        self._alerts_generated = prom.Counter(
            f"{ns}_alerts_generated_total",
            "Total alerts emitted",
            ["severity"],
            registry=registry,
        )
        self._active_alerts = prom.Gauge(
            f"{ns}_active_alerts",
            "Current number of open (non-resolved) alerts",
            registry=registry,
        )
        self._scan_duration = prom.Histogram(
            f"{ns}_scan_duration_seconds",
            "Wall-clock time of a full detection scan",
            buckets=[0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120],
            registry=registry,
        )
        self._scans_total = prom.Counter(
            f"{ns}_scans_total",
            "Total number of detection scans completed",
            registry=registry,
        )
        self._scans_in_progress = prom.Gauge(
            f"{ns}_scans_in_progress",
            "Number of scans currently running",
            registry=registry,
        )

        self._backend = "prometheus"

    def _init_fallback(self) -> None:
        """Initialise plain-dict counters used when prometheus_client is absent."""
        self._counters: Dict[str, Any] = {
            "rules_executed_total": {},   # (severity, category) -> int
            "rules_matched_total": {},    # (severity, category) -> int
            "rule_execution_errors_total": {},  # rule_id -> int
            "alerts_generated_total": {},       # severity -> int
            "active_alerts_gauge": 0,
            "scan_duration_seconds_sum": 0.0,
            "scan_duration_seconds_count": 0,
            "scans_total": 0,
            "scans_in_progress": 0,
        }
        self._backend = "dict"

    # ------------------------------------------------------------------
    # Lifecycle events
    # ------------------------------------------------------------------

    def scan_started(self) -> None:
        """Signal that a new scan has begun."""
        if self._backend == "prometheus":
            self._scans_in_progress.inc()
        else:
            with self._lock:
                self._counters["scans_in_progress"] += 1

    def scan_completed(
        self, elapsed: float, matched_count: int, alerts_count: int
    ) -> None:
        """
        Signal that a scan finished.

        Args:
            elapsed: Wall-clock seconds the scan took.
            matched_count: Number of rules that fired.
            alerts_count: Number of alerts generated.
        """
        if self._backend == "prometheus":
            self._scans_in_progress.dec()
            self._scans_total.inc()
            self._scan_duration.observe(elapsed)
        else:
            with self._lock:
                c = self._counters
                c["scans_in_progress"] = max(0, c["scans_in_progress"] - 1)
                c["scans_total"] += 1
                c["scan_duration_seconds_sum"] += elapsed
                c["scan_duration_seconds_count"] += 1

    def rule_executed(self, result: Any) -> None:
        """
        Record a rule execution result.

        Args:
            result: A :class:`~threat_engine.rules.base.RuleResult` instance.
        """
        sev = _label_severity(result.severity)
        cat = _label_category(result.category)

        if self._backend == "prometheus":
            self._rules_executed.labels(severity=sev, category=cat).inc()
            if result.matched:
                self._rules_matched.labels(severity=sev, category=cat).inc()
            if result.error:
                self._rule_errors.labels(rule_id=result.rule_id).inc()
        else:
            with self._lock:
                key = (sev, cat)
                exec_map = self._counters["rules_executed_total"]
                exec_map[key] = exec_map.get(key, 0) + 1

                if result.matched:
                    match_map = self._counters["rules_matched_total"]
                    match_map[key] = match_map.get(key, 0) + 1

                if result.error:
                    err_map = self._counters["rule_execution_errors_total"]
                    err_map[result.rule_id] = err_map.get(result.rule_id, 0) + 1

    def alert_generated(self, alert: Any) -> None:
        """
        Record an alert emission.

        Args:
            alert: An :class:`~threat_engine.alerts.models.Alert` instance.
        """
        sev = _label_severity(alert.severity)

        if self._backend == "prometheus":
            self._alerts_generated.labels(severity=sev).inc()
            self._active_alerts.inc()
        else:
            with self._lock:
                al_map = self._counters["alerts_generated_total"]
                al_map[sev] = al_map.get(sev, 0) + 1
                self._counters["active_alerts_gauge"] += 1

    def alert_resolved(self) -> None:
        """Decrement the active-alerts gauge when an alert is closed."""
        if self._backend == "prometheus":
            self._active_alerts.dec()
        else:
            with self._lock:
                self._counters["active_alerts_gauge"] = max(
                    0, self._counters["active_alerts_gauge"] - 1
                )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """
        Return a snapshot of all current metric values as a plain dict.

        This works with both the Prometheus and fallback backends.
        """
        if self._backend == "prometheus":
            # Collect current values from prometheus_client's internal samples.
            stats: Dict[str, Any] = {}
            for metric in prom.REGISTRY.collect():
                for sample in metric.samples:
                    stats[sample.name] = stats.get(sample.name, {})
                    if sample.labels:
                        label_key = str(sorted(sample.labels.items()))
                        if isinstance(stats[sample.name], dict):
                            stats[sample.name][label_key] = sample.value
                    else:
                        stats[sample.name] = sample.value
            return stats
        else:
            with self._lock:
                import copy
                return copy.deepcopy(self._counters)
