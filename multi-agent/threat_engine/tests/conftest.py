"""
threat_engine/tests/conftest.py
Shared pytest fixtures for the threat detection engine test suite.
"""
import pytest
from unittest.mock import MagicMock, patch

from ..graph.client import GraphClient
from ..rules.registry import RuleRegistry
from ..alerts.manager import AlertManager
from ..engine.detector import ThreatDetector
from ..observability.metrics import EngineMetrics


# ---------------------------------------------------------------------------
# Graph Client
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_graph_client():
    """
    Mock GraphClient that returns configurable records.

    Default behaviour:
    - ``test_connection()``  → ``True``
    - ``get_node_count()``   → ``1000``
    - ``run_query()``        → ``[]`` (empty result set, i.e. no threat hits)
    """
    client = MagicMock(spec=GraphClient)
    client.test_connection.return_value = True
    client.get_node_count.return_value = 1000
    client.run_query.return_value = []
    client.execute_read.return_value = []
    client.execute_write.return_value = []
    return client


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

@pytest.fixture
def rule_registry():
    """
    A real RuleRegistry instance with all built-in rules auto-discovered.
    """
    return RuleRegistry()


@pytest.fixture
def empty_rule_registry():
    """A RuleRegistry with no rules registered."""
    registry = RuleRegistry()
    registry._rules.clear()  # type: ignore[attr-defined]
    return registry


# ---------------------------------------------------------------------------
# Alert manager
# ---------------------------------------------------------------------------

@pytest.fixture
def alert_manager():
    """AlertManager with a 5-minute deduplication window."""
    return AlertManager(dedup_window_seconds=300)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@pytest.fixture
def engine_metrics():
    """EngineMetrics using the in-process fallback (no external server)."""
    return EngineMetrics()


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

@pytest.fixture
def threat_detector(mock_graph_client, rule_registry, alert_manager, engine_metrics):
    """
    Fully wired ThreatDetector with mocked graph, real registry, and real
    alert/metrics objects.
    """
    return ThreatDetector(
        graph_client=mock_graph_client,
        rule_registry=rule_registry,
        alert_manager=alert_manager,
        metrics=engine_metrics,
        max_workers=4,
        rule_timeout=5.0,
    )


@pytest.fixture
def dry_run_detector(mock_graph_client, rule_registry, alert_manager, engine_metrics):
    """ThreatDetector in dry-run mode (no alerts persisted)."""
    return ThreatDetector(
        graph_client=mock_graph_client,
        rule_registry=rule_registry,
        alert_manager=alert_manager,
        metrics=engine_metrics,
        max_workers=4,
        rule_timeout=5.0,
        dry_run=True,
    )
