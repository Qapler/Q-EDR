"""
Unit and integration tests for Observability (Metrics, Logging, and Health checks).
"""
from __future__ import annotations

import json
import logging
import time
import urllib.request
import unittest
from unittest.mock import MagicMock

from threat_engine.observability.metrics import EngineMetrics
from threat_engine.observability.logger import JSONFormatter, configure_logging
from threat_engine.observability.health import HealthCheck
from threat_engine.rules.base import RuleResult, Severity, RuleCategory
from threat_engine.alerts.models import Alert


class TestEngineMetrics(unittest.TestCase):
    """Tests for metric collection and stats extraction."""

    def setUp(self):
        self.metrics = EngineMetrics()

    def test_scan_lifecycle_metrics(self):
        self.metrics.scan_started()
        
        # Rule execution
        res = RuleResult(
            rule_id="M-01",
            rule_name="Metric Rule",
            severity=Severity.HIGH,
            category=RuleCategory.LATERAL_MOVEMENT,
            mitre=None,
            matched=True,
            execution_time_ms=12.5,
        )
        self.metrics.rule_executed(res)

        # Alert generation
        alert = Alert(rule_id="M-01", severity=Severity.HIGH, category=RuleCategory.LATERAL_MOVEMENT)
        self.metrics.alert_generated(alert)

        # Scan completion
        self.metrics.scan_completed(elapsed=1.25, matched_count=1, alerts_count=1)

        stats = self.metrics.get_stats()
        self.assertEqual(stats["rules_executed_total"][("high", "lateral_movement")], 1)
        self.assertEqual(stats["rules_matched_total"][("high", "lateral_movement")], 1)
        self.assertEqual(stats["alerts_generated_total"]["high"], 1)
        self.assertEqual(stats["scans_total"], 1)


class TestLogger(unittest.TestCase):
    """Tests for structured JSON logging."""

    def test_json_formatter(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test_logger",
            level=logging.WARNING,
            pathname="test.py",
            lineno=42,
            msg="Threat detected: %s",
            args=("PassTheHash",),
            exc_info=None,
        )
        record.rule_id = "LM-001"
        record.severity = "CRITICAL"

        output = formatter.format(record)
        parsed = json.loads(output)
        self.assertEqual(parsed["level"], "WARNING")
        self.assertEqual(parsed["message"], "Threat detected: PassTheHash")
        self.assertEqual(parsed["rule_id"], "LM-001")
        self.assertEqual(parsed["severity"], "CRITICAL")
        self.assertIn("timestamp", parsed)


class TestHealthCheck(unittest.TestCase):
    """Tests for system health check aggregation and HTTP endpoints."""

    def test_health_check_healthy(self):
        mock_graph = MagicMock()
        mock_graph.test_connection.return_value = True

        mock_registry = MagicMock()
        mock_registry.get_enabled.return_value = [MagicMock()]
        mock_registry.summary.return_value = {"total": 69, "enabled": 69}

        mock_alerts = MagicMock()
        mock_alerts.get_stats.return_value = {"total_alerts": 5}

        health = HealthCheck(mock_graph, mock_registry, mock_alerts)
        report = health.check_all()

        self.assertEqual(report["status"], "healthy")
        self.assertEqual(report["checks"]["neo4j"]["status"], "ok")
        self.assertEqual(report["checks"]["rules"]["status"], "ok")
        self.assertTrue(health.is_healthy())

    def test_health_check_degraded_when_db_down(self):
        mock_graph = MagicMock()
        mock_graph.test_connection.return_value = False

        mock_registry = MagicMock()
        mock_registry.get_enabled.return_value = [MagicMock()]
        mock_registry.summary.return_value = {"total": 69, "enabled": 69}

        mock_alerts = MagicMock()
        mock_alerts.get_stats.return_value = {"total_alerts": 0}

        health = HealthCheck(mock_graph, mock_registry, mock_alerts)
        report = health.check_all()

        self.assertIn(report["status"], ("degraded", "unhealthy"))
        self.assertFalse(health.is_healthy())

    def test_health_http_server(self):
        mock_graph = MagicMock()
        mock_graph.test_connection.return_value = True
        mock_registry = MagicMock()
        mock_registry.get_enabled.return_value = [MagicMock()]
        mock_registry.summary.return_value = {"total": 69}
        mock_alerts = MagicMock()
        mock_alerts.get_stats.return_value = {"total_alerts": 0}

        health = HealthCheck(mock_graph, mock_registry, mock_alerts)
        port = 18099
        health.start_http_server(port)
        time.sleep(0.5)

        try:
            req = urllib.request.Request(f"http://127.0.0.1:{port}/health")
            with urllib.request.urlopen(req, timeout=3) as response:
                self.assertEqual(response.status, 200)
                data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(data["status"], "healthy")
        finally:
            health.stop_http_server()


if __name__ == "__main__":
    unittest.main()
