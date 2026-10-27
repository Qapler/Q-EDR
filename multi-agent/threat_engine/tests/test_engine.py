"""
Unit and integration tests for ThreatDetector and DetectionPipeline.
"""
from __future__ import annotations

import time
import unittest
from unittest.mock import MagicMock

from threat_engine.rules.base import Rule, RuleResult, RuleCategory, Severity, MITRETechnique, RuleMatch
from threat_engine.rules.registry import RuleRegistry
from threat_engine.alerts.manager import AlertManager
from threat_engine.alerts.models import Alert
from threat_engine.engine.detector import ThreatDetector
from threat_engine.engine.pipeline import DetectionPipeline
from threat_engine.observability.metrics import EngineMetrics
from threat_engine.graph.client import GraphClient


def _make_rule(
    rule_id: str,
    matched: bool = False,
    severity: Severity = Severity.MEDIUM,
    category: RuleCategory = RuleCategory.LATERAL_MOVEMENT,
    error: str | None = None,
    delay: float = 0.0,
) -> Rule:
    """Mock Rule generator."""
    rule = MagicMock(spec=Rule)
    rule.rule_id = rule_id
    rule.rule_name = f"Rule {rule_id}"
    rule.severity = severity
    rule.category = category
    rule.mitre = MITRETechnique(tactic="Test", technique_id="T0000", technique_name="Test Technique")
    rule.enabled = True

    def _run(_graph):
        if delay > 0:
            time.sleep(delay)
        matches = [RuleMatch(properties={"hit": 1})] if matched else []
        return RuleResult(
            rule_id=rule_id,
            rule_name=f"Rule {rule_id}",
            severity=severity,
            category=category,
            mitre=rule.mitre,
            matched=matched,
            matches=matches,
            error=error,
        )

    rule.run.side_effect = _run
    return rule


class TestThreatDetector(unittest.TestCase):
    """Tests for ThreatDetector scanning logic."""

    def setUp(self):
        self.mock_graph = MagicMock(spec=GraphClient)
        self.mock_graph.execute_read.return_value = []
        self.registry = MagicMock(spec=RuleRegistry)
        self.alert_manager = AlertManager(dedup_window_seconds=60, output_file=None)
        self.metrics = EngineMetrics()

    def test_run_scan_zero_matches(self):
        rules = [_make_rule(f"R-{i}", matched=False) for i in range(5)]
        self.registry.get_enabled.return_value = rules
        self.registry.get_by_category.return_value = []

        detector = ThreatDetector(
            graph_client=self.mock_graph,
            rule_registry=self.registry,
            alert_manager=self.alert_manager,
            metrics=self.metrics,
            max_workers=2,
            rule_timeout=2.0,
        )

        summary = detector.run_scan()
        self.assertEqual(summary["total_rules"], 5)
        self.assertEqual(summary["matched_rules"], 0)
        self.assertEqual(summary["alerts_generated"], 0)
        self.assertGreaterEqual(summary["elapsed_seconds"], 0)
        self.assertIn("scan_", summary["scan_id"])

    def test_run_scan_with_threat_matches(self):
        rules = [
            _make_rule("R-01", matched=True, severity=Severity.CRITICAL),
            _make_rule("R-02", matched=True, severity=Severity.HIGH),
            _make_rule("R-03", matched=False),
        ]
        self.registry.get_enabled.return_value = rules
        self.registry.get_by_category.return_value = []

        detector = ThreatDetector(
            graph_client=self.mock_graph,
            rule_registry=self.registry,
            alert_manager=self.alert_manager,
            metrics=self.metrics,
            max_workers=2,
            rule_timeout=2.0,
        )

        summary = detector.run_scan()
        self.assertEqual(summary["total_rules"], 3)
        self.assertEqual(summary["matched_rules"], 2)
        self.assertEqual(summary["alerts_generated"], 2)
        self.assertEqual(len(self.alert_manager.get_active_alerts()), 2)

    def test_run_scan_dry_run_generates_no_alerts(self):
        rules = [_make_rule("R-DRY", matched=True)]
        self.registry.get_enabled.return_value = rules

        detector = ThreatDetector(
            graph_client=self.mock_graph,
            rule_registry=self.registry,
            alert_manager=self.alert_manager,
            metrics=self.metrics,
            dry_run=True,
        )

        summary = detector.run_scan()
        self.assertEqual(summary["matched_rules"], 1)
        self.assertEqual(summary["alerts_generated"], 0)
        self.assertEqual(len(self.alert_manager.get_active_alerts()), 0)

    def test_run_scan_rule_timeout_handling(self):
        # A slow rule that takes 3 seconds, with a 0.5 second timeout
        slow_rule = _make_rule("SLOW-01", delay=3.0)
        self.registry.get_enabled.return_value = [slow_rule]

        detector = ThreatDetector(
            graph_client=self.mock_graph,
            rule_registry=self.registry,
            alert_manager=self.alert_manager,
            metrics=self.metrics,
            rule_timeout=0.5,
        )

        summary = detector.run_scan()
        self.assertEqual(summary["total_rules"], 1)
        self.assertEqual(summary["error_rules"], 1)
        self.assertIn("Timeout", summary["error_rule_ids"][0][1])

    def test_run_scan_enabled_categories_filter(self):
        lm_rule = _make_rule("LM-01", category=RuleCategory.LATERAL_MOVEMENT)
        pe_rule = _make_rule("PE-01", category=RuleCategory.PRIVILEGE_ESCALATION)

        self.registry.get_by_category.side_effect = lambda cat: [lm_rule] if cat == RuleCategory.LATERAL_MOVEMENT else []

        detector = ThreatDetector(
            graph_client=self.mock_graph,
            rule_registry=self.registry,
            alert_manager=self.alert_manager,
            metrics=self.metrics,
            enabled_categories=[RuleCategory.LATERAL_MOVEMENT],
        )

        summary = detector.run_scan()
        self.assertEqual(summary["total_rules"], 1)


class TestDetectionPipeline(unittest.TestCase):
    """Tests for the background DetectionPipeline scheduler."""

    def test_pipeline_start_and_stop(self):
        mock_detector = MagicMock(spec=ThreatDetector)
        mock_detector.run_scan.return_value = {
            "scan_id": "test_scan",
            "matched_rules": 0,
            "alerts_generated": 0,
        }

        pipeline = DetectionPipeline(detector=mock_detector, interval_seconds=0.1, history_size=10)
        self.assertFalse(pipeline.is_running)

        pipeline.start()
        self.assertTrue(pipeline.is_running)

        # Allow at least 2 scan cycles
        time.sleep(0.3)
        pipeline.stop()
        self.assertFalse(pipeline.is_running)

        self.assertGreaterEqual(mock_detector.run_scan.call_count, 1)
        self.assertIsNotNone(pipeline.get_last_scan_result())
        history = pipeline.get_scan_history()
        self.assertGreaterEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()
