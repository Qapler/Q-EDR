"""
Unit and integration tests for Alert models, AlertManager, and Storage.
"""
from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timezone, timedelta
import unittest
from unittest.mock import MagicMock

from threat_engine.rules.base import Severity, RuleCategory, MITRETechnique, RuleResult, RuleMatch
from threat_engine.alerts.models import Alert, AlertStatus
from threat_engine.alerts.manager import AlertManager
from threat_engine.alerts.storage import AlertFileStorage, AlertGraphStorage


class TestAlertModel(unittest.TestCase):
    """Tests for the Alert dataclass and serialization."""

    def test_alert_defaults(self):
        alert = Alert(rule_id="LM-001", rule_name="Test LM Rule")
        self.assertEqual(alert.rule_id, "LM-001")
        self.assertEqual(alert.severity, Severity.MEDIUM)
        self.assertEqual(alert.status, AlertStatus.NEW)
        self.assertEqual(alert.occurrence_count, 1)
        self.assertFalse(alert.suppressed)

    def test_alert_to_dict_and_from_dict(self):
        mitre = MITRETechnique(
            tactic="Lateral Movement",
            technique_id="T1550",
            technique_name="Use Alternate Authentication Material",
            sub_technique_id="002",
        )
        match = RuleMatch(
            node_ids=[101, 202],
            properties={"source_ip": "10.0.0.1", "target_ip": "10.0.0.2"},
        )
        alert = Alert(
            rule_id="LM-001",
            rule_name="Pass The Hash",
            severity=Severity.CRITICAL,
            category=RuleCategory.LATERAL_MOVEMENT,
            mitre=mitre,
            matches=[match],
            match_count=1,
            description="Detected NTLM reuse",
            tags=["lateral", "ntlm"],
        )

        d = alert.to_dict()
        self.assertEqual(d["rule_id"], "LM-001")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["mitre_technique"], "T1550")
        self.assertEqual(d["match_count"], 1)

        restored = Alert.from_dict(d)
        self.assertEqual(restored.rule_id, alert.rule_id)
        self.assertEqual(restored.severity, alert.severity)
        self.assertEqual(restored.category, alert.category)
        self.assertEqual(restored.mitre.technique_id, "T1550")
        self.assertEqual(len(restored.matches), 1)


class TestAlertManager(unittest.TestCase):
    """Tests for alert deduplication, suppression, enrichment, and lifecycle."""

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl")
        self.temp_file.close()
        self.manager = AlertManager(dedup_window_seconds=10, output_file=self.temp_file.name)

    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def _create_result(self, rule_id="PE-001", matched=True, count=1):
        mitre = MITRETechnique(tactic="Privilege Escalation", technique_id="T1548", technique_name="Abuse Sudo")
        matches = [RuleMatch(properties={"pid": 1234 + i, "host": "srv-1"}) for i in range(count)]
        return RuleResult(
            rule_id=rule_id,
            rule_name=f"PrivEsc Rule {rule_id}",
            severity=Severity.HIGH,
            category=RuleCategory.PRIVILEGE_ESCALATION,
            mitre=mitre,
            matched=matched,
            matches=matches,
        )

    def test_process_rule_result_unmatched_returns_none(self):
        res = self._create_result(matched=False)
        alert = self.manager.process_rule_result(res)
        self.assertIsNone(alert)

    def test_process_rule_result_creates_new_alert(self):
        res = self._create_result()
        alert = self.manager.process_rule_result(res)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "PE-001")
        self.assertEqual(alert.occurrence_count, 1)
        self.assertEqual(alert.status, AlertStatus.NEW)
        self.assertIn("taxonomy", alert.enrichments)

    def test_alert_deduplication_within_window(self):
        res1 = self._create_result(rule_id="DEDUP-01", count=1)
        alert1 = self.manager.process_rule_result(res1)

        res2 = self._create_result(rule_id="DEDUP-01", count=2)
        alert2 = self.manager.process_rule_result(res2)

        self.assertEqual(alert1.alert_id, alert2.alert_id)
        self.assertEqual(alert2.occurrence_count, 2)
        self.assertEqual(alert2.match_count, 3)

    def test_alert_rule_suppression(self):
        self.manager.suppress("NOISY-001", reason="Known benign backup script")
        self.assertTrue(self.manager.is_suppressed("NOISY-001"))

        res = self._create_result(rule_id="NOISY-001")
        alert = self.manager.process_rule_result(res)
        self.assertTrue(alert.suppressed)
        self.assertEqual(alert.suppression_reason, "Known benign backup script")

        # Suppressed alert should not appear in active alerts
        active = self.manager.get_active_alerts()
        self.assertEqual(len(active), 0)

        # Unsuppress
        self.manager.unsuppress("NOISY-001")
        self.assertFalse(self.manager.is_suppressed("NOISY-001"))

    def test_alert_status_transitions(self):
        res = self._create_result()
        alert = self.manager.process_rule_result(res)
        alert_id = alert.alert_id

        self.assertTrue(self.manager.acknowledge(alert_id))
        self.assertEqual(self.manager.get_alert(alert_id).status, AlertStatus.ACKNOWLEDGED)

        self.assertTrue(self.manager.resolve(alert_id))
        self.assertEqual(self.manager.get_alert(alert_id).status, AlertStatus.RESOLVED)

        # Resolved alerts are excluded from get_active_alerts()
        self.assertEqual(len(self.manager.get_active_alerts()), 0)

    def test_alert_stats(self):
        res1 = self._create_result(rule_id="R-1")
        res2 = self._create_result(rule_id="R-2")
        self.manager.process_rule_result(res1)
        self.manager.process_rule_result(res2)

        stats = self.manager.get_stats()
        self.assertEqual(stats["total_alerts"], 2)
        self.assertEqual(stats["active_alerts"], 2)
        self.assertIn("HIGH", stats["by_severity"])


class TestAlertStorage(unittest.TestCase):
    """Tests for JSONL file and graph storage."""

    def test_file_storage_append_and_read(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".jsonl") as tf:
            path = tf.name

        try:
            storage = AlertFileStorage(path)
            alert = Alert(rule_id="STOR-1", rule_name="Storage Test", severity=Severity.LOW)
            storage.append(alert)

            records = storage.read_all()
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["rule_id"], "STOR-1")
        finally:
            if os.path.exists(path):
                os.remove(path)

    def test_graph_storage_calls_execute_write(self):
        mock_client = MagicMock()
        storage = AlertGraphStorage(mock_client)
        alert = Alert(rule_id="G-1", rule_name="Graph Alert")
        storage.save(alert)
        self.assertTrue(mock_client.execute_write.called)


if __name__ == "__main__":
    unittest.main()
