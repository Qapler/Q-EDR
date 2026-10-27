"""
Unit tests for Threat Detection Rules and RuleRegistry.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock
from typing import Dict, Any

from threat_engine.rules.base import Rule, RuleResult, RuleCategory, Severity, MITRETechnique
from threat_engine.rules.registry import RuleRegistry
from threat_engine.graph.client import GraphClient


class _FakeRule(Rule):
    """Test rule for unit testing."""
    rule_id = "TEST-001"
    rule_name = "Test Detection Rule"
    severity = Severity.MEDIUM
    category = RuleCategory.LATERAL_MOVEMENT
    mitre = MITRETechnique(tactic="Lateral Movement", technique_id="T1000", technique_name="Test Technique")
    enabled = True
    time_window_seconds = 3600

    def get_cypher(self) -> str:
        return "MATCH (n) RETURN n LIMIT 1"


class _DisabledRule(_FakeRule):
    rule_id = "TEST-002"
    enabled = False


class _HighSeverityRule(_FakeRule):
    rule_id = "TEST-003"
    rule_name = "High Severity Rule"
    severity = Severity.HIGH
    category = RuleCategory.PRIVILEGE_ESCALATION
    mitre = MITRETechnique(tactic="Privilege Escalation", technique_id="T1068", technique_name="Privilege Escalation")


class TestRuleCypherContract(unittest.TestCase):
    """Verify rule attributes and Cypher query contracts."""

    def test_rule_attributes(self):
        rule = _FakeRule()
        self.assertEqual(rule.rule_id, "TEST-001")
        self.assertEqual(rule.severity, Severity.MEDIUM)
        self.assertEqual(rule.category, RuleCategory.LATERAL_MOVEMENT)
        self.assertTrue(rule.enabled)
        self.assertEqual(rule.get_cypher_params(), {"time_window": 3600})
        self.assertIn("MATCH", rule.get_cypher())


class TestRuleRunBehavior(unittest.TestCase):
    """Test Rule.run() under various conditions."""

    def test_empty_results_not_matched(self):
        rule = _FakeRule()
        mock_graph = MagicMock(spec=GraphClient)
        mock_graph.execute_read.return_value = []
        mock_graph.run_query.return_value = []

        result = rule.run(mock_graph)
        self.assertFalse(result.matched)
        self.assertEqual(len(result.matches), 0)
        self.assertIsNone(result.error)
        self.assertEqual(result.rule_id, "TEST-001")

    def test_matching_results_matched(self):
        rule = _FakeRule()
        mock_graph = MagicMock(spec=GraphClient)
        mock_graph.execute_read.return_value = [{"src": "10.0.0.1", "dst": "10.0.0.2", "ids": [1, 2]}]
        mock_graph.run_query.return_value = [{"src": "10.0.0.1", "dst": "10.0.0.2", "ids": [1, 2]}]

        result = rule.run(mock_graph)
        self.assertTrue(result.matched)
        self.assertEqual(len(result.matches), 1)
        self.assertEqual(result.matches[0].node_ids, [1, 2])
        self.assertEqual(result.severity, Severity.MEDIUM)
        self.assertEqual(result.category, RuleCategory.LATERAL_MOVEMENT)

    def test_graph_exception_handled(self):
        rule = _FakeRule()
        mock_graph = MagicMock(spec=GraphClient)
        mock_graph.execute_read.side_effect = RuntimeError("Neo4j cluster unavailable")
        mock_graph.run_query.side_effect = RuntimeError("Neo4j cluster unavailable")

        result = rule.run(mock_graph)
        self.assertFalse(result.matched)
        self.assertIn("Neo4j cluster unavailable", result.error)
        self.assertEqual(result.rule_id, "TEST-001")

    def test_disabled_rule_skips_graph(self):
        rule = _DisabledRule()
        mock_graph = MagicMock(spec=GraphClient)

        result = rule.run(mock_graph)
        self.assertFalse(result.matched)
        self.assertEqual(result.error, "Rule disabled")
        self.assertFalse(mock_graph.execute_read.called)


class TestRuleRegistry(unittest.TestCase):
    """Test registry discovery, indexing, filtering, and dynamic mutation."""

    @classmethod
    def setUpClass(cls):
        cls.registry = RuleRegistry()

    def test_all_rules_loaded(self):
        # We designed 69 production rules
        self.assertGreaterEqual(len(self.registry), 50)
        self.assertEqual(len(self.registry._failed_modules), 0)

    def test_all_rules_have_unique_ids(self):
        rules = self.registry.get_all()
        ids = [r.rule_id for r in rules]
        self.assertEqual(len(ids), len(set(ids)), "Found duplicate rule IDs!")

    def test_all_rules_have_valid_cypher(self):
        for rule in self.registry.get_all():
            cypher = rule.get_cypher()
            self.assertIsInstance(cypher, str)
            self.assertGreater(len(cypher.strip()), 0, f"Rule {rule.rule_id} has empty Cypher query")
            params = rule.get_cypher_params()
            self.assertIn("time_window", params, f"Rule {rule.rule_id} missing time_window parameter")

    def test_all_categories_represented(self):
        categories = {r.category for r in self.registry.get_all()}
        # Must cover at least 8 MITRE categories
        self.assertGreaterEqual(len(categories), 8)
        self.assertIn(RuleCategory.LATERAL_MOVEMENT, categories)
        self.assertIn(RuleCategory.PRIVILEGE_ESCALATION, categories)
        self.assertIn(RuleCategory.PERSISTENCE, categories)
        self.assertIn(RuleCategory.CREDENTIAL_ACCESS, categories)
        self.assertIn(RuleCategory.IMPACT, categories)
        self.assertIn(RuleCategory.COMMAND_CONTROL, categories)

    def test_get_by_id(self):
        rules = self.registry.get_all()
        target = rules[0]
        found = self.registry.get_by_id(target.rule_id)
        self.assertEqual(found, target)
        self.assertIsNone(self.registry.get_by_id("NONEXISTENT_RULE_ID"))

    def test_get_by_category(self):
        lm_rules = self.registry.get_by_category(RuleCategory.LATERAL_MOVEMENT)
        self.assertGreater(len(lm_rules), 0)
        for r in lm_rules:
            self.assertEqual(r.category, RuleCategory.LATERAL_MOVEMENT)

    def test_get_by_severity(self):
        crit_rules = self.registry.get_by_severity(Severity.CRITICAL)
        self.assertGreater(len(crit_rules), 0)
        for r in crit_rules:
            self.assertEqual(r.severity, Severity.CRITICAL)

    def test_enable_disable(self):
        rules = self.registry.get_enabled()
        target = rules[0]
        self.registry.disable(target.rule_id)
        self.assertFalse(target.enabled)
        self.assertNotIn(target, self.registry.get_enabled())

        self.registry.enable(target.rule_id)
        self.assertTrue(target.enabled)
        self.assertIn(target, self.registry.get_enabled())

    def test_register_custom_rule(self):
        custom = _FakeRule()
        custom.rule_id = "CUSTOM-999"
        self.registry.register(custom)
        self.assertEqual(self.registry.get_by_id("CUSTOM-999"), custom)

        # Duplicate ID should raise ValueError
        with self.assertRaises(ValueError):
            self.registry.register(custom)


if __name__ == "__main__":
    unittest.main()
