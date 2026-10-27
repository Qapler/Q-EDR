"""
Unit tests for GraphClient, Schema DDL, and GraphSeeder.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from threat_engine.graph.client import (
    GraphClient,
    GraphDBError,
    GraphConnectionError,
    GraphQueryError,
    GraphAuthError,
)
from threat_engine.graph.schema import apply_schema, CONSTRAINTS, INDEXES
from threat_engine.graph.seeder import GraphSeeder


class TestGraphClient(unittest.TestCase):
    """Tests for GraphClient configuration, query dispatch, and error handling."""

    def test_client_init_and_attributes(self):
        client = GraphClient(
            uri="bolt://127.0.0.1:7687",
            username="neo4j",
            password="testpassword",
            database="threat_db",
            max_connection_pool_size=25,
        )
        self.assertEqual(client._uri, "bolt://127.0.0.1:7687")
        self.assertEqual(client._database, "threat_db")
        self.assertEqual(client._pool_size, 25)

    def test_unconnected_client_raises_connection_error(self):
        client = GraphClient(uri="bolt://localhost:7687", username="neo4j", password="password")
        with self.assertRaises(GraphConnectionError):
            client.execute_read("MATCH (n) RETURN n")

    def test_test_connection_returns_false_when_not_connected(self):
        client = GraphClient(uri="bolt://localhost:7687", username="neo4j", password="password")
        self.assertFalse(client.test_connection())

    def test_query_error_wrapping(self):
        client = GraphClient(uri="bolt://localhost:7687", username="neo4j", password="password")
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value = mock_session
        mock_session.run.side_effect = RuntimeError("Cypher syntax error")
        client._driver = mock_driver

        with self.assertRaises(GraphQueryError):
            client.execute_read("INVALID CYPHER STATEMENT")


class TestGraphSchema(unittest.TestCase):
    """Tests for schema DDL verification and application."""

    def test_ddl_lists_populated(self):
        self.assertGreater(len(CONSTRAINTS), 0)
        self.assertGreater(len(INDEXES), 0)

    def test_apply_schema_executes_ddl(self):
        mock_client = MagicMock(spec=GraphClient)
        result = apply_schema(mock_client)

        self.assertEqual(result["constraints_applied"], len(CONSTRAINTS))
        self.assertEqual(result["indexes_applied"], len(INDEXES))
        self.assertEqual(len(result["errors"]), 0)
        self.assertEqual(mock_client.execute_write.call_count, len(CONSTRAINTS) + len(INDEXES))


class TestGraphSeeder(unittest.TestCase):
    """Tests for synthetic graph attack scenario seeding."""

    def setUp(self):
        self.mock_client = MagicMock(spec=GraphClient)
        # Returns record format expected by seeder queries
        self.mock_client.execute_write.return_value = [{"cnt": 10, "count": 10}]
        self.seeder = GraphSeeder(self.mock_client)

    def test_clear_all(self):
        self.mock_client.execute_write.return_value = [{"cnt": 42}]
        result = self.seeder.clear_all()
        self.assertEqual(result["rels_deleted"], 42)
        self.assertEqual(result["nodes_deleted"], 42)

    def test_seed_lateral_movement(self):
        result = self.seeder.seed_lateral_movement()
        self.assertIsInstance(result, dict)
        self.assertIn("nodes", result)
        self.assertIn("edges", result)
        self.assertTrue(self.mock_client.execute_write.called)

    def test_seed_privilege_escalation(self):
        result = self.seeder.seed_privilege_escalation()
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_seed_persistence(self):
        result = self.seeder.seed_persistence()
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_seed_credential_access(self):
        result = self.seeder.seed_credential_access()
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_seed_ransomware(self):
        result = self.seeder.seed_ransomware()
        self.assertIn("nodes", result)
        self.assertIn("edges", result)

    def test_seed_all(self):
        summary = self.seeder.seed_all()
        self.assertIn("lateral_movement", summary)
        self.assertIn("privilege_escalation", summary)
        self.assertIn("persistence", summary)
        self.assertIn("credential_access", summary)
        self.assertIn("ransomware", summary)
        self.assertIn("defense_evasion", summary)


if __name__ == "__main__":
    unittest.main()
