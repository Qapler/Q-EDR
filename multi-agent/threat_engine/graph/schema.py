"""
Graph schema definitions: node labels, relationship types,
index/constraint DDL, and schema application helper.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .client import GraphClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Node Labels
# ---------------------------------------------------------------------------

NODE_LABELS = {
    "PROCESS":            "Process",
    "HOST":               "Host",
    "USER":               "User",
    "NETWORK_CONNECTION": "NetworkConnection",
    "FILE":               "File",
    "SERVICE":            "Service",
    "REGISTRY_KEY":       "RegistryKey",
    "DNS_QUERY":          "DNSQuery",
    "ALERT":              "Alert",
    "DOMAIN":             "Domain",
    "CREDENTIAL":         "Credential",
}

# ---------------------------------------------------------------------------
# Relationship Types
# ---------------------------------------------------------------------------

RELATIONSHIP_TYPES = {
    "SPAWNED":            "SPAWNED",
    "CONNECTED_TO":       "CONNECTED_TO",
    "ACCESSED":           "ACCESSED",
    "READS":              "READS",
    "WRITES":             "WRITES",
    "CREATED":            "CREATED",
    "DELETED":            "DELETED",
    "MODIFIED":           "MODIFIED",
    "AUTHENTICATED_TO":   "AUTHENTICATED_TO",
    "OWNS":               "OWNS",
    "HAS_PROCESS":        "HAS_PROCESS",
    "TRIGGERED":          "TRIGGERED",
    "RESOLVED_TO":        "RESOLVED_TO",
    "USES":               "USES",
}

# ---------------------------------------------------------------------------
# Schema DDL: Constraints and Indexes
# ---------------------------------------------------------------------------

CONSTRAINTS = [
    # Uniqueness constraints (also create implicit indexes)
    "CREATE CONSTRAINT process_pid_host IF NOT EXISTS FOR (p:Process) REQUIRE (p.pid, p.host_id) IS UNIQUE",
    "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
    "CREATE CONSTRAINT user_sid IF NOT EXISTS FOR (u:User) REQUIRE u.sid IS UNIQUE",
    "CREATE CONSTRAINT alert_id IF NOT EXISTS FOR (a:Alert) REQUIRE a.alert_id IS UNIQUE",
    "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
]

INDEXES = [
    # Process indexes for fast lookups
    "CREATE INDEX process_name IF NOT EXISTS FOR (p:Process) ON (p.name)",
    "CREATE INDEX process_timestamp IF NOT EXISTS FOR (p:Process) ON (p.timestamp)",
    "CREATE INDEX process_cmdline IF NOT EXISTS FOR (p:Process) ON (p.command_line)",
    "CREATE INDEX process_user IF NOT EXISTS FOR (p:Process) ON (p.username)",
    "CREATE INDEX process_integrity IF NOT EXISTS FOR (p:Process) ON (p.integrity_level)",

    # Host indexes
    "CREATE INDEX host_hostname IF NOT EXISTS FOR (h:Host) ON (h.hostname)",
    "CREATE INDEX host_os IF NOT EXISTS FOR (h:Host) ON (h.os)",

    # NetworkConnection indexes
    "CREATE INDEX netconn_dst_port IF NOT EXISTS FOR (n:NetworkConnection) ON (n.dst_port)",
    "CREATE INDEX netconn_timestamp IF NOT EXISTS FOR (n:NetworkConnection) ON (n.timestamp)",
    "CREATE INDEX netconn_protocol IF NOT EXISTS FOR (n:NetworkConnection) ON (n.protocol)",
    "CREATE INDEX netconn_direction IF NOT EXISTS FOR (n:NetworkConnection) ON (n.direction)",

    # File indexes
    "CREATE INDEX file_path IF NOT EXISTS FOR (f:File) ON (f.path)",
    "CREATE INDEX file_name IF NOT EXISTS FOR (f:File) ON (f.name)",
    "CREATE INDEX file_ext IF NOT EXISTS FOR (f:File) ON (f.extension)",
    "CREATE INDEX file_timestamp IF NOT EXISTS FOR (f:File) ON (f.timestamp)",

    # RegistryKey indexes
    "CREATE INDEX regkey_path IF NOT EXISTS FOR (r:RegistryKey) ON (r.path)",
    "CREATE INDEX regkey_timestamp IF NOT EXISTS FOR (r:RegistryKey) ON (r.timestamp)",

    # DNSQuery indexes
    "CREATE INDEX dns_domain IF NOT EXISTS FOR (d:DNSQuery) ON (d.query_name)",
    "CREATE INDEX dns_timestamp IF NOT EXISTS FOR (d:DNSQuery) ON (d.timestamp)",

    # User indexes
    "CREATE INDEX user_username IF NOT EXISTS FOR (u:User) ON (u.username)",
    "CREATE INDEX user_admin IF NOT EXISTS FOR (u:User) ON (u.is_admin)",

    # Service indexes
    "CREATE INDEX service_name IF NOT EXISTS FOR (s:Service) ON (s.name)",
    "CREATE INDEX service_state IF NOT EXISTS FOR (s:Service) ON (s.state)",
    "CREATE INDEX service_bin IF NOT EXISTS FOR (s:Service) ON (s.binary_path)",
]


def apply_schema(client: "GraphClient") -> dict:
    """
    Apply all constraints and indexes to the Neo4j database.

    Args:
        client: A connected GraphClient.

    Returns:
        Dict with counts of constraints/indexes applied and any errors.
    """
    applied_constraints = 0
    applied_indexes = 0
    errors = []

    logger.info("Applying Neo4j schema (constraints + indexes)...")

    for ddl in CONSTRAINTS:
        try:
            client.execute_write(ddl)
            applied_constraints += 1
            logger.debug(f"Applied constraint: {ddl[:60]}...")
        except Exception as exc:
            msg = f"Constraint DDL failed: {exc} | DDL: {ddl[:80]}"
            logger.warning(msg)
            errors.append(msg)

    for ddl in INDEXES:
        try:
            client.execute_write(ddl)
            applied_indexes += 1
            logger.debug(f"Applied index: {ddl[:60]}...")
        except Exception as exc:
            msg = f"Index DDL failed: {exc} | DDL: {ddl[:80]}"
            logger.warning(msg)
            errors.append(msg)

    result = {
        "constraints_applied": applied_constraints,
        "indexes_applied": applied_indexes,
        "errors": errors,
        "total_ddl": len(CONSTRAINTS) + len(INDEXES),
    }

    logger.info(
        "Schema application complete",
        extra={
            "constraints": applied_constraints,
            "indexes": applied_indexes,
            "errors": len(errors),
        },
    )
    return result
