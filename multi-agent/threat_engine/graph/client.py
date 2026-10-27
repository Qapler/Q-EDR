"""
Production Neo4j graph client with connection pooling,
retry logic, health checks, structured logging, and offline simulation mode.
"""
from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain Exceptions
# ---------------------------------------------------------------------------

class GraphDBError(Exception):
    """Base exception for all graph database errors."""


class GraphConnectionError(GraphDBError):
    """Cannot connect to Neo4j or connection was lost."""


class GraphQueryError(GraphDBError):
    """A Cypher query failed to execute."""


class GraphAuthError(GraphDBError):
    """Neo4j authentication / authorisation failed."""


# ---------------------------------------------------------------------------
# GraphClient
# ---------------------------------------------------------------------------

class GraphClient:
    """
    Production Neo4j client with connection pooling, retry logic,
    health checks, and structured logging.

    Supports both live Neo4j cluster connections (Bolt protocol)
    and an offline simulation mode for local testing without Neo4j.
    """

    def __init__(
        self,
        uri: str = "bolt://localhost:7687",
        username: str = "neo4j",
        password: str = "password",
        database: str = "neo4j",
        max_connection_pool_size: int = 50,
        connection_timeout: float = 30.0,
        max_retry_time: float = 15.0,
        mock_mode: bool = False,
    ) -> None:
        self._uri = uri
        self._username = username
        self._password = password
        self._database = database
        self._pool_size = max_connection_pool_size
        self._conn_timeout = connection_timeout
        self._retry_time = max_retry_time
        self._mock_mode = mock_mode or uri.startswith("mock://") or uri.startswith("simulated://")
        self._driver = None
        self._connected = False
        self._simulation_scenario: Optional[str] = None

        logger.info(
            "GraphClient initialised",
            extra={"uri": uri, "database": database, "pool_size": max_connection_pool_size, "mock_mode": self._mock_mode},
        )

    def set_simulation_scenario(self, scenario: Optional[str]) -> None:
        """Set the active simulated attack scenario (e.g. 'ransomware', 'lateral_movement', 'all')."""
        self._simulation_scenario = scenario

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Establish the Neo4j driver connection and verify reachability."""
        if self._mock_mode:
            self._connected = True
            logger.info("GraphClient running in simulation / mock mode", extra={"uri": self._uri})
            return

        try:
            from neo4j import GraphDatabase
            from neo4j.exceptions import AuthError, ServiceUnavailable

            self._driver = GraphDatabase.driver(
                self._uri,
                auth=(self._username, self._password),
                max_connection_pool_size=self._pool_size,
                connection_timeout=self._conn_timeout,
                max_transaction_retry_time=self._retry_time,
            )
            self._driver.verify_connectivity()
            self._connected = True
            logger.info("Neo4j connection established", extra={"uri": self._uri})
        except Exception as exc:
            exc_name = type(exc).__name__
            if "AuthError" in exc_name:
                raise GraphAuthError(f"Neo4j authentication failed for user '{self._username}': {exc}") from exc
            elif "ServiceUnavailable" in exc_name or "ConnectionError" in exc_name:
                raise GraphConnectionError(f"Neo4j service unavailable at '{self._uri}': {exc}") from exc
            else:
                raise GraphConnectionError(f"Unexpected error connecting to Neo4j: {exc}") from exc

    def close(self) -> None:
        """Gracefully close the driver and release all pooled connections."""
        self._connected = False
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception as exc:
                logger.warning("Error closing Neo4j driver", extra={"error": str(exc)})
            finally:
                self._driver = None
                logger.info("Neo4j driver closed")

    def __enter__(self) -> "GraphClient":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def _require_driver(self):
        if not self._connected and self._driver is None:
            raise GraphConnectionError(
                "GraphClient is not connected. Call connect() or use as a context manager."
            )
        return self._driver

    # ------------------------------------------------------------------
    # Session factory
    # ------------------------------------------------------------------

    @contextmanager
    def _session(self) -> Generator:
        driver = self._require_driver()
        session = driver.session(database=self._database)
        try:
            yield session
        finally:
            session.close()

    # ------------------------------------------------------------------
    # Query execution
    # ------------------------------------------------------------------

    def execute_read(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a read Cypher query and return results as a list of dicts."""
        params = params or {}
        if not self._connected and self._driver is None:
            raise GraphConnectionError("GraphClient is not connected. Call connect() or use as a context manager.")

        if self._mock_mode:
            return self._dispatch_simulation_read(cypher, params)

        t_start = time.monotonic()
        try:
            with self._session() as session:
                run_kwargs: Dict[str, Any] = {"parameters": params}
                if timeout is not None:
                    run_kwargs["timeout"] = timeout
                result = session.run(cypher, **run_kwargs)
                records = [dict(record) for record in result]
                elapsed_ms = round((time.monotonic() - t_start) * 1000, 2)
                logger.debug("Read query executed", extra={"rows": len(records), "elapsed_ms": elapsed_ms})
                return records
        except GraphConnectionError:
            raise
        except Exception as exc:
            exc_name = type(exc).__name__
            elapsed_ms = round((time.monotonic() - t_start) * 1000, 2)
            if "ServiceUnavailable" in exc_name or "ConnectionError" in exc_name:
                raise GraphConnectionError(f"Neo4j unavailable during read: {exc}") from exc
            raise GraphQueryError(
                f"Cypher read query failed after {elapsed_ms}ms: {exc}\nQuery: {cypher[:200]}"
            ) from exc

    def execute_write(
        self,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute a write Cypher statement."""
        params = params or {}
        if not self._connected and self._driver is None:
            raise GraphConnectionError("GraphClient is not connected. Call connect() or use as a context manager.")

        if self._mock_mode:
            return [{"cnt": 10, "count": 10, "deleted": 10}]

        try:
            with self._session() as session:
                result = session.run(cypher, parameters=params)
                return [dict(record) for record in result]
        except GraphConnectionError:
            raise
        except Exception as exc:
            exc_name = type(exc).__name__
            if "ServiceUnavailable" in exc_name or "ConnectionError" in exc_name:
                raise GraphConnectionError(f"Neo4j unavailable during write: {exc}") from exc
            raise GraphQueryError(f"Cypher write query failed: {exc}\nQuery: {cypher[:200]}") from exc

    # Convenient aliases
    run_query = execute_read
    execute_query = execute_read

    # ------------------------------------------------------------------
    # Simulation Query Dispatcher
    # ------------------------------------------------------------------

    def _dispatch_simulation_read(self, cypher: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Simulate realistic Cypher query evaluation for demonstration and testing."""
        c = cypher.lower()

        # Count check
        if "count(" in c and "return" in c and not "with" in c:
            return [{"cnt": 450, "count": 450}]

        scenario = self._simulation_scenario or "all"

        # 1. Lateral Movement: Pass The Hash
        if ("ntlm_hash" in c or "t1550" in c or "authenticated_to" in c) and scenario in ("all", "lateral_movement", "pth"):
            return [{
                "username": "jdoe",
                "source_ip": "10.0.0.10",
                "target_ip": "10.0.0.20",
                "target_hosts": ["10.0.0.20", "10.0.0.30", "10.0.0.40"],
                "ntlm_hash": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
                "hop_count": 3,
                "host_count": 3,
                "ids": [101, 102, 103],
            }]

        # 2. Lateral Movement: SMB Admin Share
        if ("admin$" in c or "c$" in c) and scenario in ("all", "lateral_movement", "smb"):
            return [{
                "source_ip": "10.0.0.10",
                "target_ip": "10.0.0.20",
                "share": "ADMIN$",
                "port": 445,
                "ids": [103, 104],
            }]

        # 3. Privilege Escalation: Token Impersonation / Process Injection
        if ("process_vm_write" in c or "injection" in c) and scenario in ("all", "privilege_escalation"):
            return [{
                "source_process": "malware.exe",
                "source_pid": 4200,
                "target_process": "lsass.exe",
                "target_pid": 700,
                "host_ip": "10.0.0.10",
                "ids": [4200, 700],
            }]

        # 4. Credential Access: LSASS Memory Dump
        if ("lsass" in c or "process_vm_read" in c) and scenario in ("all", "credential_access", "lsass"):
            return [{
                "source_process": "procdump.exe",
                "source_pid": 8800,
                "target_process": "lsass.exe",
                "target_pid": 700,
                "host_ip": "10.0.0.10",
                "ids": [8800, 700],
            }]

        # 5. Defense Evasion: Windows Event Log Clearing
        if ("wevtutil" in c or "clear-eventlog" in c or "log clearing" in c) and scenario in ("all", "defense_evasion"):
            return [{
                "process_name": "wevtutil.exe",
                "pid": 5100,
                "command_line": "wevtutil.exe cl Security",
                "host_ip": "10.0.0.10",
                "ids": [5100],
            }]

        # 5b. Defense Evasion: AMSI Bypass
        if "amsi" in c and scenario in ("all", "defense_evasion"):
            return [{
                "entity_id": 5200,
                "process_name": "powershell.exe",
                "pid": 5200,
                "command_line": "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)",
                "host_id": "10.0.0.10",
                "ids": [5200],
            }]

        # 6. Command & Control: Periodic Beaconing
        if ("beacon" in c or "is_external" in c) and scenario in ("all", "command_control", "beaconing"):
            return [{
                "source_ip": "10.0.0.10",
                "source_host": "WORKSTATION-01",
                "external_ip": "198.51.100.99",
                "external_host": "c2-server.evil.com",
                "dst_port": 443,
                "conn_count": 25,
                "ids": [1, 2, 3],
            }]

        # 7. Impact: Ransomware Encryption
        if (".locked" in c or "encrypt" in c or "crypto" in c) and scenario in ("all", "ransomware", "impact"):
            return [{
                "host_ip": "10.0.0.10",
                "process_name": "cryptolocker.exe",
                "pid": 7700,
                "command_line": "cryptolocker.exe --encrypt C:\\Users\\jdoe\\Documents",
                "files_modified": 100,
                "ids": [7700],
            }]

        # 8. Impact: System Recovery Inhibition (Shadow Copies)
        if ("vssadmin" in c or "delete" in c and "shadows" in c) and scenario in ("all", "impact", "ransomware"):
            return [{
                "host_ip": "10.0.0.10",
                "hostname": "WORKSTATION-01",
                "process_name": "vssadmin.exe",
                "pid": 3300,
                "command_line": "vssadmin.exe delete shadows /all /quiet",
                "ids": [3300],
            }]

        # 9. Discovery: Network Port Scan
        if ("port" in c and "scan" in c or "target_count" in c) and scenario in ("all", "discovery"):
            return [{
                "scanner_ip": "10.0.0.10",
                "target_count": 30,
                "port_count": 10,
                "ids": [10],
            }]

        # 10. Persistence: Suspicious Registry Run Key
        if ("currentversion\\run" in c or "registrykey" in c) and scenario in ("all", "persistence"):
            return [{
                "process_name": "backdoor.exe",
                "pid": 9100,
                "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor",
                "target_binary": "C:\\Users\\jdoe\\AppData\\Roaming\\backdoor.exe",
                "ids": [9100],
            }]

        return []

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def test_connection(self) -> bool:
        """Return True if Neo4j is currently reachable, False otherwise."""
        if self._mock_mode:
            return self._connected
        try:
            self._require_driver().verify_connectivity()
            return True
        except Exception:
            return False

    def get_node_count(self) -> int:
        """Return the total number of nodes in the configured database."""
        rows = self.execute_read("MATCH (n) RETURN count(n) AS cnt")
        return int(rows[0]["cnt"]) if rows else 0

    def get_relationship_count(self) -> int:
        """Return the total number of relationships in the database."""
        rows = self.execute_read("MATCH ()-[r]->() RETURN count(r) AS cnt")
        return int(rows[0]["cnt"]) if rows else 0
