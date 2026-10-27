"""
threat_engine/observability/health.py
Health-check system for the detection engine with an optional HTTP server.
"""
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional prometheus_client import for /metrics endpoint
# ---------------------------------------------------------------------------
try:
    import prometheus_client as prom  # type: ignore

    _PROMETHEUS_AVAILABLE = True
except ImportError:
    prom = None  # type: ignore
    _PROMETHEUS_AVAILABLE = False


# ---------------------------------------------------------------------------
# HealthCheck
# ---------------------------------------------------------------------------

class HealthCheck:
    """
    Composite health-check for the Q-EDR threat detection engine.

    Checks performed:
      * **Neo4j** — verifies the graph client can connect.
      * **Rules** — ensures the rule registry has at least one rule loaded.
      * **Alerts** — verifies the alert manager is reachable.

    Overall status:
      * ``"healthy"``  — all checks pass.
      * ``"degraded"`` — one or more checks pass but at least one fails.
      * ``"unhealthy"``— no checks pass.

    An optional lightweight HTTP server exposes ``/health``, ``/ready``,
    and ``/metrics`` endpoints.
    """

    def __init__(
        self,
        graph_client: Any,
        rule_registry: Any,
        alert_manager: Any,
    ) -> None:
        self._graph = graph_client
        self._registry = rule_registry
        self._alerts = alert_manager
        self._http_server: Optional[HTTPServer] = None
        self._http_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def check_neo4j(self) -> Dict[str, Any]:
        """
        Verify that the graph database is reachable.

        Returns:
            dict with keys ``status``, ``message``, and optionally ``error``.
        """
        try:
            ok = self._graph.test_connection()
            if ok:
                return {"status": "ok", "message": "Neo4j reachable"}
            return {"status": "fail", "message": "Connection test returned False"}
        except Exception as exc:  # pylint: disable=broad-except
            return {"status": "fail", "message": "Neo4j unreachable", "error": str(exc)}

    def check_rules(self) -> Dict[str, Any]:
        """
        Verify that the rule registry has rules loaded.

        Returns:
            dict with keys ``status``, ``message``, and ``rule_count``.
        """
        try:
            rules = self._registry.get_enabled()
            count = len(rules)
            if count > 0:
                return {"status": "ok", "message": f"{count} rules loaded", "rule_count": count}
            return {"status": "fail", "message": "No rules loaded", "rule_count": 0}
        except Exception as exc:  # pylint: disable=broad-except
            return {"status": "fail", "message": "Rule registry error", "error": str(exc)}

    def check_alerts(self) -> Dict[str, Any]:
        """
        Verify that the alert manager is functional.

        Returns:
            dict with keys ``status``, ``message``.
        """
        try:
            stats = self._alerts.get_stats()
            return {
                "status": "ok",
                "message": "Alert manager operational",
                "alert_stats": stats,
            }
        except Exception as exc:  # pylint: disable=broad-except
            return {"status": "fail", "message": "Alert manager error", "error": str(exc)}

    # ------------------------------------------------------------------
    # Composite check
    # ------------------------------------------------------------------

    def check_all(self) -> Dict[str, Any]:
        """
        Run all individual health checks and compute overall status.

        Returns:
            Structured health report::

                {
                    "status": "healthy" | "degraded" | "unhealthy",
                    "timestamp": "2024-…",
                    "checks": {
                        "neo4j":  { "status": "ok", … },
                        "rules":  { "status": "ok", … },
                        "alerts": { "status": "ok", … },
                    },
                }
        """
        import datetime

        checks = {
            "neo4j": self.check_neo4j(),
            "rules": self.check_rules(),
            "alerts": self.check_alerts(),
        }

        ok_count = sum(1 for v in checks.values() if v.get("status") == "ok")
        total = len(checks)

        if ok_count == total:
            overall = "healthy"
        elif ok_count == 0:
            overall = "unhealthy"
        else:
            overall = "degraded"

        return {
            "status": overall,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "checks": checks,
        }

    def is_healthy(self) -> bool:
        """Return ``True`` only when every check passes."""
        report = self.check_all()
        return report["status"] == "healthy"

    # ------------------------------------------------------------------
    # HTTP server
    # ------------------------------------------------------------------

    def start_http_server(self, port: int = 8080) -> None:
        """
        Start a lightweight HTTP server that serves:

        * ``GET /health``  — full health report as JSON.
        * ``GET /ready``   — ``200 OK`` / ``503`` based on overall health.
        * ``GET /metrics`` — Prometheus text format (if ``prometheus_client`` installed).

        The server runs in a daemon thread so it will not prevent process exit.

        Args:
            port: TCP port to listen on (default ``8080``).

        Raises:
            RuntimeError: If the server is already running.
        """
        if self._http_server is not None:
            raise RuntimeError(f"Health HTTP server is already running on port {port}")

        health_check_ref = self  # closure-safe reference

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, fmt: str, *args: Any) -> None:  # type: ignore[override]
                # Redirect HTTP access log to Python logging.
                logger.debug("Health HTTP: " + fmt % args)

            def _send_json(self, status: int, body: str) -> None:
                encoded = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def _send_text(self, status: int, body: str, content_type: str = "text/plain") -> None:
                encoded = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", f"{content_type}; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def do_GET(self) -> None:  # noqa: N802
                import json as _json

                path = self.path.split("?")[0].rstrip("/")

                if path == "/health":
                    report = health_check_ref.check_all()
                    http_status = 200 if report["status"] == "healthy" else 503
                    self._send_json(http_status, _json.dumps(report, default=str))

                elif path == "/ready":
                    if health_check_ref.is_healthy():
                        self._send_text(200, "ready\n")
                    else:
                        self._send_text(503, "not ready\n")

                elif path == "/metrics":
                    if _PROMETHEUS_AVAILABLE:
                        from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
                        data = generate_latest().decode("utf-8")
                        self._send_text(200, data, content_type=CONTENT_TYPE_LATEST)
                    else:
                        self._send_text(
                            501,
                            "prometheus_client not installed — metrics unavailable\n",
                        )
                else:
                    self._send_text(404, "not found\n")

        server = HTTPServer(("", port), _Handler)
        self._http_server = server

        def _serve() -> None:
            logger.info(
                "Health HTTP server listening",
                extra={"port": port, "paths": ["/health", "/ready", "/metrics"]},
            )
            try:
                server.serve_forever()
            except Exception:  # pylint: disable=broad-except
                logger.exception("Health HTTP server encountered an error")

        self._http_thread = threading.Thread(
            target=_serve,
            name="HealthHTTPServer",
            daemon=True,
        )
        self._http_thread.start()

    def stop_http_server(self) -> None:
        """Shut down the HTTP server if it is running."""
        if self._http_server is not None:
            self._http_server.shutdown()
            self._http_server.server_close()
            self._http_server = None
            logger.info("Health HTTP server stopped")
