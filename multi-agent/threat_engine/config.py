"""
threat_engine/config.py
=======================
Production-grade configuration management for the Q-EDR Threat Detection Engine.

Supports loading from environment variables, YAML files, or programmatic defaults.
All fields are validated on construction.
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import yaml
except ImportError:
    yaml = None

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Sub-configs
# ---------------------------------------------------------------------------


@dataclass
class Neo4jConfig:
    """Neo4j connection configuration."""

    uri: str = "bolt://localhost:7687"
    username: str = "neo4j"
    password: str = "password"
    database: str = "neo4j"
    max_connection_pool_size: int = 50
    connection_timeout: float = 30.0
    max_retry_time: float = 15.0

    def __post_init__(self) -> None:
        if not self.uri or not self.uri.startswith(("bolt://", "bolt+s://", "neo4j://", "neo4j+s://")):
            raise ValueError(
                f"Invalid Neo4j URI '{self.uri}'. Must start with bolt://, bolt+s://, neo4j://, or neo4j+s://"
            )
        if not self.username:
            raise ValueError("Neo4j username must not be empty.")
        if not self.password:
            raise ValueError("Neo4j password must not be empty.")
        if self.max_connection_pool_size < 1:
            raise ValueError("max_connection_pool_size must be >= 1.")
        if self.connection_timeout <= 0:
            raise ValueError("connection_timeout must be > 0.")
        if self.max_retry_time <= 0:
            raise ValueError("max_retry_time must be > 0.")


# ---------------------------------------------------------------------------
# Main config
# ---------------------------------------------------------------------------

_VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
_VALID_LOG_FORMATS = {"json", "text"}
_ALL_CATEGORIES = {
    "lateral_movement",
    "privilege_escalation",
    "persistence",
    "credential_access",
    "defense_evasion",
    "discovery",
    "exfiltration",
    "execution",
    "command_control",
    "impact",
}


@dataclass
class EngineConfig:
    """
    Top-level configuration for the Q-EDR Threat Detection Engine.

    Example usage::

        cfg = EngineConfig.from_env()
        cfg = EngineConfig.from_yaml("/etc/qedr/config.yaml")
    """

    neo4j: Neo4jConfig = field(default_factory=Neo4jConfig)
    scan_interval_seconds: int = 60
    rule_timeout_seconds: int = 30
    max_alerts_per_cycle: int = 1000
    alert_dedup_window_seconds: int = 300
    metrics_port: int = 8000
    health_port: int = 8001
    max_workers: int = 10
    log_level: str = "INFO"
    log_format: str = "json"
    log_file: Optional[str] = None
    alert_output_file: Optional[str] = "alerts.jsonl"
    enabled_rule_categories: List[str] = field(
        default_factory=lambda: [
            "lateral_movement",
            "privilege_escalation",
            "persistence",
            "credential_access",
            "defense_evasion",
            "discovery",
            "exfiltration",
            "execution",
            "command_control",
            "impact",
        ]
    )
    dry_run: bool = False

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        if self.scan_interval_seconds < 1:
            raise ValueError("scan_interval_seconds must be >= 1.")
        if self.rule_timeout_seconds < 1:
            raise ValueError("rule_timeout_seconds must be >= 1.")
        if self.max_alerts_per_cycle < 1:
            raise ValueError("max_alerts_per_cycle must be >= 1.")
        if self.alert_dedup_window_seconds < 0:
            raise ValueError("alert_dedup_window_seconds must be >= 0.")
        if not (1 <= self.metrics_port <= 65535):
            raise ValueError(f"metrics_port must be in range 1-65535, got {self.metrics_port}.")
        if self.log_level not in _VALID_LOG_LEVELS:
            raise ValueError(
                f"log_level '{self.log_level}' is invalid. Must be one of {_VALID_LOG_LEVELS}."
            )
        if self.log_format not in _VALID_LOG_FORMATS:
            raise ValueError(
                f"log_format '{self.log_format}' is invalid. Must be one of {_VALID_LOG_FORMATS}."
            )
        unknown = set(self.enabled_rule_categories) - _ALL_CATEGORIES
        if unknown:
            raise ValueError(
                f"Unknown rule categories: {unknown}. "
                f"Valid categories are: {_ALL_CATEGORIES}."
            )
        if not self.enabled_rule_categories:
            raise ValueError("enabled_rule_categories must contain at least one category.")
        if self.alert_output_file is not None:
            output_path = Path(self.alert_output_file)
            if output_path.is_dir():
                raise ValueError(
                    f"alert_output_file '{self.alert_output_file}' points to a directory."
                )

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "EngineConfig":
        """
        Load configuration from environment variables with sensible defaults.

        Environment variables (all optional):
            NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE,
            NEO4J_POOL_SIZE, NEO4J_CONN_TIMEOUT, NEO4J_MAX_RETRY_TIME,
            SCAN_INTERVAL_SECONDS, RULE_TIMEOUT_SECONDS, MAX_ALERTS_PER_CYCLE,
            ALERT_DEDUP_WINDOW_SECONDS, METRICS_PORT, LOG_LEVEL, LOG_FORMAT,
            ALERT_OUTPUT_FILE, ENABLED_RULE_CATEGORIES (comma-separated), DRY_RUN
        """
        neo4j = Neo4jConfig(
            uri=os.getenv("NEO4J_URI", "bolt://localhost:7687"),
            username=os.getenv("NEO4J_USERNAME", "neo4j"),
            password=os.getenv("NEO4J_PASSWORD", "password"),
            database=os.getenv("NEO4J_DATABASE", "neo4j"),
            max_connection_pool_size=int(os.getenv("NEO4J_POOL_SIZE", "50")),
            connection_timeout=float(os.getenv("NEO4J_CONN_TIMEOUT", "30.0")),
            max_retry_time=float(os.getenv("NEO4J_MAX_RETRY_TIME", "15.0")),
        )

        categories_env = os.getenv("ENABLED_RULE_CATEGORIES", "")
        categories: List[str] = (
            [c.strip() for c in categories_env.split(",") if c.strip()]
            if categories_env
            else list(_ALL_CATEGORIES)
        )

        cfg = cls(
            neo4j=neo4j,
            scan_interval_seconds=int(os.getenv("SCAN_INTERVAL_SECONDS", "60")),
            rule_timeout_seconds=int(os.getenv("RULE_TIMEOUT_SECONDS", "30")),
            max_alerts_per_cycle=int(os.getenv("MAX_ALERTS_PER_CYCLE", "1000")),
            alert_dedup_window_seconds=int(os.getenv("ALERT_DEDUP_WINDOW_SECONDS", "300")),
            metrics_port=int(os.getenv("METRICS_PORT", "8000")),
            health_port=int(os.getenv("HEALTH_PORT", "8001")),
            max_workers=int(os.getenv("MAX_WORKERS", "10")),
            log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
            log_format=os.getenv("LOG_FORMAT", "json"),
            log_file=os.getenv("LOG_FILE") or None,
            alert_output_file=os.getenv("ALERT_OUTPUT_FILE", "alerts.jsonl") or None,
            enabled_rule_categories=categories,
            dry_run=os.getenv("DRY_RUN", "false").lower() in ("true", "1", "yes"),
        )
        logger.debug("EngineConfig loaded from environment", extra={"config": repr(cfg)})
        return cfg

    @classmethod
    def from_yaml(cls, path: str) -> "EngineConfig":
        """
        Load configuration from a YAML file.

        The YAML structure mirrors the dataclass hierarchy::

            neo4j:
              uri: bolt://localhost:7687
              username: neo4j
              password: secret
              database: neo4j
              max_connection_pool_size: 50
              connection_timeout: 30.0
              max_retry_time: 15.0

            scan_interval_seconds: 60
            rule_timeout_seconds: 30
            max_alerts_per_cycle: 1000
            alert_dedup_window_seconds: 300
            metrics_port: 8000
            log_level: INFO
            log_format: json
            alert_output_file: alerts.jsonl
            enabled_rule_categories:
              - lateral_movement
              - privilege_escalation
            dry_run: false

        Args:
            path: Absolute or relative path to the YAML file.

        Returns:
            Validated EngineConfig instance.

        Raises:
            FileNotFoundError: If the YAML file does not exist.
            yaml.YAMLError: If the YAML is malformed.
            ValueError: If validation fails.
        """
        if yaml is None:
            raise ImportError("PyYAML is required to load YAML config. Install with: pip install pyyaml")

        yaml_path = Path(path).resolve()
        if not yaml_path.exists():
            raise FileNotFoundError(f"Config file not found: {yaml_path}")

        logger.info("Loading EngineConfig from YAML", extra={"path": str(yaml_path)})
        with open(yaml_path, "r", encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh) or {}

        # Build Neo4jConfig
        neo4j_data = raw.pop("neo4j", {}) or {}
        _neo4j_fields = set(Neo4jConfig.__dataclass_fields__.keys())  # type: ignore[attr-defined]
        neo4j = Neo4jConfig(**{k: v for k, v in neo4j_data.items() if k in _neo4j_fields})

        # Build EngineConfig from remaining keys
        _engine_fields = {k for k in cls.__dataclass_fields__.keys() if k != "neo4j"}  # type: ignore[attr-defined]
        engine_kwargs = {k: v for k, v in raw.items() if k in _engine_fields}

        # Normalize log_level to uppercase if present
        if "log_level" in engine_kwargs:
            engine_kwargs["log_level"] = str(engine_kwargs["log_level"]).upper()

        cfg = cls(neo4j=neo4j, **engine_kwargs)
        logger.debug("EngineConfig loaded from YAML", extra={"path": str(yaml_path), "config": repr(cfg)})
        return cfg

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def is_category_enabled(self, category: str) -> bool:
        """Return True if the given rule category is enabled."""
        return category in self.enabled_rule_categories

    def configure_logging(self) -> None:
        """
        Apply the configured log level and format to the root logger.
        When log_format='json', a simple JSON-like formatter is applied.
        """
        level = getattr(logging, self.log_level, logging.INFO)
        handler = logging.StreamHandler()

        if self.log_format == "json":
            # Minimal JSON-like format; replace with structlog in prod if desired
            fmt = (
                '{"time":"%(asctime)s","level":"%(levelname)s",'
                '"logger":"%(name)s","msg":"%(message)s"}'
            )
        else:
            fmt = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

        handler.setFormatter(logging.Formatter(fmt))
        root = logging.getLogger()
        root.setLevel(level)
        if not root.handlers:
            root.addHandler(handler)

    def __repr__(self) -> str:
        # Mask password in repr
        neo4j_repr = (
            f"Neo4jConfig(uri={self.neo4j.uri!r}, username={self.neo4j.username!r}, "
            f"password='***', database={self.neo4j.database!r})"
        )
        return (
            f"EngineConfig("
            f"neo4j={neo4j_repr}, "
            f"scan_interval_seconds={self.scan_interval_seconds}, "
            f"rule_timeout_seconds={self.rule_timeout_seconds}, "
            f"max_alerts_per_cycle={self.max_alerts_per_cycle}, "
            f"metrics_port={self.metrics_port}, "
            f"log_level={self.log_level!r}, "
            f"dry_run={self.dry_run})"
        )
