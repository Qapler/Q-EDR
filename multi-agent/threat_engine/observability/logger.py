"""
threat_engine/observability/logger.py
Structured JSON logging configuration for the threat detection engine.
"""
import logging
import sys
import json
from datetime import datetime, timezone
from typing import Optional


# Fields that are part of the standard LogRecord and should NOT be
# duplicated as extra keys in the JSON output.
_STDLIB_FIELDS = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        "message",
        "taskName",
    }
)


class JSONFormatter(logging.Formatter):
    """
    Format log records as newline-delimited JSON for structured logging
    pipelines (e.g., Fluentd, Logstash, Cloud Logging).

    Extra key/value pairs attached via the ``extra={}`` argument on the
    logging call are automatically included in the JSON document.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        log_data: dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Merge caller-supplied extras, skipping stdlib LogRecord fields.
        for key, value in record.__dict__.items():
            if key not in _STDLIB_FIELDS:
                log_data[key] = value

        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        if record.stack_info:
            log_data["stack_info"] = self.formatStack(record.stack_info)

        return json.dumps(log_data, default=str)


class TextFormatter(logging.Formatter):
    """
    Human-readable formatter with timestamp, level, logger name, and message.
    """

    _DEFAULT_FMT = "%(asctime)s [%(levelname)-8s] %(name)s: %(message)s"
    _DATE_FMT = "%Y-%m-%dT%H:%M:%S"

    def __init__(self) -> None:
        super().__init__(fmt=self._DEFAULT_FMT, datefmt=self._DATE_FMT)


def configure_logging(
    level: str = "INFO",
    fmt: str = "json",
    log_file: Optional[str] = None,
) -> None:
    """
    Configure the root logger with the specified level and format.

    Must be called once at application startup, before any loggers are used.

    Args:
        level: Logging level string (e.g. ``"DEBUG"``, ``"INFO"``).
        fmt: ``"json"`` for JSON lines, anything else for human-readable text.
        log_file: Optional file path to additionally write logs to disk.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(numeric_level)

    # Avoid adding duplicate handlers if called multiple times.
    if root.handlers:
        root.handlers.clear()

    formatter: logging.Formatter = (
        JSONFormatter() if fmt == "json" else TextFormatter()
    )

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    root.addHandler(stdout_handler)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(formatter)
            root.addHandler(file_handler)
        except OSError as exc:
            logging.getLogger(__name__).warning(
                "Could not open log file, skipping file handler",
                extra={"log_file": log_file, "error": str(exc)},
            )
