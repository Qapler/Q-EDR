from typing import Dict, Any, Optional
import json
class AgentBaseError(Exception):
    """Root exception for all errors in the Security Agent pipeline."""

    default_layer: str = "CORE"
    default_exit_code: int = 1

    def __init__(
        self,
        message: str,
        *,
        layer: Optional[str] = None,
        exit_code: Optional[int] = None,
        context: Optional[Dict[str, Any]] = None,
        original_exception: Optional[Exception] = None,
    ):
        super().__init__(message)
        self.message = message
        self.layer = layer or self.default_layer
        self.exit_code = exit_code if exit_code is not None else self.default_exit_code
        self.context = context or {}
        self.original_exception = original_exception

    def to_dict(self) -> Dict[str, Any]:
        """Serializes the exception details into a structured dictionary for logging."""
        return {
            "error_type": self.__class__.__name__,
            "layer": self.layer,
            "exit_code": self.exit_code,
            "message": self.message,
            "context": self.context,
            "cause": (
                f"{type(self.original_exception).__name__}: {self.original_exception}"
                if self.original_exception
                else None
            ),
        }

    def __str__(self) -> str:
        base = f"[{self.layer} | {self.__class__.__name__}] (Exit Code {self.exit_code}): {self.message}"
        if self.context:
            base += f" | Context: {json.dumps(self.context, default=str)}"
        if self.original_exception:
            base += f" | Cause: {type(self.original_exception).__name__}: {self.original_exception}"
        return base


# --- Config Layer Exceptions ---
class ConfigurationError(AgentBaseError):
    """Raised when .env variables are missing or invalid."""
    default_layer = "CONFIG"
    default_exit_code = 2


# --- Database Layer Exceptions ---
class DatabaseError(AgentBaseError):
    """Base exception for all DuckDB operations."""
    default_layer = "DATABASE"
    default_exit_code = 3


class DBConnectionError(DatabaseError):
    """Raised when DuckDB cannot open or lock the database file."""
    default_exit_code = 31


class QueryExecutionError(DatabaseError):
    """Raised on SQL syntax errors, missing tables, or missing columns."""
    default_exit_code = 32


class EventNotFoundError(DatabaseError):
    """Raised when the query succeeds but returns no matching event row."""
    default_exit_code = 33


# --- LLM Client Layer Exceptions ---
class LLMClientError(AgentBaseError):
    """Base exception for all local LLM client operations."""
    default_layer = "LLM_CLIENT"
    default_exit_code = 4


class EventSerializationError(LLMClientError):
    """Raised when the raw DuckDB row dictionary fails JSON serialization."""
    default_exit_code = 41


class LLMConnectionError(LLMClientError):
    """Raised when the local LLM server is unreachable or offline."""
    default_exit_code = 42


class LLMTimeoutError(LLMClientError):
    """Raised when LLM inference exceeds the configured timeout."""
    default_exit_code = 43


class LLMResponseError(LLMClientError):
    """Raised on HTTP 4xx/5xx errors, malformed JSON, or empty LLM output."""
    default_exit_code = 44