import os
import sys
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional
import duckdb
import requests
from dotenv import load_dotenv
from exceptions import (ConfigurationError,DBConnectionError,DatabaseError,LLMClientError,
LLMConnectionError,LLMResponseError,LLMTimeoutError,EventNotFoundError,EventSerializationError,QueryExecutionError,AgentBaseError)

@dataclass(frozen=True)
class AgentConfig:
    duckdb_url: str
    table_name: str
    event_column: str
    llm_api_url: str
    llm_model: str
    timeout: int

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """Loads and validates environment variables from the .env file."""
        load_dotenv()

        duckdb_url = os.getenv("DUCKDB_URL", "").strip()
        if not duckdb_url:
            raise ConfigurationError(
                message="Missing required environment variable 'DUCKDB_URL' in .env file.",
                context={"env_var": "DUCKDB_URL", "raw_value": duckdb_url},
            )

        raw_timeout = os.getenv("LLM_TIMEOUT", "30").strip()
        try:
            timeout = int(raw_timeout)
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0.")
        except ValueError as err:
            raise ConfigurationError(
                message="Invalid integer value for 'LLM_TIMEOUT'.",
                context={"env_var": "LLM_TIMEOUT", "raw_value": raw_timeout},
                original_exception=err,
            ) from err

        return cls(
            duckdb_url=duckdb_url,
            table_name=os.getenv("DUCKDB_TABLE", "events").strip(),
            event_column=os.getenv("DUCKDB_EVENT_COL", "event_type").strip(),
            llm_api_url=os.getenv("LLM_API_URL", "http://localhost:11434/api/generate").strip(),
            llm_model=os.getenv("LLM_MODEL", "llama3.2").strip(),
            timeout=timeout,
        )


# =====================================================================
# 3. Data Access Layer (DuckDB Repository)
# =====================================================================
class DuckDBRepository:
    """Encapsulates DuckDB connection management and event retrieval."""

    def __init__(self, db_url: str, table_name: str, event_column: str = "event_type"):
        self._db_url = db_url
        self._table_name = table_name
        self._event_column = event_column

    def fetch_single_event(self, event_type: str = "ProcessCreate") -> Dict[str, Any]:
        """Connects to DuckDB in read-only mode and fetches a single event record."""
        try:
            con = duckdb.connect(database=self._db_url, read_only= (self._db_url != ":memory:"))
        except duckdb.Error as err:
            raise DBConnectionError(
                message="Failed to open DuckDB database file.",
                context={"db_url": self._db_url, "read_only": (self._db_url != ":memory:")},
                original_exception=err,
            ) from err

        query = f"""
            SELECT * 
            FROM "{self._table_name}" 
            WHERE "{self._event_column}" = ? 
            LIMIT 1
        """

        try:
            with con:
                result = con.execute(query, [event_type])
                row = result.fetchone()

                if not row:
                    raise EventNotFoundError(
                        message=f"No '{event_type}' event found in table.",
                        context={
                            "db_url": self._db_url,
                            "table": self._table_name,
                            "column": self._event_column,
                            "event_type": event_type,
                        },
                    )

                columns = [desc[0] for desc in result.description]
                return dict(zip(columns, row))

        except EventNotFoundError:
            raise
        except duckdb.Error as err:
            raise QueryExecutionError(
                message="Failed to execute SQL query on DuckDB.",
                context={
                    "table": self._table_name,
                    "column": self._event_column,
                    "event_type": event_type,
                    "query": " ".join(query.split()),
                },
                original_exception=err,
            ) from err


class LocalLLMClient:
    """Handles event serialization, prompt construction, and local LLM HTTP calls."""

    def __init__(self, api_url: str, model: str, timeout: int = 30):
        self._api_url = api_url
        self._model = model
        self._timeout = timeout

    @staticmethod
    def _serialize_event(event: Dict[str, Any]) -> str:
        """Serializes the DuckDB event dictionary into a JSON string."""
        try:
            return json.dumps(event, default=str)
        except (TypeError, OverflowError, ValueError) as err:
            raise EventSerializationError(
                message="Failed to serialize raw process event dictionary to JSON.",
                context={"event_keys": list(event.keys())},
                original_exception=err,
            ) from err

    def generate_explanation(
        self,
        event: Dict[str, Any],
        instruction: str = "Explain this raw process event in one sentence.",
    ) -> str:
        """Sends the serialized event to the local LLM and returns its one-sentence explanation."""
        raw_event_json = self._serialize_event(event)
        prompt = f"{instruction}\n\nEvent Data:\n{raw_event_json}"

        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }

        try:
            response = requests.post(
                self._api_url,
                json=payload,
                timeout=self._timeout,
            )
            response.raise_for_status()
        except requests.exceptions.Timeout as err:
            raise LLMTimeoutError(
                message="Local LLM inference timed out.",
                context={
                    "api_url": self._api_url,
                    "model": self._model,
                    "timeout_sec": self._timeout,
                },
                original_exception=err,
            ) from err
        except requests.exceptions.ConnectionError as err:
            raise LLMConnectionError(
                message="Could not reach local LLM endpoint. Ensure Ollama/vLLM server is running.",
                context={"api_url": self._api_url, "model": self._model},
                original_exception=err,
            ) from err
        except requests.exceptions.HTTPError as err:
            resp = err.response if err.response is not None else response
            raise LLMResponseError(
                message="Local LLM endpoint returned an HTTP error status.",
                context={
                    "api_url": self._api_url,
                    "status_code": resp.status_code,
                    "raw_body": resp.text[:300],
                },
                original_exception=err,
            ) from err
        except requests.exceptions.RequestException as err:
            raise LLMClientError(
                message="Unexpected network failure while communicating with local LLM.",
                context={"api_url": self._api_url},
                original_exception=err,
            ) from err

        try:
            data = response.json()
        except ValueError as err:
            raise LLMResponseError(
                message="Local LLM returned a non-JSON response body.",
                context={
                    "status_code": response.status_code,
                    "raw_body": response.text[:300],
                },
                original_exception=err,
            ) from err

        # Support both Ollama (/api/generate) and OpenAI-compatible (/v1/chat/completions) schemas
        explanation = data.get("response")
        if explanation is None and "choices" in data and len(data["choices"]) > 0:
            choice = data["choices"][0]
            explanation = choice.get("text") or choice.get("message", {}).get("content")

        if not explanation or not str(explanation).strip():
            raise LLMResponseError(
                message="Local LLM JSON response did not contain a valid explanation text.",
                context={"status_code": response.status_code, "parsed_json": data},
            )

        return str(explanation).strip()



class SecurityAgent:
    """Coordinates data retrieval from DuckDB and analysis via the Local LLM."""

    PROMPT_INSTRUCTION = "Explain this raw process event in one sentence."

    def __init__(self, repo: DuckDBRepository, llm: LocalLLMClient):
        self._repo = repo
        self._llm = llm

    def analyze_process_create(self) -> Dict[str, Any]:
        """Fetches the single ProcessCreate row and generates a one-sentence LLM explanation."""
        raw_event = self._repo.fetch_single_event(event_type="ProcessCreate")
        explanation = self._llm.generate_explanation(
            event=raw_event,
            instruction=self.PROMPT_INSTRUCTION,
        )
        return {
            "event": raw_event,
            "explanation": explanation,
        }


def main() -> None:
    try:
        config = AgentConfig.from_env()

        repo = DuckDBRepository(
            db_url=config.duckdb_url,
            table_name=config.table_name,
            event_column=config.event_column,
        )
        llm_client = LocalLLMClient(
            api_url=config.llm_api_url,
            model=config.llm_model,
            timeout=config.timeout,
        )

        agent = SecurityAgent(repo=repo, llm=llm_client)

        print(f"[*] Connecting to DuckDB ({config.duckdb_url}) -> Table '{config.table_name}'...")
        result = agent.analyze_process_create()

        print("\n[+] Raw ProcessCreate Event:")
        print(json.dumps(result["event"], indent=2, default=str))

        print(f"\n[+] One-Sentence Explanation ({config.llm_model}):")
        print(result["explanation"])

    except AgentBaseError as err:
        # Single unified catch block utilizing the rich exception hierarchy
        print(f"\n[!] {err}", file=sys.stderr)
        sys.exit(err.exit_code)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user.", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()