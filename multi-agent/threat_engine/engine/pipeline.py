"""
threat_engine/engine/pipeline.py
Scheduled detection pipeline — wraps ThreatDetector in a background loop.
"""
import logging
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, Optional

from .detector import ThreatDetector

logger = logging.getLogger(__name__)


class DetectionPipeline:
    """
    Scheduled detection pipeline that runs ``ThreatDetector.run_scan()``
    every *interval_seconds* in a dedicated daemon thread.

    Lifecycle::

        pipeline = DetectionPipeline(detector, interval_seconds=60)
        pipeline.start()
        # … runs in background …
        pipeline.stop()

    Thread safety:
        ``get_last_scan_result()`` and ``get_scan_history()`` are safe to
        call from any thread; they operate under a ``threading.Lock``.
    """

    def __init__(
        self,
        detector: ThreatDetector,
        interval_seconds: float = 60.0,
        history_size: int = 100,
    ) -> None:
        """
        Args:
            detector: Configured ``ThreatDetector`` instance.
            interval_seconds: Seconds between successive scans.
            history_size: Maximum number of past scan results to retain.
        """
        if interval_seconds <= 0:
            raise ValueError(f"interval_seconds must be > 0, got {interval_seconds}")

        self._detector = detector
        self._interval = interval_seconds
        self._history_size = history_size

        self._stop_event: threading.Event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started_at: Optional[float] = None

        self._lock = threading.Lock()
        self._scan_history: Deque[Dict[str, Any]] = deque(maxlen=history_size)
        self._last_result: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # Background worker
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:
        """Main loop executed by the pipeline thread."""
        logger.info(
            "Detection pipeline started",
            extra={"interval_s": self._interval},
        )

        while not self._stop_event.is_set():
            try:
                result = self._detector.run_scan()
                with self._lock:
                    self._last_result = result
                    self._scan_history.append(result)
            except Exception:  # pylint: disable=broad-except
                logger.exception("Unexpected error during detection scan")

            # Wait for next interval, but honour stop signal early.
            self._stop_event.wait(timeout=self._interval)

        logger.info("Detection pipeline stopped")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the pipeline background thread.

        Raises:
            RuntimeError: If the pipeline is already running.
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("DetectionPipeline is already running")

        self._stop_event.clear()
        self._started_at = time.monotonic()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="DetectionPipeline",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "DetectionPipeline thread launched",
            extra={"interval_s": self._interval},
        )

    def stop(self, timeout: float = 10.0) -> None:
        """
        Signal the pipeline to stop and wait for the thread to finish.

        Args:
            timeout: Maximum seconds to wait for thread termination.
        """
        if self._thread is None:
            logger.warning("DetectionPipeline.stop() called but pipeline was never started")
            return

        logger.info("Stopping DetectionPipeline…")
        self._stop_event.set()

        self._thread.join(timeout=timeout)

        if self._thread.is_alive():
            logger.warning(
                "DetectionPipeline thread did not terminate within timeout",
                extra={"timeout_s": timeout},
            )
        else:
            logger.info("DetectionPipeline thread terminated cleanly")

        self._thread = None
        self._started_at = None

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the pipeline thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def get_last_scan_result(self) -> Optional[Dict[str, Any]]:
        """
        Return the most recent scan result dict, or ``None`` if no scan
        has completed yet.
        """
        with self._lock:
            return self._last_result

    def get_scan_history(self, n: Optional[int] = None) -> list:
        """
        Return up to *n* most recent scan result dicts (newest last).

        Args:
            n: Maximum number of entries to return. If ``None`` or larger
               than history, all available entries are returned.
        """
        with self._lock:
            history = list(self._scan_history)

        if n is not None:
            return history[-n:]
        return history

    def get_uptime(self) -> Optional[float]:
        """
        Return pipeline uptime in seconds, or ``None`` if not running.
        """
        if self._started_at is None:
            return None
        return round(time.monotonic() - self._started_at, 3)
