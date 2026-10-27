import asyncio
from typing import Any


class TelemetryBuffer:
    """Bounded asynchronous buffer for normalized telemetry events."""

    def __init__(self, maxsize: int = 10_000):
        if maxsize < 1:
            raise ValueError("maxsize must be positive")

        self.queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=maxsize
        )

    async def put(self, event: dict[str, Any]) -> None:
        # Wait for space instead of silently dropping security events.
        await self.queue.put(event)

    async def get_batch(
        self,
        batch_size: int = 200,
        flush_interval: float = 0.5,
    ) -> list[dict[str, Any]]:
        if batch_size < 1:
            raise ValueError("batch_size must be positive")

        if flush_interval <= 0:
            raise ValueError("flush_interval must be positive")

        # Wait until the first event arrives.
        first = await self.queue.get()
        batch = [first]

        # Collect more events until the batch fills or timeout expires.
        loop = asyncio.get_running_loop()
        deadline = loop.time() + flush_interval

        while len(batch) < batch_size:
            remaining = deadline - loop.time()

            if remaining <= 0:
                break

            try:
                event = await asyncio.wait_for(
                    self.queue.get(),
                    timeout=remaining,
                )
                batch.append(event)
            except asyncio.TimeoutError:
                break

        return batch

    def mark_done(self, batch: list[dict[str, Any]]) -> None:
        """Call only after the batch is successfully persisted."""
        for _ in batch:
            self.queue.task_done()

    def size(self) -> int:
        return self.queue.qsize()
