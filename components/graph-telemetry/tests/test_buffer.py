import asyncio

import pytest

from buffer import TelemetryBuffer


@pytest.mark.asyncio
async def test_batch_collects_available_events():
    buffer = TelemetryBuffer(maxsize=10)

    await buffer.put({"event_id": "1"})
    await buffer.put({"event_id": "2"})

    batch = await buffer.get_batch(
        batch_size=5,
        flush_interval=0.05,
    )

    assert [event["event_id"] for event in batch] == ["1", "2"]
    assert buffer.size() == 0

    buffer.mark_done(batch)
    await asyncio.wait_for(buffer.queue.join(), timeout=1)


@pytest.mark.asyncio
async def test_batch_stops_at_batch_size():
    buffer = TelemetryBuffer(maxsize=10)

    for i in range(4):
        await buffer.put({"event_id": str(i)})

    batch = await buffer.get_batch(
        batch_size=2,
        flush_interval=0.5,
    )

    assert len(batch) == 2
    assert buffer.size() == 2

    buffer.mark_done(batch)

    remaining = await buffer.get_batch(
        batch_size=5,
        flush_interval=0.05,
    )

    assert len(remaining) == 2
    buffer.mark_done(remaining)

    await asyncio.wait_for(buffer.queue.join(), timeout=1)


@pytest.mark.asyncio
async def test_queue_applies_backpressure():
    buffer = TelemetryBuffer(maxsize=1)

    await buffer.put({"event_id": "1"})

    producer = asyncio.create_task(
        buffer.put({"event_id": "2"})
    )

    await asyncio.sleep(0.02)
    assert not producer.done()

    batch = await buffer.get_batch(
        batch_size=1,
        flush_interval=0.05,
    )

    buffer.mark_done(batch)
    await asyncio.wait_for(producer, timeout=1)

    remaining = await buffer.get_batch(
        batch_size=1,
        flush_interval=0.05,
    )

    assert remaining[0]["event_id"] == "2"
    buffer.mark_done(remaining)

    await asyncio.wait_for(buffer.queue.join(), timeout=1)
