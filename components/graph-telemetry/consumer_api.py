
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

from buffer import TelemetryBuffer
from config import settings
from graph_writer import GraphWriter
from normalizer import normalize_event, parse_jsonl


class BatchRequest(BaseModel):
    events: list[dict[str, Any]]


@asynccontextmanager
async def lifespan(app: FastAPI):
    buffer = TelemetryBuffer(maxsize=settings.queue_maxsize)
    writer = GraphWriter(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    app.state.buffer = buffer
    app.state.writer = writer
    app.state.worker_error = None

    worker = None
    try:
        await writer.verify_connection()

        import asyncio
        worker = asyncio.create_task(
            _process_batches(app, buffer, writer)
        )
        yield
    finally:
        if worker is not None:
            worker.cancel()
            try:
                await worker
            except BaseException:
                pass
        await writer.close()


async def _process_batches(app, buffer, writer):
    import asyncio

    while True:
        batch = await buffer.get_batch(
            batch_size=settings.batch_size,
            flush_interval=settings.flush_interval_seconds,
        )
        try:
            await writer.write_batch(batch)
            buffer.mark_done(batch)
            app.state.worker_error = None
        except Exception as exc:
            app.state.worker_error = str(exc)

            # Keep this initial implementation simple:
            # stop processing instead of silently losing/reordering data.
            raise


app = FastAPI(
    title="Q-EDR Graph Telemetry Ingestion",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health(request: Request):
    return {
        "status": "ok",
        "queued_events": request.app.state.buffer.size()
        if hasattr(request.app.state, "buffer") else 0,
        "database_connected": hasattr(request.app.state, "writer"),
        "worker_error": getattr(request.app.state, "worker_error", None),
    }


@app.post("/events")
async def ingest_event(event: dict[str, Any], request: Request):
    try:
        normalized = normalize_event(event)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        await request.app.state.buffer.put(normalized)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to queue telemetry event",
        ) from exc

    return {"accepted": 1, "event_id": normalized["event_id"]}


@app.post("/events/batch")
async def ingest_batch(payload: BatchRequest, request: Request):
    try:
        normalized_events = [
            normalize_event(event) for event in payload.events
        ]
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not normalized_events:
        return {"accepted": 0, "event_ids": []}

    try:
        for event in normalized_events:
            await request.app.state.buffer.put(event)
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail="Unable to queue all telemetry events",
        ) from exc

    return {
        "accepted": len(normalized_events),
        "event_ids": [event["event_id"] for event in normalized_events],
    }


@app.post("/events/jsonl")
async def ingest_jsonl(request: Request):
    content_type = request.headers.get("content-type", "")
    if "text/plain" not in content_type:
        raise HTTPException(
            status_code=415,
            detail="Send JSONL with Content-Type: text/plain",
        )

    body = (await request.body()).decode("utf-8")

    try:
        events = parse_jsonl(body)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    for event in events:
        await request.app.state.buffer.put(event)

    return {"accepted": len(events)}


@app.get("/ready")
async def readiness(request: Request):
    if not hasattr(request.app.state, "writer"):
        raise HTTPException(status_code=503, detail="Database not initialized")

    error = getattr(request.app.state, "worker_error", None)
    if error:
        raise HTTPException(
            status_code=503,
            detail="Telemetry batch worker has failed",
        )

    return {"status": "ready"}
