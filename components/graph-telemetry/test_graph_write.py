
import asyncio
import json
from pathlib import Path

from config import settings
from graph_writer import GraphWriter
from normalizer import normalize_event


async def main():
    examples_dir = Path(__file__).resolve().parent / "examples"
    filenames = [
        "process.json",
        "file.json",
        "network.json",
        "ipc.json",
    ]

    events = []
    for filename in filenames:
        event = json.loads((examples_dir / filename).read_text())
        events.append(normalize_event(event))

    writer = GraphWriter(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    try:
        await writer.verify_connection()
        await writer.write_batch(events)
        print(f"\nSubmitted {len(events)} telemetry events.\n")

        async with writer.driver.session(
            database=settings.neo4j_database
        ) as session:
            for event in events:
                result = await session.run(
                    """
                    MATCH (ev:TelemetryEvent {event_id: $event_id})
                    OPTIONAL MATCH (ev)-[:OCCURRED_ON]->(h:Host)
                    OPTIONAL MATCH (ev)-[:INVOLVES_PROCESS]->(p:Process)
                    OPTIONAL MATCH (ev)-[:REFERENCES_FILE]->(f:File)
                    OPTIONAL MATCH (ev)-[:TARGETS_ENDPOINT]->(n:NetworkEndpoint)
                    OPTIONAL MATCH (ev)-[:REFERENCES_IPC]->(r:IPCResource)
                    RETURN ev.event_id AS event_id,
                           ev.event_type AS event_type,
                           h.host_id AS host_id,
                           p.process_entity_id AS process_id,
                           f.path AS file_path,
                           n.ip AS network_ip,
                           r.resource_id AS ipc_resource_id
                    """,
                    event_id=event["event_id"],
                )
                record = await result.single()

                if record is None:
                    print(f"FAIL: {event['event_id']} not found")
                else:
                    print("FOUND:", dict(record))

    finally:
        await writer.close()


if __name__ == "__main__":
    asyncio.run(main())
