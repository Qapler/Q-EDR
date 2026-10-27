
import asyncio
import json
from pathlib import Path

from config import settings
from graph_writer import GraphWriter
from normalizer import normalize_event


async def main():
    example_path = Path("examples/process.json")
    event = json.loads(example_path.read_text())
    event = normalize_event(event)

    writer = GraphWriter(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    try:
        await writer.verify_connection()

        # Insert one sample process telemetry event.
        await writer.write_batch([event])
        print(f"Event submitted: {event['event_id']}")

        # Verify that the event and its graph relationships exist.
        async with writer.driver.session(
            database=settings.neo4j_database
        ) as session:
            result = await session.run(
                """
                MATCH (ev:TelemetryEvent {event_id: $event_id})
                OPTIONAL MATCH (ev)-[:OCCURRED_ON]->(h:Host)
                OPTIONAL MATCH (ev)-[:INVOLVES_PROCESS]->(p:Process)
                RETURN ev.event_id AS event_id,
                       ev.event_type AS event_type,
                       h.host_id AS host_id,
                       p.process_entity_id AS process_entity_id
                """,
                event_id=event["event_id"],
            )
            record = await result.single()

        if record is None:
            print("FAIL: Event was not found in Neo4j.")
        else:
            print("SUCCESS: Event found in Neo4j!")
            print(dict(record))

    finally:
        await writer.close()


if __name__ == "__main__":
    asyncio.run(main())
