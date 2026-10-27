
import asyncio

from config import settings
from graph_writer import GraphWriter


async def main():
    writer = GraphWriter(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
        database=settings.neo4j_database,
    )

    try:
        await writer.verify_connection()
        print("SUCCESS: Connected to Neo4j!")
        print(f"Database: {settings.neo4j_database}")
        print(f"URI: {settings.neo4j_uri}")
    finally:
        await writer.close()


if __name__ == "__main__":
    asyncio.run(main())
