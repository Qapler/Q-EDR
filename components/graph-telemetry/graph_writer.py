import json
from typing import Any

from neo4j import AsyncGraphDatabase


class GraphWriter:
    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        database: str = "neo4j",
    ) -> None:
        self.driver = AsyncGraphDatabase.driver(
            uri,
            auth=(username, password),
        )
        self.database = database

    async def verify_connection(self) -> None:
        await self.driver.verify_connectivity()

    async def close(self) -> None:
        await self.driver.close()

    @staticmethod
    def _ipc_resource_id(event_type: str, data: dict[str, Any]) -> str | None:
        resource_id = data.get("resource_id")

        if resource_id is not None:
            return str(resource_id)

        for key in ("shm_id", "id", "pipe_id", "socket_id"):
            value = data.get(key)
            if value is not None:
                return str(value)

        if event_type == "ipc.pipe_create":
            read_fd = data.get("read_fd")
            write_fd = data.get("write_fd")
            if read_fd is not None or write_fd is not None:
                return f"pipe:{read_fd}:{write_fd}"

        if event_type == "ipc.socketpair_create":
            fds = data.get("fds")
            if isinstance(fds, list):
                return "socketpair:" + ":".join(map(str, fds))

        return None

    async def write_batch(self, events: list[dict[str, Any]]) -> None:
        if not events:
            return

        prepared = []

        for event in events:
            actor = event.get("actor") or {}
            data = event.get("data") or {}
            host = event["host"]
            event_type = event["event_type"]

            file_path = (
                data.get("path")
                or data.get("file_path")
                or data.get("filename")
            )

            if event_type == "filesystem.rename":
                file_path = data.get("new_path") or data.get("old_path") or file_path

            remote_addr = (
                data.get("remote_addr")
                or data.get("addr")
            )
            remote_port = (
                data.get("remote_port")
                if data.get("remote_port") is not None
                else data.get("port")
            )

            prepared.append({
                "event_id": event["event_id"],
                "event_type": event_type,
                "schema_version": event["schema_version"],
                "event_time": event.get("event_time"),
                "observed_time": event["observed_time"],
                "host_id": host["host_id"],
                "hostname": host.get("hostname"),
                "host_os": host.get("os"),
                "host_architecture": host.get("architecture"),
                "process_entity_id": actor.get("process_entity_id"),
                "parent_entity_id": actor.get("parent_entity_id"),
                "pid": actor.get("pid"),
                "ppid": actor.get("ppid"),
                "comm": actor.get("comm"),
                "exe": actor.get("exe") or data.get("exe") or data.get("executable"),
                "data_json": json.dumps(data),
                "source_json": json.dumps(event.get("source") or {}),
                "quality_json": json.dumps(event.get("quality") or {}),
                "raw_payload": json.dumps(event),
                "file_path": file_path,
                "old_path": data.get("old_path"),
                "new_path": data.get("new_path"),
                "remote_addr": remote_addr,
                "remote_port": remote_port,
                "protocol": data.get("protocol"),
                "ipc_resource_id": self._ipc_resource_id(event_type, data),
            })

        async with self.driver.session(database=self.database) as session:
            await session.execute_write(self._write_transaction, prepared)

    @staticmethod
    async def _write_transaction(tx: Any, events: list[dict[str, Any]]) -> None:
        query = """
        UNWIND $events AS e

        MERGE (h:Host {host_id: e.host_id})
        SET h.hostname = coalesce(e.hostname, h.hostname),
            h.os = coalesce(e.host_os, h.os),
            h.architecture = coalesce(e.host_architecture, h.architecture)

        MERGE (ev:TelemetryEvent {event_id: e.event_id})
        ON CREATE SET
            ev.event_type = e.event_type,
            ev.schema_version = e.schema_version,
            ev.event_time = CASE
                WHEN e.event_time IS NULL THEN null
                ELSE datetime(e.event_time)
            END,
            ev.observed_time = datetime(e.observed_time),
            ev.host_id = e.host_id,
            ev.data_json = e.data_json,
            ev.source_json = e.source_json,
            ev.quality_json = e.quality_json,
            ev.raw_payload = e.raw_payload,
            ev.file_path = e.file_path,
            ev.remote_addr = e.remote_addr,
            ev.remote_port = e.remote_port,
            ev.protocol = e.protocol

        MERGE (ev)-[:OCCURRED_ON]->(h)

        FOREACH (_ IN CASE
            WHEN e.process_entity_id IS NOT NULL THEN [1] ELSE []
        END |
            MERGE (p:Process {process_entity_id: e.process_entity_id})
            SET p.pid = e.pid,
                p.comm = e.comm,
                p.exe = e.exe
            MERGE (p)-[:RUNS_ON]->(h)
            MERGE (ev)-[:INVOLVES_PROCESS]->(p)
        )

        FOREACH (_ IN CASE
            WHEN e.process_entity_id IS NOT NULL
             AND e.parent_entity_id IS NOT NULL THEN [1] ELSE []
        END |
            MERGE (parent:Process {process_entity_id: e.parent_entity_id})
            MERGE (child:Process {process_entity_id: e.process_entity_id})
            MERGE (parent)-[:PARENT_OF]->(child)
        )

        FOREACH (_ IN CASE
            WHEN e.file_path IS NOT NULL THEN [1] ELSE []
        END |
            MERGE (f:File {file_id: e.host_id + ':' + e.file_path})
            SET f.path = e.file_path,
                f.host_id = e.host_id
            MERGE (ev)-[:REFERENCES_FILE]->(f)
        )

        FOREACH (_ IN CASE
            WHEN e.remote_addr IS NOT NULL THEN [1] ELSE []
        END |
            MERGE (n:NetworkEndpoint {
                endpoint_id: e.remote_addr + ':' +
                    coalesce(toString(e.remote_port), 'unknown')
            })
            SET n.ip = e.remote_addr,
                n.port = e.remote_port,
                n.protocol = e.protocol
            MERGE (ev)-[:TARGETS_ENDPOINT]->(n)
        )

        FOREACH (_ IN CASE
            WHEN e.event_type STARTS WITH 'ipc.'
             AND e.ipc_resource_id IS NOT NULL THEN [1] ELSE []
        END |
            MERGE (r:IPCResource {
                resource_id: e.host_id + ':' + e.ipc_resource_id
            })
            SET r.host_id = e.host_id
            MERGE (ev)-[:REFERENCES_IPC]->(r)
        )
        """

        await tx.run(query, events=events)
