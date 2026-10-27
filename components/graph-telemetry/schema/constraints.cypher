
// Unique identity for every telemetry event
CREATE CONSTRAINT telemetry_event_id IF NOT EXISTS
FOR (e:TelemetryEvent)
REQUIRE e.event_id IS UNIQUE;

// Endpoint identity
CREATE CONSTRAINT host_id IF NOT EXISTS
FOR (h:Host)
REQUIRE h.host_id IS UNIQUE;

// Process instance identity
CREATE CONSTRAINT process_entity_id IF NOT EXISTS
FOR (p:Process)
REQUIRE p.process_entity_id IS UNIQUE;

// File identity
CREATE CONSTRAINT file_id IF NOT EXISTS
FOR (f:File)
REQUIRE f.file_id IS UNIQUE;

// Network endpoint identity
CREATE CONSTRAINT network_endpoint_id IF NOT EXISTS
FOR (n:NetworkEndpoint)
REQUIRE n.endpoint_id IS UNIQUE;

// IPC resource identity
CREATE CONSTRAINT ipc_resource_id IF NOT EXISTS
FOR (r:IPCResource)
REQUIRE r.resource_id IS UNIQUE;

// Frequent event filters
CREATE INDEX telemetry_event_time IF NOT EXISTS
FOR (e:TelemetryEvent)
ON (e.event_time);

CREATE INDEX telemetry_event_type IF NOT EXISTS
FOR (e:TelemetryEvent)
ON (e.event_type);

CREATE INDEX telemetry_host_id IF NOT EXISTS
FOR (e:TelemetryEvent)
ON (e.host_id);

CREATE INDEX process_pid IF NOT EXISTS
FOR (p:Process)
ON (p.pid);

CREATE INDEX file_path IF NOT EXISTS
FOR (f:File)
ON (f.path);

CREATE INDEX network_ip IF NOT EXISTS
FOR (n:NetworkEndpoint)
ON (n.ip);
