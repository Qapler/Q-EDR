# Rust Dummy Sensor

## Purpose and limitations

This small Rust program creates three predefined, fictional cybersecurity events: a process start, a file access, and a network connection. It writes them as JSON so another component can practice reading a consistent telemetry format.

All events are synthetic (made-up examples). The program does not run attacks, inspect actual processes or files, monitor network activity, or use eBPF. It is a teaching and integration prototype, not an EDR sensor or a security-monitoring tool.

## Prerequisites

- Rust and Cargo, installed together with [rustup](https://www.rust-lang.org/tools/install).
- Check they are available in PowerShell:

  ```powershell
  rustc --version
  cargo --version
  ```

Cargo is Rust's tool for building projects, running them, and managing their libraries (dependencies).

## Setup and commands

From the repository root in PowerShell:

```powershell
cd components\dummy-sensor
cargo build
cargo run
cargo test
```

`cargo run` writes or replaces `telemetry.json` in the current directory (`components\dummy-sensor\telemetry.json`). The component's `.gitignore` excludes this generated output, so it is not included in Git by default. Each run creates the same three event examples with fresh UTC timestamps; running again replaces the prior generated file.

To check that the generated file is valid JSON using PowerShell's built-in parser, run this from the component directory:

```powershell
Get-Content telemetry.json -Raw | ConvertFrom-Json
```

PowerShell prints the parsed object if the file is valid and reports an error otherwise.

## Output format and event fields

The output is one JSON object with an `events` array. The representative file at [`examples/telemetry.json`](examples/telemetry.json) shows all three event types.

Every event contains:

- `timestamp`: when the example was generated, in UTC using RFC 3339 format (for example, `2026-10-12T12:00:00Z`).
- `source`: always `dummy_sensor`, identifying this program as the generator.
- `synthetic`: always `true`, explicitly marking the event as simulated.
- `event_type`: one of `process_start`, `file_access`, or `network_connection`.
- `process_id` and `process_name`: fictional details shared by these examples.

Event-specific fields are included only where they apply:

- `file_access` has `file_path`.
- `network_connection` has `destination_ip` and `destination_port`.
- `process_start` has no additional event-specific fields.

The IP address `192.0.2.10` is reserved for documentation examples; it does not represent an observed peer. A JSON schema is the agreed shape and field types that a program expects when reading JSON.

## Integration considerations

A downstream component can read `telemetry.json`, parse the top-level `events` array, and use `event_type` to interpret each event's fields. It should treat `process_id`, `process_name`, and the applicable event-specific fields as values for demonstration only, not as evidence from the host.

This event format is a proposed, provisional interface; confirm the schema with the teammate responsible for the consuming component before relying on it. No teammate component integration has been performed or verified. This dummy generator is separate from any future eBPF-based sensor, which would collect real kernel-level telemetry and is not implemented here.
