use chrono::{DateTime, Utc};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::process::ExitCode;

const OUTPUT_FILE: &str = "telemetry.json";
const SOURCE: &str = "dummy_sensor";

#[derive(Serialize)]
struct Telemetry {
    events: Vec<Event>,
}

#[derive(Serialize)]
#[serde(tag = "event_type", rename_all = "snake_case")]
enum Event {
    ProcessStart {
        timestamp: DateTime<Utc>,
        source: &'static str,
        synthetic: bool,
        process_id: u32,
        process_name: &'static str,
    },
    FileAccess {
        timestamp: DateTime<Utc>,
        source: &'static str,
        synthetic: bool,
        process_id: u32,
        process_name: &'static str,
        file_path: &'static str,
    },
    NetworkConnection {
        timestamp: DateTime<Utc>,
        source: &'static str,
        synthetic: bool,
        process_id: u32,
        process_name: &'static str,
        destination_ip: &'static str,
        destination_port: u16,
    },
}

fn sample_events() -> Vec<Event> {
    vec![
        Event::ProcessStart {
            timestamp: Utc::now(),
            source: SOURCE,
            synthetic: true,
            process_id: 1234,
            process_name: "python",
        },
        Event::FileAccess {
            timestamp: Utc::now(),
            source: SOURCE,
            synthetic: true,
            process_id: 1234,
            process_name: "python",
            file_path: "/tmp/example.txt",
        },
        Event::NetworkConnection {
            timestamp: Utc::now(),
            source: SOURCE,
            synthetic: true,
            process_id: 1234,
            process_name: "python",
            destination_ip: "192.0.2.10",
            destination_port: 443,
        },
    ]
}

fn main() -> ExitCode {
    match generate_telemetry() {
        Ok(()) => {
            println!("Generated synthetic telemetry at {OUTPUT_FILE}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("Failed to generate telemetry: {error}");
            ExitCode::FAILURE
        }
    }
}

fn generate_telemetry() -> Result<(), Box<dyn Error>> {
    let telemetry = Telemetry {
        events: sample_events(),
    };
    let json = serde_json::to_string_pretty(&telemetry)?;
    fs::write(OUTPUT_FILE, json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{sample_events, Telemetry};
    use chrono::DateTime;
    use serde_json::Value;

    #[test]
    fn generated_events_use_the_documented_schema() {
        let telemetry = Telemetry {
            events: sample_events(),
        };
        let json = serde_json::to_value(telemetry).expect("events should serialize to JSON");
        let events = json["events"].as_array().expect("events should be an array");
        assert_eq!(events.len(), 3);

        let expected_types = ["process_start", "file_access", "network_connection"];
        for (event, expected_type) in events.iter().zip(expected_types) {
            let timestamp = event["timestamp"]
                .as_str()
                .expect("timestamp should be a string");
            DateTime::parse_from_rfc3339(timestamp)
                .expect("timestamp should use RFC 3339 format");
            assert_eq!(event["event_type"], expected_type);
            assert_eq!(event["source"], "dummy_sensor");
            assert_eq!(event["synthetic"], true);
            assert_eq!(event["process_id"], 1234);
            assert_eq!(event["process_name"], "python");
        }

        assert_eq!(events[1]["file_path"], "/tmp/example.txt");
        assert_eq!(events[2]["destination_ip"], "192.0.2.10");
        assert_eq!(events[2]["destination_port"], 443);
        assert!(events[0].get("file_path").is_none());
        assert!(events[0].get("destination_ip").is_none());
        assert!(events[0].get("destination_port").is_none());
        assert!(events[1].get("destination_ip").is_none());
        assert!(events[1].get("destination_port").is_none());
        assert!(events[2].get("file_path").is_none());
    }

    #[test]
    fn generated_values_are_not_collected_from_the_running_machine() {
        let telemetry = Telemetry {
            events: sample_events(),
        };
        let json = serde_json::to_value(telemetry).expect("events should serialize to JSON");
        let events = json["events"].as_array().expect("events should be an array");

        assert!(events.iter().all(|event| event["synthetic"] == Value::Bool(true)));
        assert_eq!(events[2]["destination_ip"], "192.0.2.10");
    }
}
