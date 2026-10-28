use std::fs::File;
use std::io::{self, BufReader, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use ot_pcap_processor::{Analyzer, CommunicationEvent, corona_compat::LegacyMetrics};
use serde_json::{Value, json};

mod rpcap_listener;

static START_TIME: OnceLock<String> = OnceLock::new();
const MAX_LOG_RECORDS_PER_EXPORT: usize = 1_000;

fn start_time() -> &'static String {
    START_TIME.get_or_init(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos()
            .to_string()
    })
}

#[derive(Parser)]
#[command(version, about = "Passive BACnet/IP and Modbus/TCP packet processor")]
struct Cli {
    #[command(subcommand)]
    command: Mode,
}

#[derive(Subcommand)]
enum Mode {
    /// Read PCAP or PCAPNG bytes from standard input, such as tshark -w -.
    Pipe {
        #[arg(long, value_delimiter = ',', default_value = "47808")]
        bacnet_ports: Vec<u16>,
        #[arg(long, value_delimiter = ',', default_value = "502")]
        modbus_ports: Vec<u16>,
        #[arg(long)]
        otlp_endpoint: Option<String>,
        #[arg(long, default_value_t = 30)]
        export_interval: u64,
    },
    /// Analyze an existing PCAP or PCAPNG file.
    File {
        path: PathBuf,
        #[arg(long, value_delimiter = ',', default_value = "47808")]
        bacnet_ports: Vec<u16>,
        #[arg(long, value_delimiter = ',', default_value = "502")]
        modbus_ports: Vec<u16>,
        #[arg(long)]
        otlp_endpoint: Option<String>,
        #[arg(long)]
        graph: Option<PathBuf>,
        /// Write Corona RDF topology and per-edge message counts as Turtle.
        #[arg(long)]
        corona: Option<PathBuf>,
        /// Write BACnet metrics using corona-pcap-processor's legacy Turtle model.
        #[arg(long)]
        corona_compat: Option<PathBuf>,
        /// Capture device address for the legacy Corona metrics model.
        #[arg(long, requires = "corona_compat")]
        capture_device: Option<String>,
    },
    /// Run in the foreground with local tcpdump or an active-mode rpcapd peer.
    Daemon {
        #[arg(long)]
        interface: Option<String>,
        /// Listen for an active-mode rpcapd control connection (usually port 2003).
        #[arg(long)]
        rpcap_listen: Option<SocketAddr>,
        /// Interface name on the remote rpcapd host.
        #[arg(long)]
        rpcap_interface: Option<String>,
        /// Port for the separate RPCAP packet-data connection.
        #[arg(long, default_value_t = 2004)]
        rpcap_data_port: u16,
        /// Only accept connections from this rpcapd IP address.
        #[arg(long)]
        rpcap_allow_peer: Option<IpAddr>,
        /// RPCAP username; set RPCAP_PASSWORD in the environment as well.
        #[arg(long)]
        rpcap_user: Option<String>,
        #[arg(long, value_delimiter = ',', default_value = "47808")]
        bacnet_ports: Vec<u16>,
        #[arg(long, value_delimiter = ',', default_value = "502")]
        modbus_ports: Vec<u16>,
        #[arg(long)]
        otlp_endpoint: String,
        #[arg(long, default_value_t = 30)]
        export_interval: u64,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    start_time();
    let cli = Cli::parse();
    match cli.command {
        Mode::File {
            path,
            bacnet_ports,
            modbus_ports,
            otlp_endpoint,
            graph,
            corona,
            corona_compat,
            capture_device,
        } => {
            let mut analyzer = Analyzer::with_ports(bacnet_ports, modbus_ports);
            if corona_compat.is_some() {
                analyzer.corona_compat = Some(LegacyMetrics::default());
            }
            analyzer.read_capture(BufReader::new(File::open(path)?))?;
            if let Some(path) = graph {
                std::fs::write(path, analyzer.graph_dot())?;
            }
            if let Some(path) = corona {
                std::fs::write(path, analyzer.corona_turtle())?;
            }
            if let Some(mut path) = corona_compat {
                if path.extension().is_none() {
                    path.set_extension("ttl");
                }
                std::fs::write(
                    path,
                    analyzer
                        .corona_compat
                        .as_ref()
                        .expect("compatibility accumulator enabled")
                        .turtle(capture_device.as_deref()),
                )?;
            }
            if let Some(endpoint) = otlp_endpoint {
                export_pending_logs(&endpoint, &mut analyzer)?;
                export_otlp(&endpoint, &analyzer)?;
            }
            print_summary(&analyzer);
        }
        Mode::Pipe {
            bacnet_ports,
            modbus_ports,
            otlp_endpoint,
            export_interval,
        } => {
            let mut analyzer = Analyzer::with_ports(bacnet_ports, modbus_ports);
            let mut last_export = Instant::now();
            analyzer.read_capture_with(io::stdin().lock(), |state| {
                if let Some(endpoint) = &otlp_endpoint {
                    export_pending_logs(endpoint, state)
                        .map_err(|error| io::Error::other(error.to_string()))?;
                }
                if let Some(endpoint) = &otlp_endpoint
                    && last_export.elapsed() >= Duration::from_secs(export_interval.max(1))
                {
                    export_otlp(endpoint, state)
                        .map_err(|error| io::Error::other(error.to_string()))?;
                    last_export = Instant::now();
                }
                Ok(())
            })?;
            if let Some(endpoint) = otlp_endpoint {
                export_otlp(&endpoint, &analyzer)?;
            } else {
                print_summary(&analyzer);
            }
        }
        Mode::Daemon {
            interface,
            rpcap_listen,
            rpcap_interface,
            rpcap_data_port,
            rpcap_allow_peer,
            rpcap_user,
            bacnet_ports,
            modbus_ports,
            otlp_endpoint,
            export_interval,
        } => {
            if bacnet_ports.is_empty() && modbus_ports.is_empty() {
                return Err("at least one port is required".into());
            }
            if let Some(listen) = rpcap_listen {
                if interface.is_some() {
                    return Err("choose --interface or --rpcap-listen".into());
                }
                let remote_interface =
                    rpcap_interface.ok_or("--rpcap-interface is required with --rpcap-listen")?;
                let password = std::env::var("RPCAP_PASSWORD")
                    .ok()
                    .filter(|value| !value.is_empty());
                let config = rpcap_listener::RemoteConfig {
                    listen,
                    data_port: rpcap_data_port,
                    interface: remote_interface,
                    allowed_peer: rpcap_allow_peer,
                    username: rpcap_user,
                    password,
                    bacnet_ports,
                    modbus_ports,
                    otlp_endpoint,
                    export_interval: Duration::from_secs(export_interval.max(1)),
                };
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()?
                    .block_on(rpcap_listener::run(config))?;
                return Ok(());
            }
            let interface = interface.ok_or("--interface or --rpcap-listen is required")?;
            let filter = bacnet_ports
                .iter()
                .map(|port| format!("udp port {port}"))
                .chain(modbus_ports.iter().map(|port| format!("tcp port {port}")))
                .collect::<Vec<_>>()
                .join(" or ");
            let mut child = Command::new("tcpdump")
                .args(["-i", &interface, "-U", "-s", "0", "-w", "-", &filter])
                .stdout(Stdio::piped())
                .spawn()?;
            let stdout = child.stdout.take().ok_or("tcpdump stdout unavailable")?;
            let mut analyzer = Analyzer::with_ports(bacnet_ports, modbus_ports);
            let mut last_export = Instant::now();
            let processing = analyzer.read_capture_with(BufReader::new(stdout), |state| {
                if let Err(error) = export_pending_logs(&otlp_endpoint, state) {
                    eprintln!("OTLP log export failed: {error}");
                }
                if last_export.elapsed() >= Duration::from_secs(export_interval.max(1)) {
                    if let Err(error) = export_otlp(&otlp_endpoint, state) {
                        eprintln!("OTLP export failed: {error}");
                    }
                    last_export = Instant::now();
                }
                Ok(())
            });
            if processing.is_err() {
                let _ = child.kill();
            }
            let status = child.wait()?;
            processing?;
            export_otlp(&otlp_endpoint, &analyzer)?;
            export_pending_logs(&otlp_endpoint, &mut analyzer)?;
            if !status.success() {
                return Err(format!("tcpdump exited with {status}").into());
            }
        }
    }
    Ok(())
}

fn print_summary(analyzer: &Analyzer) {
    println!("Captured frames: {}", analyzer.total_packets);
    println!(
        "Decoded messages: {} (BACnet packets: {}, Modbus messages: {})",
        analyzer.decoded_packets, analyzer.bacnet_packets, analyzer.modbus_messages
    );
    println!(
        "Malformed or incomplete messages: {}",
        analyzer.malformed_packets
    );
    println!(
        "BACnet devices: {}  Modbus units: {}  Conversations: {}",
        analyzer.devices.len(),
        analyzer.modbus_units.len(),
        analyzer.edges.len()
    );
    println!(
        "Topology nodes: {}  gateway links: {}",
        analyzer.topology_nodes.len(),
        analyzer.gateway_units.len()
    );
    for (id, stats) in &analyzer.node_stats {
        println!("  {id} sent: {}  received: {}", stats.sent, stats.received);
    }
    let broadcasts: u64 = analyzer
        .sources
        .values()
        .map(|stats| stats.broadcasts)
        .sum();
    let routed: u64 = analyzer.sources.values().map(|stats| stats.routed).sum();
    println!("Broadcast messages: {broadcasts}  Routed messages: {routed}");
    let mut message_counts: BTreeMap<String, u64> = BTreeMap::new();
    for ((protocol, _), stats) in &analyzer.sources {
        for (message, count) in &stats.messages {
            *message_counts
                .entry(format!("{protocol}/{message}"))
                .or_default() += count;
        }
    }
    for (message, count) in message_counts {
        println!("  {message}: {count}");
    }
    for device in analyzer.devices.values() {
        println!(
            "  BACnet device {} at {} (vendor {})",
            device.instance, device.address, device.vendor_id
        );
    }
    for ((protocol, source, destination), stats) in &analyzer.edge_stats {
        for (message, count) in &stats.messages {
            println!("  {protocol} {source} -> {destination} {message}: {count}");
        }
    }
    for (server, unit) in &analyzer.modbus_units {
        println!("  Modbus unit {} at {}", unit, server);
    }
    let _ = io::stdout().flush();
}

fn export_otlp(endpoint: &str, analyzer: &Analyzer) -> Result<(), Box<dyn std::error::Error>> {
    let url = otlp_url(endpoint, "metrics");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_string();
    let mut metrics = Vec::new();
    for ((protocol, source), stats) in &analyzer.sources {
        let attributes = vec![attribute("protocol", protocol), attribute("source", source)];
        metrics.push(sum_metric(
            "ot_decoded_messages_total",
            stats.packets,
            &now,
            attributes.clone(),
        ));
        metrics.push(sum_metric(
            "ot_broadcast_packets_total",
            stats.broadcasts,
            &now,
            attributes.clone(),
        ));
        metrics.push(sum_metric(
            "ot_routed_packets_total",
            stats.routed,
            &now,
            attributes.clone(),
        ));
        metrics.push(sum_metric(
            "ot_forwarded_packets_total",
            stats.forwarded,
            &now,
            attributes.clone(),
        ));
        for (message, count) in &stats.messages {
            let mut labels = attributes.clone();
            labels.push(attribute("message", message));
            metrics.push(sum_metric("ot_messages_total", *count, &now, labels));
        }
        if protocol == "bacnet" {
            for (message, name) in [
                ("who_is", "bacnet_whois_requests_total"),
                ("i_am", "bacnet_iam_responses_total"),
                ("who_has", "bacnet_whohas_requests_total"),
                ("i_have", "bacnet_ihave_responses_total"),
                (
                    "read_property_request",
                    "bacnet_read_property_requests_total",
                ),
                (
                    "read_property_response",
                    "bacnet_read_property_responses_total",
                ),
                (
                    "write_property_request",
                    "bacnet_write_property_requests_total",
                ),
                (
                    "write_property_response",
                    "bacnet_write_property_responses_total",
                ),
            ] {
                if let Some(count) = stats.messages.get(message) {
                    metrics.push(sum_metric(name, *count, &now, attributes.clone()));
                }
            }
        } else if protocol == "modbus" {
            for (message, count) in &stats.messages {
                let name = if message.ends_with("_request") {
                    "modbus_requests_total"
                } else if message.ends_with("_response") {
                    "modbus_responses_total"
                } else {
                    "modbus_exceptions_total"
                };
                let mut labels = attributes.clone();
                labels.push(attribute(
                    "function",
                    message.split('_').nth(1).unwrap_or("unknown"),
                ));
                metrics.push(sum_metric(name, *count, &now, labels));
            }
        }
    }
    metrics.push(gauge_metric(
        "ot_bacnet_devices",
        analyzer.devices.len() as u64,
        &now,
    ));
    metrics.push(gauge_metric(
        "ot_modbus_units",
        analyzer.modbus_units.len() as u64,
        &now,
    ));
    metrics.push(gauge_metric(
        "ot_topology_nodes",
        analyzer.topology_nodes.len() as u64,
        &now,
    ));
    for ((protocol, source, destination), stats) in &analyzer.edge_stats {
        for (message, count) in &stats.messages {
            metrics.push(sum_metric(
                "ot_edge_messages_total",
                *count,
                &now,
                vec![
                    attribute("protocol", protocol),
                    attribute("source_device", source),
                    attribute("destination_device", destination),
                    attribute("message", message),
                ],
            ));
        }
    }
    for (id, node) in &analyzer.topology_nodes {
        metrics.push(
            json!({"name": "ot_topology_node_info", "gauge": {"dataPoints": [{
                "attributes": [attribute("device", id), attribute("node_type", &node.kind)],
                "asInt": "1", "timeUnixNano": now
            }]}}),
        );
        if let Some(stats) = analyzer.node_stats.get(id) {
            let protocol = id
                .split_once('/')
                .map_or("unknown", |(protocol, _)| protocol);
            let labels = vec![attribute("protocol", protocol), attribute("device", id)];
            metrics.push(sum_metric(
                "ot_node_sent_messages_total",
                stats.sent,
                &now,
                labels.clone(),
            ));
            metrics.push(sum_metric(
                "ot_node_received_messages_total",
                stats.received,
                &now,
                labels.clone(),
            ));
            for (direction, messages) in [
                ("sent", &stats.sent_messages),
                ("received", &stats.received_messages),
            ] {
                for (message, count) in messages {
                    let mut message_labels = labels.clone();
                    message_labels.push(attribute("direction", direction));
                    message_labels.push(attribute("message", message));
                    metrics.push(sum_metric(
                        "ot_node_messages_total",
                        *count,
                        &now,
                        message_labels,
                    ));
                }
            }
        }
    }
    for (gateway, unit) in &analyzer.gateway_units {
        metrics.push(
            json!({"name": "ot_gateway_unit_info", "gauge": {"dataPoints": [{
                "attributes": [attribute("gateway", gateway), attribute("unit", unit)],
                "asInt": "1", "timeUnixNano": now
            }]}}),
        );
    }
    for device in analyzer.devices.values() {
        metrics.push(json!({"name": "bacnet_device_info", "gauge": {"dataPoints": [{
            "attributes": [attribute("device_id", &device.instance.to_string()), attribute("vendor_id", &device.vendor_id.to_string()), attribute("address", &device.address)],
            "asInt": "1", "timeUnixNano": now
        }]}}));
    }
    metrics.push(sum_metric(
        "ot_malformed_packets_total",
        analyzer.malformed_packets,
        &now,
        vec![],
    ));
    let mut grouped: BTreeMap<String, Value> = BTreeMap::new();
    for metric in metrics {
        let name = metric["name"].as_str().unwrap_or_default().to_owned();
        if let Some(existing) = grouped.get_mut(&name) {
            let field = if metric.get("sum").is_some() {
                "sum"
            } else {
                "gauge"
            };
            if let (Some(points), Some(new_points)) = (
                existing[field]["dataPoints"].as_array_mut(),
                metric[field]["dataPoints"].as_array(),
            ) {
                points.extend(new_points.iter().cloned());
            }
        } else {
            grouped.insert(name, metric);
        }
    }
    let body = json!({"resourceMetrics": [{"resource": {"attributes": [attribute("service.name", "ot-pcap-processor")]}, "scopeMetrics": [{"scope": {"name": "ot-pcap-processor"}, "metrics": grouped.into_values().collect::<Vec<_>>()}]}]});
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let agent: ureq::Agent = agent;
    agent
        .post(&url)
        .header("content-type", "application/json")
        .send_json(&body)?;
    Ok(())
}

fn otlp_url(endpoint: &str, signal: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    let base = base
        .strip_suffix("/v1/metrics")
        .or_else(|| base.strip_suffix("/v1/logs"))
        .unwrap_or(base);
    format!("{base}/v1/{signal}")
}

fn export_pending_logs(
    endpoint: &str,
    analyzer: &mut Analyzer,
) -> Result<(), Box<dyn std::error::Error>> {
    if analyzer.pending_events().is_empty() {
        return Ok(());
    }
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(10)))
        .build()
        .into();
    let url = otlp_url(endpoint, "logs");
    while !analyzer.pending_events().is_empty() {
        let count = analyzer
            .pending_events()
            .len()
            .min(MAX_LOG_RECORDS_PER_EXPORT);
        let body = log_export_body(&analyzer.pending_events()[..count]);
        agent
            .post(&url)
            .header("content-type", "application/json")
            .send_json(&body)?;
        analyzer.acknowledge_events(count);
    }
    Ok(())
}

fn log_export_body(events: &[CommunicationEvent]) -> Value {
    let records = events.iter().map(|event| json!({
        "timeUnixNano": event.time_unix_nano.to_string(),
        "observedTimeUnixNano": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().to_string(),
        "severityNumber": 9,
        "severityText": "INFO",
        "body": {"stringValue": "ot.communication.observed"},
        "attributes": [
            attribute("protocol", &event.protocol),
            attribute("device_a", &event.device_a),
            attribute("device_b", &event.device_b),
            attribute("event.name", "ot.communication.observed"),
        ]
    })).collect::<Vec<_>>();
    json!({"resourceLogs": [{
        "resource": {"attributes": [attribute("service.name", "ot-pcap-processor")]},
        "scopeLogs": [{"scope": {"name": "ot-pcap-processor"}, "logRecords": records}]
    }]})
}

fn attribute(key: &str, value: &str) -> Value {
    json!({"key": key, "value": {"stringValue": value}})
}

fn sum_metric(name: &str, count: u64, time: &str, attributes: Vec<Value>) -> Value {
    json!({"name": name, "sum": {"aggregationTemporality": 2, "isMonotonic": true,
        "dataPoints": [{"attributes": attributes, "asInt": count.to_string(), "startTimeUnixNano": start_time(), "timeUnixNano": time}]}})
}

fn gauge_metric(name: &str, value: u64, time: &str) -> Value {
    json!({"name": name, "gauge": {"dataPoints": [{"asInt": value.to_string(), "timeUnixNano": time}]}})
}
use std::collections::BTreeMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otlp_log_body_and_signal_urls() {
        let body = log_export_body(&[CommunicationEvent {
            protocol: "modbus".into(),
            device_a: "192.0.2.1".into(),
            device_b: "192.0.2.2/unit/7".into(),
            time_unix_nano: 1_000_000_000,
        }]);
        let record = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(record["timeUnixNano"], "1000000000");
        assert_eq!(record["body"]["stringValue"], "ot.communication.observed");
        assert_eq!(
            record["attributes"][2]["value"]["stringValue"],
            "192.0.2.2/unit/7"
        );
        assert_eq!(
            otlp_url("http://localhost:4318/v1/metrics", "logs"),
            "http://localhost:4318/v1/logs"
        );
    }
}
