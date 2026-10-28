//! Passive BACnet/IP and Modbus/TCP analysis from PCAP and PCAPNG streams.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{self, Cursor, Read};
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bacnet_bip_codec::{Bvll, decode as decode_bvll};
use bacnet_encoding::apdu::header::ApduHeader;
use bacnet_npdu::Npdu;
use bacnet_services::who_is::IAmRequest;
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap_file::{
    DataLink,
    pcap::PcapReader,
    pcapng::{
        Block, PcapNgReader,
        blocks::interface_description::{InterfaceDescriptionBlock, InterfaceDescriptionOption},
    },
};
use rustmod_core::{
    encoding::Reader as ModbusReader,
    frame::tcp::decode_frame,
    pdu::{DecodedRequest, Response},
};

pub mod corona_compat;

/// A discovered BACnet device announced by I-Am.
#[derive(Debug, Clone)]
pub struct BacnetDevice {
    pub instance: u32,
    pub vendor_id: u16,
    pub address: String,
    pub network: Option<u16>,
}

/// Counts for a single observed source address and protocol.
#[derive(Debug, Default, Clone)]
pub struct SourceStats {
    pub packets: u64,
    pub broadcasts: u64,
    pub routed: u64,
    pub forwarded: u64,
    pub messages: BTreeMap<String, u64>,
}

/// A logical endpoint in the observed protocol topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyNode {
    pub kind: String,
    pub address: String,
}

/// One first-seen or hourly communication observation for an unordered device pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunicationEvent {
    pub protocol: String,
    pub device_a: String,
    pub device_b: String,
    pub time_unix_nano: u128,
}

/// Each directed device edge retains counts for every decoded message type.
#[derive(Debug, Default, Clone)]
pub struct EdgeStats {
    pub messages: BTreeMap<String, u64>,
}

/// Messages observed at one protocol-scoped device node.
#[derive(Debug, Default, Clone)]
pub struct NodeStats {
    pub sent: u64,
    pub received: u64,
    pub sent_messages: BTreeMap<String, u64>,
    pub received_messages: BTreeMap<String, u64>,
}

impl NodeStats {
    fn record_sent(&mut self, message: &str) {
        self.sent += 1;
        *self.sent_messages.entry(message.to_owned()).or_default() += 1;
    }

    fn record_received(&mut self, message: &str) {
        self.received += 1;
        *self
            .received_messages
            .entry(message.to_owned())
            .or_default() += 1;
    }
}

const PAIR_LOG_INTERVAL: Duration = Duration::from_secs(60 * 60);
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

struct CaptureInterface {
    link: DataLink,
    snaplen: u32,
    timestamp_resolution: u8,
    timestamp_offset: i64,
}

impl CaptureInterface {
    fn from_description(description: &InterfaceDescriptionBlock<'_>) -> Self {
        let mut interface = Self {
            link: description.linktype,
            snaplen: description.snaplen,
            timestamp_resolution: 6,
            timestamp_offset: 0,
        };
        for option in &description.options {
            match option {
                InterfaceDescriptionOption::IfTsResol(value) => {
                    interface.timestamp_resolution = *value;
                }
                InterfaceDescriptionOption::IfTsOffset(value) => {
                    interface.timestamp_offset = *value as i64;
                }
                _ => {}
            }
        }
        interface
    }

    fn timestamp(&self, raw_ticks: u64) -> io::Result<Duration> {
        let denominator = if self.timestamp_resolution & 0x80 == 0 {
            10_u128.checked_pow(self.timestamp_resolution as u32)
        } else {
            1_u128.checked_shl((self.timestamp_resolution & 0x7f) as u32)
        };
        let nanoseconds = denominator.map_or(0, |units_per_second| {
            u128::from(raw_ticks) * 1_000_000_000 / units_per_second
        });
        let seconds = nanoseconds / 1_000_000_000;
        let seconds =
            i128::try_from(seconds).unwrap_or(i128::MAX) + i128::from(self.timestamp_offset);
        let seconds = u64::try_from(seconds).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "PCAPNG timestamp is outside the Unix epoch range",
            )
        })?;
        Ok(Duration::new(seconds, (nanoseconds % 1_000_000_000) as u32))
    }
}

/// Aggregated passive observations. All counters describe captured traffic.
#[derive(Debug)]
pub struct Analyzer {
    pub total_packets: u64,
    pub decoded_packets: u64,
    pub malformed_packets: u64,
    pub bacnet_packets: u64,
    pub modbus_messages: u64,
    pub sources: BTreeMap<(String, String), SourceStats>,
    pub edges: BTreeMap<(String, String, String), u64>,
    pub edge_stats: BTreeMap<(String, String, String), EdgeStats>,
    pub node_stats: BTreeMap<String, NodeStats>,
    pub topology_nodes: BTreeMap<String, TopologyNode>,
    pub gateway_units: BTreeSet<(String, String)>,
    pub devices: BTreeMap<u32, BacnetDevice>,
    pub modbus_units: BTreeSet<(String, u8)>,
    pub bacnet_ports: BTreeSet<u16>,
    pub modbus_ports: BTreeSet<u16>,
    /// Optional accumulator for the earlier Python collector's BACnet metrics.
    pub corona_compat: Option<corona_compat::LegacyMetrics>,
    flows: HashMap<(IpAddr, u16, IpAddr, u16), TcpFlow>,
    pair_last_logged: HashMap<(String, String, String), Duration>,
    pending_events: Vec<CommunicationEvent>,
    observation_time: Duration,
    last_pair_prune: Duration,
}

impl Default for Analyzer {
    fn default() -> Self {
        Self::with_ports([47808], [502])
    }
}

#[derive(Debug, Default)]
struct TcpFlow {
    next_seq: Option<u32>,
    pending: Vec<u8>,
}

#[derive(Default)]
struct TrafficFlags {
    broadcast: bool,
    broadcast_peer: Option<String>,
    routed: bool,
    forwarded: bool,
}

impl Analyzer {
    /// Create an analyzer for the given BACnet/UDP and Modbus/TCP ports.
    pub fn with_ports(
        bacnet_ports: impl IntoIterator<Item = u16>,
        modbus_ports: impl IntoIterator<Item = u16>,
    ) -> Self {
        Self {
            total_packets: 0,
            decoded_packets: 0,
            malformed_packets: 0,
            bacnet_packets: 0,
            modbus_messages: 0,
            sources: BTreeMap::new(),
            edges: BTreeMap::new(),
            edge_stats: BTreeMap::new(),
            node_stats: BTreeMap::new(),
            topology_nodes: BTreeMap::new(),
            gateway_units: BTreeSet::new(),
            devices: BTreeMap::new(),
            modbus_units: BTreeSet::new(),
            bacnet_ports: bacnet_ports.into_iter().collect(),
            modbus_ports: modbus_ports.into_iter().collect(),
            corona_compat: None,
            flows: HashMap::new(),
            pair_last_logged: HashMap::new(),
            pending_events: Vec::new(),
            observation_time: Duration::ZERO,
            last_pair_prune: Duration::ZERO,
        }
    }

    /// Decode one complete captured frame using the file's link type.
    pub fn ingest_frame(&mut self, link: DataLink, frame: &[u8]) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        self.ingest_frame_at(link, frame, now);
    }

    /// Decode a frame at its capture timestamp, used for accurate offline logs.
    pub fn ingest_frame_at(&mut self, link: DataLink, frame: &[u8], timestamp: Duration) {
        self.observation_time = timestamp;
        self.total_packets += 1;
        let parsed = match link {
            DataLink::ETHERNET => SlicedPacket::from_ethernet(frame),
            DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => SlicedPacket::from_ip(frame),
            DataLink::LINUX_SLL if frame.len() >= 16 => SlicedPacket::from_ether_type(
                u16::from_be_bytes([frame[14], frame[15]]).into(),
                &frame[16..],
            ),
            DataLink::LINUX_SLL2 if frame.len() >= 20 => SlicedPacket::from_ether_type(
                u16::from_be_bytes([frame[0], frame[1]]).into(),
                &frame[20..],
            ),
            DataLink::NULL | DataLink::LOOP if frame.len() >= 4 => {
                SlicedPacket::from_ip(&frame[4..])
            }
            _ => return,
        };
        let Ok(packet) = parsed else {
            self.malformed_packets += 1;
            return;
        };
        let Some(net) = packet.net else { return };
        let (src, dst) = match net {
            NetSlice::Ipv4(ip) => (
                IpAddr::from(ip.header().source()),
                IpAddr::from(ip.header().destination()),
            ),
            NetSlice::Ipv6(ip) => (
                IpAddr::from(ip.header().source()),
                IpAddr::from(ip.header().destination()),
            ),
            _ => return,
        };
        match packet.transport {
            Some(TransportSlice::Udp(udp))
                if self.bacnet_ports.contains(&udp.source_port())
                    || self.bacnet_ports.contains(&udp.destination_port()) =>
            {
                if udp.source_port() == 47808
                    && let Some(compat) = &mut self.corona_compat
                {
                    compat.ingest(src, dst, udp.payload());
                }
                self.decode_bacnet(src, dst, udp.payload());
            }
            Some(TransportSlice::Tcp(tcp))
                if self.modbus_ports.contains(&tcp.source_port())
                    || self.modbus_ports.contains(&tcp.destination_port()) =>
            {
                self.decode_modbus_tcp(
                    (src, tcp.source_port(), dst, tcp.destination_port()),
                    tcp.sequence_number(),
                    tcp.syn(),
                    tcp.payload(),
                );
            }
            _ => {}
        }
    }

    fn observe(
        &mut self,
        protocol: &str,
        source: String,
        destination: String,
        message: String,
        flags: TrafficFlags,
    ) {
        self.decoded_packets += 1;
        if protocol == "bacnet" {
            for address in [&source, &destination] {
                self.register_bacnet_node(address);
            }
            if let Some(peer) = &flags.broadcast_peer {
                self.register_bacnet_node(peer);
            }
        }
        self.record_pair_event(protocol, &source, &destination);
        let stats = self
            .sources
            .entry((protocol.to_owned(), source.clone()))
            .or_default();
        stats.packets += 1;
        stats.broadcasts += u64::from(flags.broadcast);
        stats.routed += u64::from(flags.routed);
        stats.forwarded += u64::from(flags.forwarded);
        *stats.messages.entry(message.clone()).or_default() += 1;
        self.node_stats
            .entry(format!("{protocol}/{source}"))
            .or_default()
            .record_sent(&message);
        if !is_broadcast_endpoint(&destination) {
            self.node_stats
                .entry(format!("{protocol}/{destination}"))
                .or_default()
                .record_received(&message);
        }
        self.record_edge(protocol, &source, &destination, &message);
        if let Some(peer) = flags.broadcast_peer
            && peer != destination
        {
            self.record_pair_event(protocol, &source, &peer);
            self.record_edge(protocol, &source, &peer, &message);
        }
    }

    fn register_bacnet_node(&mut self, address: &str) {
        let kind = if is_broadcast_endpoint(address) {
            "bacnet_broadcast"
        } else if address.parse::<IpAddr>().is_ok() {
            "bacnet_ip_device"
        } else {
            "bacnet_routed_device"
        };
        self.topology_nodes
            .entry(format!("bacnet/{address}"))
            .or_insert_with(|| TopologyNode {
                kind: kind.to_owned(),
                address: address.to_owned(),
            });
    }

    fn record_pair_event(&mut self, protocol: &str, source: &str, destination: &str) {
        if source == destination {
            return;
        }
        if self.observation_time.saturating_sub(self.last_pair_prune) >= PAIR_LOG_INTERVAL {
            self.pair_last_logged
                .retain(|_, last| self.observation_time.saturating_sub(*last) < PAIR_LOG_INTERVAL);
            self.last_pair_prune = self.observation_time;
        }
        let (a, b) = if source <= destination {
            (source.to_owned(), destination.to_owned())
        } else {
            (destination.to_owned(), source.to_owned())
        };
        let key = (protocol.to_owned(), a.clone(), b.clone());
        let should_log = self
            .pair_last_logged
            .get(&key)
            .is_none_or(|last| self.observation_time.saturating_sub(*last) >= PAIR_LOG_INTERVAL);
        if should_log {
            self.pair_last_logged.insert(key, self.observation_time);
            self.pending_events.push(CommunicationEvent {
                protocol: protocol.to_owned(),
                device_a: a,
                device_b: b,
                time_unix_nano: self.observation_time.as_nanos(),
            });
        }
    }

    fn record_edge(&mut self, protocol: &str, source: &str, destination: &str, message: &str) {
        *self
            .edge_stats
            .entry((
                protocol.to_owned(),
                source.to_owned(),
                destination.to_owned(),
            ))
            .or_default()
            .messages
            .entry(message.to_owned())
            .or_default() += 1;
        *self
            .edges
            .entry((
                protocol.to_owned(),
                source.to_owned(),
                destination.to_owned(),
            ))
            .or_default() += 1;
    }

    /// Events awaiting an OTLP log export. Call `acknowledge_events` after a successful send.
    pub fn pending_events(&self) -> &[CommunicationEvent] {
        &self.pending_events
    }

    /// Remove events only after the receiver accepts them.
    pub fn acknowledge_events(&mut self, count: usize) {
        self.pending_events
            .drain(..count.min(self.pending_events.len()));
    }

    fn decode_bacnet(&mut self, source: IpAddr, destination: IpAddr, payload: &[u8]) {
        let Ok(bvll) = decode_bvll(payload) else {
            self.malformed_packets += 1;
            return;
        };
        self.bacnet_packets += 1;
        let (npdu_bytes, origin, broadcast, forwarded) = match bvll {
            Bvll::OriginalUnicastNpdu(data) => (data, source.to_string(), false, false),
            Bvll::OriginalBroadcastNpdu(data) | Bvll::DistributeBroadcastToNetwork(data) => {
                (data, source.to_string(), true, false)
            }
            Bvll::ForwardedNpdu { origin, npdu } => (npdu, origin.ip().to_string(), true, true),
            other => {
                self.observe(
                    "bacnet",
                    source.to_string(),
                    destination.to_string(),
                    format!("bvll_{}", other.function().to_raw()),
                    TrafficFlags::default(),
                );
                return;
            }
        };
        let Ok(npdu) = Npdu::decode(npdu_bytes) else {
            self.malformed_packets += 1;
            return;
        };
        let routed = npdu.source.is_some() || npdu.destination.is_some();
        let source_name = npdu.source.map_or(origin.clone(), |addr| {
            format!("{}:{}", addr.network, hex_mac(addr.mac))
        });
        let npdu_broadcast = npdu.destination.and_then(|addr| {
            addr.mac
                .is_empty()
                .then(|| format!("{}:broadcast", addr.network))
        });
        let broadcast_peer =
            npdu_broadcast.or_else(|| broadcast.then(|| format!("broadcast@{destination}")));
        let destination_name = npdu.destination.map_or_else(
            || {
                broadcast_peer
                    .clone()
                    .unwrap_or_else(|| destination.to_string())
            },
            |addr| {
                if addr.mac.is_empty() {
                    format!("{}:broadcast", addr.network)
                } else {
                    format!("{}:{}", addr.network, hex_mac(addr.mac))
                }
            },
        );
        let broadcast = broadcast || npdu.destination.is_some_and(|addr| addr.mac.is_empty());
        let (message, parameters) = if let Some(kind) = npdu.message_type {
            (format!("network_{kind:?}"), &[][..])
        } else {
            match ApduHeader::decode(npdu.payload) {
                Ok((ApduHeader::UnconfirmedRequest(service), params)) => {
                    (unconfirmed_name(service.to_raw()), params)
                }
                Ok((ApduHeader::ConfirmedRequest(header), params)) => (
                    confirmed_name("request", header.service_choice.to_raw()),
                    params,
                ),
                Ok((ApduHeader::ComplexAck { service_choice, .. }, params)) => {
                    (confirmed_name("response", service_choice.to_raw()), params)
                }
                Ok((ApduHeader::Error { service_choice, .. }, params)) => {
                    (confirmed_name("error", service_choice.to_raw()), params)
                }
                Ok((kind, params)) => (format!("{kind:?}"), params),
                Err(_) => (
                    format!("apdu_{}", npdu.payload.first().map_or(255, |b| b >> 4)),
                    &[][..],
                ),
            }
        };
        if message == "i_am"
            && let Ok(iam) = IAmRequest::decode(parameters)
        {
            self.devices.insert(
                iam.object_identifier.instance_number(),
                BacnetDevice {
                    instance: iam.object_identifier.instance_number(),
                    vendor_id: iam.vendor_id,
                    address: source_name.clone(),
                    network: npdu.source.map(|addr| addr.network),
                },
            );
        }
        self.observe(
            "bacnet",
            source_name,
            destination_name,
            message,
            TrafficFlags {
                broadcast,
                broadcast_peer,
                routed,
                forwarded,
            },
        );
    }

    fn decode_modbus_tcp(
        &mut self,
        key: (IpAddr, u16, IpAddr, u16),
        seq: u32,
        syn: bool,
        payload: &[u8],
    ) {
        if payload.is_empty() {
            return;
        }
        let (src, _source_port, dst, destination_port) = key;
        let request = self.modbus_ports.contains(&destination_port);
        if !self.flows.contains_key(&key) && self.flows.len() >= 10_000 {
            self.flows.clear();
        }
        let flow = self.flows.entry(key).or_default();
        if syn {
            flow.pending.clear();
            flow.next_seq = None;
        }
        let new_data = if let Some(next) = flow.next_seq {
            if seq == next {
                payload
            } else if seq < next {
                payload
                    .get(next.wrapping_sub(seq) as usize..)
                    .unwrap_or_default()
            } else {
                flow.pending.clear();
                payload
            }
        } else {
            payload
        };
        let end = seq.wrapping_add(payload.len() as u32);
        if flow.next_seq.is_none_or(|next| end > next) {
            flow.next_seq = Some(end);
        }
        flow.pending.extend_from_slice(new_data);
        if flow.pending.len() > 64 * 1024 {
            flow.pending.clear();
            self.malformed_packets += 1;
            return;
        }
        let mut completed = Vec::new();
        loop {
            if flow.pending.len() < 7 {
                break;
            }
            let length = u16::from_be_bytes([flow.pending[4], flow.pending[5]]) as usize;
            if flow.pending[2] != 0 || flow.pending[3] != 0 || !(2..=254).contains(&length) {
                flow.pending.clear();
                self.malformed_packets += 1;
                break;
            }
            let full_length = 6 + length;
            if flow.pending.len() < full_length {
                break;
            }
            completed.push(flow.pending.drain(..full_length).collect::<Vec<_>>());
        }
        for bytes in completed {
            let mut reader = ModbusReader::new(&bytes);
            match decode_frame(&mut reader) {
                Ok((header, pdu)) if !pdu.is_empty() => {
                    let mut pdu_reader = ModbusReader::new(pdu);
                    let parsed = if request {
                        DecodedRequest::decode(&mut pdu_reader).map(|_| ())
                    } else {
                        Response::decode(&mut pdu_reader).map(|_| ())
                    };
                    if parsed.is_err() || !pdu_reader.is_empty() {
                        self.malformed_packets += 1;
                        continue;
                    }
                    let function = pdu[0] & 0x7f;
                    let exception = pdu[0] & 0x80 != 0;
                    let client = if request {
                        src.to_string()
                    } else {
                        dst.to_string()
                    };
                    let server = if request {
                        dst.to_string()
                    } else {
                        src.to_string()
                    };
                    let unit = header.unit_id.as_u8();
                    self.modbus_units.insert((server.clone(), unit));
                    self.topology_nodes
                        .entry(format!("modbus/{client}"))
                        .or_insert_with(|| TopologyNode {
                            kind: "modbus_tcp_client".into(),
                            address: client.clone(),
                        });
                    let server_kind = if (1..=247).contains(&unit)
                        || self.gateway_units.iter().any(|(known, _)| known == &server)
                    {
                        "modbus_tcp_gateway"
                    } else {
                        "modbus_tcp_server"
                    };
                    self.topology_nodes.insert(
                        format!("modbus/{server}"),
                        TopologyNode {
                            kind: server_kind.into(),
                            address: server.clone(),
                        },
                    );
                    let target = if (1..=247).contains(&unit) {
                        let id = format!("{server}/unit/{unit}");
                        self.topology_nodes
                            .entry(format!("modbus/{id}"))
                            .or_insert_with(|| TopologyNode {
                                kind: "modbus_rtu_unit".into(),
                                address: id.clone(),
                            });
                        self.gateway_units.insert((server.clone(), id.clone()));
                        id
                    } else {
                        server
                    };
                    let (source, destination) = if request {
                        (client, target)
                    } else {
                        (target, client)
                    };
                    let message = format!(
                        "function_{function}_{}",
                        if exception {
                            "exception"
                        } else if request {
                            "request"
                        } else {
                            "response"
                        }
                    );
                    if (1..=247).contains(&unit) {
                        let gateway = if request { dst } else { src };
                        let stats = self
                            .node_stats
                            .entry(format!("modbus/{gateway}"))
                            .or_default();
                        if request {
                            stats.record_received(&message);
                        } else {
                            stats.record_sent(&message);
                        }
                    }
                    self.modbus_messages += 1;
                    self.observe(
                        "modbus",
                        source,
                        destination,
                        message,
                        TrafficFlags::default(),
                    );
                }
                _ => self.malformed_packets += 1,
            }
        }
    }

    /// A Graphviz DOT map of observed conversations and announced BACnet devices.
    pub fn graph_dot(&self) -> String {
        let mut result = String::from("digraph ot_network {\n  rankdir=LR;\n");
        for (node, info) in &self.topology_nodes {
            let devices: Vec<String> = self
                .devices
                .values()
                .filter(|d| d.address == info.address && node.starts_with("bacnet/"))
                .map(|d| format!("BACnet device {} (vendor {})", d.instance, d.vendor_id))
                .collect();
            let label = if devices.is_empty() {
                format!("{}\n{}", info.address, info.kind)
            } else {
                format!("{}\n{}\n{}", info.address, info.kind, devices.join(", "))
            };
            result.push_str(&format!(
                "  \"{}\" [label=\"{}\"];\n",
                dot_escape(node),
                dot_escape(&label)
            ));
        }
        for (gateway, unit) in &self.gateway_units {
            result.push_str(&format!(
                "  \"{}\" -> \"{}\" [style=dashed,label=\"routes to\"];\n",
                dot_escape(&format!("modbus/{gateway}")),
                dot_escape(&format!("modbus/{unit}"))
            ));
        }
        for ((protocol, src, dst), count) in &self.edges {
            result.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}: {}\"];\n",
                dot_escape(&format!("{protocol}/{src}")),
                dot_escape(&format!("{protocol}/{dst}")),
                protocol,
                count
            ));
        }
        result.push_str("}\n");
        result
    }

    /// Serialize the observed Corona topology and per-edge message counts as Turtle.
    pub fn corona_turtle(&self) -> String {
        let mut out = String::from(
            "@prefix net: <http://www.example.org/network-ontology#> .\n@prefix bacnet: <https://data.ashrae.org/bacnet/> .\n@prefix ex: <http://example.org/ot-pcap-processor/> .\n@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n\n",
        );
        for (id, node) in &self.topology_nodes {
            let class = match node.kind.as_str() {
                "bacnet_ip_device" => "bacnet:Device, net:BacnetDevice",
                "bacnet_routed_device" => "bacnet:Device, net:BacnetRoutedDevice",
                "bacnet_broadcast" => "net:BroadcastAddress",
                "modbus_tcp_client" => "net:ModbusTcpClient",
                "modbus_tcp_server" => "net:ModbusTcpServer",
                "modbus_tcp_gateway" => "net:ModbusTcpGateway",
                "modbus_rtu_unit" => "net:ModbusRtuUnit",
                _ => "net:Node",
            };
            let uri = turtle_uri("node", id);
            let status = if node.kind == "bacnet_broadcast" {
                ""
            } else {
                " ; net:HWStatus \"UNKNOWN\""
            };
            out.push_str(&format!(
                "{uri} a {class} ; net:address \"{}\" ; rdfs:label \"{}\"{status} .\n",
                turtle_escape(&node.address),
                turtle_escape(&node.address)
            ));
        }
        for device in self.devices.values() {
            let uri = turtle_uri("node", &format!("bacnet/{}", device.address));
            out.push_str(&format!("{uri} bacnet:object-identifier \"device,{}\" ; bacnet:vendor-identifier \"{}\" .\n",
                device.instance, device.vendor_id));
        }
        for (id, stats) in &self.node_stats {
            let node_uri = turtle_uri("node", id);
            out.push_str(&format!(
                "{node_uri} net:sentMessageCount {} ; net:receivedMessageCount {} .\n",
                stats.sent, stats.received
            ));
            for (direction, messages) in [
                ("sent", &stats.sent_messages),
                ("received", &stats.received_messages),
            ] {
                for (message, count) in messages {
                    let observation =
                        turtle_uri("node-observation", &format!("{id}/{direction}/{message}"));
                    out.push_str(&format!("{node_uri} net:hasNodeMessageObservation {observation} .\n{observation} a net:MessageObservation ; net:direction \"{direction}\" ; net:messageType \"{}\" ; net:count {count} .\n",
                        turtle_escape(message)));
                }
            }
        }
        for (gateway, unit) in &self.gateway_units {
            out.push_str(&format!(
                "{} net:routesTo {} .\n",
                turtle_uri("node", &format!("modbus/{gateway}")),
                turtle_uri("node", &format!("modbus/{unit}"))
            ));
        }
        for ((protocol, source, destination), stats) in &self.edge_stats {
            let edge_id = format!("{protocol}/{source}/{destination}");
            let edge_uri = turtle_uri("edge", &edge_id);
            let total: u64 = stats.messages.values().sum();
            out.push_str(&format!("{edge_uri} a net:CommunicationEdge ; net:sourceDevice {} ; net:destinationDevice {} ; net:protocol \"{protocol}\" ; net:messageCount {total} .\n",
                turtle_uri("node", &format!("{protocol}/{source}")),
                turtle_uri("node", &format!("{protocol}/{destination}"))));
            for (message, count) in &stats.messages {
                let observation = turtle_uri("observation", &format!("{edge_id}/{message}"));
                out.push_str(&format!("{edge_uri} net:hasMessageObservation {observation} .\n{observation} a net:MessageObservation ; net:messageType \"{}\" ; net:count {count} .\n",
                    turtle_escape(message)));
            }
        }
        out
    }

    /// Read a PCAP or PCAPNG stream until EOF.
    pub fn read_capture<R: Read>(&mut self, reader: R) -> io::Result<()> {
        self.read_capture_with(reader, |_| Ok(()))
    }

    /// Read a capture stream and invoke `on_packet` after each frame.
    /// The format is detected from the first four bytes without buffering to EOF.
    pub fn read_capture_with<R: Read>(
        &mut self,
        mut reader: R,
        mut on_packet: impl FnMut(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut magic = [0_u8; 4];
        reader.read_exact(&mut magic)?;
        let reader = Cursor::new(magic).chain(reader);
        if magic == PCAPNG_MAGIC {
            let mut pcapng = PcapNgReader::new(reader).map_err(io::Error::other)?;
            let mut interfaces = Vec::<CaptureInterface>::new();
            let mut last_timestamp = None;
            while let Some(block) = pcapng.next_block() {
                match block.map_err(io::Error::other)? {
                    Block::SectionHeader(_) => {
                        interfaces.clear();
                        last_timestamp = None;
                    }
                    Block::InterfaceDescription(description) => {
                        interfaces.push(CaptureInterface::from_description(&description));
                    }
                    Block::EnhancedPacket(packet) => {
                        let interface =
                            interfaces
                                .get(packet.interface_id as usize)
                                .ok_or_else(|| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "PCAPNG packet references an unknown interface",
                                    )
                                })?;
                        let raw_ticks = packet.timestamp.as_nanos() as u64;
                        let timestamp = interface.timestamp(raw_ticks)?;
                        self.ingest_frame_at(interface.link, &packet.data, timestamp);
                        last_timestamp = Some(timestamp);
                        on_packet(self)?;
                    }
                    Block::Packet(packet) => {
                        let interface = interfaces
                            .get(usize::from(packet.interface_id))
                            .ok_or_else(|| {
                                io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "PCAPNG packet references an unknown interface",
                                )
                            })?;
                        let timestamp = interface.timestamp(packet.timestamp)?;
                        self.ingest_frame_at(interface.link, &packet.data, timestamp);
                        last_timestamp = Some(timestamp);
                        on_packet(self)?;
                    }
                    Block::SimplePacket(packet) => {
                        let interface = interfaces.first().ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidData,
                                "PCAPNG simple packet has no interface",
                            )
                        })?;
                        let expected = if interface.snaplen == 0 {
                            packet.original_len
                        } else {
                            packet.original_len.min(interface.snaplen)
                        } as usize;
                        if packet.data.len() < expected {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "PCAPNG simple packet is truncated",
                            ));
                        }
                        let timestamp = last_timestamp.unwrap_or_else(|| {
                            SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap_or_default()
                        });
                        self.ingest_frame_at(interface.link, &packet.data[..expected], timestamp);
                        on_packet(self)?;
                    }
                    _ => {}
                }
            }
        } else {
            let mut pcap = PcapReader::new(reader).map_err(io::Error::other)?;
            let link = pcap.header().datalink;
            while let Some(packet) = pcap.next_packet() {
                let packet = packet.map_err(io::Error::other)?;
                self.ingest_frame_at(link, &packet.data, packet.timestamp);
                on_packet(self)?;
            }
        }
        Ok(())
    }

    /// Legacy alias for `read_capture`.
    pub fn read_pcap<R: Read>(&mut self, reader: R) -> io::Result<()> {
        self.read_capture(reader)
    }

    /// Legacy alias for `read_capture_with`.
    pub fn read_pcap_with<R: Read>(
        &mut self,
        reader: R,
        on_packet: impl FnMut(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        self.read_capture_with(reader, on_packet)
    }
}

fn hex_mac(mac: &[u8]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn is_broadcast_endpoint(address: &str) -> bool {
    address.starts_with("broadcast@") || address.ends_with(":broadcast")
}

fn unconfirmed_name(code: u8) -> String {
    match code {
        0 => "i_am".to_owned(),
        1 => "i_have".to_owned(),
        2 => "unconfirmed_cov_notification".to_owned(),
        7 => "who_has".to_owned(),
        8 => "who_is".to_owned(),
        _ => format!("unconfirmed_{code}"),
    }
}

fn confirmed_name(kind: &str, code: u8) -> String {
    let service = match code {
        1 => "confirmed_cov_notification".to_owned(),
        12 => "read_property".to_owned(),
        14 => "read_property_multiple".to_owned(),
        15 => "write_property".to_owned(),
        16 => "write_property_multiple".to_owned(),
        _ => format!("service_{code}"),
    };
    format!("{service}_{kind}")
}

fn dot_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn turtle_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn turtle_uri(kind: &str, id: &str) -> String {
    let encoded = id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("ex:{kind}-{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap_file::pcapng::blocks::{
        enhanced_packet::EnhancedPacketBlock, interface_description::InterfaceDescriptionBlock,
        simple_packet::SimplePacketBlock,
    };
    use pcap_file::pcapng::{PcapNgBlock, PcapNgWriter};
    use std::borrow::Cow;
    use std::io::Write;
    use std::net::Ipv4Addr;

    #[test]
    fn corona_compat_counts_legacy_layers_and_excludes_modbus() {
        let mut analyzer = Analyzer::with_ports([47808], [502]);
        analyzer.corona_compat = Some(corona_compat::LegacyMetrics::default());
        analyzer
            .read_capture(include_bytes!("../docs/examples/mixed-traffic.pcap").as_slice())
            .unwrap();
        let compat = analyzer.corona_compat.as_ref().unwrap();
        let source = &compat.addresses["10.0.0.1"];
        assert_eq!(source.total_packets, 3);
        assert_eq!(source.message_types["BACnet/IP"], 1);
        assert_eq!(source.message_types["OriginalBroadcastNPDU"], 1);
        assert_eq!(source.message_types["WhoIsRequest"], 1);
        assert_eq!(compat.addresses.len(), 1);
        assert_eq!(
            compat.turtle(None),
            include_str!("../docs/examples/corona-compat.ttl")
        );
    }

    fn bacnet_ip_frame(destination: [u8; 4]) -> Vec<u8> {
        let payload = [0x81, 0x0a, 0, 8, 1, 0, 0x10, 8];
        let mut frame = vec![0_u8; 20 + 8 + payload.len()];
        let frame_len = frame.len() as u16;
        frame[0] = 0x45;
        frame[2..4].copy_from_slice(&frame_len.to_be_bytes());
        frame[8] = 64;
        frame[9] = 17;
        frame[12..16].copy_from_slice(&[10, 0, 0, 1]);
        frame[16..20].copy_from_slice(&destination);
        frame[20..22].copy_from_slice(&47808_u16.to_be_bytes());
        frame[22..24].copy_from_slice(&47808_u16.to_be_bytes());
        frame[24..26].copy_from_slice(&(16_u16).to_be_bytes());
        frame[28..].copy_from_slice(&payload);
        frame
    }

    fn enhanced(interface_id: u32, raw_ticks: u64, data: &[u8]) -> Block<'_> {
        EnhancedPacketBlock {
            interface_id,
            timestamp: Duration::from_nanos(raw_ticks),
            original_len: data.len() as u32,
            data: Cow::Borrowed(data),
            options: vec![],
        }
        .into_block()
    }

    #[test]
    fn pcapng_mixed_interfaces_timestamp_options_and_simple_packets() {
        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend_from_slice(&bacnet_ip_frame([10, 0, 0, 3]));
        let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
        writer
            .write_block(&InterfaceDescriptionBlock::new(DataLink::RAW, 65_535).into_block())
            .unwrap();
        let mut second = InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535);
        second
            .options
            .push(InterfaceDescriptionOption::IfTsResol(0x80 | 10));
        second
            .options
            .push(InterfaceDescriptionOption::IfTsOffset(10));
        writer.write_block(&second.into_block()).unwrap();
        writer.write_block(&enhanced(0, 10_000_000, &raw)).unwrap();
        writer
            .write_block(&enhanced(1, 5 * 1024, &ethernet))
            .unwrap();
        writer
            .write_block(
                &SimplePacketBlock {
                    original_len: raw.len() as u32,
                    data: Cow::Borrowed(&raw),
                }
                .into_block(),
            )
            .unwrap();
        let mut analyzer = Analyzer::default();
        let mut timestamps = Vec::new();
        analyzer
            .read_capture_with(writer.into_inner().as_slice(), |state| {
                timestamps.push(state.observation_time);
                Ok(())
            })
            .unwrap();
        assert_eq!(analyzer.total_packets, 3);
        assert_eq!(analyzer.decoded_packets, 3);
        assert_eq!(
            timestamps,
            vec![
                Duration::from_secs(10),
                Duration::from_secs(15),
                Duration::from_secs(15)
            ]
        );
        assert_eq!(analyzer.pending_events().len(), 2);
        assert_eq!(analyzer.pending_events()[1].time_unix_nano, 15_000_000_000);
    }

    #[test]
    fn pcapng_signed_timestamp_offset() {
        let mut description = InterfaceDescriptionBlock::new(DataLink::RAW, 65_535);
        description
            .options
            .push(InterfaceDescriptionOption::IfTsOffset((-5_i64) as u64));
        let interface = CaptureInterface::from_description(&description);
        assert_eq!(
            interface.timestamp(10_000_000).unwrap(),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn pcapng_rejects_unknown_interface() {
        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut writer =
            PcapNgWriter::with_endianness(Vec::new(), pcap_file::Endianness::Little).unwrap();
        writer
            .write_block(&InterfaceDescriptionBlock::new(DataLink::RAW, 65_535).into_block())
            .unwrap();
        let packet_offset = writer.get_ref().len();
        writer.write_block(&enhanced(0, 1_000_000, &raw)).unwrap();
        let mut data = writer.into_inner();
        data[packet_offset + 8..packet_offset + 12].copy_from_slice(&7_u32.to_le_bytes());
        let error = Analyzer::default()
            .read_capture(data.as_slice())
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn pcapng_multiple_sections_reset_interface_ids() {
        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut ethernet = vec![0_u8; 14];
        ethernet[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        ethernet.extend_from_slice(&raw);
        let mut first = PcapNgWriter::new(Vec::new()).unwrap();
        first
            .write_block(&InterfaceDescriptionBlock::new(DataLink::RAW, 65_535).into_block())
            .unwrap();
        first.write_block(&enhanced(0, 1_000_000, &raw)).unwrap();
        let mut second = PcapNgWriter::new(Vec::new()).unwrap();
        second
            .write_block(&InterfaceDescriptionBlock::new(DataLink::ETHERNET, 65_535).into_block())
            .unwrap();
        second
            .write_block(&enhanced(0, 2_000_000, &ethernet))
            .unwrap();
        let bytes = [first.into_inner(), second.into_inner()].concat();
        let mut analyzer = Analyzer::default();
        analyzer.read_capture(bytes.as_slice()).unwrap();
        assert_eq!(analyzer.decoded_packets, 2);
        assert_eq!(analyzer.observation_time, Duration::from_secs(2));
    }

    #[test]
    fn classic_pcap_still_auto_detects() {
        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4_u32.to_le_bytes());
        bytes.extend_from_slice(&2_u16.to_le_bytes());
        bytes.extend_from_slice(&4_u16.to_le_bytes());
        bytes.extend_from_slice(&[0_u8; 8]);
        bytes.extend_from_slice(&65_535_u32.to_le_bytes());
        bytes.extend_from_slice(&101_u32.to_le_bytes());
        bytes.extend_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&raw);
        let mut analyzer = Analyzer::default();
        analyzer.read_capture(bytes.as_slice()).unwrap();
        assert_eq!(analyzer.decoded_packets, 1);
        assert_eq!(analyzer.observation_time, Duration::from_secs(3));
    }

    #[test]
    fn cooked_v2_and_loopback_link_types_decode() {
        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut cooked = vec![0_u8; 20];
        cooked[..2].copy_from_slice(&0x0800_u16.to_be_bytes());
        cooked.extend_from_slice(&raw);
        let mut loopback = vec![0_u8; 4];
        loopback.extend_from_slice(&raw);
        let mut analyzer = Analyzer::default();
        analyzer.ingest_frame_at(DataLink::LINUX_SLL2, &cooked, Duration::from_secs(1));
        analyzer.ingest_frame_at(DataLink::NULL, &loopback, Duration::from_secs(2));
        assert_eq!(analyzer.decoded_packets, 2);
    }

    #[cfg(unix)]
    #[test]
    fn pcapng_stream_emits_before_eof() {
        use std::os::unix::net::UnixStream;
        use std::sync::mpsc;

        let raw = bacnet_ip_frame([10, 0, 0, 2]);
        let mut writer = PcapNgWriter::new(Vec::new()).unwrap();
        writer
            .write_block(&InterfaceDescriptionBlock::new(DataLink::RAW, 65_535).into_block())
            .unwrap();
        writer.write_block(&enhanced(0, 1_000_000, &raw)).unwrap();
        let first_end = writer.get_ref().len();
        writer.write_block(&enhanced(0, 2_000_000, &raw)).unwrap();
        let bytes = writer.into_inner();
        let (mut producer, consumer) = UnixStream::pair().unwrap();
        consumer
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let (seen_tx, seen_rx) = mpsc::channel();
        let producer_thread = std::thread::spawn(move || {
            producer.write_all(&bytes[..first_end]).unwrap();
            seen_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            producer.write_all(&bytes[first_end..]).unwrap();
        });
        let mut analyzer = Analyzer::default();
        let mut count = 0;
        analyzer
            .read_capture_with(consumer, |_| {
                count += 1;
                if count == 1 {
                    seen_tx.send(()).unwrap();
                }
                Ok(())
            })
            .unwrap();
        producer_thread.join().unwrap();
        assert_eq!(count, 2);
        assert_eq!(analyzer.decoded_packets, 2);
    }

    #[test]
    fn bacnet_whois_and_graph() {
        let mut analyzer = Analyzer::default();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));
        analyzer.decode_bacnet(src, dst, &[0x81, 0x0b, 0, 8, 1, 0, 0x10, 8]);
        assert_eq!(analyzer.bacnet_packets, 1);
        assert_eq!(
            analyzer
                .sources
                .get(&(String::from("bacnet"), src.to_string()))
                .unwrap()
                .messages["who_is"],
            1
        );
        assert!(analyzer.graph_dot().contains("10.0.0.1"));
    }

    #[test]
    fn modbus_split_coalesced_and_retransmitted() {
        let mut analyzer = Analyzer::default();
        let src = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let dst = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let frame = [0, 1, 0, 0, 0, 6, 7, 3, 0, 0, 0, 2];
        let flow = (src, 40000, dst, 502);
        analyzer.decode_modbus_tcp(flow, 100, false, &frame[..5]);
        assert_eq!(analyzer.modbus_messages, 0);
        analyzer.decode_modbus_tcp(flow, 105, false, &frame[5..]);
        assert_eq!(analyzer.modbus_messages, 1);
        analyzer.decode_modbus_tcp(flow, 100, false, &frame);
        assert_eq!(analyzer.modbus_messages, 1);
        let both = [frame, frame].concat();
        analyzer.decode_modbus_tcp(flow, 112, false, &both);
        assert_eq!(analyzer.modbus_messages, 3);
        assert!(analyzer.modbus_units.contains(&(dst.to_string(), 7)));
    }

    #[test]
    fn modbus_gateway_pair_and_hourly_log_with_directional_counts() {
        let mut analyzer = Analyzer::default();
        let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let gateway = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let request = [0, 1, 0, 0, 0, 6, 7, 3, 0, 0, 0, 2];
        let response = [0, 1, 0, 0, 0, 5, 7, 3, 2, 0, 2];
        analyzer.observation_time = Duration::from_secs(100);
        analyzer.decode_modbus_tcp((client, 40000, gateway, 502), 10, false, &request);
        assert_eq!(analyzer.pending_events().len(), 1);
        assert_eq!(analyzer.pending_events()[0].device_b, "10.0.0.2/unit/7");
        assert_eq!(
            analyzer.topology_nodes["modbus/10.0.0.2"].kind,
            "modbus_tcp_gateway"
        );
        assert!(analyzer.graph_dot().contains("routes to"));
        analyzer.decode_modbus_tcp((gateway, 502, client, 40000), 20, false, &response);
        assert_eq!(analyzer.pending_events().len(), 1);
        analyzer.observation_time = Duration::from_secs(3_699);
        analyzer.decode_modbus_tcp((client, 40000, gateway, 502), 22, false, &request);
        assert_eq!(analyzer.pending_events().len(), 1);
        analyzer.observation_time = Duration::from_secs(3_700);
        analyzer.decode_modbus_tcp((client, 40000, gateway, 502), 34, false, &request);
        assert_eq!(analyzer.pending_events().len(), 2);
        assert_eq!(
            analyzer.edge_stats[&("modbus".into(), "10.0.0.1".into(), "10.0.0.2/unit/7".into())]
                .messages["function_3_request"],
            3
        );
        assert_eq!(
            analyzer.edge_stats[&("modbus".into(), "10.0.0.2/unit/7".into(), "10.0.0.1".into())]
                .messages["function_3_response"],
            1
        );
        let client_stats = &analyzer.node_stats["modbus/10.0.0.1"];
        assert_eq!((client_stats.sent, client_stats.received), (3, 1));
        assert_eq!(client_stats.sent_messages["function_3_request"], 3);
        let unit_stats = &analyzer.node_stats["modbus/10.0.0.2/unit/7"];
        assert_eq!((unit_stats.sent, unit_stats.received), (1, 3));
        assert_eq!(unit_stats.received_messages["function_3_request"], 3);
        let gateway_stats = &analyzer.node_stats["modbus/10.0.0.2"];
        assert_eq!((gateway_stats.sent, gateway_stats.received), (1, 3));
        analyzer.acknowledge_events(1);
        assert_eq!(analyzer.pending_events().len(), 1);
    }

    #[test]
    fn bacnet_broadcast_pair_uses_same_hourly_cache_as_unicast() {
        let mut analyzer = Analyzer::default();
        let a = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1));
        let b = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 2));
        let broadcast_address = IpAddr::V4(Ipv4Addr::new(10, 1, 1, 255));
        let npdu = [0x81, 0x0a, 0, 8, 1, 0, 0x10, 8];
        analyzer.decode_bacnet(a, b, &npdu);
        analyzer.decode_bacnet(b, a, &npdu);
        assert_eq!(analyzer.pending_events().len(), 1);
        let broadcast = [0x81, 0x0b, 0, 8, 1, 0, 0x10, 8];
        analyzer.observation_time = Duration::from_secs(100);
        analyzer.decode_bacnet(a, broadcast_address, &broadcast);
        assert_eq!(analyzer.pending_events().len(), 2);
        assert_eq!(
            analyzer.pending_events()[1].device_b,
            "broadcast@10.1.1.255"
        );
        analyzer.observation_time = Duration::from_secs(3_699);
        analyzer.decode_bacnet(a, broadcast_address, &broadcast);
        assert_eq!(analyzer.pending_events().len(), 2);
        analyzer.observation_time = Duration::from_secs(3_700);
        analyzer.decode_bacnet(a, broadcast_address, &broadcast);
        assert_eq!(analyzer.pending_events().len(), 3);
        assert_eq!(analyzer.node_stats["bacnet/10.1.1.1"].sent, 4);
        assert_eq!(analyzer.node_stats["bacnet/10.1.1.1"].received, 1);
        assert_eq!(analyzer.node_stats["bacnet/10.1.1.2"].received, 1);
        assert!(
            !analyzer
                .node_stats
                .contains_key("bacnet/broadcast@10.1.1.255")
        );
        assert_eq!(
            analyzer.edge_stats[&(
                "bacnet".into(),
                "10.1.1.1".into(),
                "broadcast@10.1.1.255".into(),
            )]
                .messages["who_is"],
            3
        );
        assert!(analyzer.corona_turtle().contains("net:BroadcastAddress"));
    }

    #[test]
    fn routed_broadcast_keeps_device_target_and_broadcast_edge() {
        let mut analyzer = Analyzer::default();
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let wire_broadcast = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255));
        let packet = [0x81, 0x0b, 0, 13, 1, 0x20, 0, 5, 1, 0x42, 0xff, 0x10, 8];
        analyzer.decode_bacnet(source, wire_broadcast, &packet);
        assert_eq!(analyzer.decoded_packets, 1);
        assert!(
            analyzer
                .edges
                .contains_key(&("bacnet".into(), "10.0.0.1".into(), "5:42".into()))
        );
        assert!(analyzer.edges.contains_key(&(
            "bacnet".into(),
            "10.0.0.1".into(),
            "broadcast@10.0.0.255".into()
        )));
        assert_eq!(analyzer.pending_events().len(), 2);
        assert_eq!(analyzer.node_stats["bacnet/5:42"].received, 1);
        assert!(
            !analyzer
                .node_stats
                .contains_key("bacnet/broadcast@10.0.0.255")
        );
    }

    #[test]
    fn bacnet_global_broadcast_is_a_pair_endpoint() {
        let mut analyzer = Analyzer::default();
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let packet = [0x81, 0x0a, 0, 12, 1, 0x20, 0xff, 0xff, 0, 0xff, 0x10, 8];
        analyzer.decode_bacnet(source, destination, &packet);
        assert_eq!(analyzer.decoded_packets, 1);
        assert!(analyzer.edges.contains_key(&(
            "bacnet".into(),
            "10.0.0.1".into(),
            "65535:broadcast".into()
        )));
        assert_eq!(analyzer.pending_events().len(), 1);
    }

    #[test]
    fn direct_modbus_server_and_corona_export() {
        let mut analyzer = Analyzer::default();
        let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let server = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let request = [0, 1, 0, 0, 0, 6, 255, 3, 0, 0, 0, 2];
        analyzer.decode_modbus_tcp((client, 40000, server, 502), 10, false, &request);
        assert!(analyzer.gateway_units.is_empty());
        assert_eq!(
            analyzer.topology_nodes["modbus/192.0.2.2"].kind,
            "modbus_tcp_server"
        );
        assert_eq!(analyzer.node_stats["modbus/192.0.2.2"].received, 1);
        let ttl = analyzer.corona_turtle();
        assert!(ttl.contains("net:ModbusTcpServer"));
        assert!(ttl.contains("net:CommunicationEdge"));
        assert!(ttl.contains("net:messageType \"function_3_request\""));
        assert!(ttl.contains("net:count 1"));
        assert!(ttl.contains("net:receivedMessageCount 1"));
        assert!(ttl.contains("net:direction \"received\""));
    }
}
