//! BACnet metric semantics from corona-pcap-processor ebfae89.
//!
//! This is deliberately separate from the network-topology model. The Python
//! collector counts the BACnet/IP, BVLL, and APDU layers independently.

use std::collections::BTreeMap;
use std::net::IpAddr;

use bacnet_bip_codec::decode as decode_bvll;
use bacnet_encoding::apdu::header::ApduHeader;
use bacnet_encoding::constructed::decode_event_notification;
use bacnet_encoding::tags::{TagClass, app_tag, decode_tag};
use bacnet_npdu::Npdu;
use bacnet_services::who_has::{WhoHasObject, WhoHasRequest};
use bacnet_services::who_is::IAmRequest;

#[derive(Debug, Default, Clone)]
pub struct LegacyAddressStats {
    pub total_packets: u64,
    pub broadcast_messages: u64,
    pub routed_messages: u64,
    pub forwarded_packets: u64,
    pub message_types: BTreeMap<String, u64>,
}

impl LegacyAddressStats {
    fn record(&mut self, message: &str, broadcast: bool) {
        self.total_packets += 1;
        self.broadcast_messages += u64::from(broadcast);
        self.routed_messages += u64::from(message == "ForwardedNPDU");
        *self.message_types.entry(message.to_owned()).or_default() += 1;
    }

    fn count(&self, message: &str) -> u64 {
        self.message_types.get(message).copied().unwrap_or(0)
    }
}

#[derive(Debug, Clone)]
pub struct LegacyDevice {
    pub id: u32,
    pub address: String,
    pub vendor_id: u16,
}

#[derive(Debug, Default)]
pub struct LegacyMetrics {
    pub addresses: BTreeMap<String, LegacyAddressStats>,
    pub devices_by_address: BTreeMap<String, LegacyDevice>,
    address_order: Vec<String>,
}

impl LegacyMetrics {
    pub fn ingest(&mut self, source: IpAddr, destination: IpAddr, payload: &[u8]) {
        let Ok(bvll) = decode_bvll(payload) else {
            return;
        };
        if let Some(bytes) = bvll.npdu()
            && let Ok(npdu) = Npdu::decode(bytes)
            && ((npdu.payload.first() == Some(&0x3c)
                && (npdu.payload.get(2) != Some(&0)
                    || npdu.payload.get(4) != Some(&26)
                    || !valid_first_read_range_segment(&npdu.payload[5..])))
                || (npdu.payload.first() == Some(&0x38)
                    && (npdu.payload.len() < 5
                        || !valid_last_read_range_segment(&npdu.payload[5..])))
                || (npdu.payload.starts_with(&[0x10, 0x04])
                    && decode_event_notification(&npdu.payload[2..]).is_err()))
        {
            return;
        }
        let source = source.to_string();
        let broadcast = destination.to_string() == "255.255.255.255";
        let stats = self.addresses.entry(source.clone()).or_default();
        stats.record("BACnet/IP", broadcast);

        let bvll_type = match bvll.function().to_raw() {
            0x00 => "Result",
            0x01 => "WriteBroadcastDistributionTable",
            0x02 => "ReadBroadcastDistributionTable",
            0x03 => "ReadBroadcastDistributionTableAck",
            0x04 => "ForwardedNPDU",
            0x05 => "RegisterForeignDevice",
            0x06 => "ReadForeignDeviceTable",
            0x07 => "ReadForeignDeviceTableAck",
            0x08 => "DeleteForeignDeviceTableEntry",
            0x09 => "DistributeBroadcastToNetwork",
            0x0a => "OriginalUnicastNPDU",
            0x0b => "OriginalBroadcastNPDU",
            _ => "UnknownBVLL",
        };
        stats.record(bvll_type, broadcast);

        let Some(npdu_bytes) = bvll.npdu() else {
            return;
        };
        let Ok(npdu) = Npdu::decode(npdu_bytes) else {
            return;
        };
        if npdu.message_type.is_some() || npdu.payload.is_empty() {
            return;
        }
        let (apdu_type, parameters, service_choice) = legacy_apdu_type(npdu.payload);
        let Some(apdu_type) = apdu_type else { return };
        self.addresses
            .entry(source.clone())
            .or_default()
            .record(apdu_type, broadcast);
        if let Some(service_type) = match service_choice {
            Some(0) => Some("IAmRequest"),
            Some(1) => Some("IHaveRequest"),
            Some(7) => Some("WhoHasRequest"),
            Some(8) => Some("WhoIsRequest"),
            _ => None,
        } && service_type != apdu_type
        {
            self.addresses
                .entry(source.clone())
                .or_default()
                .record(service_type, broadcast);
        }

        // The Python collector's direct APDU path attributes forwarded traffic
        // to the on-wire source IP as well as the BVLL forwarding layer.
        if apdu_type == "IAmRequest"
            && let Ok(iam) = IAmRequest::decode(parameters)
        {
            let address = format!("0:{source}");
            if !self.devices_by_address.contains_key(&address) {
                self.address_order.push(address.clone());
            }
            self.devices_by_address.insert(
                address.clone(),
                LegacyDevice {
                    id: iam.object_identifier.instance_number(),
                    address,
                    vendor_id: iam.vendor_id,
                },
            );
        }
    }

    fn device_metrics(&self) -> Vec<(String, Option<&LegacyDevice>, BTreeMap<&'static str, u64>)> {
        let mut selected: BTreeMap<u32, &LegacyDevice> = BTreeMap::new();
        for address in &self.address_order {
            if let Some(device) = self.devices_by_address.get(address) {
                selected.insert(device.id, device);
            }
        }
        let mut output = Vec::new();
        for (id, device) in selected {
            let mut metrics = BTreeMap::new();
            if let Some(stats) = self.addresses.get(&device.address) {
                add_metrics(&mut metrics, stats);
            }
            if let Some((network, mac)) = device.address.split_once(':')
                && network != "0"
            {
                *metrics.entry("iAmResponsesSent").or_default() += 1;
                metrics.insert(
                    if mac.len() <= 4 {
                        "mstpDevice"
                    } else {
                        "remoteNetworkDevice"
                    },
                    1,
                );
            }
            output.push((format!("dev-{id}"), Some(device), metrics));
        }
        for (address, stats) in &self.addresses {
            if self.devices_by_address.contains_key(address) {
                continue;
            }
            let mut metrics = BTreeMap::new();
            add_metrics(&mut metrics, stats);
            let key = format!("addr_{}", address.replace(':', "_"));
            output.push((key, None, metrics));
        }
        output
    }

    /// Export the earlier collector's metric ontology as RDF Turtle.
    pub fn turtle(&self, capture_device: Option<&str>) -> String {
        let mut out = String::from(
            "@prefix bacnet: <https://data.ashrae.org/bacnet/> .\n@prefix corona: <http://example.org/standards/corona/metrics#> .\n@prefix ex: <http://example.org/bacnet-impl/> .\n@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n",
        );
        let capture_uri = capture_device
            .map(|address| format!("ex:capture_{}", address.replace([':', '.'], "_")));
        if let (Some(address), Some(uri)) = (capture_device, &capture_uri) {
            out.push_str(&format!("{uri} a corona:CaptureDevice ; corona:identifier {} ; corona:name {} ; corona:description {} ; bacnet:address {} .\n", literal("capture-device"), literal("BACnet Network Capture Device"), literal("Device used to capture BACnet traffic"), literal(address)));
        }
        for (key, device, metrics) in self.device_metrics() {
            let address = device.map_or_else(
                || key.strip_prefix("addr_").unwrap_or(&key).replace('_', ":"),
                |device| device.address.clone(),
            );
            let (network, mac, kind) = address_parts(&address);
            let interface_uri = if let Some(device) = device {
                let uri = format!("ex:dev-{}", device.id);
                let interface = format!("ex:npm-{}-if0", device.id);
                out.push_str(&format!("{uri} a bacnet:Device ; bacnet:object-identifier {} ; bacnet:object-name {} ; bacnet:vendor-identifier \"{}\"^^xsd:unsignedInt ; bacnet:address {} ; bacnet:contains {interface} ; bacnet:address-type {} .\n", literal(&format!("device,{}", device.id)), literal(&format!("BACnet Device {}", device.id)), device.vendor_id, literal(&address), literal(kind)));
                interface
            } else {
                format!("ex:{key}")
            };
            out.push_str(&format!(
                "{interface_uri} a corona:NetworkInterfaceMetric, corona:ApplicationMetric ; "
            ));
            if let Some(device) = device {
                out.push_str(&format!(
                    "corona:identifier {} ; corona:name {} ; corona:description {} ; ",
                    literal(&format!("network-performance-monitor-{}", device.id)),
                    literal("Interface Performance Metrics"),
                    literal("Performance metrics from PCAP analysis.")
                ));
            } else {
                let label = match kind {
                    "ms-tp" => "BACnet MS/TP",
                    "remote-network" => "BACnet Network",
                    _ => "BACnet/IP",
                };
                out.push_str(&format!("corona:identifier {} ; corona:name {} ; corona:description {} ; bacnet:address {} ; bacnet:address-type {} ; ", literal(&format!("interface-{}", address.replace(':', "-"))), literal(&format!("{label} Interface {address}")), literal(&format!("{label} interface metrics for address {address}")), literal(&address), literal(kind)));
            }
            if network != "0" {
                out.push_str(&format!(
                    "bacnet:network-number \"{network}\"^^xsd:unsignedInt ; "
                ));
                if kind == "ms-tp" {
                    if let Ok(number) = u64::from_str_radix(mac, 16) {
                        out.push_str(&format!(
                            "bacnet:mac-address \"{number}\"^^xsd:unsignedInt ; "
                        ));
                    } else {
                        out.push_str(&format!("bacnet:mac-address {} ; ", literal(mac)));
                    }
                } else {
                    out.push_str(&format!("bacnet:mac-address {} ; ", literal(mac)));
                }
            }
            if let Some(uri) = &capture_uri {
                out.push_str(&format!("corona:observedFrom {uri} ; "));
            }
            for (name, value) in metrics {
                if value > 0 {
                    out.push_str(&format!("corona:{name} \"{value}\"^^xsd:unsignedLong ; "));
                }
            }
            out.truncate(out.len() - 3);
            out.push_str(" .\n");
        }
        out
    }
}

fn add_metrics(metrics: &mut BTreeMap<&'static str, u64>, stats: &LegacyAddressStats) {
    let mut add = |name, value| {
        if value > 0 {
            *metrics.entry(name).or_default() += value;
        }
    };
    add("packetsReceived", stats.total_packets);
    add("totalBacnetMessagesSent", stats.total_packets);
    add("broadcastPacketsSent", stats.broadcast_messages);
    add("totalBroadcastsSent", stats.broadcast_messages);
    add("globalBroadcastMessageCount", stats.broadcast_messages);
    for (message, name, request) in [
        ("WhoIsRequest", "whoIsRequestsSent", true),
        ("IAmRequest", "iAmResponsesSent", false),
        ("WhoHasRequest", "whoHasRequestsSent", true),
        ("IHaveRequest", "iHaveResponsesSent", false),
        ("ReadPropertyRequest", "readPropertyRequestsSent", true),
        ("ReadPropertyACK", "readPropertyResponsesSent", false),
        ("WritePropertyRequest", "writePropertyRequestsSent", true),
        ("WritePropertyACK", "writePropertyResponsesSent", false),
        (
            "ConfirmedCOVNotificationRequest",
            "confirmedCOVNotificationsSent",
            true,
        ),
        (
            "UnconfirmedCOVNotificationRequest",
            "unconfirmedCOVNotificationsSent",
            true,
        ),
    ] {
        let count = stats.count(message);
        add(name, count);
        if request {
            add("totalRequestsSent", count);
        } else {
            add("totalResponsesSent", count);
        }
        match message {
            "WhoIsRequest" => add("globalWhoIsRequestsSent", count),
            "WhoHasRequest" => add("globalWhoHasRequestsSent", count),
            _ => {}
        }
    }
    add("routedMessagesSent", stats.routed_messages);
    add("messagesRouted", stats.routed_messages);
    add("routedDevicesSeen", stats.routed_messages / 10);
    add("broadcastRelayed", stats.forwarded_packets);
    add("messagesForwarded", stats.forwarded_packets);
}

fn legacy_apdu_type(apdu: &[u8]) -> (Option<&'static str>, &[u8], Option<u8>) {
    if apdu.first() == Some(&0x3c) {
        return (Some("ReadRangeACK"), &apdu[5..], Some(26));
    }
    let Ok((header, parameters)) = ApduHeader::decode(apdu) else {
        return (None, &[], None);
    };
    let (name, service_choice) = match header {
        ApduHeader::UnconfirmedRequest(service) => (
            match service.to_raw() {
                0 => Some("IAmRequest"),
                1 => Some("IHaveRequest"),
                2 => Some("UnconfirmedCOVNotificationRequest"),
                8 => Some("WhoIsRequest"),
                7 if matches!(
                    WhoHasRequest::decode(parameters),
                    Ok(WhoHasRequest {
                        object: WhoHasObject::Identifier(_),
                        ..
                    })
                ) =>
                {
                    Some("WhoHasRequest")
                }
                _ => None,
            },
            Some(service.to_raw()),
        ),
        ApduHeader::ConfirmedRequest(request) => (
            match request.service_choice.to_raw() {
                1 => Some("ConfirmedCOVNotificationRequest"),
                2 => Some("ConfirmedEventNotificationRequest"),
                6 => Some("AtomicReadFileRequest"),
                12 => Some("ReadPropertyRequest"),
                15 => Some("WritePropertyRequest"),
                18 => Some("ConfirmedPrivateTransferRequest"),
                26 => Some("ReadRangeRequest"),
                _ => None,
            },
            Some(request.service_choice.to_raw()),
        ),
        ApduHeader::ComplexAck { service_choice, .. } => (
            match service_choice.to_raw() {
                6 => Some("AtomicReadFileACK"),
                12 => Some("ReadPropertyACK"),
                15 => Some("WritePropertyACK"),
                18 => Some("ConfirmedPrivateTransferACK"),
                26 => Some("ReadRangeACK"),
                _ => None,
            },
            Some(service_choice.to_raw()),
        ),
        _ => (None, None),
    };
    (name, parameters, service_choice)
}

// BACpypes3 accepts a first ReadRange segment when its item-data opening
// tag is unfinished, but rejects fragments with another unmatched inner tag.
fn valid_first_read_range_segment(data: &[u8]) -> bool {
    let mut offset = 0;
    let mut open_tags = Vec::new();
    while offset < data.len() {
        let Ok((tag, end)) = decode_tag(data, offset) else {
            return false;
        };
        if tag.is_opening {
            open_tags.push(tag.number);
            offset = end;
        } else if tag.is_closing {
            if open_tags.pop() != Some(tag.number) {
                return false;
            }
            offset = end;
        } else {
            let length = if tag.class == TagClass::Application && tag.number == app_tag::BOOLEAN {
                0
            } else {
                tag.length as usize
            };
            let Some(next) = end.checked_add(length) else {
                return false;
            };
            if next > data.len() {
                return false;
            }
            offset = next;
        }
    }
    open_tags == [5]
}

// The Python decoder accepts final ReadRange fragments with a closing tag
// carried over from an earlier segment. A mismatched inner close is rejected.
fn valid_last_read_range_segment(data: &[u8]) -> bool {
    let Ok((first, _)) = decode_tag(data, 0) else {
        return false;
    };
    if first.class == TagClass::Application && first.number > app_tag::OBJECT_IDENTIFIER {
        return false;
    }
    let mut offset = 0;
    let mut open_tags = Vec::new();
    while offset < data.len() {
        let Ok((tag, end)) = decode_tag(data, offset) else {
            return false;
        };
        if tag.is_opening {
            open_tags.push(tag.number);
            offset = end;
        } else if tag.is_closing {
            if open_tags.last() == Some(&tag.number) {
                open_tags.pop();
                offset = end;
            } else {
                return true;
            }
        } else {
            let length = if tag.class == TagClass::Application && tag.number == app_tag::BOOLEAN {
                0
            } else {
                tag.length as usize
            };
            let Some(next) = end.checked_add(length) else {
                return false;
            };
            if next > data.len() {
                return false;
            }
            offset = next;
        }
    }
    true
}

fn address_parts(address: &str) -> (&str, &str, &'static str) {
    if let Some((network, mac)) = address.split_once(':') {
        if network != "0" {
            return (
                network,
                mac,
                if mac.len() <= 4 {
                    "ms-tp"
                } else {
                    "remote-network"
                },
            );
        }
        (network, mac, "bacnet-ip")
    } else {
        ("0", "", "bacnet-ip")
    }
}

fn literal(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n");
    format!("\"{escaped}\"^^xsd:string")
}

#[cfg(test)]
mod tests {
    use super::{valid_first_read_range_segment, valid_last_read_range_segment};

    #[test]
    fn segmented_read_range_follows_legacy_tag_acceptance() {
        // A first fragment can end with item-data [5] still open.
        assert!(valid_first_read_range_segment(&[0x0c, 0, 0, 0, 1, 0x5e]));
        assert!(!valid_first_read_range_segment(&[
            0x0c, 0, 0, 0, 1, 0x5e, 0x0e
        ]));
        // Later fragments may start with a closing tag from the prior one.
        assert!(valid_last_read_range_segment(&[0x0f]));
        assert!(!valid_last_read_range_segment(&[0xd0, 0x1f]));
    }
}
