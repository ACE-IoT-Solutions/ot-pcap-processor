# Output guide

`ot-pcap-processor` produces a terminal summary, Graphviz DOT, Corona network RDF in Turtle, OTLP/HTTP metrics, and OTLP/HTTP communication logs. The checked-in [example capture](examples/mixed-traffic.pcap) contains a BACnet/IP Who-Is broadcast from `10.0.0.1` and a Modbus/TCP function 3 request from `10.0.0.1` to gateway `10.0.0.2`, Unit ID 7. It has two packet records at capture seconds 100 and 101. The complete resulting files are linked below.

## Which mode produces which output?

| Mode | Terminal summary | DOT / Turtle files | OTLP metrics | OTLP logs |
| --- | --- | --- | --- | --- |
| `file` | Always, on completion | Optional, with `--graph` / `--corona` | With `--otlp-endpoint`, at completion | With `--otlp-endpoint`, at completion |
| `pipe` | At EOF without an OTLP endpoint | Not offered | With an endpoint, periodically while packets arrive and at EOF | With an endpoint, as new or due communication pairs appear |
| `daemon --interface` | No terminal summary | Not offered | With an endpoint, periodically while packets arrive | With an endpoint, as new or due pairs appear |
| `daemon --rpcap-listen` | No terminal summary | Not offered | With an endpoint, periodically, including idle timer ticks | With an endpoint, as new or due pairs appear |

The file and pipe modes accept PCAP and PCAPNG. All modes use UDP 47808 for BACnet/IP and TCP 502 for Modbus/TCP by default. Each mode accepts `--bacnet-ports` and `--modbus-ports` to change those filters. The daemon requires `--otlp-endpoint`; its capture source is a local interface or an active RPCAP peer. Export failures are reported on stderr. In file mode an export failure also makes the command fail. In the local daemon, failed exports are reported while capture continues; remote RPCAP mode has its own reconnect and export behavior.

## Reproduce the examples

From the repository root:

```sh
cargo build --locked
python3 scripts/generate_output_examples.py
```

The generator creates the small capture, runs the CLI, receives its OTLP/HTTP JSON requests on a temporary loopback server, and writes these files:

| File | What it contains |
| --- | --- |
| [mixed-traffic.pcap](examples/mixed-traffic.pcap) | Input capture used for every example. |
| [summary.txt](examples/summary.txt) | Complete `file` mode terminal summary. |
| [network.dot](examples/network.dot) | Complete directed Graphviz map. |
| [network.ttl](examples/network.ttl) | Complete Corona network Turtle export. |
| [otlp-metrics.json](examples/otlp-metrics.json) | Complete JSON body sent to `/v1/metrics`. |
| [otlp-logs.json](examples/otlp-logs.json) | Complete JSON body sent to `/v1/logs`. |

The example generator replaces the export and observed timestamps in the OTLP JSON with fixed values so a rebuild gives the same text. The log event timestamps remain the capture timestamps. Addresses use private example traffic and do not refer to a live network.

## Terminal summary

```sh
ot-pcap-processor file docs/examples/mixed-traffic.pcap
```

The [full summary](examples/summary.txt) starts:

```text
Captured frames: 2
Decoded messages: 2 (BACnet packets: 1, Modbus messages: 1)
Malformed or incomplete messages: 0
BACnet devices: 0  Modbus units: 1  Conversations: 2
Topology nodes: 5  gateway links: 1
```

`Captured frames` counts packet records read. `Decoded messages` counts successfully classified BACnet packets and Modbus ADUs; one TCP segment can hold multiple Modbus ADUs. `Conversations` counts **directed** protocol edges, so traffic in both directions creates two entries. The per-node sent and received lines count logical endpoints. A Modbus gateway and its Unit ID can both show the same received request; do not sum node counters to infer a wire packet total. The example has no BACnet I-Am packet, so the discovered BACnet device count is zero even though BACnet source and broadcast nodes appear in the map.

In pipe mode without OTLP, this summary appears when the input ends. With OTLP, pipe mode sends telemetry and does not print an exit summary. File mode prints its summary whether or not OTLP is enabled.

## Graphviz network map

```sh
ot-pcap-processor file docs/examples/mixed-traffic.pcap --graph network.dot
dot -Tsvg network.dot -o network.svg
```

The [complete DOT example](examples/network.dot) includes:

```dot
"modbus/10.0.0.2" -> "modbus/10.0.0.2/unit/7" [style=dashed,label="routes to"];
"bacnet/10.0.0.1" -> "bacnet/broadcast@10.0.0.255" [label="bacnet: 1"];
"modbus/10.0.0.1" -> "modbus/10.0.0.2/unit/7" [label="modbus: 1"];
```

Solid arrows show observed directed communication with decoded message counts. The dashed arrow associates a Modbus/TCP gateway with an observed Unit ID. A Unit ID identifies a logical downstream endpoint; passive traffic alone cannot prove that the downstream transport is RTU. The graph is an observed communication map, not a physical cabling diagram.

## Corona network RDF

```sh
ot-pcap-processor file docs/examples/mixed-traffic.pcap --corona network.ttl
```

The [complete Turtle example](examples/network.ttl) uses the merged Corona network ontology. It declares BACnet devices and broadcast addresses, Modbus clients, gateways and logical units, directed `net:CommunicationEdge` resources, per-message observations on edges and nodes, and `net:routesTo` gateway links. For example, it describes the logical Modbus endpoint with `net:ModbusRtuUnit` and links the gateway to it. The class reflects the Unit ID routing model; it is not proof that an RTU serial bus was observed.

The `ex:` resource identifiers encode endpoint names as hexadecimal UTF-8 bytes to keep URIs stable and unambiguous. Node `net:HWStatus "UNKNOWN"` values mean that passive packet decoding supplied no hardware status. `net:sentMessageCount` and `net:receivedMessageCount` are node totals; `net:messageCount` is an edge total. `net:MessageObservation` gives counts by decoded message type. Validate an export with the [upstream Corona validator](../README.md#validate-corona-rdf).

## OTLP/HTTP metrics

```sh
ot-pcap-processor file docs/examples/mixed-traffic.pcap \
  --otlp-endpoint http://127.0.0.1:4318
```

The collector POSTs one OTLP JSON object to `/v1/metrics`. The [complete request body](examples/otlp-metrics.json) has `resourceMetrics` and a `service.name` resource attribute of `ot-pcap-processor`. Each metric contains `sum` or `gauge` data points. Cumulative sums set `aggregationTemporality` to `2` and `isMonotonic` to `true`. The OTLP JSON mapping represents integer values and Unix nanosecond timestamps as strings. Counters reset when the collector restarts.

The example contains 17 metric names and 36 data points. One edge data point is equivalent to:

```json
{
  "name": "ot_edge_messages_total",
  "sum": {
    "aggregationTemporality": 2,
    "isMonotonic": true,
    "dataPoints": [{
      "attributes": [
        {"key": "protocol", "value": {"stringValue": "modbus"}},
        {"key": "source_device", "value": {"stringValue": "10.0.0.1"}},
        {"key": "destination_device", "value": {"stringValue": "10.0.0.2/unit/7"}},
        {"key": "message", "value": {"stringValue": "function_3_request"}}
      ],
      "asInt": "1",
      "startTimeUnixNano": "1700000000000000000",
      "timeUnixNano": "1700000001000000000"
    }]
  }
}
```

Metric catalog (attributes shown are the emitted data-point attributes):

| Metric | Type and attributes | Meaning |
| --- | --- | --- |
| `ot_decoded_messages_total` | Sum; `protocol`, `source` | Decoded messages from a source. |
| `ot_messages_total` | Sum; `protocol`, `source`, `message` | Decoded messages by type and source. |
| `ot_broadcast_packets_total` | Sum; `protocol`, `source` | BACnet broadcasts observed from a source. |
| `ot_routed_packets_total` | Sum; `protocol`, `source` | BACnet messages with NPDU routing fields. |
| `ot_forwarded_packets_total` | Sum; `protocol`, `source` | Forwarded BACnet NPDU messages. |
| `bacnet_whois_requests_total`, `bacnet_iam_responses_total`, `bacnet_whohas_requests_total`, `bacnet_ihave_responses_total` | Sum; `protocol`, `source` | Named BACnet unconfirmed services. |
| `bacnet_read_property_requests_total`, `bacnet_read_property_responses_total`, `bacnet_write_property_requests_total`, `bacnet_write_property_responses_total` | Sum; `protocol`, `source` | Named BACnet confirmed service requests and responses. |
| `modbus_requests_total`, `modbus_responses_total`, `modbus_exceptions_total` | Sum; `protocol`, `source`, `function` | Modbus messages by function code and outcome. |
| `ot_edge_messages_total` | Sum; `protocol`, `source_device`, `destination_device`, `message` | Every observed directed device-to-device or device-to-broadcast message. |
| `ot_node_sent_messages_total`, `ot_node_received_messages_total` | Sum; `protocol`, `device` | Sent and received counts on logical nodes. |
| `ot_node_messages_total` | Sum; `protocol`, `device`, `direction`, `message` | Node counts by direction and message type. |
| `ot_bacnet_devices` | Gauge; none | Unique BACnet device instances learned from I-Am. |
| `ot_modbus_units` | Gauge; none | Unique observed gateway and Unit ID combinations. |
| `ot_topology_nodes` | Gauge; none | Number of discovered logical nodes. |
| `ot_topology_node_info` | Gauge of 1; `device`, `node_type` | Identity and type of each logical node. |
| `ot_gateway_unit_info` | Gauge of 1; `gateway`, `unit` | Observed Modbus gateway-to-unit relationship. |
| `bacnet_device_info` | Gauge of 1; `device_id`, `vendor_id`, `address` | Device instance and vendor announced by I-Am. |
| `ot_malformed_packets_total` | Sum; none | Malformed or incomplete protocol messages. |

Service and info metrics appear only when relevant traffic or discoveries exist. Zero-valued source and node counters may appear for an observed source or node. `ot_edge_messages_total` includes both communication directions separately. Broadcast destinations are represented as logical endpoints such as `broadcast@10.0.0.255` or `65535:broadcast`; they do not get a received node count, because no particular receiver is established by the broadcast.

## OTLP/HTTP communication logs

The collector POSTs OTLP JSON to `/v1/logs` when a communication pair is first observed. It sends another record on the first subsequent observation at least one hour after the previous record. The clock is the packet capture timestamp. The pair key ignores direction, but includes protocol; metrics continue to count every directed message. BACnet broadcasts use a device-to-broadcast pair on the same cadence. Sending a file to an OTLP receiver can therefore create historical log timestamps.

The [complete log request](examples/otlp-logs.json) has one record for the BACnet broadcast pair and one for the Modbus client-to-unit pair. A record looks like:

```json
{
  "timeUnixNano": "100000000000",
  "severityNumber": 9,
  "severityText": "INFO",
  "body": {"stringValue": "ot.communication.observed"},
  "attributes": [
    {"key": "protocol", "value": {"stringValue": "bacnet"}},
    {"key": "device_a", "value": {"stringValue": "10.0.0.1"}},
    {"key": "device_b", "value": {"stringValue": "broadcast@10.0.0.255"}},
    {"key": "event.name", "value": {"stringValue": "ot.communication.observed"}}
  ]
}
```

The full record also has `observedTimeUnixNano`, the collector's export time. Records are sent to OTLP in batches of at most 1,000. A successful receiver response removes a pending record. A failed export leaves it queued in a running process; file mode exits with an error if its export fails.

## What Alloy prints in the Podman examples

The [sample Alloy configuration](../deploy/config.alloy) receives both OTLP signals on port 4318. It prints a short metrics summary and detailed communication logs, so you can verify ingestion with:

```sh
podman compose -f deploy/compose.rpcap.yaml logs alloy
# or, for a rootful local capture deployment:
sudo podman compose -f deploy/compose.local.yaml logs alloy
```

For this capture, the debug exporters report `log_records=2`, `metrics=17`, and `data_points=36`. Detailed log output includes `Body: Str(ot.communication.observed)` and the `protocol`, `device_a`, and `device_b` attributes. The Alloy UI is bound to `http://127.0.0.1:12345` on the host. The checked-in configuration is an inspection sink; connect other Alloy exporters in its `output` block to send signals to a production backend. The [Grafana Alloy component reference](https://grafana.com/docs/alloy/latest/reference/components/) lists available receivers, processors, and exporters.
