# OT PCAP Processor

OT PCAP Processor is a Rust command-line collector for passive BACnet/IP and Modbus/TCP traffic. It reads saved PCAP and PCAPNG captures, live capture streams from `tcpdump`, `tshark`, or `dumpcap`, a local interface, or an active-mode `rpcapd` connection. It reports discovered devices and conversations, writes Graphviz and Corona RDF network maps, and exports metrics and communication logs over OTLP/HTTP.

For complete, reproducible examples of the terminal summary, DOT graph, Corona Turtle, OTLP metrics, OTLP logs, and Alloy output, see the [output guide](docs/outputs.md).

The Python distribution installs the `ot-pcap-processor` executable. It does not provide an importable Python module. Rust applications can use the `ot_pcap_processor::Analyzer` library.
Python 3.9 through 3.15 are checked in CI on Linux and macOS.

## Install

After publication to PyPI:

```sh
uv tool install ot-pcap-processor
# or inside a Python virtual environment:
python -m pip install ot-pcap-processor
```

To install this checkout before publication, use `uv tool install .` or `python -m pip install .` in a virtual environment. Building from a source distribution requires Rust 1.96.1 or newer. Prebuilt wheels do not require Rust. For Rust development, run `cargo build --release --locked`.

## Process a capture

```sh
# Print a summary and save a network map.
ot-pcap-processor file capture.pcapng --graph network.dot --corona network.ttl

# Convert the DOT map to SVG if Graphviz is installed.
dot -Tsvg network.dot -o network.svg

# Send metrics to an OTLP/HTTP receiver as well.
ot-pcap-processor file capture.pcap --otlp-endpoint http://127.0.0.1:4318
```

The graphs show observed traffic, with edge counts and BACnet device IDs learned from I-Am messages. The Turtle file uses the [Corona network standard](https://github.com/ACE-IoT-Solutions/corona-network-standard) `net:CommunicationEdge` and `net:MessageObservation` terms to retain per-message counts. Neither output infers physical cabling or switch topology.

Modbus/TCP clients and servers are separate nodes. A significant Unit ID (1–247) creates a logical downstream unit and a gateway routing link; Unit ID 0 or 255 uses the TCP server node directly. A passive Unit ID observation suggests a gateway but does not prove the downstream wire is RTU. The [Modbus/TCP implementation guide](https://modbus.org/docs/Modbus_Messaging_Implementation_Guide_V1_0b.pdf) describes these Unit ID conventions. BACnet routed addresses and announced device instances also appear in the topology.

### Validate Corona RDF

The exported Turtle is checked in CI with the merged upstream `corona-network-tool validate` command and its packaged network ontology and SHACL shapes. The CI fixture contains a BACnet broadcast and a Modbus/TCP request addressed to a downstream Unit ID. A second check, `scripts/validate_corona_topology.py`, rejects undefined `net:` terms that SHACL may not flag. To validate your own capture with the upstream tool:

```sh
git clone https://github.com/ACE-IoT-Solutions/corona-network-standard.git
(cd corona-network-standard && uv sync --python 3.11 --no-dev)
ot-pcap-processor file capture.pcapng --corona network.ttl
(cd corona-network-standard && uv run --no-sync --python 3.11 corona-network-tool validate "$(pwd)/../network.ttl")
```

Validation confirms that the RDF meets the upstream network shapes. It does not verify that passively inferred device identities or network links match the physical installation.

With `--otlp-endpoint`, the collector sends cumulative metrics to `/v1/metrics` and communication-pair log records to `/v1/logs`. Each unordered pair of protocol endpoints produces a log on first observation and again on the next observation at least one hour later. The interval uses capture timestamps, including for saved PCAP and RPCAP. Active BACnet broadcast traffic uses the same cadence for a device-to-broadcast pair, with a logical broadcast endpoint such as `broadcast@10.0.0.255` or `65535:broadcast`. Routed packets with a logical device destination retain that device edge and also count their on-wire broadcast edge. Each directed edge counts every decoded message type in `ot_edge_messages_total` with `protocol`, `source_device`, `destination_device`, and `message` attributes. Each device node has `ot_node_sent_messages_total`, `ot_node_received_messages_total`, and `ot_node_messages_total` split by direction and message type. Gateway node counters describe the Modbus/TCP messages received from clients and sent back to them; downstream unit counters describe the logical Unit ID endpoint. The Turtle output retains these node counts as well as edge counts. `ot_topology_node_info` and `ot_gateway_unit_info` expose node types and routing links. The log body is `ot.communication.observed`, with `protocol`, `device_a`, and `device_b` attributes. Configure the OTLP receiver for both metrics and logs.

## Read a live PCAP or PCAPNG stream

```sh
tcpdump -i eth0 -U -s 0 -w - 'udp port 47808 or tcp port 502' \
  | ot-pcap-processor pipe

# TShark and Wireshark's dumpcap write PCAPNG by default.
tshark -i eth0 -f 'udp port 47808 or tcp port 502' -F pcapng -w - \
  | ot-pcap-processor pipe

dumpcap -i eth0 -f 'udp port 47808 or tcp port 502' -w - \
  | ot-pcap-processor pipe

# Export cumulative metrics after 30 seconds of packet activity and at EOF.
tcpdump -i eth0 -U -s 0 -w - 'udp port 47808 or tcp port 502' \
  | ot-pcap-processor pipe --otlp-endpoint http://127.0.0.1:4318
```

Without an OTLP endpoint, `pipe` prints a summary when the input ends. The endpoint can be a base URL or a URL ending in `/v1/metrics`. Every mode accepts comma-separated `--bacnet-ports` and `--modbus-ports` options; defaults are UDP 47808 and TCP 502. The file and pipe modes detect PCAP versus PCAPNG from the stream header, so no format flag or file extension is required. Pipe mode processes complete packets as they arrive, without waiting for EOF.

## Run as a local capture daemon

```sh
ot-pcap-processor daemon --interface eth0 \
  --otlp-endpoint http://127.0.0.1:4318
```

The process stays in the foreground for a service manager. It launches `tcpdump` with a filter matching the configured protocol ports. The host needs `tcpdump` and permission to capture. Local and pipe modes send periodic metrics when packets arrive; remote RPCAP mode also sends on its timer when idle. A systemd unit (`systemd/ot-pcap-processor.service`) and a Podman Compose example (`deploy/compose.local.yaml`) are included in the source distribution.

## Receive remote captures from rpcapd

Run the collector in active RPCAP mode:

```sh
ot-pcap-processor daemon \
  --rpcap-listen 0.0.0.0:2003 \
  --rpcap-data-port 2004 \
  --rpcap-interface eth0 \
  --rpcap-allow-peer 192.0.2.10 \
  --otlp-endpoint http://127.0.0.1:4318
```

Here `eth0` names an interface **on the remote rpcapd host**, and `192.0.2.10` is that host's source IP as seen by the collector. Configure the remote `rpcapd` in active mode to connect to the collector on TCP 2003; the collector also needs TCP 2004 reachable for the packet data connection. For a null-auth test on an isolated network, the remote command is typically:

```sh
rpcapd -a collector.example.com,2003 -v -n
```

The listener accepts one capture session at a time, reconnecting after a session ends. It requests a remote capture filter compiled by `tcpdump`; if `tcpdump` is unavailable, it still filters locally but the remote host sends all captured frames. RPCAP authentication can use `--rpcap-user USER` with `RPCAP_PASSWORD` set in the environment. Standard RPCAP control and packet channels are not encrypted; use a private network or a protected tunnel for remote deployments. `--rpcap-allow-peer` is required when listening on a non-loopback address.

## Podman deployment

The `Containerfile` includes the processor and `tcpdump`. Both examples include Grafana Alloy, which receives the processor's OTLP/HTTP metrics and logs on port 4318. The sample [`deploy/config.alloy`](deploy/config.alloy) prints metric summaries and detailed communication logs to the Alloy container logs so you can confirm ingestion. Edit its `output` block to route them to your chosen Alloy exporters. The example enables Alloy's experimental level for its debug exporters. The Alloy UI is available on `http://127.0.0.1:12345`; ports 4318 and 12345 bind to host loopback only. No Prometheus backend or format conversion is required for these examples.

**Remote capture:**

```sh
cp deploy/rpcap.env.example deploy/rpcap.env
# Edit RPCAP_PEER_IP and RPCAP_INTERFACE.
podman compose --env-file deploy/rpcap.env -f deploy/compose.rpcap.yaml up --build -d
```

Inspect received metrics and communication events with `podman compose -f deploy/compose.rpcap.yaml logs alloy`.

Expose TCP 2003 and 2004 to the remote `rpcapd` host. This mode runs without capture capabilities in the container.

**Local capture on Linux:**

```sh
cp deploy/local.env.example deploy/local.env
# Edit CAPTURE_INTERFACE.
sudo podman compose --env-file deploy/local.env -f deploy/compose.local.yaml up --build -d
```

Inspect received metrics and communication events with `sudo podman compose -f deploy/compose.local.yaml logs alloy`.

The local example uses host networking and grants `NET_RAW` and `NET_ADMIN` for `tcpdump`. It is intended for a rootful Linux Podman host. `podman compose` requires an installed Compose provider.

## Metrics and decoder scope

OTLP exports include per-node sent and received counts, per-source and per-edge decoded message counts, BACnet broadcast/routed/forwarded counts, BACnet service counters, Modbus request/response/exception counters, topology nodes and gateway links, discovered BACnet device and Modbus unit gauges, and malformed input counts. Counters describe what this process has observed; they reset when it restarts. The topology and per-source BACnet counters draw on the earlier Corona PCAP processor and packet-capture agent designs.

- Input is uncompressed PCAP or PCAPNG. PCAPNG Enhanced, Simple, and legacy Packet Blocks are supported, including multiple interfaces and sections. Per-interface timestamp resolution and offset are applied to Enhanced and legacy Packet Blocks. Simple Packet Blocks have no timestamp; they use the preceding packet's timestamp in that section, or the current clock if there is none. Ethernet, raw IPv4/IPv6, Linux cooked v1/v2, and BSD loopback link types are supported.
- BACnet/IP BVLL, NPDU, APDU headers, and I-Am use the published upstream `rusty-bacnet` 0.14.0 crates. The used APIs match the ACE fork, so no fork patch is required for this release.
- Modbus/TCP MBAP and PDU decoding use `rustmod-core`. The TCP assembler handles in-order segments, overlap, retransmission, and multiple ADUs in one segment. Out-of-order gaps reset the pending flow instead of reordering traffic.
- BACnet segmented APDUs are classified but not reassembled. BACnet/SC, directly captured MS/TP, and BACnet/IPv6 BVLL are outside this version.

CI builds and functionally tests installable wheels and an sdist, then uploads a combined artifact with checksums. A separate release workflow is prepared for PyPI Trusted Publishing. Build retrieval, publisher setup, and release steps are in [`docs/releasing.md`](docs/releasing.md) in the source distribution.

## Performance comparison

On an Apple Mac16,8 with 48 GiB RAM (macOS 26.6.2), a BACnet PCAP of 6,680 packet records was repeated ten times to 66,800 records (5.79 MB). Both collectors read the capture and wrote Turtle files, with no OTLP receiver. After one warmup, five alternating runs gave these median wall times:

| Collector | Median time | Output size |
| --- | ---: | ---: |
| This Rust collector, release build | 0.079 s | 83,502 bytes |
| Earlier Python `corona-pcap-processor` at `ebfae89` | 5.667 s | 6,755 bytes |

The Rust CLI was **71.3× faster in this end-to-end run**. The outputs have different content: this collector writes network nodes, edges, and message observations, while the older Python collector writes BACnet metrics. The Python decoder yielded 66,360 of the 66,800 repeated packet records. These figures compare the full CLI paths on this capture; they are not isolated parser throughput or a claim of identical output semantics.

To reproduce with a checkout of the earlier Python collector and its `uv` environment:

```sh
git clone https://github.com/ACE-IoT-Solutions/corona-pcap-processor.git ../corona-pcap-processor
(cd ../corona-pcap-processor && git checkout ebfae89 && uv sync --frozen --python 3.11)
cargo build --release --locked
python3 scripts/benchmark_corona.py ../corona-pcap-processor/sample-pcap.pcap \
  --python-repo ../corona-pcap-processor --repeat 10 --runs 5 --warmups 1
```
