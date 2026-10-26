"""Create a small BACnet broadcast and Modbus gateway PCAP for RDF checks."""

import argparse
import struct
from pathlib import Path


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_packet(source: bytes, destination: bytes, protocol: int, payload: bytes) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    header[2:4] = struct.pack("!H", 20 + len(payload))
    header[8] = 64
    header[9] = protocol
    header[12:16] = source
    header[16:20] = destination
    header[10:12] = struct.pack("!H", internet_checksum(header))
    return bytes(header) + payload


def ethernet_frame(destination_mac: bytes, ip_packet: bytes) -> bytes:
    return destination_mac + bytes.fromhex("0200000000010800") + ip_packet


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    client = bytes([10, 0, 0, 1])
    server = bytes([10, 0, 0, 2])
    broadcast = bytes([10, 0, 0, 255])

    bacnet = bytes([0x81, 0x0B, 0, 8, 1, 0, 0x10, 8])
    udp = struct.pack("!HHHH", 47808, 47808, 8 + len(bacnet), 0) + bacnet
    broadcast_frame = ethernet_frame(
        b"\xff" * 6, ipv4_packet(client, broadcast, 17, udp)
    )

    modbus = bytes([0, 1, 0, 0, 0, 6, 7, 3, 0, 0, 0, 1])
    tcp = bytearray(struct.pack("!HHIIHHHH", 40000, 502, 1, 0, 0x5018, 4096, 0, 0) + modbus)
    pseudo_header = client + server + struct.pack("!BBH", 0, 6, len(tcp))
    tcp[16:18] = struct.pack("!H", internet_checksum(pseudo_header + tcp))
    gateway_frame = ethernet_frame(
        bytes.fromhex("020000000002"), ipv4_packet(client, server, 6, tcp)
    )

    with args.output.open("wb") as output:
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for timestamp, frame in [(100, broadcast_frame), (101, gateway_frame)]:
            output.write(struct.pack("<IIII", timestamp, 0, len(frame), len(frame)))
            output.write(frame)


if __name__ == "__main__":
    main()
