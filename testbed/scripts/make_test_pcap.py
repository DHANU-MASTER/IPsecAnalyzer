#!/usr/bin/env python3
"""Generate a realistic IPsec capture (IKE + ESP) without external libraries.

Usage:
    python make_test_pcap.py [-o output.pcap] [--esp-packets N] [--mode tunnel|transport]

The produced file contains a short IKEv2 negotiation (UDP 500) followed by an
ESP (protocol 50) data phase, with plausible packet sizes and inter-arrival
times. It is intended for exercising the analyzer's feature extraction,
classification and scoring pipeline (and for automated tests).
"""

import argparse
import random
import struct
import time

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    dst = b"\x00\x11\x22\x33\x44\x55"
    src = b"\x66\x77\x88\x99\xaa\xbb"
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, src: str, dst: str, protocol: int, ttl: int = 64) -> bytes:
    total_length = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,               # version 4, header length 5 words
        0,                  # DSCP/ECN
        total_length,
        random.randint(0, 0xFFFF),  # identification
        0,                  # flags/fragment offset
        ttl,
        protocol,
        0,                  # checksum (not validated by the analyzer)
        bytes(map(int, src.split("."))),
        bytes(map(int, dst.split("."))),
    )
    return header + payload


def udp(payload: bytes, sport: int, dport: int) -> bytes:
    length = 8 + len(payload)
    return struct.pack("!HHHH", sport, dport, length, 0) + payload


def ike_header(initiator_spi: bytes, responder_spi: bytes, exchange_type: int,
               flags: int, message_id: int, length: int) -> bytes:
    return (
        initiator_spi
        + responder_spi
        + struct.pack("!BBBB", 0x21, 0x20, exchange_type, flags)  # IKEv2 major 2
        + struct.pack("!I", message_id)
        + struct.pack("!I", length)
    )


def build_packets(esp_packets: int, mode: str, seed: int):
    """Returns a list of (timestamp_seconds, raw_packet_bytes)."""
    random.seed(seed)
    packets = []
    t = time.time() - 120
    client, server = "10.0.1.2", "10.0.1.3"

    init_spi = bytes.fromhex("0f1e2d3c4b5a6978")
    resp_spi = bytes.fromhex("88796a5b4c3d2e1f")

    # --- IKE_SA_INIT (request/response) ---
    for i, (src, dst, sport, dport, flags) in enumerate([
        (client, server, 500, 500, 0x08),
        (server, client, 500, 500, 0x20),
    ]):
        payload = bytes(random.getrandbits(8) for _ in range(260))
        body = ike_header(init_spi, b"\x00" * 8 if i == 0 else resp_spi,
                          34, flags, 0, 28 + len(payload)) + payload
        pkt = ethernet(ipv4(udp(body, sport, dport), src, dst, 17))
        packets.append((t, pkt))
        t += 0.002

    # --- IKE_AUTH (request/response, encrypted in reality) ---
    for i, (src, dst, sport, dport, flags) in enumerate([
        (client, server, 500, 500, 0x08),
        (server, client, 500, 500, 0x20),
    ]):
        payload = bytes(random.getrandbits(8) for _ in range(380))
        body = ike_header(init_spi, resp_spi, 35, flags, 1, 28 + len(payload)) + payload
        pkt = ethernet(ipv4(udp(body, sport, dport), src, dst, 17))
        packets.append((t, pkt))
        t += 0.004

    # --- ESP data phase ---
    # Tunnel mode: ESP wraps the whole inner packet. Transport mode: smaller.
    inner_overhead = 14 + 20 + 8 if mode == "transport" else 0
    for i in range(esp_packets):
        # Mixed traffic: ACKs, small requests, bulk transfers
        roll = random.random()
        if roll < 0.45:
            inner = random.randint(40, 120)
        elif roll < 0.85:
            inner = random.randint(300, 800)
        else:
            inner = random.randint(1100, 1400)

        esp_payload = bytes(random.getrandbits(8) for _ in range(inner))
        esp = struct.pack("!II", 0x0000BEEF, i + 1) + esp_payload + b"\x00" * 12
        pkt = ethernet(ipv4(esp, client, server, 50))
        packets.append((t, pkt))

        # Inter-arrival: bursts of chatty traffic with occasional gaps
        t += random.choice([0.002, 0.004, 0.008, 0.015, 0.030, 0.090, 0.400])

    return packets


def write_pcap(path: str, packets):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535,
                                 LINKTYPE_ETHERNET))
        for timestamp, raw in packets:
            seconds = int(timestamp)
            micros = int((timestamp - seconds) * 1_000_000)
            handle.write(struct.pack("<IIII", seconds, micros, len(raw), len(raw)))
            handle.write(raw)


def main():
    parser = argparse.ArgumentParser(description="Generate a synthetic IPsec pcap")
    parser.add_argument("-o", "--output", default="ipsec_sample.pcap")
    parser.add_argument("--esp-packets", type=int, default=60)
    parser.add_argument("--mode", choices=["tunnel", "transport"], default="tunnel")
    parser.add_argument("--seed", type=int, default=2026)
    args = parser.parse_args()

    packets = build_packets(args.esp_packets, args.mode, args.seed)
    write_pcap(args.output, packets)

    # Ethernet is 14 bytes and the IPv4 protocol field sits 9 bytes into the
    # IP header; the UDP destination port follows 14 + 20 + 2 bytes.
    ike = sum(1 for _, raw in packets if raw[23] == 17 and raw[36:38] in (b"\x01\xf4", b"\x11\x94"))
    esp = sum(1 for _, raw in packets if raw[23] == 50)
    duration = packets[-1][0] - packets[0][0]
    print(f"wrote {args.output}: {len(packets)} packets "
          f"(IKE={ike}, ESP={esp}, duration={duration:.2f}s, mode={args.mode})")


if __name__ == "__main__":
    main()
