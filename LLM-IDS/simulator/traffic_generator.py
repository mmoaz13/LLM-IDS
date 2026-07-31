"""Builds synthetic packet sequences for common traffic patterns (SYN flood,
port scan, benign browsing) so the IDS can be demoed and tested without a
real network, live capture, or admin/root privileges.

Important: this module only *constructs* Scapy Packet objects in memory and
serializes them to .pcap bytes/files. Nothing here ever calls send(),
sendp(), or sr() — no packets are transmitted on any interface. The output
is consumed entirely offline through the existing Upload PCAP pipeline
(sniffer/pcap_reader.py), exactly like a capture file a user uploaded
themselves.
"""

import os
import random
import tempfile
import time

from scapy.all import IP, TCP, Raw, wrpcap

# Private/documentation-reserved address ranges only, so anything a user
# opens in Wireshark or greps out of a generated pcap is obviously fake
# demo data rather than a real host.
_ATTACKER_NET = "203.0.113"     # TEST-NET-3 (RFC 5737)
_SCANNER_NET = "198.51.100"     # TEST-NET-2 (RFC 5737)
_TARGET_IP = "192.0.2.10"       # TEST-NET-1 (RFC 5737)
_CLIENT_IP = "192.0.2.50"
_SERVER_IP = "203.0.113.200"


def _stamped(pkt, ts):
    pkt.time = ts
    return pkt


def generate_syn_flood(attacker_ip: str = _ATTACKER_NET + ".77", target_ip: str = _TARGET_IP,
                        target_port: int = 80, num_packets: int = 200) -> list:
    """Many SYNs hammering one destination port from a single fixed 5-tuple,
    with no completed handshakes — this collapses into ONE flow with an
    extreme packet count, zero ACKs, and syn_without_ack=True: a clean
    per-flow flood signature. (A real flood often spreads across randomized
    source IPs, but this IDS classifies flow-by-flow, so a single-flow flood
    is what a per-flow detector can actually see and flag.)"""
    base_time = time.time()
    sport = random.randint(1024, 65535)
    packets = []
    for i in range(num_packets):
        pkt = IP(src=attacker_ip, dst=target_ip) / TCP(
            sport=sport, dport=target_port, flags="S", seq=random.randint(0, 2**32 - 1)
        )
        packets.append(_stamped(pkt, base_time + i * 0.002))
    return packets


def generate_port_scan(scanner_ip: str = _SCANNER_NET + ".77", target_ip: str = _TARGET_IP,
                        port_count: int = 200) -> list:
    """One source IP sweeping many destination ports with a single SYN each
    and no completed handshakes — a textbook recon signature. Note this
    necessarily produces one flow *per port* (a 5-tuple flow can't span
    multiple destination ports) — the flood-like pattern only becomes
    visible when you look across flows sharing this source IP, which is
    exactly what per-flow classification structurally can't do. The
    dashboard's Simulate tab groups results by source IP afterward so you
    can see that aggregate picture even though each flow was judged alone."""
    base_time = time.time()
    packets = []
    ports = random.sample(range(1, 65535), port_count)
    for i, port in enumerate(ports):
        sport = random.randint(1024, 65535)
        pkt = IP(src=scanner_ip, dst=target_ip) / TCP(
            sport=sport, dport=port, flags="S", seq=random.randint(0, 2**32 - 1)
        )
        packets.append(_stamped(pkt, base_time + i * 0.01))
    return packets


def generate_benign_web_browsing(client_ip: str = _CLIENT_IP, server_ip: str = _SERVER_IP,
                                  server_port: int = 443, num_requests: int = 5) -> list:
    """A handful of normal-looking request/response exchanges: full
    handshake, balanced traffic in both directions, clean FIN close on each —
    should classify as Benign, useful as a contrast case."""
    base_time = time.time()
    t = base_time
    packets = []
    for i in range(num_requests):
        sport = 40000 + i
        seq_c = random.randint(0, 2**32 - 1)
        seq_s = random.randint(0, 2**32 - 1)

        packets.append(_stamped(
            IP(src=client_ip, dst=server_ip) / TCP(sport=sport, dport=server_port, flags="S", seq=seq_c), t))
        t += 0.02
        packets.append(_stamped(
            IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1), t))
        t += 0.02
        packets.append(_stamped(
            IP(src=client_ip, dst=server_ip) / TCP(
                sport=sport, dport=server_port, flags="A", seq=seq_c + 1, ack=seq_s + 1)
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example\r\n\r\n"), t))
        t += 0.05
        packets.append(_stamped(
            IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 40)
            / Raw(load=b"HTTP/1.1 200 OK\r\n\r\n<html>ok</html>"), t))
        t += 0.03
        packets.append(_stamped(
            IP(src=client_ip, dst=server_ip) / TCP(
                sport=sport, dport=server_port, flags="FA", seq=seq_c + 40, ack=seq_s + 40), t))
        t += 0.01
        packets.append(_stamped(
            IP(src=server_ip, dst=client_ip) / TCP(
                sport=server_port, dport=sport, flags="FA", seq=seq_s + 40, ack=seq_c + 41), t))
        t += 1.5  # gap before the next "request"
    return packets


SCENARIOS = {
    "syn_flood": {
        "label": "SYN Flood",
        "description": (
            "~200 SYNs hammering one connection (fixed source/destination) in "
            "rapid succession, no ACKs — a single flow with a clean flood "
            "signature."
        ),
        "generator": generate_syn_flood,
    },
    "port_scan": {
        "label": "Port Scan",
        "description": (
            "One source IP sweeping ~200 destination ports with unanswered "
            "SYNs — a reconnaissance signature that only becomes visible "
            "across flows sharing a source IP (see the grouped summary "
            "after analyzing)."
        ),
        "generator": generate_port_scan,
    },
    "benign_browsing": {
        "label": "Benign Web Browsing",
        "description": (
            "A handful of normal HTTPS-style request/response exchanges with "
            "clean handshakes and closes."
        ),
        "generator": generate_benign_web_browsing,
    },
}


def packets_to_pcap_bytes(packets: list) -> bytes:
    """Serialize a list of Scapy packets to .pcap file bytes, entirely
    in-memory from the caller's point of view (a temp file is used
    internally because Scapy's writer wants a real path)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        wrpcap(tmp_path, packets)
        with open(tmp_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp_path)
