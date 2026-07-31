"""
=============================================================================
test_pcap_reader.py — Test suite for sniffer/pcap_reader.py
=============================================================================

Coverage areas
--------------
  1. End-of-file flushing   (regression test: flows that never close via
                              FIN/RST must still be returned — this is the
                              bug pop_all_flows() was added to fix)
  2. Multi-flow handling    (distinct 5-tuples all counted)
  3. Non-IP packets         (ARP etc. skipped without error)
  4. Progress reporting     (callback invoked with correct totals)

Uses real Scapy packets, written to a real temp .pcap file and read back —
this is an integration test of the actual file format round trip, not a
mocked one.

Run
---
    pytest tests/test_pcap_reader.py -v

Requirements
------------
    pip install pytest scapy
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import ARP, Ether, IP, TCP, UDP

from simulator.traffic_generator import packets_to_pcap_bytes
from sniffer.pcap_reader import process_pcap


# ===========================================================================
# 1. End-of-file flushing (regression test)
# ===========================================================================

class TestEndOfFileFlushing:

    def test_flow_without_fin_or_rst_is_still_returned(self):
        """A flow made only of SYNs (never closed, never times out in real
        wall-clock time during the fast in-process read) must still show up
        once the file is exhausted. Before pop_all_flows() existed, this
        flow would be silently dropped."""
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S"),
        ]
        seen = []
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=seen.append)

        assert summary["total_flows"] == 1
        assert len(seen) == 1
        assert seen[0]["statistics"]["packet_count"] == 2

    def test_flow_closed_by_fin_is_returned(self):
        """Sanity check: the normal close path still works after the change."""
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S"),
            IP(src="10.0.0.2", dst="10.0.0.1") / TCP(sport=80, dport=5000, flags="SA"),
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="FA"),
        ]
        seen = []
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=seen.append)
        assert summary["total_flows"] == 1
        assert len(seen) == 1


# ===========================================================================
# 2. Multi-flow handling
# ===========================================================================

class TestMultiFlowHandling:

    def test_distinct_five_tuples_all_counted(self):
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="10.0.0.3") / TCP(sport=5001, dport=80, flags="S"),
            IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=6000, dport=53),
        ]
        seen = []
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=seen.append)
        assert summary["total_flows"] == 3
        assert len(seen) == 3

    def test_total_packets_reported_in_summary(self):
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S")
                   for _ in range(7)]
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=lambda f: None)
        assert summary["total_packets"] == 7


# ===========================================================================
# 3. Non-IP packets
# ===========================================================================

class TestNonIpPackets:

    def test_arp_packets_are_skipped_without_error(self):
        # Both packets must share a link-layer type (Ethernet here) or Scapy's
        # pcap writer silently mangles whichever one doesn't match.
        packets = [
            Ether() / ARP(),
            Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S"),
        ]
        seen = []
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=seen.append)
        assert summary["total_flows"] == 1  # only the IP packet produced a flow
        assert summary["total_packets"] == 2  # but both packets were counted


# ===========================================================================
# 4. Progress reporting
# ===========================================================================

class TestProgressReporting:

    def test_progress_callback_receives_correct_totals(self):
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S")
                   for _ in range(4)]
        calls = []
        process_pcap(
            packets_to_pcap_bytes(packets),
            on_flow_ready=lambda f: None,
            progress_callback=lambda done, total: calls.append((done, total)),
        )
        assert calls == [(1, 4), (2, 4), (3, 4), (4, 4)]

    def test_no_progress_callback_required(self):
        """progress_callback is optional — omitting it must not raise."""
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S")]
        summary = process_pcap(packets_to_pcap_bytes(packets), on_flow_ready=lambda f: None)
        assert summary["total_packets"] == 1
