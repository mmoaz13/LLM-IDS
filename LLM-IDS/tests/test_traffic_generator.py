"""
=============================================================================
test_traffic_generator.py — Test suite for simulator/traffic_generator.py
=============================================================================

Coverage areas
--------------
  1. SYN flood shape        (single flow, all SYN, no ACKs)
  2. Port scan shape        (single source, many distinct ports, no ACKs)
  3. Benign browsing shape  (balanced, closed connections)
  4. packets_to_pcap_bytes  (round-trips through a real pcap file)
  5. SCENARIOS registry     (every entry is runnable and well-formed)

These exercise the real Scapy packet objects (no mocking) since the whole
point of this module is producing well-formed synthetic packets — but
nothing here ever sends a packet on a real interface.

Run
---
    pytest tests/test_traffic_generator.py -v

Requirements
------------
    pip install pytest scapy
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import IP, TCP, rdpcap

from simulator import traffic_generator as tg

# ===========================================================================
# 1. SYN flood shape
# ===========================================================================

class TestSynFlood:

    def test_default_packet_count(self):
        packets = tg.generate_syn_flood(num_packets=50)
        assert len(packets) == 50

    def test_all_packets_share_one_five_tuple(self):
        """The flood must collapse into a single flow: fixed source IP/port
        and destination IP/port across every packet."""
        packets = tg.generate_syn_flood(num_packets=20)
        five_tuples = {
            (p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport) for p in packets
        }
        assert len(five_tuples) == 1

    def test_every_packet_is_syn_only(self):
        packets = tg.generate_syn_flood(num_packets=20)
        assert all(p[TCP].flags == "S" for p in packets)

    def test_respects_custom_target(self):
        packets = tg.generate_syn_flood(target_ip="1.2.3.4", target_port=443, num_packets=5)
        assert all(p[IP].dst == "1.2.3.4" for p in packets)
        assert all(p[TCP].dport == 443 for p in packets)


# ===========================================================================
# 2. Port scan shape
# ===========================================================================

class TestPortScan:

    def test_default_packet_count(self):
        packets = tg.generate_port_scan(port_count=50)
        assert len(packets) == 50

    def test_single_source_ip(self):
        packets = tg.generate_port_scan(scanner_ip="9.9.9.9", port_count=20)
        assert all(p[IP].src == "9.9.9.9" for p in packets)

    def test_destination_ports_are_distinct(self):
        packets = tg.generate_port_scan(port_count=30)
        dports = [p[TCP].dport for p in packets]
        assert len(set(dports)) == len(dports)

    def test_every_packet_is_syn_only(self):
        packets = tg.generate_port_scan(port_count=10)
        assert all(p[TCP].flags == "S" for p in packets)


# ===========================================================================
# 3. Benign browsing shape
# ===========================================================================

class TestBenignBrowsing:

    def test_produces_six_packets_per_request(self):
        packets = tg.generate_benign_web_browsing(num_requests=3)
        assert len(packets) == 18  # SYN, SYN-ACK, ACK+GET, PSH-ACK+response, FIN-ACK x2

    def test_traffic_flows_both_directions(self):
        packets = tg.generate_benign_web_browsing(
            client_ip="1.1.1.1", server_ip="2.2.2.2", num_requests=1
        )
        srcs = {p[IP].src for p in packets}
        assert srcs == {"1.1.1.1", "2.2.2.2"}

    def test_each_exchange_includes_a_full_handshake_and_close(self):
        packets = tg.generate_benign_web_browsing(num_requests=1)
        flags_seen = [p[TCP].flags for p in packets]
        assert "S" in flags_seen
        assert "SA" in flags_seen
        assert flags_seen.count("FA") == 2  # both sides close cleanly


# ===========================================================================
# 4. packets_to_pcap_bytes
# ===========================================================================

class TestPacketsToPcapBytes:

    def test_round_trips_through_a_real_pcap_file(self, tmp_path):
        packets = [IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
                   for _ in range(3)]
        pcap_bytes = tg.packets_to_pcap_bytes(packets)

        out_file = tmp_path / "roundtrip.pcap"
        out_file.write_bytes(pcap_bytes)
        read_back = rdpcap(str(out_file))

        assert len(read_back) == 3
        assert read_back[0][IP].src == "10.0.0.1"

    def test_returns_nonempty_bytes(self):
        packets = tg.generate_syn_flood(num_packets=5)
        pcap_bytes = tg.packets_to_pcap_bytes(packets)
        assert isinstance(pcap_bytes, bytes)
        assert len(pcap_bytes) > 0

    def test_empty_packet_list_does_not_raise(self):
        pcap_bytes = tg.packets_to_pcap_bytes([])
        assert isinstance(pcap_bytes, bytes)


# ===========================================================================
# 5. SCENARIOS registry
# ===========================================================================

class TestScenariosRegistry:

    def test_every_scenario_has_required_fields(self):
        for key, scenario in tg.SCENARIOS.items():
            assert "label" in scenario
            assert "description" in scenario
            assert callable(scenario["generator"])

    def test_every_scenario_generator_produces_packets(self):
        for key, scenario in tg.SCENARIOS.items():
            packets = scenario["generator"]()
            assert len(packets) > 0, f"{key} produced no packets"

    def test_every_scenario_is_serializable_to_pcap(self):
        for key, scenario in tg.SCENARIOS.items():
            packets = scenario["generator"]()
            pcap_bytes = tg.packets_to_pcap_bytes(packets)
            assert len(pcap_bytes) > 0, f"{key} failed to serialize"
