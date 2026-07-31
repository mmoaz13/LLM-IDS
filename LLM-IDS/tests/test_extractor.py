"""
=============================================================================
test_extractor.py — Test suite for features/extractor.py
=============================================================================

Coverage areas
--------------
  1. Statistics computation     (packet/byte counts, averages, direction split)
  2. Packets-per-second guard   (short/single-packet flows must not spike pps)
  3. Protocol info passthrough  (5-tuple fields land in the output unchanged)
  4. TCP flag counting          (per-flag totals, syn_without_ack heuristic)
  5. Flow ID formatting

Run
---
    pytest tests/test_extractor.py -v

Requirements
------------
    pip install pytest
    (No network access, no root privileges, no Ollama needed.)
"""

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sniffer.flow_tracker import Flow, PacketRecord
from features.extractor import compute_features

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_flow(packets, start_time=1000.0, last_seen=None, protocol="TCP",
                key=("10.0.0.1", "10.0.0.2", 5000, 80, "TCP")):
    if last_seen is None:
        last_seen = start_time + (packets[-1].timestamp - packets[0].timestamp if packets else 0)
    return Flow(key=key, start_time=start_time, last_seen=last_seen, packets=packets)


def _pkt(t, size=100, direction="fwd", flags=""):
    return PacketRecord(timestamp=t, size=size, direction=direction, tcp_flags=flags)


# ===========================================================================
# 1. Statistics computation
# ===========================================================================

class TestStatistics:

    def test_packet_and_byte_counts(self):
        packets = [_pkt(1000.0, size=100), _pkt(1000.1, size=200), _pkt(1000.2, size=300)]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.2)
        features = compute_features(flow)
        assert features["statistics"]["packet_count"] == 3
        assert features["statistics"]["byte_count"] == 600

    def test_avg_packet_size(self):
        packets = [_pkt(1000.0, size=100), _pkt(1000.1, size=300)]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.1)
        features = compute_features(flow)
        assert features["statistics"]["avg_packet_size"] == 200.0

    def test_avg_packet_size_zero_when_no_packets(self):
        flow = _make_flow([], start_time=1000.0, last_seen=1000.0)
        features = compute_features(flow)
        assert features["statistics"]["avg_packet_size"] == 0

    def test_fwd_and_rev_counts_split_correctly(self):
        packets = [
            _pkt(1000.0, direction="fwd"),
            _pkt(1000.1, direction="fwd"),
            _pkt(1000.2, direction="rev"),
        ]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.2)
        features = compute_features(flow)
        assert features["statistics"]["fwd_packet_count"] == 2
        assert features["statistics"]["rev_packet_count"] == 1

    def test_duration_reflects_start_and_last_seen(self):
        flow = _make_flow([_pkt(1000.0)], start_time=1000.0, last_seen=1002.5)
        features = compute_features(flow)
        assert features["statistics"]["duration_seconds"] == 2.5


# ===========================================================================
# 2. Packets-per-second guard (regression test for the pps-inflation bug)
# ===========================================================================

class TestPacketsPerSecondGuard:

    def test_single_packet_flow_reports_zero_pps(self):
        """A lone packet has start_time == last_seen (duration 0). This must
        not be divided into a huge or undefined rate."""
        flow = _make_flow([_pkt(1000.0)], start_time=1000.0, last_seen=1000.0)
        features = compute_features(flow)
        assert features["statistics"]["packets_per_second"] == 0.0

    def test_very_short_flow_does_not_spike_pps(self):
        """Two packets a few milliseconds apart (e.g. a DNS query/response)
        must not be reported as an extreme packet rate."""
        flow = _make_flow([_pkt(1000.000), _pkt(1000.004)],
                           start_time=1000.000, last_seen=1000.004)
        features = compute_features(flow)
        assert features["statistics"]["packets_per_second"] == 0.0

    def test_sustained_flow_reports_real_pps(self):
        """Once a flow has run long enough for a rate to be meaningful, pps
        must be computed normally."""
        flow = _make_flow([_pkt(1000.0)], start_time=1000.0, last_seen=1001.0)
        # 10 packets over 1 real second -> pps should be computed, not zeroed
        packets = [_pkt(1000.0 + i * 0.1) for i in range(10)]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.9)
        features = compute_features(flow)
        assert features["statistics"]["packets_per_second"] == pytest.approx(10 / 0.9, rel=0.01)

    def test_no_division_by_zero_error(self):
        """Zero-duration flows must not raise, regardless of packet count."""
        packets = [_pkt(1000.0), _pkt(1000.0), _pkt(1000.0)]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.0)
        features = compute_features(flow)  # must not raise ZeroDivisionError
        assert features["statistics"]["packets_per_second"] == 0.0


# ===========================================================================
# 3. Protocol info passthrough
# ===========================================================================

class TestProtocolInfo:

    def test_protocol_info_fields(self):
        flow = _make_flow(
            [_pkt(1000.0)], start_time=1000.0, last_seen=1000.0,
            key=("192.168.1.10", "8.8.8.8", 54321, 53, "UDP"),
        )
        features = compute_features(flow)
        info = features["protocol_info"]
        assert info == {
            "protocol": "UDP",
            "src_ip": "192.168.1.10",
            "dst_ip": "8.8.8.8",
            "src_port": 54321,
            "dst_port": 53,
        }


# ===========================================================================
# 4. TCP flag counting
# ===========================================================================

class TestFlagCounting:

    def test_flag_counts_across_packets(self):
        packets = [
            _pkt(1000.0, flags="S"),
            _pkt(1000.1, flags="SA"),
            _pkt(1000.2, flags="PA"),
            _pkt(1000.3, flags="FA"),
        ]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.3)
        flags = compute_features(flow)["flags"]
        assert flags["syn_count"] == 2
        assert flags["ack_count"] == 3
        assert flags["psh_count"] == 1
        assert flags["fin_count"] == 1
        assert flags["rst_count"] == 0
        assert flags["urg_count"] == 0

    def test_syn_without_ack_true_when_no_ack_seen(self):
        packets = [_pkt(1000.0, flags="S"), _pkt(1000.1, flags="S")]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.1)
        flags = compute_features(flow)["flags"]
        assert flags["syn_without_ack"] is True

    def test_syn_without_ack_false_when_ack_present(self):
        packets = [_pkt(1000.0, flags="S"), _pkt(1000.1, flags="SA")]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.1)
        flags = compute_features(flow)["flags"]
        assert flags["syn_without_ack"] is False

    def test_syn_without_ack_false_when_no_syn_at_all(self):
        packets = [_pkt(1000.0, flags="A")]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.0)
        flags = compute_features(flow)["flags"]
        assert flags["syn_without_ack"] is False

    def test_udp_flow_has_zero_flag_counts(self):
        packets = [_pkt(1000.0, flags=""), _pkt(1000.1, flags="")]
        flow = _make_flow(packets, start_time=1000.0, last_seen=1000.1, protocol="UDP")
        flags = compute_features(flow)["flags"]
        assert all(v == 0 or v is False for v in flags.values())


# ===========================================================================
# 5. Flow ID formatting
# ===========================================================================

class TestFlowId:

    def test_flow_id_format(self):
        flow = _make_flow(
            [_pkt(1000.0)], start_time=1000.0, last_seen=1000.0,
            key=("10.0.0.1", "10.0.0.2", 5000, 80, "TCP"),
        )
        features = compute_features(flow)
        assert features["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"
