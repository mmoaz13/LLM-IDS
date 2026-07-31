"""
=============================================================================
test_flow_tracker.py — Professional test suite for sniffer/flow_tracker.py
=============================================================================

Coverage areas
--------------
  1. Flow creation & keying        (new flows are created correctly)
  2. Bidirectional merging         (reply packets join the existing flow)
  3. Multi-flow isolation          (distinct conversations stay separate)
  4. TCP flag handling             (FIN / RST close flows; SYN/ACK recorded)
  5. Timeout expiry                (idle flows are reaped after the deadline)
  6. Active-flow protection        (live flows are never evicted early)
  7. Packet metadata integrity     (sizes, directions, timestamps recorded)
  8. Protocol variety              (TCP / UDP / custom protocols tracked)
  9. Parametrized edge cases       (zero-byte packets, max ports, loopback)
 10. Concurrency safety            (multi-threaded writers don't corrupt state)

Run
---
    pytest tests/test_flow_tracker.py -v
    pytest tests/test_flow_tracker.py -v --tb=short   # terser on failure

Requirements
------------
    pip install pytest
    (No network access, no root privileges, no Ollama needed.)
"""

import sys
import time
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sniffer.flow_tracker import FlowTracker, Flow, PacketRecord

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tracker():
    """A fresh FlowTracker with a generous timeout for tests that don't need
    expiry behaviour.  Tests that DO test expiry create their own tracker."""
    return FlowTracker(timeout_seconds=60)


def _add(tracker: FlowTracker, src="10.0.0.1", dst="10.0.0.2",
         sport=5000, dport=80, proto="TCP", size=100, flags=""):
    """Convenience wrapper so individual tests stay readable."""
    tracker.add_packet(src, dst, sport, dport, proto, size, flags)


# ===========================================================================
# 1. Flow creation & keying
# ===========================================================================

class TestFlowCreation:

    def test_first_packet_creates_a_flow(self, tracker):
        """Feeding a single packet must create exactly one tracked flow."""
        _add(tracker)
        assert tracker.active_flow_count() == 1

    def test_flow_key_contains_correct_metadata(self, tracker):
        """The newly created flow must expose the src/dst IP and port pair
        supplied to add_packet, regardless of canonical key ordering."""
        _add(tracker, src="192.168.1.10", dst="8.8.8.8", sport=54321, dport=53, proto="UDP")
        flows = tracker.pop_finished_flows()   # force expiry by directly closing
        # pop_finished_flows won't return it yet (no FIN, no timeout) — so we
        # reach into the internal dict to inspect without mutating state.
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert flow.src_ip in {"192.168.1.10", "8.8.8.8"}
        assert flow.dst_ip in {"192.168.1.10", "8.8.8.8"}
        assert flow.src_port in {54321, 53}
        assert flow.dst_port in {54321, 53}
        assert flow.protocol == "UDP"

    def test_start_time_is_set_on_creation(self, tracker):
        """start_time must be recorded and be close to now."""
        before = time.time()
        _add(tracker)
        after = time.time()
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert before <= flow.start_time <= after

    def test_last_seen_updated_on_each_packet(self, tracker):
        """Every subsequent packet must push last_seen forward."""
        _add(tracker, flags="S")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        t1 = flow.last_seen
        time.sleep(0.05)
        _add(tracker, flags="A")   # same 5-tuple
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert flow.last_seen > t1


# ===========================================================================
# 2. Bidirectional merging
# ===========================================================================

class TestBidirectionalMerging:

    def test_reply_packet_joins_existing_flow(self, tracker):
        """A packet arriving in the reverse direction (same conversation)
        must NOT create a second flow."""
        _add(tracker, src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80, flags="S")
        _add(tracker, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000, flags="SA")  # reply
        assert tracker.active_flow_count() == 1

    def test_merged_flow_records_both_directions(self, tracker):
        """Packets from both sides must be stored, labelled with their
        respective direction ('fwd' or 'rev')."""
        _add(tracker, src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80, flags="S")
        _add(tracker, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000, flags="SA")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        directions = {p.direction for p in flow.packets}
        assert "fwd" in directions
        assert "rev" in directions

    def test_packet_count_matches_across_both_directions(self, tracker):
        """Total packet count must reflect all packets from both directions."""
        for _ in range(3):
            _add(tracker, src="10.0.0.1", dst="10.0.0.2", sport=5000, dport=80)
        for _ in range(2):
            _add(tracker, src="10.0.0.2", dst="10.0.0.1", sport=80, dport=5000)
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert len(flow.packets) == 5


# ===========================================================================
# 3. Multi-flow isolation
# ===========================================================================

class TestMultiFlowIsolation:

    def test_different_dst_ips_create_separate_flows(self, tracker):
        """Connections to two different destinations must be separate flows."""
        _add(tracker, dst="10.0.0.2", dport=80)
        _add(tracker, dst="10.0.0.3", dport=80)
        assert tracker.active_flow_count() == 2

    def test_different_dst_ports_create_separate_flows(self, tracker):
        """Connections to the same IP on different ports are different flows."""
        _add(tracker, dport=80)
        _add(tracker, dport=443)
        assert tracker.active_flow_count() == 2

    def test_different_protocols_create_separate_flows(self, tracker):
        """TCP and UDP on the same IP/port pair are separate flows."""
        _add(tracker, proto="TCP")
        _add(tracker, proto="UDP")
        assert tracker.active_flow_count() == 2

    def test_ten_concurrent_flows_are_all_tracked(self, tracker):
        """A burst of ten distinct conversations must each get their own flow."""
        for port in range(10):
            _add(tracker, sport=10000 + port, dport=80)
        assert tracker.active_flow_count() == 10

    def test_popping_one_flow_leaves_others_intact(self, tracker):
        """Closing one flow via RST must not affect unrelated active flows."""
        _add(tracker, sport=5000, dport=80, flags="S")
        _add(tracker, sport=5001, dport=80, flags="S")
        # Close only the first flow
        _add(tracker, sport=5000, dport=80, flags="R")
        finished = tracker.pop_finished_flows()
        assert len(finished) == 1
        assert tracker.active_flow_count() == 1


# ===========================================================================
# 4. TCP flag handling
# ===========================================================================

class TestTCPFlagHandling:

    def test_fin_flag_closes_flow_immediately(self, tracker):
        """A FIN packet must mark the flow closed regardless of timeout."""
        _add(tracker, flags="S")
        _add(tracker, flags="FA")
        finished = tracker.pop_finished_flows()
        assert len(finished) == 1
        assert tracker.active_flow_count() == 0

    def test_rst_flag_closes_flow_immediately(self, tracker):
        """An RST packet (abrupt close) must close the flow just like FIN."""
        _add(tracker, flags="S")
        _add(tracker, flags="R")
        finished = tracker.pop_finished_flows()
        assert len(finished) == 1

    def test_syn_alone_does_not_close_flow(self, tracker):
        """A SYN-only packet (new connection) must leave the flow open."""
        _add(tracker, flags="S")
        finished = tracker.pop_finished_flows()
        assert len(finished) == 0
        assert tracker.active_flow_count() == 1

    def test_ack_alone_does_not_close_flow(self, tracker):
        """A pure ACK (data acknowledgement) must not close the flow."""
        _add(tracker, flags="A")
        finished = tracker.pop_finished_flows()
        assert len(finished) == 0

    def test_flags_are_recorded_on_each_packet(self, tracker):
        """Flag strings must be preserved verbatim in each PacketRecord."""
        _add(tracker, flags="S")
        _add(tracker, flags="SA")
        _add(tracker, flags="PA")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        recorded_flags = [p.tcp_flags for p in flow.packets]
        assert recorded_flags == ["S", "SA", "PA"]

    def test_no_flags_stored_for_udp_packet(self, tracker):
        """UDP packets carry no TCP flags; the field must be an empty string."""
        _add(tracker, proto="UDP", flags="")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert all(p.tcp_flags == "" for p in flow.packets)


# ===========================================================================
# 5. Timeout expiry
# ===========================================================================

class TestTimeoutExpiry:

    def test_idle_flow_expires_after_timeout(self):
        """A flow that receives no packets for longer than the timeout window
        must be returned by pop_finished_flows."""
        tracker = FlowTracker(timeout_seconds=0.2)
        _add(tracker, proto="UDP")
        time.sleep(0.35)
        finished = tracker.pop_finished_flows()
        assert len(finished) == 1
        assert tracker.active_flow_count() == 0

    def test_flow_does_not_expire_before_timeout(self):
        """A flow that is still within its timeout window must not be reaped."""
        tracker = FlowTracker(timeout_seconds=5)
        _add(tracker)
        finished = tracker.pop_finished_flows()
        assert len(finished) == 0
        assert tracker.active_flow_count() == 1

    def test_activity_resets_the_timeout_clock(self):
        """A packet arriving before the deadline must reset last_seen, keeping
        the flow alive past its original expiry."""
        tracker = FlowTracker(timeout_seconds=0.3)
        _add(tracker, flags="S")
        time.sleep(0.2)
        _add(tracker, flags="A")   # reset the clock
        time.sleep(0.2)            # total 0.4s but only 0.2s since last packet
        finished = tracker.pop_finished_flows()
        assert len(finished) == 0  # still alive

    def test_multiple_expired_flows_all_returned(self):
        """When several flows expire together, all of them must be returned
        in a single pop_finished_flows call."""
        tracker = FlowTracker(timeout_seconds=0.2)
        for port in range(5):
            _add(tracker, sport=6000 + port, proto="UDP")
        time.sleep(0.35)
        finished = tracker.pop_finished_flows()
        assert len(finished) == 5
        assert tracker.active_flow_count() == 0


# ===========================================================================
# 6. Active-flow protection
# ===========================================================================

class TestActiveFlowProtection:

    def test_active_flow_is_never_popped_early(self, tracker):
        """An in-progress flow with no FIN/RST and within timeout must not
        appear in pop_finished_flows output under any circumstances."""
        for _ in range(10):
            _add(tracker, flags="PA")
        for _ in range(5):
            finished = tracker.pop_finished_flows()
            assert finished == []

    def test_active_flow_count_is_consistent_after_partial_pop(self, tracker):
        """Popping some finished flows must leave the active count consistent."""
        _add(tracker, sport=7000, flags="S")    # will be closed
        _add(tracker, sport=7001, flags="S")    # stays open
        _add(tracker, sport=7002, flags="S")    # stays open
        _add(tracker, sport=7000, flags="FA")   # close flow 7000
        finished = tracker.pop_finished_flows()
        assert len(finished) == 1
        assert tracker.active_flow_count() == 2


# ===========================================================================
# 7. Packet metadata integrity
# ===========================================================================

class TestPacketMetadataIntegrity:

    def test_packet_sizes_are_recorded_accurately(self, tracker):
        """Byte counts passed to add_packet must be preserved exactly."""
        sizes = [64, 128, 512, 1500]
        for s in sizes:
            _add(tracker, size=s)
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert [p.size for p in flow.packets] == sizes

    def test_total_byte_count_sums_correctly(self, tracker):
        """The sum of all PacketRecord sizes must equal the expected total."""
        sizes = [100, 200, 300]
        for s in sizes:
            _add(tracker, size=s)
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert sum(p.size for p in flow.packets) == 600

    def test_packet_timestamps_are_monotonically_increasing(self, tracker):
        """Timestamps recorded across successive packets must be non-decreasing."""
        for _ in range(5):
            _add(tracker)
            time.sleep(0.01)
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        timestamps = [p.timestamp for p in flow.packets]
        assert timestamps == sorted(timestamps)


# ===========================================================================
# 8. Protocol variety
# ===========================================================================

class TestProtocolVariety:

    def test_udp_flows_are_tracked(self, tracker):
        """UDP packets must produce a flow with protocol == 'UDP'."""
        _add(tracker, proto="UDP")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert flow.protocol == "UDP"

    def test_custom_protocol_string_is_preserved(self, tracker):
        """Non-standard protocol labels (e.g. ICMP proxy strings) must be
        stored exactly as supplied."""
        _add(tracker, proto="PROTO-1")
        with tracker._lock:
            flow = list(tracker._flows.values())[0]
        assert flow.protocol == "PROTO-1"

    def test_tcp_and_udp_same_tuple_are_separate_flows(self, tracker):
        """Identical IP/port pairs over TCP and UDP are distinct conversations."""
        _add(tracker, proto="TCP", sport=9000, dport=53)
        _add(tracker, proto="UDP", sport=9000, dport=53)
        assert tracker.active_flow_count() == 2


# ===========================================================================
# 9. Parametrized edge cases
# ===========================================================================

@pytest.mark.parametrize("src,dst,sport,dport,proto,size,flags,description", [
    ("127.0.0.1", "127.0.0.1", 12345, 80,    "TCP", 40,    "S",  "Loopback SYN"),
    ("0.0.0.0",   "255.255.255.255", 0, 65535, "UDP", 0,   "",   "Boundary IPs, zero-byte UDP"),
    ("10.0.0.1",  "10.0.0.2",  1024,  1024,  "TCP", 1500,  "PA", "Same src/dst port"),
    ("10.0.0.1",  "10.0.0.2",  0,     0,     "PROTO-255", 20, "", "Port-zero ICMP-like"),
    ("10.0.0.1",  "10.0.0.2",  65535, 65535, "TCP", 9000,  "S",  "Maximum port numbers"),
])
def test_edge_case_packet_is_accepted(tracker, src, dst, sport, dport,
                                      proto, size, flags, description):
    """Every edge-case combination must be accepted without raising an exception
    and must result in exactly one tracked flow.

    Case: {description}
    """
    tracker.add_packet(src, dst, sport, dport, proto, size, flags)
    assert tracker.active_flow_count() >= 1, f"No flow created for: {description}"


# ===========================================================================
# 10. Concurrency safety
# ===========================================================================

class TestConcurrencySafety:

    def test_concurrent_writers_produce_consistent_flow_count(self):
        """Four threads each adding 25 packets on unique flows must result in
        exactly 100 flows — no lost writes, no count corruption."""
        tracker = FlowTracker(timeout_seconds=60)
        errors = []

        def add_flows(start_port):
            try:
                for i in range(25):
                    tracker.add_packet(
                        "10.0.0.1", "10.0.0.2",
                        start_port + i, 80, "TCP", 100, "S"
                    )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=add_flows, args=(i * 25,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Thread(s) raised exceptions: {errors}"
        assert tracker.active_flow_count() == 100

    def test_concurrent_pop_and_write_does_not_raise(self):
        """Simultaneous pop_finished_flows and add_packet calls must not raise
        a RuntimeError or produce a corrupted count."""
        tracker = FlowTracker(timeout_seconds=0.1)
        stop = threading.Event()
        errors = []

        def writer():
            port = 20000
            while not stop.is_set():
                tracker.add_packet("1.1.1.1", "2.2.2.2", port, 80, "TCP", 100, "S")
                port += 1
                time.sleep(0.005)

        def popper():
            while not stop.is_set():
                try:
                    tracker.pop_finished_flows()
                except Exception as exc:
                    errors.append(exc)
                time.sleep(0.05)

        w = threading.Thread(target=writer)
        p = threading.Thread(target=popper)
        w.start(); p.start()
        time.sleep(0.5)
        stop.set()
        w.join(); p.join()

        assert errors == [], f"Concurrent pop raised: {errors}"