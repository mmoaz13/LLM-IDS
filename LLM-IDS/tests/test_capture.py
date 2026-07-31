"""
=============================================================================
test_capture.py — Test suite for sniffer/capture.py
=============================================================================

Coverage areas
--------------
  1. list_interfaces()        (shape, sorting — machine-dependent contents)
  2. PacketSniffer packet routing (TCP/UDP/other/non-IP -> FlowTracker calls)
  3. start_async() success path  (started_callback fires -> returns cleanly)
  4. start_async() failure path  (socket-open exception -> raised to caller,
                                   nothing left half-started)
  5. stop_async()

AsyncSniffer itself is mocked throughout — these tests don't touch a real
network interface or require any privileges.

Run
---
    pytest tests/test_capture.py -v
"""

import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.all import IP, TCP, UDP

from sniffer.capture import PacketSniffer, list_interfaces
from sniffer.flow_tracker import FlowTracker

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeAsyncSniffer:
    """Stands in for scapy.all.AsyncSniffer. `outcome` controls what start()
    simulates: 'success' fires started_callback, 'permission_error' mimics a
    socket-open failure (exception set, started_callback never called,
    thread dies immediately), 'silent_failure' mimics the thread dying
    without setting .exception (defensive fallback path)."""

    def __init__(self, iface=None, prn=None, store=None, started_callback=None, outcome="success"):
        self.iface = iface
        self.prn = prn
        self.running = False
        self.thread = None
        self.exception = None
        self._started_callback = started_callback
        self._outcome = outcome

    def start(self):
        if self._outcome == "permission_error":
            self.exception = PermissionError("Operation not permitted")
            self.thread = threading.Thread(target=lambda: None)
            self.thread.start()
            self.thread.join()
            self.running = False
            return
        if self._outcome == "silent_failure":
            self.thread = threading.Thread(target=lambda: None)
            self.thread.start()
            self.thread.join()
            self.running = False
            return
        # success
        self.running = True
        self.thread = threading.Thread(target=lambda: None)
        self.thread.start()
        if self._started_callback:
            self._started_callback()

    def stop(self):
        self.running = False


# ===========================================================================
# 1. list_interfaces()
# ===========================================================================

class TestListInterfaces:

    def test_returns_a_list(self):
        entries = list_interfaces()
        assert isinstance(entries, list)

    def test_entries_have_expected_shape(self):
        entries = list_interfaces()
        for entry in entries:
            assert set(entry.keys()) == {"label", "name", "iface"}
            assert isinstance(entry["label"], str)
            assert isinstance(entry["name"], str)

    def test_entries_are_sorted_by_label(self):
        entries = list_interfaces()
        labels = [e["label"].lower() for e in entries]
        assert labels == sorted(labels)


# ===========================================================================
# 2. PacketSniffer packet routing
# ===========================================================================

class TestPacketRouting:

    def test_tcp_packet_is_routed_to_tracker(self):
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000, dport=80, flags="S")
        sniffer._handle_packet(pkt)
        assert tracker.active_flow_count() == 1

    def test_udp_packet_is_routed_to_tracker(self):
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=6000, dport=53)
        sniffer._handle_packet(pkt)
        assert tracker.active_flow_count() == 1

    def test_non_ip_packet_is_skipped(self):
        from scapy.all import ARP, Ether
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker)
        sniffer._handle_packet(Ether() / ARP())
        assert tracker.active_flow_count() == 0

    def test_packet_count_increments_for_every_packet_including_skipped(self):
        from scapy.all import ARP, Ether
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker)
        sniffer._handle_packet(Ether() / ARP())  # skipped, but still "seen"
        sniffer._handle_packet(IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1, dport=2, flags="S"))
        assert sniffer.packet_count == 2


# ===========================================================================
# 3. start_async() success path
# ===========================================================================

class TestStartAsyncSuccess:

    @patch("sniffer.capture.AsyncSniffer")
    def test_returns_without_raising_when_started_callback_fires(self, mock_cls):
        mock_cls.side_effect = lambda **kwargs: FakeAsyncSniffer(outcome="success", **kwargs)
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker, interface="eth0")
        sniffer.start_async(ready_timeout=1)  # must not raise
        assert sniffer._async_sniffer is not None
        assert sniffer._async_sniffer.running is True


# ===========================================================================
# 4. start_async() failure path
# ===========================================================================

class TestStartAsyncFailure:

    @patch("sniffer.capture.AsyncSniffer")
    def test_permission_error_is_raised_to_caller(self, mock_cls):
        mock_cls.side_effect = lambda **kwargs: FakeAsyncSniffer(outcome="permission_error", **kwargs)
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker, interface="eth0")
        with pytest.raises(PermissionError):
            sniffer.start_async(ready_timeout=1)

    @patch("sniffer.capture.AsyncSniffer")
    def test_silent_failure_raises_runtime_error(self, mock_cls):
        """Thread dies without setting .exception and without calling
        started_callback — the defensive fallback must still surface an
        error rather than reporting success."""
        mock_cls.side_effect = lambda **kwargs: FakeAsyncSniffer(outcome="silent_failure", **kwargs)
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker, interface="eth0")
        with pytest.raises(RuntimeError):
            sniffer.start_async(ready_timeout=1)


# ===========================================================================
# 5. stop_async()
# ===========================================================================

class TestStopAsync:

    def test_stop_async_without_prior_start_does_not_raise(self):
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker)
        sniffer.stop_async()  # must not raise

    @patch("sniffer.capture.AsyncSniffer")
    def test_stop_async_calls_stop_on_the_underlying_sniffer(self, mock_cls):
        mock_cls.side_effect = lambda **kwargs: FakeAsyncSniffer(outcome="success", **kwargs)
        tracker = FlowTracker(timeout_seconds=60)
        sniffer = PacketSniffer(tracker, interface="eth0")
        sniffer.start_async(ready_timeout=1)
        underlying = sniffer._async_sniffer
        sniffer.stop_async()
        assert underlying.running is False
        assert sniffer._async_sniffer is None
