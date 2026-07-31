"""A start/stoppable live capture session, for use from the dashboard.

main.py's while-loop (sniff -> track -> classify -> save, forever, until
Ctrl+C) works fine for a CLI process, but the dashboard needs the same
pipeline startable and stoppable on demand from a button click, and able to
report live status back to the UI. This wraps that loop as an object that
can be held in st.session_state and survive across Streamlit reruns.
"""

import threading
import time

import config
from analyzer.llm_client import LLMClient
from features.extractor import compute_features
from sniffer.capture import PacketSniffer
from sniffer.flow_tracker import FlowTracker
from storage import db


class LiveCaptureSession:
    def __init__(self, interface, interface_label: str, llm_client: LLMClient = None,
                 flow_timeout_seconds: float = None, expiry_check_interval: float = None):
        self.interface = interface
        self.interface_label = interface_label
        self.flow_timeout_seconds = flow_timeout_seconds or config.FLOW_TIMEOUT_SECONDS
        self.expiry_check_interval = expiry_check_interval or config.EXPIRY_CHECK_INTERVAL
        self.llm = llm_client or LLMClient()

        self.tracker = FlowTracker(timeout_seconds=self.flow_timeout_seconds)
        self.sniffer = PacketSniffer(self.tracker, interface=interface)

        self._stop_event = threading.Event()
        self._worker_thread = None
        self.started_at = None
        self.flows_classified = 0
        self.last_error = None

    @property
    def running(self) -> bool:
        return self._worker_thread is not None and self._worker_thread.is_alive()

    @property
    def packets_seen(self) -> int:
        return self.sniffer.packet_count

    @property
    def active_flow_count(self) -> int:
        return self.tracker.active_flow_count()

    def start(self):
        """Starts the sniffer and the classify/save loop. Raises if the
        sniffer itself fails to start (e.g. insufficient privileges) —
        nothing is left running in that case."""
        if self.running:
            return
        self._stop_event.clear()
        self.sniffer.start_async()  # raises on failure; nothing else started yet
        self.started_at = time.time()
        self._worker_thread = threading.Thread(target=self._classify_loop, daemon=True)
        self._worker_thread.start()

    def stop(self):
        self._stop_event.set()
        self.sniffer.stop_async()
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5)
        self._worker_thread = None

    def _classify_loop(self):
        while not self._stop_event.is_set():
            time.sleep(self.expiry_check_interval)
            for flow in self.tracker.pop_finished_flows():
                try:
                    features = compute_features(flow)
                    verdict = self.llm.classify(features)
                    db.save_result(features, verdict)
                    self.flows_classified += 1
                except Exception as exc:
                    # Keep the loop alive on a single bad flow — an IDS that
                    # stops watching traffic because one classification blew
                    # up is worse than one that logs and keeps going.
                    self.last_error = str(exc)
