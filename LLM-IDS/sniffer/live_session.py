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
        # Every flow this session has classified, in order — the dashboard
        # shows this directly rather than reading the (globally-persistent,
        # cross-session) database, so the table only ever reflects what this
        # capture actually saw.
        self.results = []

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

    def stop(self, progress_callback=None):
        """Stops the sniffer and the background loop, then classifies
        whatever flows were still in progress (not yet closed or timed out)
        rather than discarding them. Without this, stopping shortly after
        starting would silently drop most of what was just captured — the
        same issue pcap_reader.py had before it gained pop_all_flows().

        progress_callback(done, total), if given, is called once per
        flushed flow so the caller can show progress for what may be a
        slow step (each flow is a real LLM call).
        """
        self._stop_event.set()
        self.sniffer.stop_async()
        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5)
        self._worker_thread = None

        remaining = self.tracker.pop_all_flows()
        for i, flow in enumerate(remaining, start=1):
            self._classify_and_record(flow)
            if progress_callback:
                progress_callback(i, len(remaining))

    def _classify_loop(self):
        # wait() returns as soon as _stop_event is set, unlike sleep() —
        # so stop() doesn't have to wait out a full expiry_check_interval
        # before it can join this thread.
        while not self._stop_event.wait(timeout=self.expiry_check_interval):
            for flow in self.tracker.pop_finished_flows():
                self._classify_and_record(flow)

    def _classify_and_record(self, flow):
        try:
            features = compute_features(flow)
            verdict = self.llm.classify(features)
            row_id = db.save_result(features, verdict)
            self.results.append({
                # Mirrors the shape of a storage.db row (id + features_json)
                # so report_generator / save_feedback can use this entry
                # directly — the dashboard never has to fall back to a
                # database-wide lookup just to act on a flow it already has.
                "id": row_id,
                "flow_id": features["flow_id"],
                "classification": verdict["classification"],
                "confidence": round(verdict["confidence"], 2),
                "explanation": verdict["explanation"],
                "features_json": features,
            })
            self.flows_classified += 1
        except Exception as exc:
            # Keep the loop alive on a single bad flow — an IDS that
            # stops watching traffic because one classification blew
            # up is worse than one that logs and keeps going.
            self.last_error = str(exc)
