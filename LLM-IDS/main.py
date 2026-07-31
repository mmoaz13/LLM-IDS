"""Orchestrates the full pipeline: sniff -> track flows -> extract features
-> classify with the local LLM -> store result.

Run this (it needs root/admin to sniff), then run the dashboard separately
in another terminal to watch results come in:
    sudo python3 main.py
    streamlit run dashboard/app.py
"""

import threading
import time

import config
from analyzer.llm_client import LLMClient
from features.extractor import compute_features
from sniffer.capture import PacketSniffer
from sniffer.flow_tracker import FlowTracker
from storage import db


def main():
    db.init_db()
    tracker = FlowTracker(timeout_seconds=config.FLOW_TIMEOUT_SECONDS)
    sniffer = PacketSniffer(tracker, interface=config.NETWORK_INTERFACE)
    llm = LLMClient()

    sniff_thread = threading.Thread(target=sniffer.start, daemon=True)
    sniff_thread.start()
    print(f"Sniffing started on interface: {config.NETWORK_INTERFACE or 'default'}")
    print(f"Using model: {config.OLLAMA_MODEL} via {config.OLLAMA_HOST}")
    print("Waiting for flows to complete... (Ctrl+C to stop)\n")

    try:
        while True:
            time.sleep(config.EXPIRY_CHECK_INTERVAL)
            for flow in tracker.pop_finished_flows():
                features = compute_features(flow)
                verdict = llm.classify(features)
                db.save_result(features, verdict)
                print(f"[{verdict['classification']:>10}] {features['flow_id']} — {verdict['explanation']}")
    except KeyboardInterrupt:
        print("\nStopping.")


if __name__ == "__main__":
    main()