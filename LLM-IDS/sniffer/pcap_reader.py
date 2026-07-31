"""Reads packets from an uploaded .pcap / .pcapng file and feeds them through
the exact same FlowTracker pipeline used for live capture.

The only difference from capture.py is the source: instead of a live
interface, packets come from rdpcap(). Everything downstream is identical.
"""

import os
import tempfile
from typing import Callable, List

from scapy.all import rdpcap, IP, TCP, UDP

from sniffer.flow_tracker import FlowTracker, Flow
from features.extractor import compute_features


def _tcp_flags_str(tcp_layer) -> str:
    return str(tcp_layer.flags)


def process_pcap(
    file_bytes: bytes,
    on_flow_ready: Callable[[dict, dict], None],
    timeout_seconds: float = 15,
    progress_callback: Callable[[int, int], None] = None,
) -> dict:
    """
    Read a pcap file from raw bytes, run every packet through a FlowTracker,
    extract features from completed flows, and call on_flow_ready(features, verdict)
    for each one.

    Parameters
    ----------
    file_bytes       : raw bytes of the uploaded .pcap file
    on_flow_ready    : callback(features_dict) called per finished flow
    timeout_seconds  : idle timeout for flow expiry (same semantics as live capture)
    progress_callback: optional callback(packets_done, total_packets)

    Returns
    -------
    summary dict with total_packets, total_flows, classifications breakdown
    """

    # Write bytes to a temp file so Scapy can read it
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(file_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    finally:
        os.unlink(tmp_path)

    tracker = FlowTracker(timeout_seconds=timeout_seconds)
    total = len(packets)
    summary = {"total_packets": total, "total_flows": 0,
               "Benign": 0, "Suspicious": 0, "Attack": 0}

    for idx, pkt in enumerate(packets):
        if progress_callback:
            progress_callback(idx + 1, total)

        if IP not in pkt:
            continue

        ip = pkt[IP]
        size = len(pkt)

        if TCP in pkt:
            tcp = pkt[TCP]
            tracker.add_packet(ip.src, ip.dst, tcp.sport, tcp.dport,
                               "TCP", size, _tcp_flags_str(tcp))
        elif UDP in pkt:
            udp = pkt[UDP]
            tracker.add_packet(ip.src, ip.dst, udp.sport, udp.dport,
                               "UDP", size)
        else:
            tracker.add_packet(ip.src, ip.dst, 0, 0,
                               f"PROTO-{ip.proto}", size)

    # Force-close every remaining flow (file is finished, no more packets coming).
    # pop_finished_flows() only returns flows that are already closed or timed
    # out relative to *wall-clock* time — since this whole loop runs in a few
    # milliseconds, flows without an explicit FIN/RST (e.g. a scan or flood
    # that never completes a handshake) would never qualify and would be
    # silently dropped. pop_all_flows() drains everything unconditionally,
    # which is correct here because there are no more packets coming.
    for flow in tracker.pop_all_flows():
        features = compute_features(flow)
        on_flow_ready(features)
        summary["total_flows"] += 1

    return summary