"""Turns a raw Flow (a bundle of packets) into the three feature groups from
the architecture diagram: statistics, protocol info, and flags.
"""

from collections import Counter

from sniffer.flow_tracker import Flow


def compute_features(flow: Flow) -> dict:
    duration = flow.last_seen - flow.start_time
    packet_count = len(flow.packets)
    total_bytes = sum(p.size for p in flow.packets)

    fwd_count = sum(1 for p in flow.packets if p.direction == "fwd")
    rev_count = packet_count - fwd_count

    # A flow with only a handful of packets over a near-zero duration isn't
    # actually a "high rate" — there just isn't enough time between packets
    # to divide by. Only compute pps once duration is long enough that the
    # rate is meaningful; otherwise report 0 rather than an inflated number
    # (e.g. a single DNS request/response pair would otherwise show as
    # 1000+ pps and get misread by the LLM as a flood).
    MIN_DURATION_FOR_RATE = 0.05  # seconds
    if duration >= MIN_DURATION_FOR_RATE:
        packets_per_second = round(packet_count / duration, 2)
    else:
        packets_per_second = 0.0

    statistics = {
        "duration_seconds": round(duration, 3),
        "packet_count": packet_count,
        "byte_count": total_bytes,
        "avg_packet_size": round(total_bytes / packet_count, 1) if packet_count else 0,
        "packets_per_second": packets_per_second,
        "fwd_packet_count": fwd_count,
        "rev_packet_count": rev_count,
    }

    protocol_info = {
        "protocol": flow.protocol,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
    }

    flag_counts = Counter()
    for p in flow.packets:
        for ch in p.tcp_flags:
            flag_counts[ch] += 1

    flags = {
        "syn_count": flag_counts.get("S", 0),
        "ack_count": flag_counts.get("A", 0),
        "fin_count": flag_counts.get("F", 0),
        "rst_count": flag_counts.get("R", 0),
        "psh_count": flag_counts.get("P", 0),
        "urg_count": flag_counts.get("U", 0),
        # cheap heuristic, NOT a verdict — just extra context for the LLM
        "syn_without_ack": flag_counts.get("S", 0) > 0 and flag_counts.get("A", 0) == 0,
    }

    return {
        "flow_id": f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}/{flow.protocol}",
        "statistics": statistics,
        "protocol_info": protocol_info,
        "flags": flags,
    }