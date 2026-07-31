"""Groups raw packets into flows keyed by the 5-tuple, and tracks when a flow
should be considered finished (timeout of inactivity, or an explicit TCP
FIN/RST close).
"""

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Tuple

FlowKey = Tuple[str, str, int, int, str]  # (ip_a, ip_b, port_a, port_b, protocol)


@dataclass
class PacketRecord:
    timestamp: float
    size: int
    direction: str        # "fwd" (first-seen direction) or "rev" (reply direction)
    tcp_flags: str = ""   # e.g. "S", "SA", "PA", "FA" ...


@dataclass
class Flow:
    key: FlowKey
    start_time: float
    last_seen: float
    packets: List[PacketRecord] = field(default_factory=list)
    closed: bool = False  # True once we've seen a FIN or RST

    @property
    def src_ip(self) -> str:
        return self.key[0]

    @property
    def dst_ip(self) -> str:
        return self.key[1]

    @property
    def src_port(self) -> int:
        return self.key[2]

    @property
    def dst_port(self) -> int:
        return self.key[3]

    @property
    def protocol(self) -> str:
        return self.key[4]


class FlowTracker:
    """Thread-safe store of in-progress flows.

    Packets are fed in one at a time via add_packet(); a separate loop (in
    main.py) periodically calls pop_finished_flows() to collect anything
    that's closed or gone idle, so it can be handed off to feature
    extraction.
    """

    def __init__(self, timeout_seconds: float = 15):
        self.timeout_seconds = timeout_seconds
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = Lock()

    @staticmethod
    def _make_key(src_ip, dst_ip, src_port, dst_port, protocol) -> Tuple[FlowKey, str]:
        """Canonicalize so both directions of one conversation map to the
        same flow key, and report which direction this packet travelled.
        """
        forward = (src_ip, dst_ip, src_port, dst_port, protocol)
        reverse = (dst_ip, src_ip, dst_port, src_port, protocol)
        if forward <= reverse:
            return forward, "fwd"
        return reverse, "rev"

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, protocol, size, tcp_flags=""):
        key, direction = self._make_key(src_ip, dst_ip, src_port, dst_port, protocol)
        now = time.time()
        with self._lock:
            flow = self._flows.get(key)
            if flow is None:
                flow = Flow(key=key, start_time=now, last_seen=now)
                self._flows[key] = flow
            flow.last_seen = now
            flow.packets.append(
                PacketRecord(timestamp=now, size=size, direction=direction, tcp_flags=tcp_flags)
            )
            if "F" in tcp_flags or "R" in tcp_flags:
                flow.closed = True

    def pop_finished_flows(self) -> List[Flow]:
        """Remove and return every flow that is closed or has timed out."""
        now = time.time()
        finished = []
        with self._lock:
            for key in list(self._flows.keys()):
                flow = self._flows[key]
                if flow.closed or (now - flow.last_seen) > self.timeout_seconds:
                    finished.append(self._flows.pop(key))
        return finished

    def active_flow_count(self) -> int:
        with self._lock:
            return len(self._flows)