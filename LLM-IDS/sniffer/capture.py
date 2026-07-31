"""Live packet capture using Scapy. Feeds every IP packet into a FlowTracker.

Note: capturing raw packets requires elevated privileges — run with sudo on
Linux/macOS, or as Administrator on Windows (with Npcap installed).
"""

from typing import Optional

from scapy.all import sniff, IP, TCP, UDP

from sniffer.flow_tracker import FlowTracker


def _tcp_flags_str(tcp_layer) -> str:
    """Scapy exposes TCP flags as a FlagValue object; this gives a short
    string like 'S', 'SA', 'FA', matching what flow_tracker expects.
    """
    return str(tcp_layer.flags)


class PacketSniffer:
    """Wraps scapy.sniff() and pushes each captured packet into a FlowTracker."""

    def __init__(self, flow_tracker: FlowTracker, interface: Optional[str] = None):
        self.flow_tracker = flow_tracker
        self.interface = interface

    def _handle_packet(self, packet):
        if IP not in packet:
            return  # skip non-IP traffic (ARP, etc.)

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        size = len(packet)

        if TCP in packet:
            tcp = packet[TCP]
            self.flow_tracker.add_packet(
                src_ip, dst_ip, tcp.sport, tcp.dport, "TCP", size, _tcp_flags_str(tcp)
            )
        elif UDP in packet:
            udp = packet[UDP]
            self.flow_tracker.add_packet(src_ip, dst_ip, udp.sport, udp.dport, "UDP", size)
        else:
            # ICMP and anything else without ports — keep the protocol number
            # so it still shows up as its own flow type.
            self.flow_tracker.add_packet(src_ip, dst_ip, 0, 0, f"PROTO-{ip_layer.proto}", size)

    def start(self):
        """Blocking call — run this in its own thread (see main.py)."""
        sniff(iface=self.interface, prn=self._handle_packet, store=False)