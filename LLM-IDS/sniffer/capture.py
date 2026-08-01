"""Live packet capture using Scapy. Feeds every IP packet into a FlowTracker.

Note: capturing raw packets requires elevated privileges — run with sudo on
Linux/macOS, or as Administrator on Windows (with Npcap installed).
"""

import threading
from typing import Optional

from scapy.all import IFACES, AsyncSniffer, sniff, IP, TCP, UDP

from sniffer.flow_tracker import FlowTracker


def _tcp_flags_str(tcp_layer) -> str:
    """Scapy exposes TCP flags as a FlagValue object; this gives a short
    string like 'S', 'SA', 'FA', matching what flow_tracker expects.
    """
    return str(tcp_layer.flags)


def list_interfaces() -> list:
    """Friendly, sorted (label, iface) entries for every network interface
    Scapy can see. `iface` is the actual object Scapy's iface= parameter
    expects — passing the object (rather than converting it to a name
    string) sidesteps the \\Device\\NPF_{GUID} formatting Windows requires,
    since Scapy resolves the object directly.
    """
    entries = []
    for iface in IFACES.values():
        name = getattr(iface, "name", None) or str(iface)
        description = getattr(iface, "description", None) or name
        entries.append({"label": description, "name": name, "iface": iface})
    entries.sort(key=lambda e: e["label"].lower())
    return entries


class PacketSniffer:
    """Wraps Scapy's sniffing into a FlowTracker feed, in either blocking
    (start) or background-thread (start_async/stop_async) mode."""

    def __init__(self, flow_tracker: FlowTracker, interface: Optional[str] = None):
        self.flow_tracker = flow_tracker
        self.interface = interface
        self.packet_count = 0
        self._async_sniffer = None
        self._last_sniff_error = None

    @property
    def sniff_error(self):
        """The exception that killed the background sniff thread, if any —
        e.g. the adapter was unplugged mid-capture. Live while capturing
        (callers can poll this during capture, not just after stopping),
        and still readable afterward even though stop_async() discards the
        underlying AsyncSniffer object."""
        if self._async_sniffer is not None and self._async_sniffer.exception is not None:
            self._last_sniff_error = self._async_sniffer.exception
        return self._last_sniff_error

    def _handle_packet(self, packet):
        self.packet_count += 1

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

    def start_async(self, ready_timeout: float = 5.0):
        """Non-blocking: starts capture in a background thread and returns
        only once capture has actually begun — or raises if it failed to
        (e.g. missing admin/root privileges), rather than leaving the
        caller to discover a silently-dead thread later. Used by the
        dashboard's Live Capture tab.
        """
        started_event = threading.Event()
        self._async_sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._handle_packet,
            store=False,
            started_callback=started_event.set,
        )
        self._async_sniffer.start()

        started_event.wait(timeout=ready_timeout)
        thread_alive = (
            self._async_sniffer.thread is not None
            and self._async_sniffer.thread.is_alive()
        )

        # Scapy opens the raw socket before invoking started_callback, so a
        # permission/adapter failure raises inside the sniff thread and
        # lands here as .exception, before started_callback ever fires.
        if self._async_sniffer.exception is not None:
            raise self._async_sniffer.exception
        if not started_event.is_set() and not thread_alive:
            raise RuntimeError(
                "Packet capture failed to start. This usually means the "
                "process needs admin/root privileges, or (Windows) Npcap "
                "isn't installed."
            )

    def stop_async(self):
        if self._async_sniffer is None:
            return
        _ = self.sniff_error  # snapshot into _last_sniff_error before it's discarded
        try:
            if self._async_sniffer.running:
                self._async_sniffer.stop()
        except Exception as exc:
            # stop() itself re-raises a stored sniff-thread exception in
            # some cases — don't let that escape stop_async() (callers
            # expect stopping to always succeed), but don't discard it
            # either, unlike before.
            self._last_sniff_error = self._last_sniff_error or exc
        _ = self.sniff_error  # stop() may have surfaced a new one too
        self._async_sniffer = None
