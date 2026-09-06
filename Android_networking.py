import os
import re


def start_hotspot(Name, Password, ghz):
    """Start an Android WiFi hotspot and return its networking info.

    Returns a dict:
        {
            "gateway":  e.g. "192.168.43.1",
            "subnet":   e.g. "192.168.43.0/24",
            "interface": e.g. "ap0"
        }
    Raises RuntimeError if the hotspot cannot be started/parsed.
    """
    cmd = f"su -c 'cmd wifi start-softap {Name} wpa2 {Password} -b {ghz} -w 80'"

    with os.popen(cmd) as stdout:
        text = stdout.read()

    m_iface = re.search(r"mIface='([^']+)", text)
    if not m_iface:
        raise RuntimeError(f"Could not parse hotspot interface from: {text!r}")
    iface = m_iface.group(1)

    with os.popen(f"ip a | grep {iface}") as stdout:
        text = stdout.read()

    m_net = re.search(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})", text)
    if not m_net:
        raise RuntimeError(f"Could not parse hotspot network from: {text!r}")
    network = m_net.group(1)

    ip_part, prefix = network.rsplit("/", 1)
    octets = ip_part.split(".")
    if len(octets) != 4 or not prefix.isdigit():
        raise RuntimeError(f"Invalid hotspot network: {network!r}")

    gateway = ip_part
    subnet = ".".join(octets[:3]) + ".0/24"

    return {
        "gateway": gateway,
        "subnet": subnet,
        "interface": iface,
    }

def stop_hotspot():
    cmd = f"su -c 'cmd wifi stop-softap'"
    os.system(cmd)


def discover_hosts(subnet):
    """Return {ip: mac} for hosts on the given subnet using an ARP scan."""
    import scapy.all as scapy

    hosts = {}
    ans, unans = scapy.arping(subnet, verbose=0)
    for sent, received in ans:
        if received.haslayer(scapy.ARP):
            hosts[received.psrc] = received.hwsrc
    return hosts