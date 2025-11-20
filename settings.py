import networking

settings = {}


def update(interface, subnet, console, console_port, mobile):
    with open("puller.settings", "w") as f:
        f.write(f"interface {interface}\nsubnet {subnet}\nconsole {console}\nconsole_port {console_port}\nmobile {mobile}")

def read():
    with open("puller.settings", "r") as f:
        for line in f.readlines():
            setting, rule = line.split(" ")
            settings[setting] = rule.strip()
        return settings


def Recieve_INFO(Router, target):
    ip_macs = networking.RecieveHosts(Router)
    ips = []
    Target_IP = target
    Target_MAC = ip_macs[Target_IP]

    Spoof_IP = Router
    Spoof_MAC = ip_macs[Spoof_IP]

    Router_IP = Router
    for ip in ip_macs.keys():
        if ip != target:
            ips.append(ip)

    return Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Router_IP, ips




