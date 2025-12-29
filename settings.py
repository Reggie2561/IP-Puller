import networking

settings = {}

# updates settings in the puller.settings file
def update(interface, subnet, console, console_port, mobile, local_sniff):
    with open("puller.settings", "w") as f:
        f.write(f"interface {interface}\nsubnet {subnet}\nconsole {console}\nconsole_port {console_port}\nmobile {mobile}\nlocal {local_sniff}")
# function for reading puller.settings
def read():
    with open("puller.settings", "r") as f:
        for line in f.readlines():
            setting, rule = line.split(" ")
            settings[setting] = rule.strip()
        return settings

# gives you list of all clients but not the xboxs,ps,pc,ect
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




