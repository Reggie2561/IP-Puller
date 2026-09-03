import networking

settings = {}

# updates settings in the puller.settings file
def update(interface, router_ip, subnet, console, console_port, PullType, mobile):
    with open("puller.settings", "w") as f:
        f.write(f"interface {interface}\nrouter_ip {router_ip}\nsubnet {subnet}\nconsole {console}\nconsole_port {console_port}\npullingMethod {PullType.replace(' ', '_')}\nmobile {mobile}")
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
    read()
    if settings["pullingMethod"] != "Local_Pulling":
        Target_MAC = ip_macs.get(Target_IP)
    else:
        Target_MAC = "00:00:00:00:00:00"

    Spoof_IP = Router
    Spoof_MAC = ip_macs.get(Spoof_IP)

    Router_IP = Router
    for ip in ip_macs.keys():
        if ip != target:
            ips.append(ip)

    return Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Router_IP, ips




