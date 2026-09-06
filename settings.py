import networking

settings = {}

# updates settings in the puller.settings file
def update(interface, router_ip, subnet, console, console_port, PullingMode,
           hotspot_name="", hotspot_password="", hotspot_band="", auth_key=""):
    with open("puller.settings", "w") as f:
        f.write(
            f"PullingMode {PullingMode}\n"
            f"interface {interface}\n"
            f"router_ip {router_ip}\n"
            f"subnet {subnet}\n"
            f"console {console}\n"
            f"console_port {console_port}\n"
            f"hotspot_name {hotspot_name}\n"
            f"hotspot_password {hotspot_password}\n"
            f"hotspot_band {hotspot_band}\n"
            f"access_key {auth_key}"
        )

# function for reading puller.settings
def read():
    with open("puller.settings", "r") as f:
        for line in f.readlines():
            setting, rule = line.strip().split(" ", 1)
            settings[setting.strip()] = rule.strip()
    return settings


# returns the networking info used to start a sniff/session for the selected mode
def Recieve_INFO(Router, target):
    local = []
    Target_IP = target
    Target_MAC = "00:00:00:00:00:00"
    Spoof_IP = Router
    Spoof_MAC = "00:00:00:00:00:00"
    Router_IP = Router

    mode = settings.get("PullingMode", "External_Pulling")

    if mode in ("Mobile_Pulling", "External_Pulling"):
        ip_macs = networking.RecieveHosts(Router)
        Target_MAC = ip_macs.get(Target_IP, "00:00:00:00:00:00")
        Spoof_MAC = ip_macs.get(Spoof_IP, "00:00:00:00:00:00")
        local = [ip for ip in ip_macs if ip != target]

    return Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Router_IP, local