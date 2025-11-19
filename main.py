import os
import puller2 as puller
import scapy.all as scapy
import ipaddress
import networking
import setup
import settings

setup.check()

settings = {}


with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()



active_interface = []





def main_page():
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")
    art = """\
--.--.--.   .--.     . .         
  |  |   )  |   )    | |         
  |  |--'   |--'.  . | | .-. .--.
  |  |      |   |  | | |(.-' |   
--'--'      '   `--`-`-`-`--''  
======================================
  """
    print(art)
    pick = input("\n1. Discord Server\n2. press ENTER to continue\n\nChoice (1-2): ")

    if pick == "1":
        print("Discord Server Code: AXHy4A4U\nDiscord Username: Reggie2561")
        input("Press ENTER to Continue")

def main():

    counter = 0
    main_page()
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")




    if settings["console_port"] == "null":
        Console_port = input("Enters Console Internal Port: ")
    else:
        Console_port = settings["console_port"]





    ### starting sniffing alg
    if os.name == "nt":
        os.system("cls")
    elif os.name == "posix":
        os.system("clear")



    puller.startwebsite()


main()
