import os
import puller2 as puller
import setup
import settings


setup.check()
input("\n\nPress enter to continue...")
settings = {}


with open("puller.settings", "r") as f:
    for line in f.readlines():
        settings_name, setting = line.split(" ")
        settings[settings_name.strip()] = setting.strip()



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


    ### starting website
    puller.startwebsite()


main()
