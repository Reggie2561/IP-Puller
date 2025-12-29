import os

# ==========================================
# Compiles C for IPV4 Forwarding for Phones! (note switching to a rooted method for a Wi-Fi bridge mode or wifi hotspot.)
# ==========================================
def ipv4_foward(interface, victim_mac, router_mac):
    try:
        clang = os.popen("clang --version")
        clang = clang.read()
        if "clang/" not in clang or not "installed" not in clang:
            os.popen("pkg update")
            os.popen("pkg upgrade")
            os.popen("pkg install clang")
    except:
        print("Failed to update")

    try:
        with open("mobile", "r") as f:
            pass
    except FileNotFoundError:
        os.popen("clang -O3 -march=native -o mobile Mobile.c")

    try:
        os.system(f"sudo ./mobile {interface} {victim_mac} {router_mac}")
    except:
        print("Failed to start mobile forwarder.")
