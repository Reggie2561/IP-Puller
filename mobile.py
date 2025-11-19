import os

# ==========================================
# Compiles C for IPV4 Forwarding for Phones
# ==========================================
def ipv4_foward(interface, victim, router):
    try:
        with open("mobile", "r") as f:
            pass
    except FileNotFoundError:
        os.popen("clang -O3 -march=native -o mobile Mobile.c")
    try:
        os.popen(f"sudo ./mobile {interface} {victim} {router}")
    except Exception as e:
        print("Failed to start mobile forwarder.")
