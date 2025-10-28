import subprocess
import os
if os.name == "nt":
    import winreg

def enable_ipv4_forwarding_win(interface, status):
    path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
    value_name = "IPEnableRouter"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ) as key:
            value, value_type = winreg.QueryValueEx(key, value_name)
    except:
        pass

    if status == 1 and value == 0:
        try:

            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 1)
            winreg.CloseKey(key)
        except PermissionError:
            print("Permission denied. Run as Administrator.")
            return

        try:

            subprocess.Popen(
                ["netsh", "interface", "ipv4", "set", "interface", interface, "forwarding=enabled"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=False)

            print("IPv4 Forwarding Applied (no reboot).")

        except Exception as e:
            print("[-] Error while applying forwarding:", e)
    elif status == 0:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "IPEnableRouter", 0, winreg.REG_DWORD, 0)
            winreg.CloseKey(key)
        except PermissionError:
            print("Permission denied. Run as Administrator.")
            return

        try:

            subprocess.Popen(
                ["netsh", "interface", "ipv4", "set", "interface", interface, "forwarding=disabled"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, shell=False)

            print("IPv4 Forwarding Applied (no reboot).")

        except Exception as e:
            print("[-] Error while applying forwarding:", e)

def recieve_interface():
    output = subprocess.check_output("netsh interface show interface", shell=False, text=True)
    interfaces = []
    lines = output.splitlines()[3:]
    count = 0
    for line in lines:
        if line.strip():
            parts = line.split()
            interface_name = " ".join(parts[3:])
            count += 1
            print(f"{count} :{interface_name}")
            interfaces.append(interface_name)

    pick = input("Pick an interface: ")
    return interfaces[int(pick)-1]
