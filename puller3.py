import time
import threading
import traceback
from collections import deque
import urllib.parse
import requests
from bs4 import BeautifulSoup
from scapy.all import sniff, IP, UDP
import IP_INFO
import Store
from datetime import datetime
from flask import Flask, jsonify, request, render_template
import settings as setting
import networking
import os
import ipaddress
from ping import ping
sniff_running = False
sniff_thread = None


# Shared global data
stop_event = threading.Event()
target = []
invalid_local_hosts = []
captured_ips = {}
connected = []
disconnected = {}
concurrent_connection = {}
new_connection = {}
removed = {}
last_seen = {}  # track last update time per IP
left_session = {}
join_times = {}
pps_history = {}
unstable = {}
settings = {}
needed_info = {}
first_joined = {}
pc_filters = {}
filters = {}
app = Flask(__name__)


# -----------------------
# PC network auto-detection (for Local Pulling)
# -----------------------
def iface_netinfo_all():
    """Parse ipconfig/ip a once, return {interface: {router_ip, subnet, local_ip}}."""
    result = {}
    if os.name == "nt":
        output = os.popen("ipconfig").read()
        sections = []
        current_header = ""
        current_lines = []
        for line in output.splitlines():
            if "adapter" in line and ":" in line:
                if current_lines:
                    sections.append((current_header, current_lines))
                inner = line.split("adapter", 1)[1].split(":")[0].strip()
                current_header = inner
                current_lines = []
            else:
                current_lines.append(line)
        if current_lines:
            sections.append((current_header, current_lines))

        for adapter, lines in sections:
            ip_line = None
            mask_line = None
            gw_line = None
            for line in lines:
                if "IPv4 Address" in line:
                    ip_line = line.split(":")[-1].strip()
                elif ip_line and "Subnet Mask" in line:
                    mask_line = line.split(":")[-1].strip()
                elif ip_line and "Default Gateway" in line:
                    gw = line.split(":")[-1].strip()
                    if gw:
                        gw_line = gw
                        break
            if ip_line and mask_line:
                net = ipaddress.IPv4Network(f"{ip_line}/{mask_line}", strict=False)
                result[adapter] = {
                    "router_ip": gw_line or ip_line,
                    "subnet": str(net),
                    "local_ip": ip_line,
                }
    else:
        import subprocess
        gw = os.popen("ip route show default 2>/dev/null | awk '{print $3}'").read().strip()
        iface = os.popen("ip route show default 2>/dev/null | awk '{print $5}'").read().strip()
        local_ip = ""
        subnet = ""
        iface_friendly = iface
        # Populate result for the default-route interface
        port_lines = subprocess.run(
            ["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True
        ).stdout.splitlines()
        for line_ in port_lines:
            parts = line_.split()
            if len(parts) >= 4 and parts[1] == iface:
                local_ip = parts[3].split("/")[0]
                subnet = parts[3]
                break
        result[iface_friendly] = {
            "router_ip": gw,
            "subnet": subnet,
            "local_ip": local_ip,
        }
    return result


def detect_pc_network(interface=None):
    """Detect the active interface, gateway and subnet for the local machine.
    If interface is given, return info for that interface only.
    """
    if os.name == "nt":
        import windows
        interfaces = windows.receive_interface()
    else:
        interfaces = networking.recieve_interface() if os.name == "posix" else []

    up_ifaces = [i for i in interfaces if i]
    all_info = iface_netinfo_all()

    if not all_info:
        return {"interface": up_ifaces[0] if up_ifaces else "", "router_ip": "", "subnet": "", "local_ip": ""}

    # If a specific interface was requested, return its live info (case-insensitive)
    if interface:
        for name, info in all_info.items():
            if name.strip().lower() == interface.strip().lower():
                return {
                    "interface": name,
                    "router_ip": info.get("router_ip", ""),
                    "subnet": info.get("subnet", ""),
                    "local_ip": info.get("local_ip", ""),
                }
        # Requested interface not found in parse: fall back to first parsed
        name, info = next(iter(all_info.items()))
        return {
            "interface": name,
            "router_ip": info.get("router_ip", ""),
            "subnet": info.get("subnet", ""),
            "local_ip": info.get("local_ip", ""),
        }

    # No interface given: prefer the interface that owns a default gateway
    for name, info in all_info.items():
        if info.get("router_ip"):
            return {
                "interface": name,
                "router_ip": info["router_ip"],
                "subnet": info.get("subnet", ""),
                "local_ip": info.get("local_ip", ""),
            }
    name, info = next(iter(all_info.items()))
    return {
        "interface": name,
        "router_ip": info.get("router_ip", ""),
        "subnet": info.get("subnet", ""),
        "local_ip": info.get("local_ip", ""),
    }


# -----------------------
# Flask: index (dynamic)
# -----------------------
@app.route("/")
def index():
    return render_template("index.html")


# -----------------------
# Naming/renaming/removing usernames POST endpoint
# -----------------------
@app.route("/save_username", methods=["POST"])
def save_username():
    data = request.get_json()
    ip = data.get("ip")
    username = data.get("username")

    if username != "":
        with open("IPINFO.db", "a") as f:
            f.write(f"\n{username},{ip}")
        if ip in captured_ips.keys():
            captured_ips[ip][6] = username
        if ip in left_session.keys():
            left_session[ip][7] = username
    return "", 204

@app.route("/delete_username", methods=["POST"])
def delete_username():
    data = request.get_json()
    ip = data.get("ip")
    IP_INFO.remove(ip)
    if ip in captured_ips.keys():
        captured_ips[ip][6] = "N/A"
    if ip in left_session.keys():
        left_session[ip][7] = "N/A"

    return "", 204

@app.route("/rename_username", methods=["POST"])
def rename_username():
    data = request.get_json()
    ip = data.get("ip")
    new_name = data.get("new_username")
    IP_INFO.rename(ip, new_name)
    if ip in captured_ips.keys():
        captured_ips[ip][6] = new_name
    if ip in left_session.keys():
        left_session[ip][7] = new_name

    return "", 204


# -----------------------
# /update_ips (PUT)
# -----------------------
@app.route("/update_ips", methods=["PUT"])
def update_ips():
    result = []
    for ip, info in captured_ips.items():
        status = (
            "blue" if ip in new_connection else
            "green" if ip in connected and ip not in new_connection else
            "yellow" if ip in disconnected else
            "purple" if ip in removed else
            "red"
        )

        def safe_get(index):
            return info[index] if len(info) > index else ""

        row = {
            "ip": ip,
            "fields": [
                {"label": "IP", "value": ip},
                {"label": "Time", "value": safe_get(0)},
                {"label": "ISP", "value": safe_get(1)},
                {"label": "Country", "value": safe_get(2)},
                {"label": "State", "value": safe_get(3)},
                {"label": "City", "value": safe_get(4)},
                {"label": "ZIP", "value": safe_get(5)},
                {"label": "Type", "value": safe_get(7)}, #9 for port
                {"label": "Username", "value": safe_get(6)},
                {"label": "Joined Times", "value": safe_get(8)},
                {"label": "pps", "value": concurrent_connection.get(ip, {}).get("pps_avg", 0)}
            ],
            "status": status
        }
        result.append(row)
    # --------------------------
    # Compute stats for top bar
    # --------------------------
    stats = {
        "concurrent": len(captured_ips),
        "connected": len(connected),
        "removed": len(removed),
        "new_connection": len(new_connection),
        "left_players": len(left_session),
    }

    return jsonify({"rows": result, "stats": stats})


# ---------------------
# updates left players
# ---------------------
@app.route("/update_left_ips", methods=["PUT"])
def update_left_ips():
    result = []

    for ip, info in left_session.items():
        def safe_get(index):
            return info[index] if len(info) > index else ""

        row = {
            "ip": ip,
            "fields": [
                {"label": "IP", "value": ip},
                {"label": "Time\nLeft", "value": safe_get(0)},
                {"label": "ISP", "value": safe_get(1)},
                {"label": "Country", "value": safe_get(2)},
                {"label": "State", "value": safe_get(3)},
                {"label": "City", "value": safe_get(4)},
                {"label": "ZIP", "value": safe_get(5)},
                {"label": "Username", "value": safe_get(7)},
                {"label": "Left Times", "value": safe_get(8)}
            ]
        }
        result.append(row)
    result.reverse()
    return jsonify({"rows": result})


# ----------------------
# multitool front end
# ----------------------

@app.route("/ReggiesMultiTool", methods=["GET"])
def ReggiesMultiTool():
    return render_template('multitool.html')

@app.route("/LiveView", methods=["GET"])
def LiveView():
    field_names = ["IP", "Time\nJoined", "ISP", "Country", "State", "City", "ZIP", "Type", "Username", "Joined Times", "PPS"]
    left_field_names = ["IP", "Time\nLeft", "ISP", "Country", "State", "City", "ZIP", "Username", "Left Times"]

    return render_template('LiveView.html', field_names=field_names, left_field_names=left_field_names)

@app.route("/settings", methods=["GET"])
def settings_view():
    return render_template('index.html')


# ----------------------
# multitool back end
# ----------------------
@app.route('/Ping+<target>', methods=['POST'])
def ping_target(target):
    ip = urllib.parse.unquote_plus(target)
    results = ping(ip)
    return jsonify({"text": results})


@app.route('/Conn_type+<target>', methods=['POST'])
def Conn_type(target):
    ip = urllib.parse.unquote_plus(target)

    data = requests.get(f"http://ip-api.com/json/{ip}?fields=org,as,mobile,proxy,hosting").json()

    text = f"Organization: {data['org']}\nAS Number: {data['as']}\nMobile?: {data['mobile']}\nVPN?: {data['proxy']}\nHosting?: {data['hosting']}"

    return jsonify({"text": text})


@app.route('/nmap+<target>', methods=['POST'])
def nmap_target(target):
    ip = urllib.parse.unquote_plus(target)
    session = requests.session()

    session.headers.update({
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"})
    session.get("https://hackertarget.com/nmap-online-port-scanner/")
    data = session.post('https://hackertarget.com/nmap-online-port-scanner/', data={"theinput": f"{ip}",
                                                                                    "thetest": "nmap",
                                                                                    "name_of_nonce_field": "admin",
                                                                                    "_wp_http_referer": "/nmap-online-port-scanner/"
                                                                                    })

    soup = BeautifulSoup(data.content, "html.parser")
    results = soup.find_all("pre", attrs={"class": "bg-f9"}, id="formResponse")

    return jsonify({
        "target": ip,
        "results": results[0].get_text(strip=True) if results else "No output found."
    })


@app.route('/usernameLookUp+<username>', methods=['POST'])
def username_lookup_target(username):
    # -------------------------
    # Normalize username input
    # -------------------------
    username = urllib.parse.unquote_plus(username).replace("%20", " ").strip()

    try:

        dict_of_ips_usernames = IP_INFO.get_username(username=username, mode="gamertags")
        # --------------------------------------
        # Prepare JSON response with all pairs
        # --------------------------------------
        results = []
        for user, ip in dict_of_ips_usernames.items():
            results.append({"Gamertag": user, "IP": ip})

        return jsonify({"Results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# gives all local network ips except for the xboxes ip used for filtering out requests
# -----------------------
@app.route("/get_local_hosts", methods=["POST"])
def get_local_hosts():
    r = request.get_json()
    router = r["router"] ## should come in a string 192.168.1.1

    return jsonify(networking.RecieveHosts(str(router).strip()))
# give website ability to give all active interfaces for the interface selection menu in settings
@app.route("/get_interface", methods=["POST"])
def get_interface():
    interfaces = networking.recieve_interface()
    return jsonify(interfaces)
# -----------------------
# get current saved settings (for restoring the settings page)
# -----------------------
@app.route("/get_settings", methods=["POST"])
def get_settings():
    cfg = {k: v for k, v in setting.read().items()}
    return jsonify(cfg)


# -----------------------
# give the settings page its saved/current interface list + auto-detected PC info
# -----------------------
@app.route("/get_pc_netinfo", methods=["POST"])
def get_pc_netinfo():
    try:
        r = request.get_json() or {}
        interface = r.get("interface", "")
        return jsonify(detect_pc_network(interface or None))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Mobile Pulling: auto-detect the phone hotspot network info
# -----------------------
def get_hotspot_creds():
    return (
        str(settings.get("hotspot_name", "") or "WirelessHotspot"),
        str(settings.get("hotspot_password", "") or "Password123"),
        str(settings.get("hotspot_band", "") or "5"),
    )


@app.route("/get_mobile_netinfo", methods=["POST"])
def get_mobile_netinfo():
    try:
        import Android_networking
        name, password, band = get_hotspot_creds()
        return jsonify(Android_networking.start_hotspot(name, password, band))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Mobile Pulling: discover consoles connected to the hotspot
# -----------------------
@app.route("/get_mobile_hosts", methods=["POST"])
def get_mobile_hosts():
    r = request.get_json() or {}
    subnet = r.get("subnet", "")
    if not subnet:
        try:
            import Android_networking
            name, password, band = get_hotspot_creds()
            hot = Android_networking.start_hotspot(name, password, band)
            subnet = hot["subnet"]
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    try:
        import Android_networking
        return jsonify(Android_networking.discover_hosts(str(subnet).strip()))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# For the settings page
@app.route("/save_settings", methods=["POST"])
def save_settings():
    global needed_info, settings
    data = request.get_json()
    PullingMode = str(data["PullingMode"])
    interface = str(data.get("interface", ""))
    router_ip = str(data.get("router", ""))
    console = str(data.get("console", ""))
    port = str(data.get("port", ""))
    subnet = str(data.get("subnet", ""))
    hotspot_name = str(data.get("hotspot_name", "") or "WirelessHotspot")
    hotspot_password = str(data.get("hotspot_password", "") or "Password123")
    hotspot_band = str(data.get("hotspot_band", "") or "5")

    # -------------------------
    # Background auto-fill for Mobile / Local
    # -------------------------
    if PullingMode == "Mobile_Pulling":
        # Hotspot provides gateway/subnet/interface automatically.
        # If the frontend already auto-detected and passed them, keep them.
        try:
            import Android_networking
            hot = Android_networking.start_hotspot(hotspot_name, hotspot_password, hotspot_band)
            interface = hot["interface"]
            router_ip = hot["gateway"]
            subnet = hot["subnet"]
        except Exception as e:
            print("Mobile hotspot detection failed:", e)
            if not subnet:
                parts = router_ip.split(".")
                if len(parts) == 4:
                    subnet = ".".join(parts[:3]) + ".0/24"
    elif PullingMode == "Local_Pulling":
        # PC provides interface/gateway/subnet automatically; honor user iface pick
        try:
            pc = detect_pc_network()
            if not interface or interface in ("", "None"):
                interface = pc.get("interface", "")
            if not router_ip or router_ip in ("", "None"):
                router_ip = pc.get("router_ip", "")
            if not subnet:
                subnet = pc.get("subnet", "")
            if not console or console in ("", "None"):
                console = pc.get("local_ip", "")
        except Exception as e:
            print("Local network detection failed:", e)
    else:
        # External Pulling: derive subnet from router_ip
        if not subnet:
            parts = router_ip.split(".")
            if len(parts) == 4:
                subnet = ".".join(parts[:3]) + ".0/24"

    setting.update(interface, router_ip, subnet, console, port, PullingMode,
                   hotspot_name, hotspot_password, hotspot_band)

    settings.update({
        "PullingMode": PullingMode,
        "interface": interface,
        "router_ip": router_ip,
        "subnet": subnet,
        "console": console,
        "console_port": port,
        "hotspot_name": hotspot_name,
        "hotspot_password": hotspot_password,
        "hotspot_band": hotspot_band,
    })
    return jsonify({"ok": True, "settings": settings})
#starts the sniffing loop with the selected game
@app.route("/sniff/start", methods=["POST"])
def sniff_start():
    global sniff_running, sniff_thread

    if sniff_running:
        return "running", 204
    Router_IP = str(settings.get("router_ip", ""))
    mode = settings.get("PullingMode", "External_Pulling")

    data = request.get_json()
    game_choice = data.get("game_choice", "3.1")
    interface = settings.get("interface", "")
    console_port = settings.get("console_port", "")
    Target_IP = settings.get("console", "")

    stop_event.clear()

    # ---------------------------------------------------------------
    # Local Pulling: sniff the PC interface directly, no ARP spoofing
    # ---------------------------------------------------------------
    if mode == "Local_Pulling":
        needed_info.update({"interface": interface, "is_local": True})
        setup_sniffer(Target_IP, [], console_port)

        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4), daemon=False)

        sniff_thread = threading.Thread(target=sniffing, args=(game_choice, interface), daemon=False)

        sniff_thread.start()
        sniff_running = True
        conn_thread.start()
        conn_thread2.start()

        return "Started", 204

    # ---------------------------------------------------------------
    # Mobile Pulling: sniff the phone hotspot interface, no ARP spoofing
    # (same capture model as Local but on the phone's hotspot iface)
    # ---------------------------------------------------------------
    if mode == "Mobile_Pulling":
        needed_info.update({"interface": interface, "is_local": True})
        setup_sniffer(Target_IP, [], console_port)

        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4), daemon=False)

        sniff_thread = threading.Thread(target=sniffing, args=(game_choice, interface), daemon=False)

        sniff_thread.start()
        sniff_running = True
        conn_thread.start()
        conn_thread2.start()

        return "Started", 204

    # ---------------------------------------------------------------
    # External Pulling: ARP spoof from this PC toward the console
    # ---------------------------------------------------------------
    Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Router_IP, local = setting.Recieve_INFO(Router_IP, Target_IP)

    needed_info.update({"Target_IP": Target_IP, "Target_MAC": Target_MAC, "Spoof_IP": Spoof_IP, "Spoof_MAC": Spoof_MAC, "Routers_IP": Router_IP, "local": local, "interface": interface, "is_local": False})

    setup_sniffer(Target_IP, local, console_port)
    sniff_running = True
    sniff_thread = threading.Thread(target=sniffing, args=(game_choice, interface), daemon=False)
    sniff_thread.start()

    if str(game_choice).startswith("2"):
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0, True), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4, True), daemon=False)
    else:
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4), daemon=False)

    networking.Allow_ipv4_fowarding(1, interface)

    arp_thread = threading.Thread(target=networking.Packet_Sender, args=(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Spoof_MAC, stop_event), daemon=False)
    arp_thread.start()

    conn_thread.start()
    conn_thread2.start()

    print("started sniffing")
    return "Started", 204
# resets all lists except left session and stops the sniffing loop
@app.route("/sniff/stop", methods=["POST"])
def sniff_stop():
    global sniff_running
    sniff_running = False
    stop_event.set()



    if not needed_info.get("is_local", False):
        try:
            networking.Packet_Sender(needed_info["Target_IP"], needed_info["Target_MAC"], needed_info["Spoof_IP"], needed_info["Spoof_MAC"], needed_info["Routers_IP"], None, reset_arp=True)
        except KeyError:
            pass
        time.sleep(4)

        try:
            networking.Allow_ipv4_fowarding(0, needed_info["interface"])
        except KeyError:
            pass

    captured_ips.clear()
    connected.clear()
    removed.clear()
    new_connection.clear()
    last_seen.clear()
    pps_history.clear()
    unstable.clear()
    new_connection.clear()

    return "", 204



def start_site():
    app.run(host="0.0.0.0", port=1234, debug=True, use_reloader=False)



# ------------------------
# Packet handling PS. Most game traffic for p2p is udp protocol, servers usually use TCP
# ------------------------
def handle_packet(packet):
    try:
        if IP in packet and UDP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = str(packet[UDP].sport)


            if src_ip == target[0]:
                src_ip = dst_ip
            if src_ip not in captured_ips and src_ip not in invalid_local_hosts:
                Store.Store_ip(src_ip)
                info = IP_INFO.get_ip(src_ip)
                # ---------------------------------------------------
                # Pad the info so we always have at least 7 elements
                # ---------------------------------------------------
                info = tuple(list(info) + [""] * (7 - len(info)))
                if src_ip in join_times:
                    join_times[src_ip] = join_times[src_ip] + 1
                else:
                    join_times[src_ip] = 1
                # -----------------------------------------------
                # Store captured IP info with consistent indices
                # -----------------------------------------------

                captured_ips[src_ip] = [
                    datetime.now().strftime('%H:%M:%S'),
                    info[0],  # isp
                    info[1],  # country
                    info[2],  # state
                    info[3],  # city
                    info[4],  # zip
                    info[5],  # username
                    info[6],  # type
                    join_times[src_ip],
                    src_port
                ]
                concurrent_connection[src_ip] = {"packets": 1, "pps": 0}
                new_connection[src_ip] = time.time()
            else:
                concurrent_connection[src_ip]["packets"] += 1

        elif IP in packet and packet.haslayer("TCP"):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = str(packet["TCP"].sport)

            if src_ip == target[0]:
                src_ip = dst_ip

            if src_ip not in captured_ips and src_ip not in invalid_local_hosts:
                Store.Store_ip(src_ip)
                info = IP_INFO.get_ip(src_ip)
                info = tuple(list(info) + [""] * (8 - len(info)))
                if src_ip in join_times:
                    join_times[src_ip] = join_times[src_ip] + 1
                else:
                    join_times[src_ip] = 1

                captured_ips[src_ip] = [
                    datetime.now().strftime('%H:%M:%S'),
                    info[0],  # isp
                    info[1],  # country
                    info[2],  # state
                    info[3],  # city
                    info[4],  # zip
                    info[5],  # username
                    info[6],  # type
                    join_times[src_ip],
                    src_port
                ]

                concurrent_connection[src_ip] = {"packets": 1, "pps": 0}
                new_connection[src_ip] = time.time()
            else:
                concurrent_connection[src_ip]["packets"] += 1

    except:
        error = traceback.format_exc()
        print(error)


# -----------------------
# Connection tracking
# -----------------------
def conncurent(stop,offset=0, server=False):
    # --------------------------------------------
    # Configurable parameters
    # --------------------------------------------
    cya_ip = 20  # Seconds until removed connection marked as left_session
    stuck_timeout = 30  # Seconds until stuck IPs are purged
    check_delay = 8  # Snapshot interval
    min_pps = 0.25  # PPS threshold for activity
    max_unstable_hits = 2  # Consecutive low PPS counts before disconnect
    pps_window_len = 3  # Sliding window size for PPS average
    max_left_session = 30  # Max entries stored in left_session
    server_min = 50 # If Server is chosen a higher pps is usual so if we are looking for servers we only want servers output

    # --------------------------------------------
    # Globals assumed from outer scope
    # --------------------------------------------
    global concurrent_connection, captured_ips, pps_history
    global last_seen, connected, unstable, disconnected
    global removed, left_session, new_connection
    global sniff_running

    # --------------------------------------------
    # Thread-safe guard for shared dicts
    # --------------------------------------------
    lock = threading.RLock()

    # --------------------------------------------
    # Thread start offset (stagger start times)
    # --------------------------------------------
    if offset > 0:
        time.sleep(offset)

    # --------------------------------------------
    # Connection tracking loop
    # --------------------------------------------
    while not stop.is_set():
        start_cycle = time.time()
        try:
            # Snapshot before
            with lock:
                base_items = {k: v.copy() for k, v in concurrent_connection.items()}

            time.sleep(check_delay)

            # Snapshot after
            with lock:
                after_items = {k: v.copy() for k, v in concurrent_connection.items()}

            current = time.time()

            # ---------------------------------------------------
            # Compare snapshots and update PPS / activity tracking
            # ---------------------------------------------------
            for conn, before_data in base_items.items():
                if not isinstance(before_data, dict):
                    continue

                count_before = before_data.get("packets", 0)
                count_after = after_items.get(conn, {}).get("packets", 0)
                pps = max((count_after - count_before) / check_delay, 0.0)
                # --------------
                # PPS averaging
                # --------------
                dq = pps_history.setdefault(conn, deque(maxlen=pps_window_len))
                dq.append(pps)
                pps_avg = sum(dq) / len(dq)

                concurrent_connection.setdefault(conn, {})
                concurrent_connection[conn]["pps"] = round(pps)
                concurrent_connection[conn]["pps_avg"] = round(pps_avg)
                # --------------------------
                # Active → update last_seen
                # ---------------------------
                if pps_avg > min_pps:
                    last_seen[conn] = current
                elif conn not in last_seen:
                    # ------------------------------------------------------
                    # Initialize last_seen for IPs that never became active
                    # -------------------------------------------------------
                    last_seen[conn] = start_cycle

                # ---------------------------
                # NEW → CONNECTED
                # ---------------------------
                if not server:
                    if conn not in connected and pps_avg >= min_pps:
                        connected.append(conn)
                else:
                    if conn not in connected and pps_avg >= server_min:
                        connected.append(conn)

                # ---------------------------
                # Unstable handling
                # ---------------------------
                if conn not in unstable:
                    unstable[conn] = {"count": 0, "last_flap": current}
                elif pps < min_pps:
                    unstable[conn]["count"] += 1
                    unstable[conn]["last_flap"] = current

                # Too unstable → removed
                if unstable[conn]["count"] >= max_unstable_hits:
                    if conn in connected:
                        connected.remove(conn)
                        removed[conn] = current
                        unstable.pop(conn, None)

            # ------------------------
            # Cleanup new_connection
            # ------------------------
            for new_ip, start_time in list(new_connection.items()):
                if current - start_time > 5:
                    new_connection.pop(new_ip, None)

            # ------------------------
            # removed → left_session
            # ------------------------
            for conn, t in list(removed.items()):
                if current - t > cya_ip:
                    removed.pop(conn, None)

                    info = captured_ips.get(conn, [])
                    if conn not in left_session.keys():
                        left_session[conn] = [
                            datetime.now().strftime('%H:%M:%S'),
                            info[1] if len(info) > 1 else "",
                            info[2] if len(info) > 2 else "",
                            info[3] if len(info) > 3 else "",
                            info[4] if len(info) > 4 else "",
                            info[5] if len(info) > 5 else "",
                            info[8] if len(info) > 8 else "",
                            info[6] if len(info) > 6 else "",
                            1,
                        ]
                    else:
                        left_session[conn][8] += 1
                        left_session[conn][0] = datetime.now().strftime('%H:%M:%S')

                    # Cleanup connection data
                    captured_ips.pop(conn, None)
                    concurrent_connection.pop(conn, None)
                    pps_history.pop(conn, None)

            # ------------------------
            # Cleanup stuck IPs
            # ------------------------
            for conn, last_time in list(last_seen.items()):
                if current - last_time > stuck_timeout:
                    for d in [
                        concurrent_connection,
                        captured_ips,
                        new_connection,
                        disconnected,
                        removed,
                        unstable,
                    ]:
                        d.pop(conn, None)
                    if conn in connected:
                        connected.remove(conn)
                    last_seen.pop(conn, None)
                    pps_history.pop(conn, None)
            # Limit for left_session
            while len(left_session) >= max_left_session:
                del left_session[next(iter(left_session))]

        except Exception:
            print("Concurrent Loop Error:\n" + traceback.format_exc())

        # -----------------------
        # Maintain perfect timing for threads
        # -----------------------
        elapsed = time.time() - start_cycle
        sleep_time = max(0, int(check_delay) - int(elapsed))
        time.sleep(sleep_time)


# -----------------
# Sniffing wrapper
# -----------------
def setup_sniffer(Target_IP, localhosts, console_port):
    target.clear()
    target.append(Target_IP)
    Store.reset_ip()

    # Remove Target_IP properly
    if Target_IP in localhosts:
        localhosts.remove(Target_IP)

    global filters
    global pc_filters
    local_filter = f"host {Target_IP}" if Target_IP else ""
    if local_filter:
        local_filter += " and not net 192.81.241.0/24"
    filters = {
            "1.1": f"udp src port 6672 and {local_filter}",
            "1.2": f"((udp src port {console_port}) or (udp src port 3074) or (udp src port 50306)) and {local_filter}",
            "1.3": f"udp src port 3075 and {local_filter}",
            "1.4": f"(udp port {console_port} or udp port 3074) and {local_filter}",
            "1.5": f"udp port {console_port} and {local_filter}",
            "2.1": f"udp and src portrange 49152-65535 and {local_filter}",
            "2.2": f"(udp and ((src port 2700 or src port 2500 or src port 3600 or src port 3800 or src port 2400 or (src port >= 61101 and src port <= 63614)))) and {local_filter}",
            "2.3": f"udp port {console_port} and {local_filter}",
            "2.4": f"udp port {console_port} and {local_filter}",
            "3.1": f"{local_filter}"
        }

    #filters = {
    #        "1.1": f"udp src port 6672 and {filter_nets}",
    #        "1.2": f"((udp src port {console_port}) or (udp src port 3074) or (udp src port 50306)) and ({filter_nets})",
    #        "1.3": f"udp src port 3075 and not net 192.168.0.0/16 and {filter_nets}",
    #        "1.4": f"(udp port {console_port} or udp port 3074) and {filter_nets}",
    #        "1.5": f"udp port {console_port} and {filter_nets}",
    #        "2.1": f"udp and src portrange 49152-65535 and not net 192.168.0.0/16 and {filter_nets}",
    #        "2.2": f"(udp and ((src port 2700 or src port 2500 or src port 3600 or src port 3800 or src port 2400 or (src port >= 61101 and src port <= 63614))) and ({filter_nets}))",
    #        "2.3": f"udp port {console_port} and {filter_nets}",
    #        "2.4": f"udp port {console_port} and {filter_nets}",
    #        "3.1": f""
    #    }

# starts a scapy sniff() to capture traffic
def sniffing(game_choice, interface):
    global sniff_running, filters
    sniff_running = True
    if not sniff_running:
        return

    sniff(
        iface=interface,
        filter=filters.get(game_choice, ""),
        prn=handle_packet,
        store=0,
        stop_filter=lambda pkt: stop_event.is_set()
    )


# -------------------
# Start all threads
# -------------------
def startwebsite():

    with open("puller.settings", "r") as f:
        for line in f.readlines():
            setting_name, setting_val = line.strip().split(" ", 1)
            settings[setting_name.strip()] = setting_val.strip()

    start_site()
    print("\n[INFO] KeyboardInterrupt received — shutting down...")

    stop_event.set()

    print("======================\n\nDONE Please Close The Terminal\n\n======================")



