import os
import time
import threading
import traceback
from collections import deque
import urllib.parse
import requests
from bs4 import BeautifulSoup
from scapy.all import sniff, IP, UDP
import scapy.all as scapy
import IP_INFO
import Store
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request, render_template
import settings as setting
import networking
import windows
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
filters = {}
app = Flask(__name__)


# -----------------------
# Flask: index (dynamic)
# -----------------------
@app.route("/")
def index():
    return render_template("index.html")


# -----------------------
# Save username POST endpoint
# -----------------------
@app.route("/save_username", methods=["POST"])
def save_username():
    data = request.get_json()
    ip = data.get("ip")
    username = data.get("username")

    if username != "":
        with open("IPINFO.db", "a") as f:
            f.write(f"\n{username},{ip}")
            captured_ips[ip][6] = username
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
# Start Flask and Contains Core inner Workings of the HTML
# -----------------------
@app.route("/get_local_hosts", methods=["POST"])
def get_local_hosts():
    r = request.get_json()
    router = r["router"] ## should come in a string 192.168.1.1

    return jsonify(networking.RecieveHosts(str(router).strip()))

@app.route("/get_interface", methods=["POST"])
def get_interface():
    interfaces = networking.recieve_interface()
    return jsonify(interfaces)

@app.route("/save_settings", methods=["POST"])
def save_settings():
    global needed_info, settings
    data = request.get_json()
    interface = str(data["interface"])
    subnet = str(data["subnet"])
    console = str(data["console"])
    port = str(data["port"])
    mobile = str(data["mobile"])

      ## should come in a string 192.168.1.1
    parts = subnet.split(".")
    subnet = ".".join(parts[:3]) + ".0/24"

    setting.update(interface, subnet, console, port, mobile)
    settings.update({"interface": interface, "subnet": subnet, "console": console, "port": port, "mobile": mobile})
    print(settings)
    return ""

@app.route("/sniff/start", methods=["POST"])
def sniff_start():
    global sniff_running, sniff_thread

    Router_IP = str(settings["subnet"]).replace("0/24", "1")
    Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Router_IP, local = setting.Recieve_INFO(Router_IP, settings["console"])
    needed_info.update({"Target_IP": Target_IP, "Target_MAC": Target_MAC, "Spoof_IP": Spoof_IP, "Spoof_MAC": Spoof_MAC, "Routers_IP": Router_IP, "local": local, "interface": settings["interface"]})
    if sniff_running:
        return "running", 204
    data = request.get_json()
    game_choice = data.get("game_choice", "3.1")
    interface = settings["interface"]

    print(game_choice, interface)

    setup_sniffer(Target_IP, local, settings["console_port"])
    sniff_running = True
    sniff_thread = threading.Thread(
        target=sniffing,
        args=(game_choice, interface),
        daemon=False,
    )
    sniff_thread.start()

    if str(game_choice).startswith("2"):
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0, True), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4, True), daemon=False)
    else:
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0), daemon=False)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4), daemon=False)

    networking.Allow_ipv4_fowarding(1, interface)
    if Target_IP is not None:
        import mobile as mobile_script

        if settings["mobile"] == "yes":
            mobile_foward_thread = threading.Thread(target=mobile_script.ipv4_foward, args=(Spoof_IP, Target_IP, Spoof_IP), daemon=False)

            mobile_foward_thread.start()
    arp_thread = threading.Thread(target=networking.Packet_Sender,
                                  args=(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Spoof_MAC, stop_event),
                                  daemon=False)
    arp_thread.start()
    conn_thread.start()
    conn_thread2.start()

    print("started sniffing")
    return "Started", 204

@app.route("/sniff/stop", methods=["POST"])
def sniff_stop():
    global sniff_running
    sniff_running = False
    stop_event.set()



    networking.Packet_Sender(needed_info["Target_IP"], needed_info["Target_MAC"], needed_info["Spoof_IP"], needed_info["Spoof_MAC"], needed_info["Routers_IP"], None, reset_arp=True)
    time.sleep(4)
    networking.Allow_ipv4_fowarding(0, needed_info["interface"])
    captured_ips.clear()
    connected.clear()
    removed.clear()
    new_connection.clear()
    last_seen.clear()
    pps_history.clear()
    unstable.clear()
    return "", 204



def start_site():
    app.run(host="0.0.0.0", port=1234, debug=True, use_reloader=False)


def load_info():
    global needed_info
    return needed_info
# ------------------------
# Packet handling
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
        if not sniff_running:
            break
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
            # Limit left_session size
            while len(left_session) >= max_left_session:
                del left_session[next(iter(left_session))]

        except Exception:
            print("Concurrent Loop Error:\n" + traceback.format_exc())

        # -----------------------
        # Maintain perfect timing
        # -----------------------
        elapsed = time.time() - start_cycle
        sleep_time = max(0, check_delay - elapsed)
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
    filter_nets = ""
    for ip in localhosts:
        if filter_nets == "":
            filter_nets += f"not net {ip}/32 "
        else:
            filter_nets += f"and not net {ip}/32 "
    global filters
    filters = {
        "1.1": f"udp src port 6672 and not net 177.237.0.0/16 and not net 192.81.0.0/16 and not net 192.168.0.0/16 and {filter_nets}",
        "1.2": f"((udp src port {console_port}) or (udp src port 3074) or (udp src port 50306)) and ({filter_nets})",
        "1.3": f"udp src port 3075 and not net 192.168.0.0/16 and {filter_nets}",
        "1.4": f"(udp port {console_port} or udp port 3074) and {filter_nets}",
        "1.5": f"udp port {console_port} and {filter_nets}",
        "2.1": f"udp and src portrange 49152-65535 and not net 192.168.0.0/16 and {filter_nets}",
        "2.2": f"(udp and ((src port 2700 or src port 2500 or src port 3600 or src port 3800 or src port 2400 or (src port >= 61101 and src port <= 63614))) and ({filter_nets}))",
        "2.3": f"udp port {console_port} and {filter_nets}",
        "2.4": f"udp port {console_port} and {filter_nets}",
        "3.1": f"{filter_nets}"
    }


def sniffing(game_choice, interface):
    global sniff_running, filters
    sniff_running = True

    if not sniff_running:
        return  # sniff stops if sniff_running becomes False

    sniff(
        iface=interface,
        filter=filters.get(game_choice, ""),
        prn=handle_packet,
        store=0,
        stop_filter=lambda pkt: not sniff_running
    )


# -------------------
# Start all threads
# -------------------
def startwebsite():

    with open("puller.settings", "r") as f:
        for line in f.readlines():
            settings_name, setting = line.split(" ")
            settings[settings_name.strip()] = setting.strip()

    start_site()
    print("\n[INFO] KeyboardInterrupt received — shutting down...")


    stop_event.set()
    print("======================\n\nResettings connections to your console\nPlease Be Patient should take about 6 seconds\n\n======================")

    print("======================\n\nDONE Please Close The Terminal\n\n======================")



