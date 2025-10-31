import requests
import time



def get_username(ip=None, username=None, mode="ip"):
    usernames = {}
    with open("IPINFO.db", "r") as f:
        for line in f:
            if not line or "," not in line:
                continue
            if mode == "ip":
                if ip in line:
                    u, ip = line.split(",")

                    return u
            else:
                u, ip = line.split(",")
                if username.lower() in u.lower():
                    usernames[u] = ip.replace("\n", "")
    if mode != "ip":
        return usernames
    else:
        return "NOT FOUND"

def get_ip(ip):
    try:
        ip_info = requests.get(f"http://ip-api.com/json/{ip}?fields=message,country,countryCode,regionName,city,zip,isp,org,mobile,proxy,hosting,query").json()

        isp = ip_info["isp"]
        country = ip_info["countryCode"]
        state = ip_info["regionName"]
        city = ip_info["city"]
        zip = ip_info["zip"]

        if str(ip_info["proxy"]) == "True":
            type = "VPN"
        elif str(ip_info["hosting"]) == "True":
            type = "Hosting"
        elif str(ip_info["mobile"]) == "True":
            type = "Mobile"
        else:
            type = "Residential"

        username = get_username(ip, mode="ip")

        time.sleep(0.25)
        return isp, country, state, city, zip, username, type
    except Exception as e:
        f = "FAILED"
        username = get_username(ip)
        return f, f, f, f, f, username, f
