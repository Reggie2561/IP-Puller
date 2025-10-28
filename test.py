import requests
def traceroute_scan(ip):
    data = requests.post("https://traceroute-online.com/query", data={
        "target": ip,
        "query_type": "mtr"
    })
    return jsonify(data)

traceroute_scan("1.1.1.1")
