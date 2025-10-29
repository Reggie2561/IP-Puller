import os

installed = []
required = ["beautifulsoup4", "flask", "requests", "scapy"]
def check():
    with os.popen('pip list') as stdout:
        results = stdout.read().strip().split('\n')
        for result in results:
            if "beautifulsoup4" in result:
                installed.append("beautifulsoup4")
            if "flask" in result:
                installed.append("flask")
            if "scapy" in result:
                installed.append("scapy")
            if "requests" in result:
                installed.append("requests")

    for item in required:
        if item not in installed:
            os.system("pip install " + item)

