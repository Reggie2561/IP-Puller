

def Store_ip(ip_address):
    with open("test.txt", "a") as ip_file:
        ip_file.write(f"{ip_address}+")
        ip_file.close()

def reset_ip():
    with open("test.txt", "w") as ip_file:
        ip_file.write("")
        ip_file.close()

def remove_ip(ip_address):
    with open("test.txt", "r") as ip_file:
        data = ip_file.read()
        ip_file.close()
        with open("test.txt", "w") as ip_file:
            ip_file.write(data.replace(f"{ip_address}+", ""))
            ip_file.close()

def retrieve_ip():
    with open("test.txt", "r") as ip_file:
        data = ip_file.read()
        new_data = (data.split("+"))
        ip_file.close()
        return tuple(new_data)






