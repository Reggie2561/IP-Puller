router = "192.168.1.1"

parts = router.split(".")   # ["192", "168", "1", "1"]
subnet = ".".join(parts[:3]) + ".0/24"

print(subnet)