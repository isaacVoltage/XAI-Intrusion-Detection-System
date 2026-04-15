from scapy.all import sniff, conf

# Dynamically find the correct interface by its IP address
def find_vbox_interface():
    for iface in conf.ifaces.values():
        # Check if this interface has the IP you found earlier
        if iface.ip == "192.168.29.194": # Temporarily use your active Wi-Fi IP
            return iface
    return None

target_iface = find_vbox_interface()

if target_iface:
    print(f"Success! Found Interface: {target_iface.description}")
    print(f"Internal Name: {target_iface.name}")
    print("Sniffing for 10 seconds... Send pings from Kali now.")
    sniff(iface=target_iface, prn=lambda x: print(x.summary()), timeout=10)
else:
    print("Error: Could not find an interface with IP 192.168.56.1.")
    print("Current available IPs are:", [i.ip for i in conf.ifaces.values() if i.ip])