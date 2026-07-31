from scapy.all import IFACES

for iface in IFACES.values():
    print(f"Name: {iface.name}")
    print(f"Description: {iface.description}")
    print(f"GUID: {iface.guid}")
    print("-" * 50)