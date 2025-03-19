from scapy.all import sniff, wrpcap

packets = []

def packet_callback(packet):
	packets.append(packet)
	print(packet.summary())

sniff(prn=packet_callback, store=False, iface="eth0")
wrpcap("captured_traffic.pcap", packets)
print("Packets saved to captured_traffic.pcap")

