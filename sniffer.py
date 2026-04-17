from scapy.all import sniff

def process_packet(packet):
	print(packet.summary())

print("starting packet capture ....")

sniff(prn=process_packet ,store =False)
