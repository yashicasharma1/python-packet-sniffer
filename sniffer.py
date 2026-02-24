from scapy.all import *


def packet_show(packet):
    if packet.haslayer(IP):
        print(packet[IP].src, " - ", packet[IP].dst, end=" ")

        if packet.haslayer(TCP):
            print(", TCP, sport: ", packet[TCP].sport, ", dport: ", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("UDP, sport: ", packet[UDP].sport, ", dport: ", packet[UDP].dport)

        elif packet.haslayer(ICMP):
            print("Protocol: ICMP")
        else:
            print("protocol: Other")
    elif packet.haslayer(ARP):
        print("Protocol: ARP, ", packet[ARP].hwsrc, ", ", packet[ARP].hwdst)


print("Sniffing started...\n")
sniff(prn=packet_show, store=False)