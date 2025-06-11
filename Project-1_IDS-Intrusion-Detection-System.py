from scapy.all import *
from scapy.layers.dhcp import DHCP
import threading
import time
import winsound

def alert_beep():
    winsound.Beep(2000, 700)

def mac_flood_detector():
    mac_packet_counts = {}
    threshold = 100
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, mac_packet_counts
        if Ether in packet:
            mac_src = packet[Ether].src
            mac_packet_counts[mac_src] = mac_packet_counts.get(mac_src, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_packets = sum(mac_packet_counts.values())
            if total_packets > threshold:
                print(f"[MAC Flood] ---- Detected {total_packets} MAC packets in interval --> possible flooding!")
                alert_beep()
            else:
                print(f"[MAC Flood] ----{total_packets}---- MAC packets --> Normal traffic")
            mac_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", prn=detect, store=0)

def tcp_syn_flood_detector():
    tcp_packet_counts = {}
    threshold = 200
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, tcp_packet_counts
        if packet.haslayer(TCP) and packet.haslayer(IP):
            tcp_layer = packet[TCP]
            if tcp_layer.flags == 'S':
                src_ip = packet[IP].src
                tcp_packet_counts[src_ip] = tcp_packet_counts.get(src_ip, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_syn_packets = sum(tcp_packet_counts.values())
            if total_syn_packets > threshold:
                print(f"[TCP SYN Flood]  Detected {total_syn_packets} SYN packets --> possible flooding!")
                alert_beep()
            else:
                print(f"[TCP SYN Flood] {total_syn_packets} SYN packets - Normal traffic")
            tcp_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", filter="tcp", prn=detect, store=0)

def udp_flood_detector():
    udp_packet_counts = {}
    threshold = 200
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, udp_packet_counts
        if packet.haslayer(UDP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            udp_packet_counts[src_ip] = udp_packet_counts.get(src_ip, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_udp_packets = sum(udp_packet_counts.values())
            if total_udp_packets > threshold:
                print(f"[UDP Flood]  Detected {total_udp_packets} UDP packets --> possible flooding!")
                alert_beep()
            else:
                print(f"[UDP Flood] {total_udp_packets} UDP packets --> Normal traffic")
            udp_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", filter="udp", prn=detect, store=0)

def icmp_flood_detector():
    icmp_packet_counts = {}
    threshold = 100
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, icmp_packet_counts
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            icmp_packet_counts[src_ip] = icmp_packet_counts.get(src_ip, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_icmp_packets = sum(icmp_packet_counts.values())
            if total_icmp_packets > threshold:
                print(f"[ICMP Flood]  Detected {total_icmp_packets} ICMP packets - possible flooding!")
                alert_beep()
            else:
                print(f"[ICMP Flood] {total_icmp_packets} ICMP packets --> Normal traffic")
            icmp_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", filter="icmp", prn=detect, store=0)

def arp_flood_detector():
    arp_packet_counts = {}
    threshold = 100
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, arp_packet_counts
        if packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            arp_packet_counts[src_ip] = arp_packet_counts.get(src_ip, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_arp_packets = sum(arp_packet_counts.values())
            if total_arp_packets > threshold:
                print(f"[ARP Flood]  Detected {total_arp_packets} ARP packets - possible flooding!")
                alert_beep()
            else:
                print(f"[ARP Flood]  {total_arp_packets} ARP packets -->  Normal traffic")
            arp_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", filter="arp", prn=detect, store=0)

def dhcp_starvation_detector():
    dhcp_packet_counts = {}
    threshold = 50
    interval = 5
    last_time = time.time()

    def detect(packet):
        nonlocal last_time, dhcp_packet_counts
        if packet.haslayer(DHCP):
            mac = packet[Ether].src
            dhcp_packet_counts[mac] = dhcp_packet_counts.get(mac, 0) + 1

        current_time = time.time()
        if current_time - last_time > interval:
            total_dhcp_packets = sum(dhcp_packet_counts.values())
            if total_dhcp_packets > threshold:
                print(f"[DHCP Starvation]  Detected {total_dhcp_packets} DHCP packets --> possible starvation!")
                alert_beep()
            else:
                print(f"[DHCP Starvation]  {total_dhcp_packets} DHCP packets --> Normal traffic")
            dhcp_packet_counts.clear()
            last_time = current_time

    sniff(iface="Wi-Fi", filter="udp and (port 67 or 68)", prn=detect, store=0)

def deauth_flood_detector():
    deauth_count = 0
    threshold = 30
    interval = 5
    last_time = time.time()

    def detect(pkt):
        nonlocal deauth_count, last_time
        if pkt.haslayer(Dot11):
            if pkt.type == 0 and pkt.subtype == 12:  # Deauth frame
                deauth_count += 1

        current_time = time.time()
        if current_time - last_time > interval:
            if deauth_count > threshold:
                print(f"[Deauth Flood] ☣️ Detected {deauth_count} Deauthentication frames --> possible flooding!")
                alert_beep()
            else:
                print(f"[Deauth Flood] ✅ {deauth_count} Deauthentication frames --> Normal traffic")
            deauth_count = 0
            last_time = current_time

    sniff(iface="Wi-Fi", prn=detect, store=0)

# --- Thread Starters (Same Style as Your Code) ---
mac_thread = threading.Thread(target=mac_flood_detector)
tcp_thread = threading.Thread(target=tcp_syn_flood_detector)
udp_thread = threading.Thread(target=udp_flood_detector)
icmp_thread = threading.Thread(target=icmp_flood_detector)
arp_thread = threading.Thread(target=arp_flood_detector)
dhcp_thread = threading.Thread(target=dhcp_starvation_detector)
deauth_thread = threading.Thread(target=deauth_flood_detector)

mac_thread.start()
tcp_thread.start()
udp_thread.start()
icmp_thread.start()
arp_thread.start()
dhcp_thread.start()
deauth_thread.start()
