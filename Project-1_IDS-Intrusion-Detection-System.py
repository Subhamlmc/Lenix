from scapy.all import Ether, sniff , TCP,IP
import time
import winsound
import threading
starting_time = time.time()
stopping_timer = 5
def mac_sniffer(packet):
    global starting_time
    global stopping_timer 
    threshold = 4
    mac_collector = set()

    if Ether in packet:
        mac_src = packet[Ether].src
        mac_collector.add(mac_src)

        current_time = time.time()
        if current_time - starting_time > stopping_timer:
            if len(mac_collector) > threshold:
                print(f"Found {len(mac_collector)} macs  in Your Internet ")
            else:
                print("No MAC flooding detected.")
                print(f"Found {len(mac_collector)} macs in Your Internet ")

            mac_collector.clear()
            starting_time = current_time
tcp_collector = set()
starting_time = time.time()
stopping_timer = 10  
threshold_for_tcp = 15 

def tcp_detector(packet):
    global starting_time

    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp_layer = packet[TCP]
        if tcp_layer.flags == 'S':
            ip_src = packet[IP].src
            tcp_collector.add(ip_src)

        current_time_for_tcp = time.time()
        if current_time_for_tcp - starting_time > stopping_timer:
            if len(tcp_collector) > threshold_for_tcp:
                print(f" High TCP SYN activity! Found {len(tcp_collector)} unique IPs sending SYN packets.")
                winsound.beep(1500, 4000)
            else:
                print(" No TCP SYN flooding detected.")
                print(f"Found {len(tcp_collector)} unique SYN sources.")

            tcp_collector.clear()
            starting_time = current_time_for_tcp

def thread_for_mac():
    sniff(iface="Wi-Fi", prn=mac_sniffer,store=0)
def thread_for_tcp():
    sniff(iface="Wi-Fi",filter="tcp",store=0,prn=tcp_detector)

mac_thread=threading.Thread(target=thread_for_mac)
tcp_thread=threading.Thread(target=thread_for_tcp)



mac_thread.start()
tcp_thread.start()
        
    
