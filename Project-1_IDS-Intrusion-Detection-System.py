from scapy.all import Ether, sniff
import time
import winsound
mac = set()
starting_time = time.time()
stopping_timer = 5
threshold = 4

def mac_sniffer(packet):
    global starting_time, mac

    if Ether in packet:
        mac_src = packet[Ether].src
        mac.add(mac_src)

        current_time = time.time()
        if current_time - starting_time > stopping_timer:
            if len(mac) > threshold:
                print(f"Found {len(mac)} macs  in Your Internet ")
                winsound.Beep(1500,5000)
            else:
                print("No MAC flooding detected.")
                print(f"Found {len(mac)} macs in Your Internet ")

            mac.clear()
            starting_time = current_time

sniff(iface="Wi-Fi", prn=mac_sniffer)
        
    
