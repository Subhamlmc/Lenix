import random
import subprocess
import time

def generate_valid_mac():
    first_byte = random.randint(0x00, 0xff)
    first_byte = (first_byte & 0b11111110) | 0b00000010
    mac = [first_byte] + [random.randint(0x00, 0xff) for _ in range(5)]
    return ":".join(f"{x:02x}" for x in mac)

interface = "wlan0" #select one which is in monitor mode like the adapter's one

while True:
    new_mac = generate_valid_mac()
    print(f"Changing MAC to: {new_mac}")
    subprocess.run(["sudo", "ifconfig", interface, "down"])
    subprocess.run(["sudo", "ifconfig", interface, "hw", "ether", new_mac])
    subprocess.run(["sudo", "ifconfig", interface, "up"])
    time.sleep(10) 
