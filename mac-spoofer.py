import random
import time
import subprocess
alphabet = "ABCDEF"
digits = "0123456789"
blender= alphabet + digits

while True:
    mixer = ""
    for _ in range(6):
        pair = random.choice(blender) + random.choice(blender)
        mixer += pair + ":"
    mixer = mixer.rstrip(":") 
    time.sleep(2)
    subprocess.run(["sudo","ifconfig","Wi-Fi","down"])
    time.sleep(2)
    subprocess.run(["sudo","ifconfig","Wi-Fi","hw","ether",mixer])
    time.sleep(2)
    subprocess.run(["sudo","ifconfig","Wi-Fi","up"])
    time.sleep(15)