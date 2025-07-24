import os
import subprocess
import sys
from colorama import Fore, Style

def show_banner():
    print(Fore.CYAN + r"""
   ____   ____  _____ _   _   ____   ____  _    _  ____  _____  ______ _____ 
  / __ \ / __ \|  __ \ \ | | |  _ \ / __ \| |  | |/ __ \|  __ \|  ____|  __ \
 | |  | | |  | | |__) |  \| | | |_) | |  | | |  | | |  | | |__) | |__  | |__) |
 | |  | | |  | |  _  /| . ` | |  _ <| |  | | |  | | |  | |  ___/|  __| |  _  / 
 | |__| | |__| | | \ \| |\  | | |_) | |__| | |__| | |__| | |    | |____| | \ \ 
  \____/ \____/|_|  \_\_| \_| |____/ \____/ \____/ \____/|_|    |______|_|  \_\
                                                                             
                🚀 Automated Nmap Scanner
            Made by Subham Lamichhane
    """ + Style.RESET_ALL)

def scan(target, description, *args):
    print(Fore.YELLOW + f"[+] {description}..." + Style.RESET_ALL)
    command = ["nmap"] + list(args) + [target]
    subprocess.run(command)

def main():
    show_banner()
    if len(sys.argv) < 2:
        print("Usage: python3 auto_nmap.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    scans = [
        ("Ping Scan", "-sn"),
        ("SYN Scan", "-sS"),
        ("TCP Connect Scan", "-sT"),
        ("UDP Scan", "-sU"),
        ("Service Version Detection", "-sV"),
        ("OS Detection", "-O"),
        ("Aggressive Scan", "-A"),
        ("Top 100 Ports Scan", "--top-ports", "100"),
        ("Scan All Ports", "-p-", "-T4"),
        ("Stealth FIN Scan", "-sF"),
        ("Null Scan", "-sN"),
        ("Xmas Scan", "-sX"),
        ("Maimon Scan", "-sM"),
        ("ACK Scan", "-sA"),
        ("Window Scan", "-sW"),
        ("ICMP Echo Disabled", "-Pn"),
        ("Traceroute Enabled", "--traceroute"),
        ("Scan with Default Scripts", "-sC"),
        ("Script Scan (Vuln)", "--script=vuln"),
        ("Script Scan (Brute)", "--script=brute"),
        ("Script Scan (Auth)", "--script=auth"),
        ("Script Scan (Malware)", "--script=malware"),
        ("Spoofed MAC", "--spoof-mac", "0"),
        ("Decoy Scan", "-D", "RND:10"),
        ("Fragmented Packets", "-f"),
        ("Aggressive Timing", "-T5"),
        ("Polite Timing", "-T0"),
        ("Min Rate 100pps", "--min-rate", "100"),
        ("Max Retries 2", "--max-retries", "2"),
        ("DNS Resolution Disabled", "-n"),
        ("Use System DNS", "--system-dns"),
        ("Grepable Output", "-oG", "scan.grep"),
        ("XML Output", "-oX", "scan.xml"),
        ("All Output Formats", "-oA", "fullscan"),
        ("TCP Idle Scan", "-sI", "192.168.1.100"),  # Change dummy IP
        ("FTP Bounce Scan", "-b", "ftp.example.com"),  # Change dummy server
        ("Timing Template T3", "-T3"),
        ("Fragmented with Decoy", "-f", "-D", "192.168.1.100"),
        ("Scan Specific Port", "-p", "22"),
        ("Top 2000 Ports", "--top-ports", "2000"),
        ("Scan with Intense OS Guessing", "-O", "--osscan-guess"),
        ("List Scan (no packets sent)", "-sL"),
        ("Random Target Scan", "-iR", "5"),
        ("Read Targets from File", "-iL", "targets.txt"),
        ("Exclude IPs", "--exclude", "192.168.1.1"),
        ("Aggressive with Traceroute", "-A", "--traceroute"),
        ("Timing with Parallelism", "--min-parallelism", "50"),
        ("Idle Scan on Port 80", "-sI", "192.168.1.100", "-p", "80"),
        ("Bad Checksum Scan", "--badsum"),
        ("Packet Trace Enabled", "--packet-trace"),
    ]

    for description, *args in scans[:50]:
        try:
            scan(target, description, *args)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted." + Style.RESET_ALL)
            break
main()
