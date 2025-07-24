import subprocess
import sys
from colorama import Fore, Style, init

init(autoreset=True)

def show_banner():
    print(Fore.CYAN + r"""
   ____   ____  _____ _   _   ____   ____  _    _  ____  _____  ______ _____ 
  / __ \ / __ \|  __ \ \ | | |  _ \ / __ \| |  | |/ __ \|  __ \|  ____|  __ \
 | |  | | |  | | |__) |  \| | | |_) | |  | | |  | | |  | | |__) | |__  | |__) |
 | |  | | |  | |  _  /| . ` | |  _ <| |  | | |  | | |  | |  ___/|  __| |  _  / 
 | |__| | |__| | | \ \| |\  | | |_) | |__| | |__| | |__| | |    | |____| | \ \ 
  \____/ \____/|_|  \_\_| \_| |____/ \____/ \____/ \____/|_|    |______|_|  \_\
                                                                             
                🚀 OPEN SOURCE Automated Nmap Scanner
                     Made by Subham Lamichhane
    """)

scans = [
    # --- Stealth scans ---
    ("Stealth SYN Scan", ["-sS"]),
    ("TCP Connect Scan", ["-sT"]),
    ("UDP Scan", ["-sU"]),
    ("FIN Scan", ["-sF"]),
    ("NULL Scan", ["-sN"]),
    ("XMAS Scan", ["-sX"]),
    ("Maimon Scan", ["-sM"]),
    ("ACK Scan", ["-sA"]),
    ("Window Scan", ["-sW"]),
    ("Idle Scan (requires zombie host)", ["-sI", "192.168.1.100"]),

    # --- Discovery scans ---
    ("Ping Scan (host discovery only)", ["-sn"]),
    ("ARP Ping Scan (local subnet only)", ["-PR"]),
    ("Disable Ping (assume hosts are up)", ["-Pn"]),
    ("ICMP Echo Ping", ["-PE"]),
    ("TCP SYN Ping to port 80", ["-PS80"]),
    ("TCP ACK Ping to port 443", ["-PA443"]),
    ("UDP Ping to port 53", ["-PU53"]),
    ("Traceroute Enabled", ["--traceroute"]),

    # --- Version & OS detection ---
    ("Service Version Detection", ["-sV"]),
    ("Aggressive Version Detection", ["-sV", "--version-intensity", "9"]),
    ("OS Detection", ["-O"]),
    ("OS Detection with OS Guess", ["-O", "--osscan-guess"]),
    ("OS Detection Limited", ["-O", "--osscan-limit"]),

    # --- NSE scripts (default and categories) ---
    ("Default Script Scan", ["-sC"]),
    ("Vulnerability Scripts", ["--script", "vuln"]),
    ("Brute Force Scripts", ["--script", "brute"]),
    ("Auth Scripts", ["--script", "auth"]),
    ("Discovery Scripts", ["--script", "discovery"]),
    ("Malware Scripts", ["--script", "malware"]),
    ("Safe Scripts", ["--script", "safe"]),
    ("Intrusive Scripts", ["--script", "intrusive"]),
    ("Exploit Scripts", ["--script", "exploit"]),

    # --- Port ranges ---
    ("Scan Top 100 TCP Ports", ["--top-ports", "100"]),
    ("Scan Top 1000 TCP Ports", ["--top-ports", "1000"]),
    ("Scan All Ports", ["-p-", "-T4"]),
    ("Scan Ports 1-1024", ["-p", "1-1024"]),
    ("Scan Ports 80,443,8080", ["-p", "80,443,8080"]),

    # --- Timing and performance ---
    ("Timing Template 0 (Paranoid)", ["-T0"]),
    ("Timing Template 1 (Sneaky)", ["-T1"]),
    ("Timing Template 3 (Normal)", ["-T3"]),
    ("Timing Template 5 (Insane)", ["-T5"]),
    ("Max Retries 1", ["--max-retries", "1"]),
    ("Min Rate 1000 packets per second", ["--min-rate", "1000"]),

    # --- Evasion and spoofing ---
    ("Fragment Packets", ["-f"]),
    ("Spoof MAC Address (0)", ["--spoof-mac", "0"]),
    ("Use Decoys (random 5)", ["-D", "RND:5"]),
    ("Use Fake Source Port 53", ["--source-port", "53"]),

    # --- Output options ---
    ("Normal Output", ["-oN", "scan_normal.txt"]),
    ("XML Output", ["-oX", "scan.xml"]),
    ("Grepable Output", ["-oG", "scan_grep.txt"]),
    ("All Formats Output", ["-oA", "scan_all"]),

    # --- Firewall evasion ---
    ("Bad Checksum Packets", ["--badsum"]),
    ("IP Options (LSRR)", ["--ip-options", "lsrr"]),
    ("TTL 64", ["--ttl", "64"]),

    # --- More NSE scripts for specific services ---
    ("HTTP Enumeration Scripts", ["--script", "http-enum"]),
    ("HTTP Vulnerability Scripts", ["--script", "http-vuln*"]),
    ("SSH Enumeration Scripts", ["--script", "ssh-hostkey,ssh-auth-methods"]),
    ("FTP Enumeration Scripts", ["--script", "ftp-anon,ftp-vsftpd-backdoor"]),
    ("DNS Enumeration Scripts", ["--script", "dns-zone-transfer,dns-recursion"]),
    ("SMB Enumeration Scripts", ["--script", "smb-enum*"]),
    ("SNMP Enumeration Scripts", ["--script", "snmp-info,snmp-interfaces"]),

    # --- Misc scans ---
    ("UDP Scan Top 100 Ports", ["-sU", "--top-ports", "100"]),
    ("TCP SYN Scan + OS Detection + Version", ["-sS", "-O", "-sV"]),
    ("Aggressive Scan (OS + Version + Scripts + Traceroute)", ["-A"]),
    ("Comprehensive Scan (all TCP ports, OS, Version, Scripts)", ["-p-", "-A"]),

    # ---CCTV RTSP scan ---
    ("CCTV RTSP Scan (Port 554) with RTSP NSE scripts",
     ["-p", "554", "--script", "rtsp-url-brute,rtsp-methods,rtsp-server-state,media-info"]),

    # --- More port specific scans ---
    ("Scan Ports 21,22,23,25,53", ["-p", "21,22,23,25,53"]),
    ("Scan Ports 80,443,8000,8080,8443", ["-p", "80,443,8000,8080,8443"]),
    ("Scan Ports 3306,3389,5900,8080", ["-p", "3306,3389,5900,8080"]),

    # --- More NSE script categories ---
    ("Malware + Vulnerability Scripts", ["--script", "malware,vuln"]),
    ("Brute + Auth Scripts", ["--script", "brute,auth"]),
    ("Discovery + Safe Scripts", ["--script", "discovery,safe"]),
    ("Intrusive + Exploit Scripts", ["--script", "intrusive,exploit"]),

    # --- Combine timing and evasion ---
    ("Aggressive + Fragmentation", ["-T5", "-f"]),
    ("Sneaky + Decoys", ["-T1", "-D", "RND:5"]),
    ("Normal + Spoof MAC", ["-T3", "--spoof-mac", "0"]),
    ("Paranoid + Bad Checksum", ["-T0", "--badsum"]),

    # --- Additional scans with NSE script subsets ---
    ("HTTP Scripts (enum, vuln, bruteforce)", ["--script", "http-enum,http-vuln*,http-brute"]),
    ("SMB Scripts (enum, vuln)", ["--script", "smb-enum*,smb-vuln*"]),
    ("DNS Scripts (zone-transfer, recursion, srv)", ["--script", "dns-zone-transfer,dns-recursion,dns-srv-service"]),
    ("SNMP Scripts (info, brute)", ["--script", "snmp-info,snmp-brute"]),
    ("SSH Scripts (hostkey, brute)", ["--script", "ssh-hostkey,ssh-brute"]),

    # --- More miscellaneous scans ---
    ("Traceroute + Verbose", ["--traceroute", "-v"]),
    ("Scan with Packet Trace", ["--packet-trace"]),
    ("Scan with Verbose Output", ["-v"]),
    ("Scan with Very Verbose Output", ["-vv"]),
    ("Scan with Debug Output", ["-d"]),

    # --- Scan with timing tweaks ---
    ("Timing 4 + Max Retries 2", ["-T4", "--max-retries", "2"]),
    ("Timing 2 + Min Rate 100", ["-T2", "--min-rate", "100"]),
    ("Timing 3 + Max RTT Timeout 100ms", ["-T3", "--max-rtt-timeout", "100ms"]),

    # --- Scan with spoofed ports ---
    ("Spoof Source Port 53 + Fragment", ["--source-port", "53", "-f"]),
    ("Decoys + TTL 64", ["-D", "RND:3", "--ttl", "64"]),

    # --- More port focused scans ---
    ("Scan UDP Ports 53,67,123", ["-sU", "-p", "53,67,123"]),
    ("Scan TCP Ports 22,80,443,8080", ["-p", "22,80,443,8080"]),

    # --- Scripts for specific vulnerabilities ---
    ("Heartbleed Vulnerability Script", ["--script", "ssl-heartbleed"]),
    ("Shellshock Vulnerability Script", ["--script", "http-shellshock"]),
    ("SMB Vulnerability Scripts", ["--script", "smb-vuln*"]),
    ("Apache Struts Vulnerability Scripts", ["--script", "http-vuln-cve2017-5638"]),

    # --- Misc advanced scans ---
    ("IP Protocol Scan", ["-sO"]),
    ("Version Intensity 9", ["-sV", "--version-intensity", "9"]),
    ("Service Info NSE Script", ["--script", "service-info"]),

    # --- Scan with NSE scripts targeting specific CVEs ---
    ("NSE Scripts for CVE-2020-5902 (F5 BIG-IP)", ["--script", "http-vuln-cve2020-5902"]),
    ("NSE Scripts for CVE-2017-5638 (Apache Struts)", ["--script", "http-vuln-cve2017-5638"]),
]

def list_scans():
    print(Fore.MAGENTA + "\nAvailable Scans:\n" + Style.RESET_ALL)
    for i, (desc, _) in enumerate(scans, 1):
        print(f"{i:03}) {desc}")

def run_scan(target, scan_args, desc):
    print(Fore.YELLOW + f"\n[Running] Scan: {desc}" + Style.RESET_ALL)
    command = ["nmap"] + scan_args + [target]
    subprocess.run(command)

def main():
    show_banner()

    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    while True:
        list_scans()
        choice = input(Fore.CYAN + "\nEnter scan number or 'q' to quit: " + Style.RESET_ALL).strip()
        if choice.lower() == "q":
            print(Fore.GREEN + "Exiting. Happy scanning!" + Style.RESET_ALL)
            break

        if not choice.isdigit() or not (1 <= int(choice) <= len(scans)):
            print(Fore.RED + "Invalid selection, try again." + Style.RESET_ALL)
            continue

        idx = int(choice) - 1
        desc, args = scans[idx]
        run_scan(target, args, desc)

if __name__ == "__main__":
    main()
