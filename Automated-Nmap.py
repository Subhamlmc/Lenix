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
        print("Usage: python3 auto_nmap_100.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    scans = [
        # Basic
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
        ("No Ping (All hosts up)", "-Pn"),
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
        ("Disable DNS Resolution", "-n"),
        ("Use System DNS", "--system-dns"),
        ("Grepable Output", "-oG", "scan.grep"),
        ("XML Output", "-oX", "scan.xml"),
        ("All Output Formats", "-oA", "fullscan"),
        ("TCP Idle Scan", "-sI", "192.168.1.100"),
        ("FTP Bounce Scan", "-b", "ftp.example.com"),
        ("Timing Template T3", "-T3"),
        ("Fragmented with Decoy", "-f", "-D", "192.168.1.100"),
        ("Scan Port 22 Only", "-p", "22"),
        ("Top 2000 Ports", "--top-ports", "2000"),
        ("Guess OS Aggressively", "-O", "--osscan-guess"),
        ("List Targets Only", "-sL"),
        ("Random Targets", "-iR", "5"),
        ("Read From File", "-iL", "targets.txt"),
        ("Exclude IP", "--exclude", "192.168.1.1"),
        ("Traceroute + Aggressive", "-A", "--traceroute"),
        ("Parallelism Level 50", "--min-parallelism", "50"),
        ("Idle Scan on Port 80", "-sI", "192.168.1.100", "-p", "80"),
        ("Bad Checksum", "--badsum"),
        ("Enable Packet Trace", "--packet-trace"),
        ("Reason Reporting", "--reason"),
        ("Only Show Open Ports", "--open"),
        ("Use TCP ACK Ping", "-PA"),
        ("Use UDP Ping", "-PU"),
        ("Use ICMP Timestamp Ping", "-PP"),
        ("Use ICMP Netmask Ping", "-PM"),
        ("Set TTL", "--ttl", "64"),
        ("Scan with Version Light", "--version-light"),
        ("Scan with Version All", "--version-all"),
        ("Scan Top 10 Ports", "--top-ports", "10"),
        ("Scan Top 1000 UDP", "-sU", "--top-ports", "1000"),
        ("Scan TCP Ports 1-1024", "-sS", "-p", "1-1024"),
        ("Scan Ports 80,443,8080", "-p", "80,443,8080"),
        ("Randomize Ports", "--randomize-hosts"),
        ("Increase Max Scan Delay", "--scan-delay", "1s"),
        ("Scan Delay 100ms", "--scan-delay", "100ms"),
        ("Limit Host Timeout", "--host-timeout", "10m"),
        ("Force IP Scan", "--send-ip"),
        ("Set Source Port", "--source-port", "53"),
        ("Aggressive Script Timing", "--script-args", "timing=aggressive"),
        ("Detect Firewall", "-sA"),
        ("Service Fingerprint", "-sV", "--version-intensity", "9"),
        ("Enable ICMP Echo", "-PE"),
        ("Use DNS Servers", "--dns-servers", "8.8.8.8"),
        ("Scan With Specific Interface", "-e", "eth0"),
        ("Add IP Options", "--ip-options", "LSRR"),
        ("Enable Verbose Output", "-v"),
        ("Increase Verbosity", "-vv"),
        ("Debug Level 1", "-d"),
        ("Debug Level 3", "-d3"),
        ("Scan With Script Trace", "--script-trace"),
        ("Scan With Updated NSE DB", "--script-updatedb"),
        ("Show Script Help", "--script-help=ssl-heartbleed"),
        ("Output with Style", "--stylesheet", "nmap.xsl"),
        ("Force IPv6", "-6"),
        ("Use IPv6 with Aggressive", "-6", "-A"),
        ("Show Interface List", "--iflist"),
        ("Scan Port Range with Tuning", "-T2", "-p", "1-500"),
        ("OS Detection with Limit", "--osscan-limit"),
        ("Use Custom MTU", "--mtu", "24"),
        ("Output in Normal Format", "-oN", "output.txt"),
        ("Aggressive Timing With All Ports", "-T5", "-p-"),
        ("Use NSE Safe Category", "--script", "safe"),
        ("Use NSE Default Category", "--script", "default"),
        ("Brute FTP Login", "--script", "ftp-brute"),
        ("Scan Tor Exit Node", "--proxies", "socks4://127.0.0.1:9050"),
        ("Scan with ARP Ping", "-PR"),
        ("Scan with IPv6 Traceroute", "-6", "--traceroute"),
        ("TCP Window Scan on Port 445", "-sW", "-p", "445"),
        ("Detect RDP Service", "--script", "rdp-enum-encryption"),
        ("HTTP Title Grab", "--script", "http-title"),
        ("SMTP User Enum", "--script", "smtp-enum-users"),
        ("DNS Zone Transfer", "--script", "dns-zone-transfer")
    ]

    for index, (description, *args) in enumerate(scans[:100], start=1):
        try:
            print(Fore.CYAN + f"\n[Scan {index}/100]" + Style.RESET_ALL)
            scan(target, description, *args)
        except KeyboardInterrupt:
            print(Fore.RED + "\n[!] Scan interrupted." + Style.RESET_ALL)
            break
main()
