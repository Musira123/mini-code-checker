import sys

# pattern to look for -> (description, CWE ID)
RULES = {
    "eval(": ("Dangerous eval() use", "CWE-95"),
    "exec(": ("Dangerous exec() use", "CWE-95"),
    "pickle.loads": ("Unsafe deserialization", "CWE-502"),
    "md5": ("Weak hashing algorithm", "CWE-327"),
    "sha1": ("Weak hashing algorithm", "CWE-327"),
    "password =": ("Possible hardcoded password", "CWE-798"),
    "secret =": ("Possible hardcoded secret", "CWE-798"),
    "shell=True": ("Possible command injection", "CWE-78"),
}


def scan_file(filename):
    """Read a file and return a list of findings."""
    findings = []
    with open(filename, encoding="utf-8") as f:
        for number, line in enumerate(f, start=1):
            for pattern, (message, cwe) in RULES.items():
                if pattern in line:
                    findings.append((number, message, cwe, line.strip()))
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 checker.py <file.py>")
        return

    filename = sys.argv[1]
    findings = scan_file(filename)

    print(f"Scanning: {filename}\n")
    for number, message, cwe, code in findings:
        print(f"Line {number}: {message} [{cwe}]")
        print(f"    {code}")

    print(f"\nDone. {len(findings)} possible issue(s) found.")

    # Count findings per CWE
    counts = {}
    for _, _, cwe, _ in findings:
        counts[cwe] = counts.get(cwe, 0) + 1
    if counts:
        print("\nSummary:")
        for cwe, total in counts.items():
            print(f"  {cwe}: {total}")

    # Save a report file
    with open("report.txt", "w", encoding="utf-8") as out:
        for number, message, cwe, code in findings:
            out.write(f"Line {number}: {message} [{cwe}]\n")
    print("\nReport saved to report.txt")


main()
