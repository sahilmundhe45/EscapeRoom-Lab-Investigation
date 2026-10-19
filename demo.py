#!/usr/bin/env python3
"""Run every tool once on the synthetic sample data (works on Windows, macOS, Linux)."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(ROOT, "data", "sample")
SRC = os.path.join(ROOT, "src")

STEPS = [
    ("Q2-Q4  SSH brute-force counts", ["ssh_failures.py", os.path.join(S, "ssh.log")]),
    ("Q5-Q6  Weak passwords with sudo rights", ["audit_sudo.py", os.path.join(S, "john_output.txt"), os.path.join(S, "sudoers.log")]),
    ("Q7-Q8, Q16  HTTP downloads", ["http_downloads.py", os.path.join(S, "http.log")]),
    ("Q9     File hashes (of the sample ssh.log)", ["hash_check.py", os.path.join(S, "ssh.log")]),
    ("Q12    Missing path in ps.log", ["ps_check.py", os.path.join(S, "ps.log")]),
    ("Q17    Decode command constants", ["decode_commands.py"]),
    ("IOC    Scan sample logs for indicators", ["scan_iocs.py", S]),
]

for title, cmd in STEPS:
    print(f"\n=== {title} ===")
    subprocess.run([sys.executable, os.path.join(SRC, cmd[0])] + cmd[1:], check=True)
