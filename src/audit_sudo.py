#!/usr/bin/env python3
"""Q5-Q6: which cracked accounts also have sudo rights?

Inputs:
  * John the Ripper output (what ``john`` prints, e.g. ``forgot (manager)``,
    or ``john --show`` lines such as ``manager:forgot:...``)
  * sudoers.log (lines such as ``sean ALL=(ALL) ALL``)

Passwords are masked unless you pass --reveal (keep real credentials out of
screenshots and out of the repository).

Usage:
    python src/audit_sudo.py john_output.txt sudoers.log [--reveal]
"""
import argparse
import re

PAREN = re.compile(r"^(?P<pw>\S+)\s+\((?P<user>[^)\s]+)\)\s*$")
COLON = re.compile(r"^(?P<user>[^:\s#]+):(?P<pw>[^:\s]+)(:.*)?$")
SUDO = re.compile(r"^(?P<user>[A-Za-z_][\w.-]*)\s+\S+\s*=\s*\(.*\)")


def parse_john(text):
    cracked = {}
    for line in text.splitlines():
        line = line.strip()
        m = PAREN.match(line) or COLON.match(line)
        if m:
            cracked[m["user"]] = m["pw"]
    return cracked


def parse_sudoers(text):
    users = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "%", "Defaults")):
            continue
        m = SUDO.match(line)
        if m:
            users.add(m["user"])
    return users


def audit(cracked, sudo_users):
    return sorted(set(cracked) & sudo_users)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("john_output")
    ap.add_argument("sudoers")
    ap.add_argument("--reveal", action="store_true", help="show cracked passwords")
    args = ap.parse_args()
    cracked = parse_john(open(args.john_output, encoding="utf-8", errors="replace").read())
    sudo = parse_sudoers(open(args.sudoers, encoding="utf-8", errors="replace").read())
    print(f"Cracked accounts ({len(cracked)}): {', '.join(sorted(cracked))}")
    print(f"Sudo accounts    ({len(sudo)}): {', '.join(sorted(sudo))}")
    print("Weak password AND sudo rights:")
    for user in audit(cracked, sudo):
        print(f"  {user}:{cracked[user] if args.reveal else '********'}")


if __name__ == "__main__":
    main()
