#!/usr/bin/env python3
"""Q12: is an expected path present in a process listing (ps.log)?

Usage:
    python src/ps_check.py ps.log [--path /var/mail/mail]

If the malware path is NOT in the listing although the malware is installed,
that is consistent with something hiding it (see the sysmod.ko finding).
One snapshot cannot prove concealment on its own.
"""
import argparse


def find_lines(text, needle):
    return [(i, ln) for i, ln in enumerate(text.splitlines(), 1) if needle in ln]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log")
    ap.add_argument("--path", default="/var/mail/mail", help="path to look for")
    args = ap.parse_args()
    text = open(args.log, encoding="utf-8", errors="replace").read()
    hits = find_lines(text, args.path)
    if hits:
        print(f"FOUND {args.path} on {len(hits)} line(s):")
        for no, ln in hits:
            print(f"  {no}: {ln.strip()}")
    else:
        print(f"MISSING: {args.path} does not appear in {args.log}")
        print("-> anomaly: expected entry absent (possible concealment)")


if __name__ == "__main__":
    main()
