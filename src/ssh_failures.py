#!/usr/bin/env python3
"""Q2-Q4: count SSH attempts, failures and successes from a Zeek ssh.log.

Equivalent to the Zui query:  _path=="ssh" | count() by auth_success

Usage:
    python src/ssh_failures.py path/to/ssh.log [--json]

Note: SSH is encrypted, so Zeek *infers* auth_success. A value of ``null``
(unknown) is counted as a failed attempt, which matches the lab answer.
"""
import argparse
import json
from collections import Counter

from zeek_utils import is_true, read_zeek


def summarize(records):
    total = successes = 0
    sources = Counter()
    for rec in records:
        total += 1
        successes += is_true(rec.get("auth_success"))
        sources[rec.get("id.orig_h")] += 1
    return {
        "total_attempts": total,
        "successful": successes,
        "failed": total - successes,
        "top_sources": sources.most_common(5),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log", help="Zeek ssh.log (TSV) or JSON-lines export")
    ap.add_argument("--json", action="store_true", help="print JSON")
    args = ap.parse_args()
    result = summarize(read_zeek(args.log))
    if args.json:
        print(json.dumps(result, indent=2))
        return
    print(f"Total SSH attempts : {result['total_attempts']}")
    print(f"Successful         : {result['successful']}")
    print(f"Failed (Q4 answer) : {result['failed']}")
    print("Top source IPs     :")
    for ip, n in result["top_sources"]:
        print(f"  {ip}  ({n} attempts)")


if __name__ == "__main__":
    main()
