#!/usr/bin/env python3
"""Search files/folders for the lab's indicators of compromise (data/iocs.json).

Usage:
    python src/scan_iocs.py path [path ...] [--iocs data/iocs.json]

Files are only READ as bytes, never executed. Read-only triage helper.
"""
import argparse
import json
import os

DEFAULT_IOCS = os.path.join(os.path.dirname(__file__), "..", "data", "iocs.json")


def load_iocs(path):
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return [(kind, value) for kind, values in data.items() if kind != "_note" for value in values]


def iter_files(paths):
    for p in paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                for n in names:
                    yield os.path.join(root, n)
        else:
            yield p


def scan_file(path, iocs):
    hits = []
    try:
        with open(path, "rb") as handle:
            for no, line in enumerate(handle, 1):
                low = line.lower()
                for kind, value in iocs:
                    if value.lower().encode() in low:
                        hits.append((no, kind, value))
    except OSError:
        pass
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--iocs", default=DEFAULT_IOCS)
    args = ap.parse_args()
    iocs = load_iocs(args.iocs)
    total = 0
    for f in iter_files(args.paths):
        for no, kind, value in scan_file(f, iocs):
            total += 1
            print(f"{f}:{no}: [{kind}] {value}")
    print(f"{total} indicator hit(s)")


if __name__ == "__main__":
    main()
