#!/usr/bin/env python3
"""Q9: compute MD5 / SHA-1 / SHA-256 of a file, never executing it.

Usage:
    python src/hash_check.py sample_file [--expect-md5 772b620736b760c1d736b1e6ba2f885b]

A matching hash only shows it is the same file as a known sample; it does not
by itself prove the file is malicious.
"""
import argparse
import hashlib


def file_hashes(path, chunk=1024 * 1024):
    digests = {n: hashlib.new(n) for n in ("md5", "sha1", "sha256")}
    with open(path, "rb") as handle:
        while block := handle.read(chunk):
            for d in digests.values():
                d.update(block)
    return {n: d.hexdigest() for n, d in digests.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("file")
    ap.add_argument("--expect-md5", help="compare against a known MD5")
    args = ap.parse_args()
    for name, value in file_hashes(args.file).items():
        print(f"{name.upper():7}: {value}")
        if name == "md5" and args.expect_md5:
            same = value.lower() == args.expect_md5.lower()
            print(f"         matches expected MD5: {'YES' if same else 'NO'}")


if __name__ == "__main__":
    main()
