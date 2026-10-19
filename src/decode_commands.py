#!/usr/bin/env python3
"""Q17: decode the command constants compared inside the malware.

In the disassembly, the malware compares a value against 0x4e4f5000 and
0x52554e3a. Read as big-endian bytes these are ASCII text:
    0x4e4f5000 -> 'N' 'O' 'P' NUL   -> NOP
    0x52554e3a -> 'R' 'U' 'N' ':'   -> RUN
(The same result is produced by CyberChef's "From Hex" recipe.)

Usage:
    python src/decode_commands.py                 # uses the two lab constants
    python src/decode_commands.py 0x4e4f5000 0x52554e3a
"""
import argparse

LAB_CONSTANTS = ["0x4e4f5000", "0x52554e3a"]


def decode_constant(value):
    """Turn a 32-bit constant like 0x4e4f5000 into its raw bytes."""
    number = int(value, 16)
    width = max(4, (number.bit_length() + 7) // 8)
    return number.to_bytes(width, "big")


def command_name(raw):
    """Strip NUL padding and the trailing ':' separator."""
    return raw.decode("ascii", errors="replace").strip("\x00").rstrip(":")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("constants", nargs="*", default=LAB_CONSTANTS)
    args = ap.parse_args()
    names = []
    for const in args.constants:
        raw = decode_constant(const)
        name = command_name(raw)
        names.append(name)
        print(f"{const}  bytes={raw!r}  ->  {name}")
    print("Answer (alphabetical, comma-separated): " + ",".join(sorted(names)))


if __name__ == "__main__":
    main()
