"""Tiny helpers for reading Zeek logs.

Supports both formats you will meet in this lab:
  * Zeek TSV logs (``ssh.log``, ``http.log`` with ``#fields`` header lines)
  * JSON-lines exports (for example, query results exported from Zui)

Nested keys are flattened, so ``{"id": {"orig_h": "1.2.3.4"}}`` becomes
``record["id.orig_h"]`` in both formats.
"""
import json

TRUE_VALUES = {"t", "true", "1", "yes"}


def is_true(value):
    """Return True for Zeek/JSON truthy values (T, true, True, 1)."""
    return value is True or str(value).strip().lower() in TRUE_VALUES


def _flatten(data, prefix=""):
    flat = {}
    for key, value in data.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            flat.update(_flatten(value, name + "."))
        else:
            flat[name] = value
    return flat


def read_zeek(path):
    """Yield one flat dict per log record in ``path``."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        lines = [ln.rstrip("\n") for ln in handle if ln.strip()]
    if not lines:
        return
    if lines[0].lstrip().startswith("{"):          # JSON lines
        for line in lines:
            yield _flatten(json.loads(line))
        return
    fields = []                                    # Zeek TSV
    for line in lines:
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#"):
            continue
        else:
            values = line.split("\t")
            record = {}
            for name, value in zip(fields, values):
                record[name] = None if value == "-" else ("" if value == "(empty)" else value)
            yield record
