#!/usr/bin/env python3
"""Q7-Q8, Q16: summarise HTTP requests from a Zeek http.log.

Shows the download tool (User-Agent), the first-stage downloads (/d/N) and
the later requests the malware makes (/n/...), grouped by server.

Usage:
    python src/http_downloads.py path/to/http.log
"""
import argparse
import re
from collections import Counter

from zeek_utils import read_zeek

STAGE1 = re.compile(r"^/d/\d+$")   # the three installation files
REMOTE = re.compile(r"^/n/")       # files the malware requests later


def summarize(records):
    gets = [r for r in records if (r.get("method") or "").upper() == "GET"]
    agents = Counter(r.get("user_agent") or "(none)" for r in gets)
    stage1 = [r for r in gets if STAGE1.match(r.get("uri") or "")]
    remote = [r for r in gets if REMOTE.match(r.get("uri") or "")]
    return {
        "get_requests": len(gets),
        "user_agents": agents.most_common(),
        "wget_seen": any("wget" in a.lower() for a in agents),
        "stage1": [(r["host"], r["uri"]) for r in stage1],
        "remote_count": len(remote),
        "remote_by_host": Counter(r["host"] for r in remote).most_common(),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("log", help="Zeek http.log (TSV) or JSON-lines export")
    args = ap.parse_args()
    s = summarize(list(read_zeek(args.log)))
    print(f"GET requests          : {s['get_requests']}")
    print("User-Agents           :")
    for agent, n in s["user_agents"]:
        print(f"  {agent}  x{n}")
    print(f"Wget used (Q7)        : {'YES' if s['wget_seen'] else 'no'}")
    print(f"Stage-1 downloads (Q8): {len(s['stage1'])}")
    for host, uri in s["stage1"]:
        print(f"  {host}{uri}")
    print(f"Later /n/ requests (Q16): {s['remote_count']}")
    for host, n in s["remote_by_host"]:
        print(f"  {host}  x{n}")


if __name__ == "__main__":
    main()
