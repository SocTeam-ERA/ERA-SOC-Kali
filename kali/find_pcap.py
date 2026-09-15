#!/usr/bin/env python3
"""
find_pcap.py
------------
Look up which .pcap (if any) is attached to recent traffic-related alerts,
so you know exactly what to open in Wireshark for a given alert -- without
needing to read raw JSON by hand.

Usage:
    python3 find_pcap.py                  # last 15 alerts that have a pcap
    python3 find_pcap.py 185.220.101.4    # only alerts matching this text
                                           # (an IP, a title keyword, etc.)
    python3 find_pcap.py --all            # all of them, not just the last 15
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ALERTS_LOG = DATA_DIR / "alerts.jsonl"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("term", nargs="?", default=None,
                    help="only show alerts whose title/description/IP contains this text")
    ap.add_argument("--all", action="store_true", help="show all matches, not just the last 15")
    args = ap.parse_args()

    if not ALERTS_LOG.exists():
        print(f"[!] {ALERTS_LOG} not found.", file=sys.stderr)
        return 1

    term = args.term.lower() if args.term else None
    matches = []
    for line in ALERTS_LOG.read_text().splitlines():
        if not line.strip():
            continue
        a = json.loads(line)
        pcap = a.get("details", {}).get("pcap")
        if not pcap:
            continue
        if term:
            haystack = " ".join(str(a.get(k, "")) for k in
                                ("title", "description", "source_ip", "hostname")).lower()
            if term not in haystack:
                continue
        matches.append(a)

    if not matches:
        print("No alerts with a saved .pcap match that search." if term
              else "No alerts with a saved .pcap yet.")
        return 0

    shown = matches if args.all else matches[-15:]
    for a in shown:
        print(f"{a['timestamp']}  {a['severity'].upper():8} {a['title']}")
        print(f"    pcap: {a['details']['pcap']}")
    if not args.all and len(matches) > len(shown):
        print(f"\n({len(matches) - len(shown)} more not shown -- use --all to see everything)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
