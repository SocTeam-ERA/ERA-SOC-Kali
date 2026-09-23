#!/usr/bin/env python3
"""
l2_to_alerts.py
---------------
Runs the l2_watch detectors continuously against Zeek's live logs:

  dhcp.log  -> a DHCP server that is not on the trusted list is handing out addresses
  conn.log  -> a Router Advertisement from an IPv6 router that is not on the trusted list

One process, one thread per log (a tail of a log never returns, so two logs need two
loops). On the very first start it learns the trusted lists from the Zeek history before it
starts watching, so the servers that have always been there do not each raise an alert.

Each follower publishes its parse health (see reader_health.py), so a Zeek format change
shows up as an alert instead of as silence.

Usage:
    python3 l2_to_alerts.py --follow              # continuous (systemd: soc-l2-watch.service)
    python3 l2_to_alerts.py --dhcp-log F --conn-log F   # other paths (tests)
"""
from __future__ import annotations
import argparse, os, sys, threading, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import tail_follow  # noqa: E402
from zeek_tsv import ZeekTSVReader, read_header_lines  # noqa: E402
from reader_health import Reporter  # noqa: E402
import l2_watch  # noqa: E402

DEFAULT_DHCP = Path("/opt/zeek/logs/current/dhcp.log")
DEFAULT_CONN = Path("/opt/zeek/logs/current/conn.log")


def follow(path: Path, name: str, handle, needle: str = "") -> None:
    """Feed every row of `path` (and of the log that replaces it at each hourly rotation) to
    `handle`. `needle` skips lines that cannot matter before parsing them: conn.log is ~10 MB
    an hour and only ICMP rows are of interest."""
    reader = ZeekTSVReader()
    for header in read_header_lines(path):
        reader.feed(header)
    appears_later = not path.exists()      # Zeek creates some logs lazily: read a late one from its first line
    health = Reporter(name, reader)
    for line in tail_follow(path, from_start=appears_later):
        if needle and needle not in line and not line.startswith("#"):
            continue
        row = reader.feed(line)
        health.tick()
        if row:
            handle(row)


def guarded(target, name: str) -> None:
    """A detector thread must outlive any single bad row or transient error."""
    while True:
        try:
            target()
        except Exception as e:  # noqa: BLE001
            print(f"[!] {name}: {type(e).__name__}: {e} -- restarting in 5 s", file=sys.stderr, flush=True)
        time.sleep(5)


def main() -> int:
    ap = argparse.ArgumentParser(description="Zeek dhcp.log/conn.log -> rogue DHCP server / rogue IPv6 router alerts")
    ap.add_argument("--follow", action="store_true", help="run continuously (for the systemd service)")
    ap.add_argument("--dhcp-log", default=str(DEFAULT_DHCP))
    ap.add_argument("--conn-log", default=str(DEFAULT_CONN))
    args = ap.parse_args()

    learned = l2_watch.ensure_baselines()
    if learned:
        print(f"[*] learned the trusted list(s) from the Zeek history: {', '.join(learned)}", flush=True)

    dhcp, ra = l2_watch.DhcpWatch(), l2_watch.RaWatch()
    threads = [
        threading.Thread(target=guarded, name="l2-dhcp", daemon=True,
                         args=(lambda: follow(Path(args.dhcp_log), "l2_dhcp", dhcp.feed), "dhcp")),
        threading.Thread(target=guarded, name="l2-ra", daemon=True,
                         args=(lambda: follow(Path(args.conn_log), "l2_conn", ra.feed, needle="icmp"), "ra")),
    ]
    for t in threads:
        t.start()
    print("[*] l2_to_alerts: watching dhcp.log and conn.log", flush=True)
    while True:               # the threads are daemons: this loop is what keeps the process alive
        time.sleep(3600)


if __name__ == "__main__":
    raise SystemExit(main())
