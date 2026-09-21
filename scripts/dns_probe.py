#!/usr/bin/env python3
"""
dns_probe.py -- a once-a-minute record of whether this machine can reach its DNS servers
and its gateway, so intermittent network trouble leaves evidence with timestamps.

Why: Claude Code sessions here have shown "Can't reach the API server (EAI_AGAIN)" and
SSH sessions have been reset, and it was not clear whether the network, the DNS servers
or the machine itself was to blame. A record kept every minute answers that afterwards.

Each run (from cron, one line in data/dns_probe.jsonl) checks:
  dns:<server>   a real lookup of PROBE_NAME against each nameserver in /etc/resolv.conf
  resolver       the same lookup through the system resolver (what applications use)
  gateway        one ping to the default gateway
It only sends a few tiny packets a minute to the machine's own DNS servers and gateway.

    python3 dns_probe.py --probe            one check, appended to the log (cron runs this)
    python3 dns_probe.py --report [HOURS]   episodes of failures and gaps with no data
                                            (default: the last 24 hours)
A gap with no data at all means the machine was off or cron was not running (a reboot).
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
LOG = DATA_DIR / "dns_probe.jsonl"
RESOLV = Path(os.environ.get("DNS_PROBE_RESOLV", "/etc/resolv.conf"))
PROBE_NAME = os.environ.get("DNS_PROBE_NAME", "api.anthropic.com")
KEEP_DAYS = 14
DNS_TIMEOUT = 2          # seconds, one try per server
GAP_MINUTES = 3          # no line for this long = the machine (or cron) was down


def nameservers() -> list[str]:
    try:
        return re.findall(r"^\s*nameserver\s+(\S+)", RESOLV.read_text(), re.MULTILINE)
    except OSError:
        return []


def default_gateway() -> str | None:
    try:
        out = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"default via (\S+)", out)
        return m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        return None


def timed(cmd: list, ok_if) -> dict:
    start = time.monotonic()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=DNS_TIMEOUT + 5)
        ok = r.returncode == 0 and bool(ok_if(r.stdout))
    except (OSError, subprocess.SubprocessError):
        ok = False
    return {"ok": ok, "ms": round((time.monotonic() - start) * 1000)}


def probe() -> dict:
    row: dict = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "dns": {}}
    for ns in nameservers():
        row["dns"][ns] = timed(["dig", f"@{ns}", PROBE_NAME, "A", "+short", "+tries=1", f"+time={DNS_TIMEOUT}"],
                               lambda out: re.search(r"\d+\.\d+\.\d+\.\d+", out))
    row["resolver"] = timed(["getent", "hosts", PROBE_NAME], lambda out: out.strip())
    gw = default_gateway()
    if gw:
        row["gateway"] = timed(["ping", "-c1", "-W1", gw], lambda out: True)
        row["gateway"]["ip"] = gw
    return row


def append(row: dict) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    try:
        os.chmod(LOG, 0o664)
    except OSError:
        pass


def prune() -> None:
    """Keep KEEP_DAYS of history; done once an hour, when the minute is 00."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)).isoformat(timespec="seconds")
    try:
        lines = LOG.read_text().splitlines()
    except OSError:
        return
    keep = [ln for ln in lines if ln and json.loads(ln).get("ts", "") >= cutoff]
    if len(keep) != len(lines):
        tmp = LOG.with_suffix(".tmp")
        tmp.write_text("\n".join(keep) + "\n")
        os.replace(tmp, LOG)


def failed_targets(row: dict) -> list[str]:
    bad = [f"dns:{ns}" for ns, r in row.get("dns", {}).items() if not r["ok"]]
    if not row.get("resolver", {}).get("ok", True):
        bad.append("resolver")
    if not row.get("gateway", {}).get("ok", True):
        bad.append("gateway")
    return bad


def report(hours: float) -> str:
    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    rows = []
    try:
        for ln in LOG.read_text().splitlines():
            r = json.loads(ln)
            if r.get("ts", "") >= since:
                rows.append(r)
    except (OSError, ValueError):
        pass
    if not rows:
        return f"no probe data in the last {hours:g} hours (is the cron line installed?)"
    parse = lambda t: datetime.fromisoformat(t)
    out = [f"Probe of {PROBE_NAME}: {len(rows)} checks from {rows[0]['ts']} to {rows[-1]['ts']} (UTC)"]

    # latency per DNS server
    lat: dict = {}
    for r in rows:
        for ns, v in r["dns"].items():
            if v["ok"]:
                lat.setdefault(ns, []).append(v["ms"])
    for ns, v in sorted(lat.items()):
        v.sort()
        out.append(f"  dns {ns}: median {v[len(v) // 2]} ms, p95 {v[int(len(v) * 0.95) - 1] if len(v) > 1 else v[0]} ms")

    # failure episodes: consecutive failing checks (gap <= GAP_MINUTES) become one episode
    episodes, cur = [], None
    for r in rows:
        bad = failed_targets(r)
        t = parse(r["ts"])
        if bad:
            if cur and (t - cur["end"]) <= timedelta(minutes=GAP_MINUTES):
                cur["end"] = t
                cur["n"] += 1
                cur["targets"].update(bad)
            else:
                cur = {"start": t, "end": t, "n": 1, "targets": set(bad)}
                episodes.append(cur)
    out.append("")
    if episodes:
        out.append(f"Failure episodes ({len(episodes)}):")
        for e in episodes:
            out.append(f"  {e['start']:%m-%d %H:%M} -> {e['end']:%H:%M} UTC  ({e['n']} failed check(s))  "
                       f"failing: {', '.join(sorted(e['targets']))}")
    else:
        out.append("No failures recorded: every DNS server, the system resolver and the gateway answered every time.")

    # gaps with no data at all = machine off or cron stopped
    gaps = []
    for a, b in zip(rows, rows[1:]):
        d = parse(b["ts"]) - parse(a["ts"])
        if d > timedelta(minutes=GAP_MINUTES):
            gaps.append((parse(a["ts"]), parse(b["ts"]), d))
    if gaps:
        out.append("")
        out.append(f"Gaps with no data ({len(gaps)}) -- the machine was off or cron was not running:")
        for a, b, d in gaps:
            out.append(f"  {a:%m-%d %H:%M} -> {b:%H:%M} UTC  ({int(d.total_seconds() // 60)} min)")
    return "\n".join(out)


def main() -> int:
    args = sys.argv[1:]
    if "--report" in args:
        i = args.index("--report")
        hours = float(args[i + 1]) if len(args) > i + 1 else 24.0
        print(report(hours))
        return 0
    if "--probe" in args:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        lock = open(DATA_DIR / ".dns_probe.lock", "a")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return 0                      # the previous probe is still running
        row = probe()
        append(row)
        if datetime.now(timezone.utc).minute == 0:
            prune()
        bad = failed_targets(row)
        if "-v" in args:
            print(json.dumps(row))
        return 1 if bad and "-v" in args else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
