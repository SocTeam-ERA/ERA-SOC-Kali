#!/usr/bin/env python3
"""
osquery_to_alerts.py
---------------------
Tails osqueryd's results log (/var/log/osquery/osqueryd.results.log,
one JSON object per row, written by osquery.conf's scheduled queries --
osquery computes the added/removed diff itself, so this script never has to
maintain its own state file for "did this port already exist") and turns
host-level changes into SOC alerts: new listening sockets, new local users,
new cron jobs, new setuid/setgid binaries, and loaded kernel modules. This
is host-side visibility that complements the network-side nmap/Suricata
detectors -- it catches things bound to localhost or firewalled from the
network, and classic persistence/privilege-escalation indicators nmap
can't see at all.

NOTE on a false alarm: kernel_modules_loaded was briefly removed from
osquery.conf after results.log appeared to go quiet for long stretches --
misread at the time as the whole scheduler hanging. Querying the live
daemon's own osquery_schedule table (SELECT name, executions,
last_executed FROM osquery_schedule, via osqueryi --connect
/var/osquery/osquery.em) showed the OTHER queries had actually been
executing on schedule the whole time; results.log just stays silent when
a query's differential diff is empty (nothing changed), which isn't a
hang at all. kernel_modules_loaded is back in the schedule -- if it turns
out to have a real, distinct problem (its own osquery_schedule row shows
0 executions, or it's denylisted), that's the query to check with the
same live-daemon technique before assuming anything.

Baseline handling: the FIRST time osqueryd runs each scheduled query (fresh
install, or the query's result table was empty before), every existing row
comes back as "added" -- there's nothing to diff against yet. Confirmed
empirically on this box: the very first listening_ports cycle reported
every currently-listening port as "added", including long-running services
like sshd, and suid_binaries's first cycle reported all ~110 setuid/setgid
binaries already on disk. Alerting on that whole dump would flood the
dashboard the moment this is turned on (the same class of problem as the
Suricata/traffic-monitor false-positive incidents earlier). So this script
tracks, in data/osquery_seen_queries.json, the "counter" value of the
FIRST batch it has seen for each query name (osquery's own per-query
execution counter -- every row in one scheduled run shares the same
counter) and stays quiet on every row that still carries that first
counter -- once a row shows up with a counter higher than the recorded
baseline, that's a genuine post-baseline change and gets alerted, along
with everything after it.

Usage:
    python3 osquery_to_alerts.py --follow                  # continuous (systemd)
    python3 osquery_to_alerts.py --log /path/to/results.log  # one-shot, custom path
"""
from __future__ import annotations
import argparse, json, os, sys, tempfile, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, tail_follow  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
SEEN_QUERIES_FILE = DATA_DIR / "osquery_seen_queries.json"
DEFAULT_LOG = Path("/var/log/osquery/osqueryd.results.log")

# (severity for "added", severity for "removed" -- None means "don't alert
# on this action at all") per scheduled query name (must match osquery.conf).
QUERY_RULES = {
    "listening_ports":       {"added": "medium",   "removed": None},
    "local_users":           {"added": "critical",  "removed": "normal"},
    "cron_jobs":             {"added": "medium",   "removed": "normal"},
    "kernel_modules_loaded": {"added": "medium",   "removed": None},
    "suid_binaries":         {"added": "critical",  "removed": None},
}

TITLE_BUILDERS = {
    "listening_ports": lambda c: f"New listening port: {c.get('address')}:{c.get('port')} "
                                  f"({c.get('name') or 'unknown process'})",
    "local_users":     lambda c: f"Local user account: {c.get('username')} (uid {c.get('uid')})",
    "cron_jobs":       lambda c: f"Scheduled task: {c.get('command')}",
    "kernel_modules_loaded": lambda c: f"Kernel module loaded: {c.get('name')}",
    "suid_binaries":   lambda c: f"setuid/setgid binary: {c.get('path')} (owner {c.get('username')})",
}


def load_seen(path: Path) -> dict:
    """Return {query_name: first_seen_counter}."""
    try:
        return json.loads(path.read_text()).get("baseline_counter", {})
    except (OSError, json.JSONDecodeError):
        return {}


def mark_seen(path: Path, seen: dict) -> None:
    """Atomic write (tempfile + os.replace) -- a crash or kill mid-write must
    never leave this file truncated/corrupted, since a corrupted read forces
    every query back into "first batch" baseline mode and silently swallows
    whatever real change was in flight. Same pattern as soc_core.py's
    snapshot write."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"baseline_counter": seen}, f)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def handle_row(row: dict, seen: dict) -> bool:
    """Return True if an alert was emitted. `seen` maps query name -> the
    counter value of that query's first-ever batch (the baseline to ignore)."""
    name = row.get("name")
    action = row.get("action")
    counter = row.get("counter")
    rules = QUERY_RULES.get(name)
    if rules is None:
        return False

    if name not in seen:
        seen[name] = counter
        return False  # first time we've ever seen this query -- record its baseline counter
    if counter == seen[name]:
        return False  # still part of that same first batch -- stay quiet

    severity = rules.get(action)
    if severity is None:
        return False

    columns = row.get("columns", {})
    build_title = TITLE_BUILDERS.get(name, lambda c: f"{name}: {c}")
    verb = "appeared" if action == "added" else "removed"
    hostname = (row.get("decorations") or {}).get("hostname") or row.get("hostIdentifier")

    emit_alert(Alert(
        type="intrusion" if name in ("local_users", "suid_binaries", "kernel_modules_loaded") else "vuln",
        severity=severity,
        title=f"{build_title(columns)} [{verb}]",
        hostname=hostname, detector="osquery",
        description=f"osquery {name}: {action} -- {columns}",
        details={"query": name, "action": action, "columns": columns},
    ))
    return True


def _process_line(line: str, seen: dict) -> bool:
    line = line.strip()
    if not line:
        return False
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return False
    before = dict(seen)
    emitted = handle_row(row, seen)
    if seen != before:
        mark_seen(SEEN_QUERIES_FILE, seen)
    return emitted


def process_file(path: Path, follow: bool) -> int:
    seen = load_seen(SEEN_QUERIES_FILE)
    n = 0
    if follow:
        # tail_follow() survives osqueryd rotating/truncating its own
        # results log -- see soc_core.tail_follow()'s docstring for why a
        # plain seek(0,2)+readline() loop can't.
        for line in tail_follow(path, from_start=False):
            if _process_line(line, seen):
                n += 1
        return n
    with path.open("r", errors="ignore") as fh:
        for line in fh:
            if _process_line(line, seen):
                n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="osquery results log -> SOC alerts")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="Path to osqueryd.results.log")
    ap.add_argument("--follow", action="store_true", help="Tail continuously (for the systemd service)")
    args = ap.parse_args()

    path = Path(args.log)
    if not path.exists():
        print(f"[x] {path} not found -- is osqueryd running?", file=sys.stderr)
        return 1

    n = process_file(path, args.follow)
    if not args.follow:
        print(f"[*] osquery_to_alerts: {n} alert(s) forwarded from {path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
