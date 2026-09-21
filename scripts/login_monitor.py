#!/usr/bin/env python3
"""
login_monitor.py
----------------
Monitors authentication activity and raises intrusion alerts. It reads Linux
auth logs (SSH / sudo / PAM) and can also ingest a Windows Security-log CSV
export, so you can watch logins across the company domain.

What it detects:
    * Successful login       -> normal   (who logged in, from which IP)
    * Failed login           -> tracked; a burst becomes a brute-force alert
    * Brute force             -> medium   (N failures from one IP in a window)
    * Root / admin login      -> medium
    * Login from a NEW / foreign IP (not in known_ips)  -> escalated
    * Successful login right after many failures         -> critical
      (classic "brute force finally succeeded" pattern)

Usage:
    # Follow the live SSH log on the Ubuntu server
    sudo python3 login_monitor.py --auth-log /var/log/auth.log --follow

    # Analyse an exported Windows Security log (CSV: time,event_id,user,ip,host)
    python3 login_monitor.py --windows-csv security_export.csv

    # Try it with the included demo data (no root, no real logs needed)
    python3 login_monitor.py --demo

Config:
    --known-ips known_ips.txt   one trusted IP/CIDR per line; logins from
                                outside these ranges are escalated.
    --threshold 5               failures from one IP before a brute-force alert
    --window 120                seconds the failures must fall within
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from soc_core import Alert, emit_alert, resolve_hostname, tail_follow, confirm_demo_on_live_instance

# --- SSH auth.log patterns ------------------------------------------------- #
RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port")
RE_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port")
RE_INVALID = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")

ADMIN_USERS = {"root", "admin", "administrator", "domain admin", "sysadmin"}


class BruteForceTracker:
    """Keeps a sliding window of failures per source IP."""

    def __init__(self, threshold: int, window: int):
        self.threshold = threshold
        self.window = window
        self.failures: dict[str, deque] = defaultdict(deque)
        self.alerted: set[str] = set()

    def record_failure(self, ip: str, now: float) -> bool:
        dq = self.failures[ip]
        dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) < self.threshold:
            # burst has cooled off (old failures aged out of the window) --
            # un-flag it so a fresh burst from this IP can alert again,
            # instead of staying silenced forever after the first alert.
            self.alerted.discard(ip)
            return False
        if ip not in self.alerted:
            self.alerted.add(ip)
            return True
        return False

    def recent_failures(self, ip: str) -> int:
        return len(self.failures.get(ip, ()))

    def clear(self, ip: str) -> None:
        self.failures.pop(ip, None)
        self.alerted.discard(ip)


def is_known_ip(ip: str, known) -> bool:
    if not known:
        return True  # if no allow-list is configured, treat all as known
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return any(addr in net for net in known)


def load_known_ips(path: str | None):
    nets = []
    if not path:
        return nets
    with open(path) as fh:
        for ln in fh:
            ln = ln.strip()
            if ln and not ln.startswith("#"):
                try:
                    nets.append(ipaddress.ip_network(ln, strict=False))
                except ValueError:
                    pass
    return nets


# One "Login from NEW IP" alert per (ip, user) per this many seconds: an admin working from
# an address that is not in known_ips.txt logs in many times a day, and each login was its own
# alert (2026-09-21: the same IP three times in two hours). Failures and brute-force patterns
# are not affected. In memory, so a service restart re-alerts once.
NEW_IP_COOLDOWN = float(os.environ.get("SOC_NEW_IP_COOLDOWN", str(24 * 3600)))
_new_ip_last: dict = {}


def handle_event(kind: str, user: str, ip: str, host: str | None,
                 tracker: BruteForceTracker, known) -> None:
    """kind in {failed, accepted, invalid}."""
    now = time.time()
    known_ip = is_known_ip(ip, known)
    hostname = host or resolve_hostname(ip)
    is_admin = user.lower() in ADMIN_USERS

    if kind in ("failed", "invalid"):
        burst = tracker.record_failure(ip, now)
        if burst:
            emit_alert(Alert(
                type="intrusion", severity="critical" if is_admin else "medium",
                title=f"Brute-force: {tracker.recent_failures(ip)} failed logins from {ip}",
                source_ip=ip, hostname=hostname, user=user,
                detector="login_monitor",
                description=f"{tracker.recent_failures(ip)} failed authentication attempts "
                            f"from {ip} within the detection window "
                            f"(target user '{user}').",
                details={"failures": tracker.recent_failures(ip), "admin_target": is_admin,
                         "known_ip": known_ip},
            ))
        elif not known_ip:
            emit_alert(Alert(
                type="intrusion", severity="medium",
                title=f"Failed login from unknown IP {ip} (user '{user}')",
                source_ip=ip, hostname=hostname, user=user,
                detector="login_monitor",
                description=f"Failed login for '{user}' from {ip}, which is outside the "
                            f"trusted IP ranges.",
                details={"known_ip": False},
            ))

    elif kind == "accepted":
        recent = tracker.recent_failures(ip)
        if recent >= tracker.threshold:
            # succeeded after many failures -> likely compromise
            emit_alert(Alert(
                type="intrusion", severity="critical",
                title=f"Successful login after {recent} failures — possible compromise ({ip})",
                source_ip=ip, hostname=hostname, user=user,
                detector="login_monitor",
                description=f"User '{user}' logged in from {ip} immediately after {recent} "
                            f"failed attempts. Classic brute-force-succeeded pattern.",
                details={"prior_failures": recent, "known_ip": known_ip},
            ))
        elif not known_ip and now - _new_ip_last.get((ip, user), 0) < NEW_IP_COOLDOWN:
            print(f"[*] repeat login from new IP {ip} (user '{user}') within the cooldown -- not re-alerted")
        elif not known_ip:
            _new_ip_last[(ip, user)] = now
            emit_alert(Alert(
                type="intrusion", severity="critical" if is_admin else "medium",
                title=f"Login from NEW IP {ip} (user '{user}')",
                source_ip=ip, hostname=hostname, user=user,
                detector="login_monitor",
                description=f"User '{user}' successfully logged in from {ip}, which is not in "
                            f"the known/trusted IP list.",
                details={"known_ip": False, "admin": is_admin},
            ))
        else:
            emit_alert(Alert(
                type="intrusion", severity="medium" if is_admin else "normal",
                title=f"{'Admin ' if is_admin else ''}login: {user} from {ip}",
                source_ip=ip, hostname=hostname, user=user,
                detector="login_monitor",
                description=f"User '{user}' logged in from {ip}.",
                details={"known_ip": True, "admin": is_admin},
            ))
        tracker.clear(ip)


def parse_line(line: str):
    for kind, rx in (("failed", RE_FAILED), ("accepted", RE_ACCEPTED), ("invalid", RE_INVALID)):
        m = rx.search(line)
        if m:
            return kind, m.group("user"), m.group("ip")
    return None


def process_auth_log(path: str, follow: bool, tracker, known):
    if follow:
        # tail_follow() survives auth.log's weekly logrotate rotation --
        # see its docstring: a plain seek(0,2)+readline() loop (what this
        # used to be) goes silently, permanently blind the moment the file
        # rotates, since the held handle keeps pointing at the old inode.
        for line in tail_follow(path, from_start=False):
            parsed = parse_line(line)
            if parsed:
                kind, user, ip = parsed
                handle_event(kind, user, ip, None, tracker, known)
        return
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            parsed = parse_line(line)
            if parsed:
                kind, user, ip = parsed
                handle_event(kind, user, ip, None, tracker, known)


def process_windows_csv(path: str, tracker, known):
    """CSV columns (with header): time,event_id,user,ip,host
    Event 4624 = success, 4625 = failure (Windows Security log)."""
    import csv
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            eid = str(row.get("event_id", "")).strip()
            user = row.get("user", "?").strip()
            ip = row.get("ip", "").strip()
            host = row.get("host", "").strip() or None
            if not ip:
                continue
            if eid == "4625":
                handle_event("failed", user, ip, host, tracker, known)
            elif eid == "4624":
                handle_event("accepted", user, ip, host, tracker, known)


def run_demo(tracker, known):
    """Replay a realistic sequence so you can see alerts without real logs."""
    confirm_demo_on_live_instance()
    print("[*] Demo mode: replaying a synthetic attack sequence...", file=sys.stderr)
    attacker = "203.0.113.77"
    for _ in range(6):                       # brute force burst
        handle_event("failed", "root", attacker, None, tracker, known)
    handle_event("accepted", "root", attacker, None, tracker, known)  # then success -> critical
    handle_event("accepted", "jsmith", "10.10.5.20", "WKS-JSMITH", tracker, known)  # normal
    handle_event("accepted", "administrator", "198.51.100.9", None, tracker, known)  # new IP admin


def main() -> int:
    ap = argparse.ArgumentParser(description="Login / intrusion monitor -> SOC alerts")
    ap.add_argument("--auth-log", help="Path to Linux auth log (e.g. /var/log/auth.log)")
    ap.add_argument("--windows-csv", help="Windows Security-log CSV export")
    ap.add_argument("--follow", action="store_true", help="Tail the auth log continuously")
    ap.add_argument("--known-ips", help="File of trusted IPs/CIDRs (one per line)")
    ap.add_argument("--threshold", type=int, default=5, help="Failures before brute-force alert")
    ap.add_argument("--window", type=int, default=120, help="Failure window in seconds")
    ap.add_argument("--demo", action="store_true", help="Replay a synthetic attack sequence")
    args = ap.parse_args()

    known = load_known_ips(args.known_ips)
    tracker = BruteForceTracker(args.threshold, args.window)

    if args.demo:
        run_demo(tracker, known)
    elif args.windows_csv:
        process_windows_csv(args.windows_csv, tracker, known)
    elif args.auth_log:
        process_auth_log(args.auth_log, args.follow, tracker, known)
    else:
        ap.error("choose one of --demo, --auth-log, or --windows-csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
