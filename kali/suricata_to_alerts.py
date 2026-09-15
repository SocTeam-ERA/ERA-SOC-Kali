#!/usr/bin/env python3
"""
suricata_to_alerts.py
----------------------
Tails Suricata's eve.json and turns "alert" events into SOC alerts, using
the signature database Suricata already manages (Emerging Threats Open,
~68k rules via suricata-update) -- a real IDS engine, a step up from the
hand-written heuristics in traffic_to_alerts.py.

Filters out decoder/protocol-anomaly noise (Suricata severity 3) by
default -- confirmed on this network: within the first few minutes,
severity 3 was 466 "SURICATA Ethertype unknown" / "Generic Protocol
Command Decode" events (almost certainly consumer/IoT devices on Guest
WiFi doing non-standard L2 chatter), not a security event. Only severity
1-2 (Suricata's own "this is worth a look" tier) get forwarded by default.

Like traffic_to_alerts.py, checks the scan-in-progress marker
(data/scan_in_progress, set by mark_scan_start in lib.sh) and skips
forwarding while an authorized scan is running -- Suricata watches the
same wire and would otherwise flag this box's own nmap/zmap/arp-scan
traffic as an attack on itself, the exact false-positive class already
found and fixed for traffic_to_alerts.py earlier today.

Usage:
    python3 suricata_to_alerts.py --follow                # continuous (systemd)
    python3 suricata_to_alerts.py --eve /path/to/eve.json  # one-shot, custom log path
    SURICATA_MIN_SEVERITY=3 python3 suricata_to_alerts.py --follow  # forward everything
"""
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, resolve_hostname, scan_active, tail_follow  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DEFAULT_EVE = Path("/var/log/suricata/eve.json")

# Suricata severity: 1 = highest priority ... 3 = lowest. Forward anything
# at or above (numerically <=) this. 2 = skip the decoder/anomaly noise
# tier (3) but keep everything Suricata itself considers worth a look.
MIN_SEVERITY = int(os.environ.get("SURICATA_MIN_SEVERITY", "2"))

SEV_MAP = {1: "critical", 2: "medium", 3: "normal"}

# Rough category -> our alert type, by keyword. Falls back to "intrusion"
# (a reasonable default for "the IDS flagged something on the wire").
CATEGORY_TYPE_HINTS = [
    (("trojan", "malware", "coin mining", "cryptomining"), "malware"),
    (("phishing", "social engineering"), "phishing"),
    (("web application attack", "exploit", "attempted admin", "attempted user"), "vuln"),
    (("network scan", "potential scan", "port scan"), "port_scan"),
]


def guess_type(category: str) -> str:
    cat = (category or "").lower()
    for keywords, t in CATEGORY_TYPE_HINTS:
        if any(k in cat for k in keywords):
            return t
    return "intrusion"


def handle_event(event: dict) -> bool:
    """Return True if an alert was emitted."""
    if event.get("event_type") != "alert":
        return False
    a = event.get("alert", {})
    severity = a.get("severity")
    if severity is None or severity > MIN_SEVERITY:
        return False
    if scan_active():
        return False

    src = event.get("src_ip")
    dst = event.get("dest_ip")
    signature = a.get("signature") or "Suricata alert"
    category = a.get("category") or ""

    emit_alert(Alert(
        type=guess_type(category), severity=SEV_MAP.get(severity, "medium"),
        title=f"{signature} ({src} -> {dst})" if src and dst else signature,
        source_ip=src, hostname=resolve_hostname(src) if src else None,
        detector="suricata",
        description=(f"Suricata: {signature} [{category}]. {src or '?'} -> {dst or '?'}"
                     + (f":{event['dest_port']}" if event.get("dest_port") else "")),
        details={"signature": signature, "category": category,
                 "suricata_severity": severity, "sid": a.get("signature_id"),
                 "gid": a.get("gid"), "proto": event.get("proto"),
                 "src_port": event.get("src_port"), "dest_port": event.get("dest_port"),
                 "in_iface": event.get("in_iface")},
    ))
    return True


def process_file(path: Path, follow: bool) -> int:
    n = 0
    if follow:
        # tail_follow() survives eve.json's weekly logrotate rotation (same
        # /etc/logrotate.d/ schedule as auth.log) -- a plain seek(0,2)+
        # readline() loop goes silently blind the moment it rotates. See
        # soc_core.tail_follow()'s docstring -- confirmed as a real, active
        # bug for login_monitor.py's auth.log tailing; eve.json was on the
        # same weekly schedule and would have hit it the same way.
        for line in tail_follow(path, from_start=False):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if handle_event(event):
                n += 1
        return n
    with path.open("r", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if handle_event(event):
                n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="Suricata eve.json -> SOC alerts")
    ap.add_argument("--eve", default=str(DEFAULT_EVE), help="Path to eve.json")
    ap.add_argument("--follow", action="store_true", help="Tail continuously (for the systemd service)")
    args = ap.parse_args()

    path = Path(args.eve)
    if not path.exists():
        print(f"[x] {path} not found -- is Suricata running?", file=sys.stderr)
        return 1

    n = process_file(path, args.follow)
    if not args.follow:
        print(f"[*] suricata_to_alerts: {n} alert(s) forwarded from {path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
