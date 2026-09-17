#!/usr/bin/env python3
"""
seed_demo_data.py
-----------------
Generates a realistic batch of alerts across all detectors and severities so
you can demo the dashboard with a populated feed (before the real scripts are
wired to live data sources). Run:

    python3 seed_demo_data.py          # ~40 alerts spread over the last 12h
    python3 seed_demo_data.py --count 80

It writes through soc_core.emit_alert, so the output uses the exact same
schema and files (data/alerts.json + data/alerts.jsonl) as the real scripts.
"""
from __future__ import annotations
import argparse, random
from datetime import datetime, timezone, timedelta
import soc_core
from soc_core import Alert, ALERTS_SNAPSHOT, ALERTS_LOG, DATA_DIR, confirm_demo_on_live_instance
import json

INTERNAL = ["10.10.5.20", "10.10.5.31", "10.10.2.14", "10.10.2.15", "10.10.9.4",
            "192.168.1.44", "192.168.1.60", "10.10.1.7"]
EXTERNAL = ["203.0.113.77", "198.51.100.9", "45.83.12.201", "185.220.101.4",
            "91.219.236.18", "103.94.185.22", "203.0.113.66"]
USERS = ["jsmith", "mgarcia", "administrator", "root", "svc_backup", "adominguez",
         "helpdesk", "kdenton"]
HOSTS = ["WKS-JSMITH", "WKS-MGARCIA", "DC01", "FILE-SRV", "WEB01", "MAIL01", None]

TEMPLATES = [
    ("port_scan", "medium", "Open port {p}/tcp ({s}) on {ip}", "{ip} exposes {s} on port {p}."),
    ("port_scan", "critical", "Open port 3389/tcp (RDP) on {ip} (NOT in baseline)",
     "RDP exposed on {ip}, outside the approved baseline."),
    ("port_scan", "critical", "Open port 445/tcp (SMB) on {ip}", "SMB reachable on {ip}."),
    ("intrusion", "critical", "Brute-force: {n} failed logins from {ip}",
     "{n} failed SSH attempts from {ip} targeting '{u}'."),
    ("intrusion", "critical", "Successful login after {n} failures — possible compromise ({ip})",
     "'{u}' authenticated from {ip} right after {n} failures."),
    ("intrusion", "medium", "Login from NEW IP {ip} (user '{u}')",
     "'{u}' logged in from {ip}, outside trusted ranges."),
    ("intrusion", "normal", "Login: {u} from {ip}", "'{u}' logged in from {ip}."),
    ("phishing", "critical", "Phishing indicators in email: Unusual sign-in activity",
     "Credential-harvest email, SPF/DKIM/DMARC fail, link to raw IP."),
    ("phishing", "medium", "Phishing indicators in email: Invoice attached",
     "Invoice lure with macro-enabled attachment from {ip}."),
    ("malware", "critical", "Suspicious file: invoice.pdf.exe (critical)",
     "File claims to be a PDF but is a Windows PE; double extension."),
    ("malware", "medium", "Suspicious file: update.docm (medium)",
     "Macro-enabled Office document with AutoOpen macro."),
    ("vuln", "critical", "CVE: outdated OpenSSH on {ip}",
     "Vulnerable OpenSSH banner detected by nmap on {ip}."),
    ("vuln", "medium", "Weak TLS (TLS 1.0) on {ip}:443", "Legacy TLS 1.0 enabled on {ip}."),
]


def make(now, i):
    t, sev, title, desc = random.choice(TEMPLATES)
    ip = random.choice(EXTERNAL if sev == "critical" else INTERNAL + EXTERNAL)
    u = random.choice(USERS)
    n = random.randint(5, 40)
    p = random.choice([22, 21, 23, 3306, 8080, 5900])
    s = {22: "SSH", 21: "FTP", 23: "Telnet", 3306: "MySQL", 8080: "HTTP-alt", 5900: "VNC"}[p]
    fields = dict(ip=ip, u=u, n=n, p=p, s=s)
    ts = (now - timedelta(minutes=random.randint(0, 720),
                          seconds=random.randint(0, 59))).isoformat()
    a = Alert(type=t, severity=sev, title=title.format(**fields),
              source_ip=ip if t != "malware" else None,
              hostname=random.choice(HOSTS), user=u if t == "intrusion" else None,
              detector={"port_scan": "port_scanner", "intrusion": "login_monitor",
                        "phishing": "phishing_detector", "malware": "malware_detector",
                        "vuln": "kali_scan"}[t],
              description=desc.format(**fields),
              status=random.choice(["open", "open", "open", "acknowledged", "resolved"]))
    a.timestamp = ts
    return a


def confirm_fresh() -> None:
    """--fresh permanently deletes the current alert history -- make sure
    that's really what's wanted before wiping real data by accident."""
    if not (ALERTS_SNAPSHOT.exists() or ALERTS_LOG.exists()):
        return  # nothing to delete, no need to prompt
    print("[!] --fresh will PERMANENTLY DELETE the current alert history:")
    print(f"      {ALERTS_SNAPSHOT}")
    print(f"      {ALERTS_LOG}")
    print("[!] This cannot be undone. If this is the real SOC data dir "
          "(not a throwaway/demo one), say no.")
    ans = input("Type 'yes' to confirm: ")
    if ans != "yes":
        print("[x] Not confirmed. Aborting.")
        raise SystemExit(2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=42)
    ap.add_argument("--fresh", action="store_true", help="Clear existing alerts first")
    args = ap.parse_args()
    confirm_demo_on_live_instance()
    if args.fresh:
        confirm_fresh()
        ALERTS_SNAPSHOT.unlink(missing_ok=True)
        ALERTS_LOG.unlink(missing_ok=True)
    now = datetime.now(timezone.utc)
    alerts = sorted((make(now, i) for i in range(args.count)), key=lambda a: a.timestamp)
    # write directly (sorted, so snapshot ends newest-first)
    from soc_core import emit_alert
    for a in alerts:
        emit_alert(a, echo=False)
    print(f"[*] Seeded {args.count} demo alerts -> {ALERTS_SNAPSHOT}")


if __name__ == "__main__":
    main()
