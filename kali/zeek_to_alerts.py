#!/usr/bin/env python3
"""
zeek_to_alerts.py
------------------
Tails Zeek's notice.log (JSON lines -- see local.zeek's
`@load policy/tuning/json-logs`) and turns Zeek's own curated notices into
SOC alerts. Zeek complements Suricata: Suricata matches signatures against
packet content (the Emerging Threats Open ruleset), Zeek analyzes
connection-level behavior (SSH brute-forcing, vulnerable software versions,
SQL injection patterns, invalid/expired TLS certs, DNS pointing at external
hosting, etc. -- see local.zeek's @load lines for the full policy set this
project enabled). notice.log is already Zeek's own "this is worth a look"
filter -- unlike raw conn.log/dns.log (which log every single connection
and every single query, purely for archival/search, never meant to be
alerted on one-for-one), so unlike Suricata's decoder noise this script
does NOT need a severity threshold.

It does still need one exclusion, confirmed empirically within minutes of
first deploying this Zeek cluster: CaptureLoss::Too_Little_Traffic fired
repeatedly for the low-traffic VLANs (Printers, Guest WiFi, Office) --
that is Zeek reporting on its OWN capture health, not a security event.
See NOISE_NOTICE_TYPES below; add to it if another purely-operational
notice type turns up the same way.

Usage:
    python3 zeek_to_alerts.py --follow                 # continuous (systemd)
    python3 zeek_to_alerts.py --log /path/to/notice.log  # one-shot, custom path
"""
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, resolve_hostname, scan_active, tail_follow  # noqa: E402
from zeek_tsv import ZeekTSVReader, read_header_lines  # noqa: E402
from reader_health import Reporter  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DEFAULT_LOG = Path("/opt/zeek/logs/current/notice.log")

# Zeek reporting on its own capture/operational health, not a security
# event. Confirmed empirically: CaptureLoss::Too_Little_Traffic fired
# repeatedly within minutes of first standing up this cluster, for every
# low-traffic VLAN worker (Printers, Guest WiFi, Office).
#
# CaptureLoss::Too_Much_Loss belongs here for the exact same reason -- it's
# Zeek reporting on its own capture health, not an attacker on the wire --
# but was missing from this set. Confirmed 2026-09-17: worker-floor (eth0)
# hit ~100% estimated loss every ~15min (Zeek's CaptureLossPeriod) and it
# alerted as a medium-severity "intrusion", indistinguishable from a real
# detection.
#
# NOTE on root cause, corrected same day: first assumed a single worker
# process couldn't keep up with eth0's traffic volume and split it into
# multiple processes (lb_procs in /opt/zeek/etc/node.cfg) -- that did NOT
# fix it (loss recurred within minutes even at lb_procs=3), and CPU usage
# on every worker-floor process stayed under 1% the whole time, which
# rules out "not enough processing capacity" as the actual cause.
# CaptureLoss::Too_Much_Loss estimates loss from TCP sequence/ACK gaps, not
# from a capture queue backing up -- it fires when Zeek isn't seeing BOTH
# directions of other hosts' conversations, which points at eth0 not being
# a true bidirectional mirror/SPAN port at the Proxmox vswitch level, not
# at anything Zeek-side. Same suspected root cause as this project's
# separate, still-unresolved SSH/network-loop investigation on the same
# interface. Not fixable from this project's side -- keep the suppression
# above regardless of whether the underlying capture gap ever gets fixed.
NOISE_NOTICE_TYPES = {
    "CaptureLoss::Too_Little_Traffic",
    "CaptureLoss::Dropped_Packets",
    "CaptureLoss::Too_Much_Loss",
}

# Rough notice-type -> our alert type, by prefix/keyword. Falls back to
# "intrusion" (a reasonable default for "Zeek flagged this connection").
# Brute-force notices map to "intrusion", matching login_monitor.py's own
# convention for the exact same event class ("Brute-force: N failed logins
# from ...") -- keeping them separate types (they used to fall under
# "port_scan" here) would split identical attacks into different dashboard
# buckets depending on which detector happened to catch them.
TYPE_HINTS = [
    (("Scan::",), "port_scan"),
    (("SSH::Password_Guessing", "FTP::Bruteforcing"), "intrusion"),
    (("SSL::", "Software::Vulnerable"), "vuln"),
    (("SQL_Injection", "Signatures::"), "vuln"),
    (("DNS::External_Name",), "phishing"),
    (("MHR::",), "malware"),
]

# A handful of notice types that are clearly serious enough to treat as
# critical regardless of Zeek's own default priority -- confirmed working
# credential compromise / known-malicious file, not just a suspicious
# pattern.
CRITICAL_NOTICE_TYPES = {
    "MHR::Malware_Hash_Registry_Match",
    "SSH::Password_Guessing",
}


def guess_type(note: str) -> str:
    for keywords, t in TYPE_HINTS:
        if any(note.startswith(k) for k in keywords):
            return t
    return "intrusion"


def handle_event(event: dict) -> bool:
    """Return True if an alert was emitted."""
    note = event.get("note")
    if not note or note in NOISE_NOTICE_TYPES:
        return False
    if scan_active():
        return False

    src = event.get("src")
    dst = event.get("dst")
    msg = event.get("msg") or note
    severity = "critical" if note in CRITICAL_NOTICE_TYPES else "medium"

    emit_alert(Alert(
        type=guess_type(note), severity=severity,
        title=f"{note}: {msg}" if len(msg) < 80 else f"{note}: {msg[:77]}...",
        source_ip=src, hostname=resolve_hostname(src) if src else None,
        detector="zeek",
        description=(f"Zeek notice [{note}]: {msg}"
                     + (f" ({src} -> {dst})" if src and dst else "")),
        details={"note": note, "msg": msg, "src": src, "dst": dst,
                 "peer_descr": event.get("peer_descr"),
                 "p": event.get("p")},
    ))
    return True


def process_file(path: Path, follow: bool) -> int:
    """Forward every notice in `path`. The log may be JSON or Zeek's classic TSV (see
    zeek_tsv.py for why that matters: it silently flipped on 2026-09-21 and this
    forwarder went two days without forwarding a single notice)."""
    n = 0
    reader = ZeekTSVReader()
    if follow:
        # Zeek creates notice.log lazily, on the first notice after each hourly rotation, so a
        # quiet hour leaves no current file at all. A file that does not exist yet must be read
        # from its beginning once it appears (tail_follow() would otherwise skip to its end and
        # lose the very notice that created it, and the TSV header with it).
        appears_later = not path.exists()
        for header in read_header_lines(path):
            reader.feed(header)
        # tail_follow() survives zeekctl's own log rotation/archiving (it
        # replaces the live file at this path when it rotates), the same
        # way it handles logrotate for the other detectors -- see
        # soc_core.tail_follow()'s docstring.
        health = Reporter("zeek_to_alerts", reader)  # lets source_health notice a format this reader cannot parse
        for line in tail_follow(path, from_start=appears_later):
            event = reader.feed(line)
            health.tick()
            if event and handle_event(event):
                n += 1
        return n
    with path.open("r", errors="ignore") as fh:
        for line in fh:
            event = reader.feed(line)
            if event and handle_event(event):
                n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="Zeek notice.log -> SOC alerts")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="Path to notice.log")
    ap.add_argument("--follow", action="store_true", help="Tail continuously (for the systemd service)")
    args = ap.parse_args()

    path = Path(args.log)
    if not path.exists():
        if not args.follow:
            print(f"[x] {path} not found -- is the Zeek cluster running?", file=sys.stderr)
            return 1
        # As a service, exiting here made systemd restart us in a tight loop (12 times in a
        # minute on 2026-09-22 18:49) and the watchdog raise a critical "service down" for what
        # was only a quiet hour with no notice.log yet. Wait for it instead.
        print(f"[*] {path} does not exist yet (Zeek writes it on the first notice of the hour) -- waiting.",
              flush=True)

    n = process_file(path, args.follow)
    if not args.follow:
        print(f"[*] zeek_to_alerts: {n} alert(s) forwarded from {path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
