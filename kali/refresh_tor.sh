#!/usr/bin/env bash
# =====================================================================
#  refresh_tor.sh — wraps proxy_check.py --refresh-tor with the scan
#  marker so Suricata/Zeek don't flag this box's own request.
# =====================================================================
#  proxy_check.py --refresh-tor fetches check.torproject.org's exit-node
#  list over HTTPS. That DNS lookup + TLS connection to a "Tor Checker"
#  domain is exactly what Suricata's ET INFO rules for Tor usage/external-IP
#  checks are built to catch -- confirmed 2026-09-17: this box's own daily
#  refresh was showing up as a medium-severity "intrusion" alert
#  (detector=suricata) in the live feed, indistinguishable from an actual
#  compromised host checking Tor. mark_scan_start/mark_scan_end (below) is
#  the same marker suricata_to_alerts.py and zeek_to_alerts.py already
#  check via soc_core.scan_active() to suppress this exact false-positive
#  class for nmap/arp-scan/nikto -- reused here instead of duplicating that
#  battle-tested locking/self-healing logic in Python for a one-off HTTPS GET.
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

mark_scan_start
# NOT exec: mark_scan_start's cleanup runs on this shell's EXIT trap, which
# exec would skip entirely by replacing this process before it ever exits.
python3 "$(dirname "$0")/../scripts/proxy_check.py" --refresh-tor
