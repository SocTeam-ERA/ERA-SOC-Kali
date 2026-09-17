#!/usr/bin/env bash
# =====================================================================
#  scheduled_vuln_scan.sh — weekly deep vuln scan (nikto/whatweb/full
#  nmap 'vuln' category/SNMP), run unattended via soc-vuln-scan.timer.
# =====================================================================
#  3_vuln_scan.sh with no arguments falls back to every CIDR in
#  targets.conf -- which, unlike scheduled_scan.sh's regular 4h scan,
#  includes Guest/Employees WiFi (192.168.8.0/24). That's fine for an
#  analyst running it by hand against a specific approved host, but NOT
#  for an unattended weekly job: nikto and the full 'vuln' NSE category
#  against random personal phones/laptops on guest WiFi is exactly the
#  privacy problem scheduled_scan.sh's filter_guest_wifi() already exists
#  to prevent for the regular scan. This wrapper reuses the most recent
#  live-hosts list scheduled_scan.sh's own arp discovery already produced
#  (arp_live_<stamp>_scan.txt), which has Guest WiFi filtered out and
#  offline hosts excluded, instead of letting 3_vuln_scan.sh fall back to
#  everything in targets.conf.
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

LATEST="$(ls -t "$RESULTS_DIR"/arp_live_*_scan.txt 2>/dev/null | head -1)"
if [ -z "$LATEST" ] || [ ! -s "$LATEST" ]; then
  warn "No live-hosts file found (results/arp_live_*_scan.txt) -- has scheduled_scan.sh run yet? Aborting."
  exit 1
fi
log "Using live hosts from: $LATEST (Guest WiFi already excluded)"
exec "$(dirname "$0")/3_vuln_scan.sh" "$LATEST"
