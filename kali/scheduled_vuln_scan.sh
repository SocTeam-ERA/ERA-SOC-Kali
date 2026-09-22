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
# Same standing authorization as scheduled_scan.sh: this runs unattended from
# soc-vuln-scan.timer, so 3_vuln_scan.sh's interactive "type yes" prompt has
# nobody to answer it. Without this the first weekly run (2026-09-20) aborted
# in under a second and scanned nothing.
export SCAN_AUTHORIZED=yes
source "$(dirname "$0")/lib.sh"

LATEST="$(ls -t "$RESULTS_DIR"/arp_live_*_scan.txt 2>/dev/null | head -1)"
if [ -z "$LATEST" ] || [ ! -s "$LATEST" ]; then
  warn "No live-hosts file found (results/arp_live_*_scan.txt) -- has scheduled_scan.sh run yet? Aborting."
  exit 1
fi
log "Using live hosts from: $LATEST (Guest WiFi already excluded)"

# Captures the XML report path 3_vuln_scan.sh echoes as its last line (the same
# convention 0_run_all.sh uses for a manual run), while `tee /dev/fd/2` still
# streams everything -- the batch progress, nikto/whatweb output -- to the
# journal via stderr. This used to be `exec 3_vuln_scan.sh ...`, which replaced
# this whole process, so nothing was left running to read that path: the vuln
# scan's own findings (the 'vuln'/ftp-anon/http-default-accounts/ssl-* category
# -- this job's entire reason to exist) were produced as a report file and then
# never turned into an alert. Confirmed 2026-09-22: 3_vuln_scan.sh only calls
# nmap_to_alerts.py itself for the separate SNMP check; the main vuln-category
# XML has always relied on a caller doing that afterward, same as
# SERVICES_XML/VULN_XML in 0_run_all.sh -- this script was never that caller.
VULN_XML="$("$(dirname "$0")/3_vuln_scan.sh" "$LATEST" | tee /dev/fd/2 | tail -n1)"
if [[ ! -s "$VULN_XML" ]]; then
  err "3_vuln_scan.sh produced no XML report -- nothing to import"
  exit 1
fi
log "Importing vulnerability findings into the SOC feed: $VULN_XML"
# Same --diff-state file the regular scheduled_scan.sh uses (not the manual
# run's port_state_manual.json): the *_vulns state it derives from that path
# is what makes "No longer detected" work instead of re-alerting every finding
# every week, and it should be the SAME lineage the rest of the automated
# pipeline already tracks, not a second, disconnected one.
python3 "$(dirname "$0")/nmap_to_alerts.py" "$VULN_XML" \
    --baseline 22,443 \
    --diff-state /opt/sentinel-soc/data/port_state.json
