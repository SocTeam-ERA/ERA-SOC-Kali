#!/usr/bin/env bash
# =====================================================================
#  0_run_all.sh — Full recon: discovery -> services -> vuln -> report
# =====================================================================
#  One command to run the whole workflow against targets.conf, feed the
#  results into the SOC dashboard, and drop a summary report you can hand
#  to IT / managers.
#
#  Usage:
#     ./0_run_all.sh
#     FAST=1 ./0_run_all.sh          # quicker (top-1000 ports)
#     SCAN_AUTHORIZED=yes ./0_run_all.sh   # skip the interactive prompt
#     DIFF_STATE=0 ./0_run_all.sh    # full inventory alert every run (default: only opens/closes)
#
#  Produces, under results/:
#     live_hosts_<stamp>.txt, services_<stamp>.*, vuln_<stamp>.*
#     REPORT_<stamp>.txt      <- readable summary for humans
#  ...and imports everything into ../data/alerts.json for the dashboard.
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"
DIR="$(dirname "$0")"

banner "SOC NETWORK RECON — FULL RUN"
log "Results dir: $RESULTS_DIR"
authorize
export SCAN_AUTHORIZED=yes   # already confirmed; don't re-prompt sub-steps

# 1. discovery
LIVE=$("$DIR/1_host_discovery.sh" | tail -n1)
[[ -f "$LIVE" ]] || { err "discovery produced no host list"; exit 1; }

# 2. services
SERVICES_XML=$(FAST="${FAST:-0}" "$DIR/2_port_service_scan.sh" "$LIVE" | tail -n1)

# 3. vuln
VULN_XML=$("$DIR/3_vuln_scan.sh" "$LIVE" | tail -n1)

# 4. import into the SOC feed (if python + soc_core available)
#    --diff-state keeps repeat manual runs from re-flooding the dashboard
#    with an alert for every already-known open port; only opens/closes get
#    alerted (vulnerabilities are still always reported, diff mode or not).
#    This uses its own state file, separate from the scheduled job's
#    (port_state.json): that job only checks the top 1000 ports (FAST=1),
#    while this script defaults to all 65535 -- sharing one file between
#    differently-scoped scans would misreport out-of-scope ports as
#    "closed" just because a narrower scan didn't look at them.
#    Set DIFF_STATE=0 to go back to a full-inventory alert every run.
DIFF_ARGS=()
if [[ "${DIFF_STATE:-1}" != "0" ]]; then
  DIFF_ARGS=(--diff-state "$DIR/../data/port_state_manual.json")
fi
if command -v python3 >/dev/null 2>&1; then
  log "Importing results into the SOC dashboard feed..."
  python3 "$DIR/nmap_to_alerts.py" "$SERVICES_XML" --baseline "${BASELINE:-22,443}" "${DIFF_ARGS[@]}" || true
  python3 "$DIR/nmap_to_alerts.py" "$VULN_XML" --baseline "${BASELINE:-22,443}" "${DIFF_ARGS[@]}" || true
fi

# 5. human-readable report
REPORT="$RESULTS_DIR/REPORT_${STAMP}.txt"
{
  echo "==================================================================="
  echo " SOC NETWORK RECON REPORT"
  echo " Generated: $(date -u)  (UTC)"
  echo " Operator : ${USER:-unknown} on $(hostname)"
  echo "==================================================================="
  echo
  echo "-- Live hosts ------------------------------------------------------"
  cat "$LIVE"
  echo
  echo "-- Open services (summary) ----------------------------------------"
  grep -E '^[0-9]+/tcp' "${SERVICES_XML%.xml}.nmap" 2>/dev/null | sort | uniq -c | sort -rn || true
  echo
  echo "-- Vulnerability findings -----------------------------------------"
  grep -iE 'VULNERABLE|CVE-' "${VULN_XML%.xml}.nmap" 2>/dev/null || echo "  (none reported by NSE)"
  echo
  echo "-- Recommended next steps -----------------------------------------"
  echo "  * Close/justify every high-risk open port (RDP/SMB/Telnet/DB)."
  echo "  * Patch or isolate hosts with CVE findings above."
  echo "  * Enforce MFA and disable legacy/cleartext protocols."
  echo "  * Re-scan after remediation to confirm fixes."
} | tee "$REPORT"

ok "Full run complete. Report: $REPORT"
ok "Alerts pushed to the dashboard feed: ../data/alerts.json"
