#!/usr/bin/env bash
# =====================================================================
#  scheduled_scan.sh — periodic authorized sweep for the SOC
# =====================================================================
#  Run unattended by the systemd unit  soc-scan.service  (via soc-scan.timer).
#  Pipeline:  ARP discovery (L2, all VLANs) -> nmap service scan -> alerts.
#  No intrusive vuln checks here; that stays manual and coordinated.
#
#  Env inherited from the service (e.g. SOC_MAX_SNAPSHOT) is respected.
# ---------------------------------------------------------------------
set -uo pipefail
export SCAN_AUTHORIZED=yes
cd /opt/sentinel-soc/kali || exit 1

echo "[scheduled_scan] $(date -Is) starting"

# 1) fast L2 discovery across every authorized VLAN (arp-scan)
LIVE="$(./1c_arp_discovery.sh | tail -n1)"
if [ ! -s "$LIVE" ]; then
  echo "[scheduled_scan] no live hosts found — nothing to scan"
  exit 0
fi
echo "[scheduled_scan] live hosts file: $LIVE"

# 2) service / version scan on the live hosts (fast profile).
#    Guest WiFi (192.168.8.0/24) is personal devices: we DISCOVER it (above)
#    but do NOT port-scan it — privacy. Strip it before the nmap step.
#    NOTE: grep -v exits 1 (not 0) when every line matches the excluded
#    pattern, i.e. when ALL live hosts this run happen to be Guest WiFi. A
#    "|| cp" fallback there would silently copy the UNFILTERED list on
#    exactly that case -- the one time filtering matters most. An empty
#    SCAN_LIST is the correct outcome, not a failure, so just swallow the
#    exit code instead of falling back to it.
SCAN_LIST="${LIVE%.txt}_scan.txt"
grep -vE '^192\.168\.8\.' "$LIVE" > "$SCAN_LIST" || true
echo "[scheduled_scan] port-scanning $(wc -l < "$SCAN_LIST") hosts (Guest WiFi excluded)"
SERVICES_XML="$(FAST=1 ./2_port_service_scan.sh "$SCAN_LIST" | tail -n1)"
if [ ! -s "$SERVICES_XML" ]; then
  echo "[scheduled_scan] no service XML produced — exiting"
  exit 0
fi
echo "[scheduled_scan] service scan XML: $SERVICES_XML"

# 3) turn nmap results into SOC alerts.
#    --baseline  : expected-open ports don't escalate to critical.
#    --diff-state: change-detection — after the first (baseline) run, only alert
#                  on ports that OPEN or CLOSE vs the previous scan (kills noise).
#                  port_state_v2.json (not the old port_state.json): the state
#                  is now keyed by MAC address instead of IP -- confirmed
#                  2026-09-18, a DHCP lease renewal made a known device look
#                  brand new (every normal port flagged "new") under the old
#                  IP-keyed scheme. A new filename lets this cut over through
#                  the existing "first run seeds the baseline quietly" path
#                  instead of trying to reinterpret the old schema.
python3 nmap_to_alerts.py "$SERVICES_XML" \
    --baseline 22,443 \
    --diff-state /opt/sentinel-soc/data/port_state_v2.json

echo "[scheduled_scan] $(date -Is) done"
