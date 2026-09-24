#!/usr/bin/env bash
# =====================================================================
#  2_port_service_scan.sh — Port + service/version scan of live hosts
# =====================================================================
#  Takes a file of live hosts (from step 1) or targets.conf and runs a
#  TCP SYN scan with service/version and OS detection.
#
#  Usage:
#     ./2_port_service_scan.sh results/live_hosts_XXXX.txt
#     ./2_port_service_scan.sh                 # falls back to targets.conf
#     FAST=1 ./2_port_service_scan.sh ...      # top-1000 ports only (quicker)
#     INCLUDE_GUEST_WIFI=1 ./2_port_service_scan.sh ...  # scan it anyway (see below)
#     SKIP_UDP=1 ./2_port_service_scan.sh ...  # skip the UDP sweep below
#
#  Everything above this line is TCP-only (-sS). A misconfigured DNS
#  resolver, an SNMP daemon still on its default community string, or an
#  exposed NTP service are all completely invisible to a TCP-only scan, so
#  this script also runs a small, targeted UDP sweep (DNS/NTP/SNMP -- the
#  highest-value, most commonly-misconfigured UDP services) and imports it
#  separately with its own diff-state, so repeat runs don't flood either.
#
#  Guest WiFi (192.168.8.0/24) is personal devices, not company assets, so
#  this script excludes it by default no matter how it's called -- whether
#  fed a live-hosts file from step 1/1b/1c, called with bare targets on the
#  CLI, or falling back to targets.conf. This used to only be enforced by
#  scheduled_scan.sh, which meant any manual chain (as the docstrings here
#  literally suggest) skipped the privacy filter entirely. Set
#  INCLUDE_GUEST_WIFI=1 for the rare case where scanning it is genuinely
#  needed (e.g. investigating a specific incident).
#
#  Output:
#     results/services_<stamp>.xml    # machine-readable (feeds the JSON step)
#     results/services_<stamp>.nmap   # human-readable
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

require_tool nmap nmap
authorize
mark_scan_start
banner "PORT & SERVICE SCAN"

GUEST_WIFI_RE='^192\.168\.8\.'

filter_guest_wifi() {  # stdin -> stdout, Guest WiFi lines removed (unless opted in)
  if [[ "${INCLUDE_GUEST_WIFI:-0}" == "1" ]]; then
    cat
  else
    grep -vE "$GUEST_WIFI_RE" || true
  fi
}

if [[ $# -gt 0 && -f "$1" ]]; then
  FILTERED="$RESULTS_DIR/_targets_filtered_${STAMP}.txt"
  filter_guest_wifi < "$1" > "$FILTERED"
  TARGET_ARG=(-iL "$FILTERED"); log "Scanning hosts listed in $1 (Guest WiFi excluded)"
  UDP_STATE_NAME="udp_state.json"   # a live-hosts file is the broad/scheduled-style case
elif [[ $# -gt 0 ]]; then
  TARGET_ARG=()
  for t in "$@"; do
    if [[ "${INCLUDE_GUEST_WIFI:-0}" == "1" || ! "$t" =~ $GUEST_WIFI_RE ]]; then
      TARGET_ARG+=("$t")
    fi
  done
  log "Scanning: ${TARGET_ARG[*]:-<nothing left after excluding Guest WiFi>}"
  # Bare targets on the CLI are a one-off/narrow check (like scanning a
  # single host to verify something) -- NOT the same scope as a full VLAN
  # sweep. Sharing one UDP diff-state file between the two would make every
  # host missing from this narrower run look like its ports just "closed"
  # (confirmed: this exact scenario just flooded the feed with 117 false
  # "CLOSED" alerts). Same reasoning as port_state.json vs
  # port_state_manual.json for the TCP side.
  UDP_STATE_NAME="udp_state_manual.json"
else
  read_targets | filter_guest_wifi > "$RESULTS_DIR/_targets_${STAMP}.txt"
  TARGET_ARG=(-iL "$RESULTS_DIR/_targets_${STAMP}.txt"); log "Scanning targets.conf (Guest WiFi excluded)"
  UDP_STATE_NAME="udp_state.json"
fi

OUT="$RESULTS_DIR/services_${STAMP}"

if [[ "${FAST:-0}" == "1" ]]; then
  PORTSPEC="--top-ports 1000"
else
  PORTSPEC="-p-"   # all 65535 TCP ports (thorough, slower)
fi

# -sS SYN scan | -sV version detect | -O OS detect | -sC default NSE scripts
# -T4 timing | --open only show open ports
# shellcheck disable=SC2086
sudo /usr/local/sbin/soc-nmap -sS -sV -O -sC -T4 --open $PORTSPEC \
     -oA "$OUT" "${TARGET_ARG[@]}" | tee "${OUT}.log"

ok "Service scan complete -> ${OUT}.nmap  (XML: ${OUT}.xml)"

# --- UDP: small, fixed, high-value port set. --open only reports nmap's
# confirmed "open" state, not the ambiguous "open|filtered" every
# non-responding UDP port gets by default, so a host that simply doesn't
# run DNS/NTP/SNMP won't show up here at all. Diff-state uses UDP_STATE_NAME
# (set above) so a narrow/manual target list never diffs against the broad
# scheduled sweep's state -- see the comment where it's set.
UDP_PORTS="${UDP_PORTS:-53,123,161}"
if [[ "${SKIP_UDP:-0}" != "1" ]]; then
  UDP_OUT="$RESULTS_DIR/services_udp_${STAMP}"
  log "UDP sweep on ports $UDP_PORTS (DNS/NTP/SNMP)..."
  sudo /usr/local/sbin/soc-nmap -sU -sV -T4 --open -p "$UDP_PORTS" \
       -oA "$UDP_OUT" "${TARGET_ARG[@]}" | tee "${UDP_OUT}.log"
  if command -v python3 >/dev/null 2>&1; then
    python3 "$SUITE_DIR/nmap_to_alerts.py" "${UDP_OUT}.xml" \
        --baseline "${BASELINE:-}" \
        --diff-state "$SUITE_DIR/../data/$UDP_STATE_NAME" || true
  fi
else
  log "SKIP_UDP=1 -- skipping the UDP sweep."
fi

echo "${OUT}.xml"
