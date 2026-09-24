#!/usr/bin/env bash
# =====================================================================
#  1_host_discovery.sh — Find live hosts across the authorized subnets
# =====================================================================
#  Runs a fast ping/ARP sweep (no port scan yet) so you know what is
#  actually up before spending time on deep scans.
#
#  Usage:
#     ./1_host_discovery.sh                 # uses targets.conf
#     ./1_host_discovery.sh 10.10.20.0/24   # override targets on the CLI
#
#  Output:
#     results/live_hosts_<stamp>.txt        # one live IP per line
#     results/host_discovery_<stamp>.gnmap  # raw nmap grepable output
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

require_tool nmap nmap
authorize
mark_scan_start
banner "HOST DISCOVERY"

if [[ $# -gt 0 ]]; then TARGETS="$*"; else TARGETS="$(read_targets)"; fi
[[ -n "$TARGETS" ]] || { err "no targets"; exit 1; }
log "Targets: $(echo "$TARGETS" | tr '\n' ' ')"

OUT_LIVE="$RESULTS_DIR/live_hosts_${STAMP}.txt"
OUT_RAW="$RESULTS_DIR/host_discovery_${STAMP}"

# -sn = ping scan (no ports).  -PE/-PP/-PM = ICMP echo/timestamp/netmask.
# -PS/-PA on common ports catches hosts that block ICMP.  --min-rate speeds it up.
# shellcheck disable=SC2086
sudo /usr/local/sbin/soc-nmap -sn -PE -PP -PS21,22,23,80,443,3389 -PA80,443 \
     --min-rate 500 -oA "$OUT_RAW" $TARGETS | tee "$RESULTS_DIR/host_discovery_${STAMP}.log"

grep "Up$" "${OUT_RAW}.gnmap" | awk '{print $2}' > "$OUT_LIVE" || true
COUNT=$(wc -l < "$OUT_LIVE" | tr -d ' ')
ok "Live hosts: $COUNT  ->  $OUT_LIVE"
echo "$OUT_LIVE"   # print path so the orchestrator can capture it
