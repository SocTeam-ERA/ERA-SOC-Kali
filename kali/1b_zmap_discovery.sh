#!/usr/bin/env bash
# =====================================================================
#  1b_zmap_discovery.sh — FAST internal host discovery with zmap
# =====================================================================
#  zmap is much faster than nmap for sweeping large internal ranges,
#  BUT its default blocklist excludes RFC1918 (private) networks, so a
#  plain `zmap 10.0.0.0/8` finds nothing internally. This script fixes
#  that by pointing zmap at kali/zmap-blocklist.conf (which leaves
#  private ranges scannable) and does a single-port liveness sweep.
#
#  It probes a small set of "is anything here" ports one at a time
#  (zmap scans one port per run) and unions the live hosts. The result
#  is a live-hosts file you can feed straight into the nmap steps:
#
#     ./1b_zmap_discovery.sh 10.10.20.0/24
#     PORTS="443 445 3389" ./1b_zmap_discovery.sh 10.10.0.0/16
#     ./2_port_service_scan.sh results/zmap_live_<stamp>.txt
#
#  Requirements: sudo apt install zmap     (nmap is still used downstream)
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

require_tool zmap zmap
authorize
mark_scan_start
banner "ZMAP FAST DISCOVERY (internal)"

if [[ $# -gt 0 ]]; then TARGETS="$*"; else TARGETS="$(read_targets | tr '\n' ' ')"; fi
[[ -n "$TARGETS" ]] || { err "no targets"; exit 1; }

BLOCK="$SUITE_DIR/zmap-blocklist.conf"
[[ -f "$BLOCK" ]] || { err "missing $BLOCK"; exit 1; }

# Ports used only to decide "host is alive". TCP SYN sweep.
PORTS="${PORTS:-80 443 445 22 3389}"
RATE="${RATE:-10000}"          # packets/sec — keep modest on production nets
OUT_LIVE="$RESULTS_DIR/zmap_live_${STAMP}.txt"
TMP="$RESULTS_DIR/_zmap_${STAMP}"
: > "$TMP"

warn "zmap uses a custom blocklist so RFC1918 is scannable. Authorized targets only."
log "Targets: $TARGETS"
log "Liveness ports: $PORTS   rate: ${RATE}pps"

for p in $PORTS; do
  log "zmap sweep on tcp/$p ..."
  # -p port | -b custom blocklist | -r rate | -q quiet | -o results to stdout list
  # shellcheck disable=SC2086
  sudo zmap -p "$p" -b "$BLOCK" -r "$RATE" -q $TARGETS 2>>"$RESULTS_DIR/zmap_${STAMP}.log" \
      | awk 'NF' >> "$TMP" || warn "zmap on tcp/$p returned nonzero (continuing)"
done

sort -u "$TMP" > "$OUT_LIVE" 2>/dev/null || true
rm -f "$TMP"
COUNT=$(wc -l < "$OUT_LIVE" | tr -d ' ')
ok "Live hosts (union across ports): $COUNT  ->  $OUT_LIVE"
echo "  Next:  ./2_port_service_scan.sh $OUT_LIVE"
echo "$OUT_LIVE"
