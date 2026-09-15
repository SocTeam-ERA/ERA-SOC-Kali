#!/usr/bin/env bash
# =====================================================================
#  1c_arp_discovery.sh — FAST L2 host discovery with arp-scan
# =====================================================================
#  This Kali sits directly on each authorized VLAN (one NIC per VLAN),
#  so ARP is the right primitive: it is instant, reliable, and cannot
#  be blocked by a host/L3 firewall (it works at layer 2). zmap/masscan
#  are built to scan THROUGH a router and do not fit directly-connected
#  subnets — arp-scan does.
#
#  For every authorized VLAN it runs arp-scan on that VLAN's interface,
#  unions the live IPs, and prints the live-hosts file path on the LAST
#  line so it drops straight into the nmap step:
#
#     ./1c_arp_discovery.sh
#     ./2_port_service_scan.sh results/arp_live_<stamp>.txt
#
#  As a bonus it also saves MAC + vendor per host (asset inventory), and
#  feeds that into arp_to_alerts.py, which remembers the known MACs per
#  VLAN and raises a "new/unknown device" alert the first time an
#  unrecognized MAC shows up (Guest WiFi is excluded — see that script).
#  Requirements: sudo apt install arp-scan
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

require_tool arp-scan arp-scan
authorize
mark_scan_start
banner "ARP DISCOVERY (L2, per interface)"

# interface : CIDR  — the 6 authorized VLANs (edit here if wiring changes).
# Mirrors kali/targets.conf; each VLAN is on its own directly-connected NIC.
VLANS=(
  "eth0:10.69.0.0/16"      # VLAN 301  Floor
  "eth1:10.201.0.0/16"     # VLAN 7    Management
  "eth2:10.21.0.0/16"      # VLAN 21   Wiping
  "eth3:192.168.61.0/24"   # VLAN 61   Printers
  "eth4:192.168.7.0/24"    # VLAN 670  Office
  "eth5:192.168.8.0/24"    # VLAN 696  Guest / Employees WiFi
)

# Keep VLANS[] and targets.conf in sync: they describe the same scope from
# two angles (interface+CIDR here, CIDR-only there). Warn (don't fail) if
# they drift apart so an edit to one side doesn't silently go stale.
CONFIGURED_CIDRS="$(read_targets | sort -u)"
VLAN_CIDRS="$(printf '%s\n' "${VLANS[@]}" | sed 's/^[^:]*://' | sort -u)"
if [[ "$CONFIGURED_CIDRS" != "$VLAN_CIDRS" ]]; then
  warn "VLANS[] in this script does not match targets.conf — update both together:"
  diff <(echo "$CONFIGURED_CIDRS") <(echo "$VLAN_CIDRS") 2>/dev/null | sed 's/^/    /' || true
fi

BW="${ARP_BW:-512000}"          # bandwidth cap (bits/s) — paces the big /16 sweeps
RETRY="${ARP_RETRY:-2}"         # retries per host (ARP is reliable; 2 is plenty)
OUT_LIVE="$RESULTS_DIR/arp_live_${STAMP}.txt"
RAW="$RESULTS_DIR/arp_raw_${STAMP}.txt"
ASSETS="$RESULTS_DIR/arp_assets_${STAMP}.tsv"     # cidr<TAB>iface<TAB>ip<TAB>mac<TAB>vendor -> feeds arp_to_alerts.py
TMP="$RESULTS_DIR/_arp_${STAMP}"
VLAN_TMP="$RESULTS_DIR/_arp_vlan_${STAMP}"
: > "$TMP"; : > "$RAW"; : > "$ASSETS"

warn "arp-scan is L2 and authorized-scope only. One sweep per VLAN."
for entry in "${VLANS[@]}"; do
  IFACE="${entry%%:*}"
  CIDR="${entry#*:}"
  if ! ip link show "$IFACE" >/dev/null 2>&1; then
    warn "interface $IFACE not present — skipping $CIDR"
    continue
  fi
  log "arp-scan $CIDR on $IFACE ..."
  # unicast ARP to every address in the range; first field of each line = IP
  sudo arp-scan --interface="$IFACE" --bandwidth="$BW" --retry="$RETRY" "$CIDR" \
      2>>"$RESULTS_DIR/arp_${STAMP}.log" > "$VLAN_TMP" \
      || warn "arp-scan on $IFACE returned nonzero (continuing)"
  cat "$VLAN_TMP" >> "$RAW"
  grep -Eo '^([0-9]{1,3}\.){3}[0-9]{1,3}' "$VLAN_TMP" >> "$TMP"
  # tag each IP/MAC/vendor line with which VLAN it came from, so the asset
  # tracker (arp_to_alerts.py) can tell a Management-VLAN device apart from
  # a Guest-WiFi one and pick the right severity.
  awk -F'\t' -v cidr="$CIDR" -v iface="$IFACE" \
      '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && NF >= 2 { print cidr"\t"iface"\t"$1"\t"$2"\t"$3 }' \
      "$VLAN_TMP" >> "$ASSETS"
done
rm -f "$VLAN_TMP"

sort -u -t. -k1,1n -k2,2n -k3,3n -k4,4n "$TMP" > "$OUT_LIVE" 2>/dev/null \
  || sort -u "$TMP" > "$OUT_LIVE"
rm -f "$TMP"
COUNT=$(wc -l < "$OUT_LIVE" | tr -d ' ')
ok "Live hosts (union across VLANs): $COUNT  ->  $OUT_LIVE"
ok "MAC + vendor detail saved to: $RAW  (asset inventory)"

# New/unknown-device detection: diff this run's MACs per VLAN against the
# known baseline and alert on anything new (Guest WiFi is intentionally
# skipped inside arp_to_alerts.py — see its SKIP_VLANS).
if command -v python3 >/dev/null 2>&1; then
  log "Checking for new/unknown devices per VLAN..."
  python3 "$SUITE_DIR/arp_to_alerts.py" "$ASSETS"
else
  warn "python3 not found — asset list saved at $ASSETS (check manually)."
fi

echo "  Next:  ./2_port_service_scan.sh $OUT_LIVE"
echo "$OUT_LIVE"
