#!/usr/bin/env bash
# =====================================================================
#  5_vlan_segmentation_test.sh — cross-VLAN reachability / segmentation test
# =====================================================================
#  This Kali sits directly on all 6 authorized VLANs (one NIC per VLAN),
#  which makes it uniquely positioned to test whether the VLANs are
#  actually isolated from each other the way they're supposed to be --
#  but that same multi-homing is exactly what makes a NAIVE test
#  meaningless: since this box has a directly-connected route to every
#  VLAN's subnet, simply pinging a host on VLAN B from VLAN A's interface
#  only proves Kali itself can reach it (trivially true, it's on both
#  networks already), not whether an ORDINARY single-homed host on VLAN A
#  would be allowed through by the real firewall/router in between.
#
#  So for each (source VLAN, destination VLAN) pair, this temporarily
#  overrides the route to the destination gateway to go OUT VIA THE
#  SOURCE VLAN'S OWN GATEWAY instead of Kali's directly-connected
#  shortcut -- forcing the probe through the same path an ordinary host
#  on that VLAN would have to take, so the real gateway/firewall gets a
#  chance to block it (or not). The temporary route is removed right
#  after each single probe, and a trap guarantees cleanup even if this
#  is interrupted mid-run.
#
#  Probe: ICMP ping to the destination VLAN's gateway. Confirmed
#  empirically that all 6 gateways answer ping directly, while TCP
#  443/22 were intermittently filtered/unresponsive during testing --
#  ICMP is the more reliable signal here.
#
#  Needs root for the temporary route add/del (ip route). Run this one
#  interactively, in a real terminal -- not through an automation layer
#  that can't hold an interactive sudo session.
#
#  Usage:
#     sudo ./5_vlan_segmentation_test.sh
#
#  Output:
#     results/vlan_segmentation_<stamp>.tsv
#     Alerts for every REACHABLE cross-VLAN pair (should be none, ideally)
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

authorize
mark_scan_start
banner "VLAN SEGMENTATION TEST"

if [[ $EUID -ne 0 ]]; then
  err "This needs root (temporary 'ip route' changes). Run: sudo $0"
  exit 1
fi

# interface : CIDR : name -- mirrors targets.conf / 1c_arp_discovery.sh's VLANS[].
VLANS=(
  "eth0:10.69.0.0/16:Floor"
  "eth1:10.201.0.0/16:Management"
  "eth2:10.21.0.0/16:Wiping"
  "eth3:192.168.61.0/24:Printers"
  "eth4:192.168.7.0/24:Office"
  "eth5:192.168.8.0/24:Guest-Employee-WiFi"
)

gateway_of() {
  python3 -c "import ipaddress,sys; print(ipaddress.ip_network(sys.argv[1], strict=False).network_address + 1)" "$1"
}

RESULTS_FILE="$RESULTS_DIR/vlan_segmentation_${STAMP}.tsv"
printf 'source_vlan\tdest_vlan\tsource_gw\tdest_gw\tresult\n' > "$RESULTS_FILE"

# Safety net: if this gets interrupted between 'ip route add' and the
# matching 'ip route del' for whatever pair is in flight, don't leave a
# stray cross-VLAN route sitting on a production appliance.
CURRENT_ROUTE=""
cleanup_route() {
  if [[ -n "$CURRENT_ROUTE" ]]; then
    # shellcheck disable=SC2086
    ip route del $CURRENT_ROUTE 2>/dev/null || true
    CURRENT_ROUTE=""
  fi
}
trap cleanup_route EXIT

TOTAL=0
REACHABLE=0

for src in "${VLANS[@]}"; do
  SRC_IFACE="${src%%:*}"
  SRC_REST="${src#*:}"
  SRC_CIDR="${SRC_REST%%:*}"
  SRC_NAME="${SRC_REST#*:}"

  if ! ip link show "$SRC_IFACE" >/dev/null 2>&1; then
    warn "interface $SRC_IFACE not present -- skipping $SRC_NAME as a source"
    continue
  fi
  SRC_GW="$(gateway_of "$SRC_CIDR")"

  for dst in "${VLANS[@]}"; do
    DST_IFACE="${dst%%:*}"
    DST_REST="${dst#*:}"
    DST_CIDR="${DST_REST%%:*}"
    DST_NAME="${DST_REST#*:}"

    [[ "$SRC_IFACE" == "$DST_IFACE" ]] && continue
    if ! ip link show "$DST_IFACE" >/dev/null 2>&1; then
      continue
    fi
    DST_GW="$(gateway_of "$DST_CIDR")"

    TOTAL=$((TOTAL + 1))
    CURRENT_ROUTE="$DST_GW/32 via $SRC_GW dev $SRC_IFACE"
    ip route add $CURRENT_ROUTE 2>/dev/null || true

    if timeout 3 ping -c 2 -W 1 -I "$SRC_IFACE" "$DST_GW" >/dev/null 2>&1; then
      RESULT="REACHABLE"
      REACHABLE=$((REACHABLE + 1))
      warn "$SRC_NAME -> $DST_NAME: REACHABLE (should this be blocked?)"
    else
      RESULT="blocked"
      ok "$SRC_NAME -> $DST_NAME: blocked"
    fi

    cleanup_route

    printf '%s\t%s\t%s\t%s\t%s\n' "$SRC_NAME" "$DST_NAME" "$SRC_GW" "$DST_GW" "$RESULT" >> "$RESULTS_FILE"
  done
done

trap - EXIT
echo
log "Tested $TOTAL cross-VLAN pair(s), $REACHABLE reachable (not isolated)."
ok "Results: $RESULTS_FILE"

if command -v python3 >/dev/null 2>&1; then
  python3 "$SUITE_DIR/vlan_segmentation_to_alerts.py" "$RESULTS_FILE"
fi
