#!/usr/bin/env bash
# =====================================================================
#  4_traffic_capture.sh — Passive traffic monitoring with tshark
# =====================================================================
#  IMPORTANT — why this is a SEPARATE script:
#  tshark is NOT a scanner. Its target is a network INTERFACE (e.g. eth0),
#  not an IP address. That is why it fails the IP-based authorization gate
#  used by the nmap/zmap scripts. Capture belongs to its own gate:
#  "am I authorized to monitor traffic on THIS interface / network?"
#
#  This script captures traffic (live on an interface, or from a .pcap),
#  extracts the fields traffic_to_alerts.py needs, and turns suspicious
#  traffic into SOC alerts.
#
#  Usage:
#     sudo ./4_traffic_capture.sh -i eth0 -c 2000      # live: 2000 packets
#     sudo ./4_traffic_capture.sh -i eth0 -d 60        # live: 60 seconds
#     ./4_traffic_capture.sh -r capture.pcap           # offline pcap (no sudo)
#
#  Requirements: sudo apt install tshark
#  (During install, answer "Yes" to let non-root users capture, OR run with sudo.)
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"
DIR="$(dirname "$0")"

require_tool tshark tshark
banner "PASSIVE TRAFFIC CAPTURE (tshark)"

IFACE=""; PCAP=""; COUNT=""; DURATION=""
while getopts "i:r:c:d:" opt; do
  case "$opt" in
    i) IFACE="$OPTARG";;
    r) PCAP="$OPTARG";;
    c) COUNT="$OPTARG";;
    d) DURATION="$OPTARG";;
    *) err "usage: $0 -i <iface> [-c count | -d seconds]  |  -r <file.pcap>"; exit 1;;
  esac
done

# --- interface-specific authorization gate (NOT the IP gate) ---
capture_authorize() {
  if [[ "${CAPTURE_AUTHORIZED:-no}" == "yes" ]]; then return; fi
  warn "You are about to CAPTURE NETWORK TRAFFIC on '${IFACE:-$PCAP}'."
  warn "Only monitor interfaces/networks your organization authorized you to observe."
  read -rp "Type 'yes' to confirm capture authorization: " ans
  [[ "$ans" == "yes" ]] || { err "Not authorized. Aborting."; exit 2; }
}

FIELDS=(-T fields -E separator=/t
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport
  -e _ws.col.Protocol -e dns.qry.name -e http.host -e tcp.flags.syn -e tcp.flags.ack)

TSV="$RESULTS_DIR/traffic_${STAMP}.tsv"

if [[ -n "$PCAP" ]]; then
  [[ -f "$PCAP" ]] || { err "pcap not found: $PCAP"; exit 1; }
  log "Reading offline capture: $PCAP"
  tshark -r "$PCAP" "${FIELDS[@]}" > "$TSV" 2>/dev/null
elif [[ -n "$IFACE" ]]; then
  capture_authorize
  STOP=()
  [[ -n "$COUNT" ]] && STOP+=(-c "$COUNT")
  [[ -n "$DURATION" ]] && STOP+=(-a duration:"$DURATION")
  [[ ${#STOP[@]} -eq 0 ]] && STOP+=(-c 2000)   # default safety stop
  log "Capturing on $IFACE (${STOP[*]}) ... Ctrl-C to stop early"
  # capture filter: IP traffic only, skip our own SSH noise is optional
  sudo tshark -i "$IFACE" "${STOP[@]}" "${FIELDS[@]}" > "$TSV" 2>/dev/null
else
  err "give -i <iface> for live capture, or -r <file.pcap> for offline"
  exit 1
fi

LINES=$(wc -l < "$TSV" | tr -d ' ')
ok "Captured $LINES packet records -> $TSV"

# analyse -> alerts
if command -v python3 >/dev/null 2>&1; then
  log "Analysing traffic for suspicious patterns..."
  python3 "$DIR/traffic_to_alerts.py" "$TSV" \
      --ioc-ips "$DIR/ioc_ips.txt" --bad-domains "$DIR/bad_domains.txt"
  ok "Traffic alerts pushed to the dashboard feed (../data/alerts.json)."
else
  warn "python3 not found — raw capture saved at $TSV (analyse it later)."
fi
