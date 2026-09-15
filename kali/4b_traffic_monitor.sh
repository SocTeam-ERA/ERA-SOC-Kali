#!/usr/bin/env bash
# =====================================================================
#  4b_traffic_monitor.sh — CONTINUOUS passive traffic monitoring
# =====================================================================
#  4_traffic_capture.sh is a manual, one-shot tool: nothing is watching
#  the wire unless someone remembers to run it. This is the always-on
#  version -- captures on every interface at once (`-i any`, so all 6
#  VLANs this Kali sits on), in fixed windows, feeding each window
#  straight into traffic_to_alerts.py (unchanged, same detection logic
#  as the manual tool) so IOC contact / port-scan-on-the-wire / cleartext
#  protocols / suspicious DNS get caught close to live instead of only
#  when someone happens to be watching.
#
#  LIMITATION -- be aware of this: each window is analysed independently,
#  with no memory of the previous one. A slow/low scan spread out below
#  the per-window threshold (default window: 180s, port-scan threshold:
#  15 distinct ports in traffic_to_alerts.py) can fall between the
#  cracks. A loud, bursty scan within one window is still caught
#  immediately.
#
#  WIRESHARK: every window is captured as a real .pcap (not just the
#  extracted summary fields), but only kept when that window actually
#  raised an alert -- everything else is discarded so this doesn't fill
#  the disk. A kept capture lives in results/flagged_captures/ and its
#  path is recorded in the alert's details.pcap, so opening the exact
#  traffic behind an alert in Wireshark is just `wireshark <that path>`.
#  The retention job (cleanup_results.sh) ages these out same as
#  everything else under results/.
#
#  Meant to run as a systemd service (Restart=always), not interactively
#  -- see soc-traffic-monitor.service. Runs fine as a non-root member of
#  the 'wireshark' group (setcap already applied to dumpcap by
#  setup-kali-soc.sh), root also works.
#
#  Usage:
#     CAPTURE_AUTHORIZED=yes ./4b_traffic_monitor.sh   # required, see below
#     IFACE=eth1 CAPTURE_AUTHORIZED=yes ./4b_traffic_monitor.sh   # one interface only
#     WINDOW=60 CAPTURE_AUTHORIZED=yes ./4b_traffic_monitor.sh    # shorter/longer window (seconds)
#
#  Requirements: same as 4_traffic_capture.sh (tshark).
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"
DIR="$(dirname "$0")"

require_tool tshark tshark
banner "CONTINUOUS TRAFFIC MONITOR"

IFACE="${IFACE:-any}"
WINDOW="${WINDOW:-180}"

# Same "capture is its own authorization gate" principle as
# 4_traffic_capture.sh -- but this runs unattended via systemd, so an
# interactive prompt won't work. Require the env var explicitly instead;
# the systemd unit sets it, which is itself a deliberate, reviewable
# decision made when the service is installed, not a silent default-on.
if [[ "${CAPTURE_AUTHORIZED:-no}" != "yes" ]]; then
  err "Set CAPTURE_AUTHORIZED=yes to confirm you're authorized to continuously"
  err "monitor traffic on interface '$IFACE'. This runs unattended, so there is"
  err "no interactive prompt -- the confirmation has to be explicit up front."
  exit 2
fi

warn "Continuous traffic monitor on interface '$IFACE', ${WINDOW}s windows. Ctrl-C to stop."

# Sweep away any _traffic_live_* leftovers from a previous run that didn't
# shut down cleanly (killed mid-cycle, crashed, etc.) -- these are always
# meant to be transient, so anything still here at startup is stale.
rm -f "$RESULTS_DIR"/_traffic_live_*.tsv "$RESULTS_DIR"/_traffic_live_*.pcap 2>/dev/null || true

FIELDS=(-T fields -E separator=/t
  -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport
  -e _ws.col.Protocol -e dns.qry.name -e http.host -e tcp.flags.syn -e tcp.flags.ack)

FLAGGED_DIR="$RESULTS_DIR/flagged_captures"
mkdir -p "$FLAGGED_DIR"
chmod g+rwX,g+s "$FLAGGED_DIR" 2>/dev/null || true

while true; do
  TS="$(date +%Y%m%d_%H%M%S)"
  PCAP_TMP="$RESULTS_DIR/_traffic_live_${TS}.pcap"
  PCAP_FINAL="$FLAGGED_DIR/traffic_${TS}.pcap"
  TSV="$RESULTS_DIR/_traffic_live_${TS}.tsv"

  # Checked before AND after the capture: an authorized scan (1_/1b_/1c_/2_/
  # 3_*.sh, via mark_scan_start in lib.sh) active at either edge of this
  # window means its own probe/reply traffic could be in here -- skip
  # analysis rather than flag this box's own scan as an attack on itself.
  SCAN_WAS_ACTIVE=0
  [[ -s "$SCAN_MARKER_FILE" ]] && SCAN_WAS_ACTIVE=1

  # Capture the real packets for this window (not just extracted fields) --
  # this is what makes the Wireshark hand-off possible.
  tshark -i "$IFACE" -a "duration:$WINDOW" -w "$PCAP_TMP" 2>/dev/null \
      || warn "tshark window at $TS returned nonzero (continuing)"

  [[ -s "$SCAN_MARKER_FILE" ]] && SCAN_WAS_ACTIVE=1

  if [[ "$SCAN_WAS_ACTIVE" == "1" ]]; then
    log "An authorized scan was active during this window -- skipping traffic analysis."
    rm -f "$PCAP_TMP"
  elif [[ -s "$PCAP_TMP" ]]; then
    # Extract the same summary fields traffic_to_alerts.py needs -- read
    # from the pcap just captured, not a second live capture.
    tshark -r "$PCAP_TMP" "${FIELDS[@]}" > "$TSV" 2>/dev/null
    if [[ -s "$TSV" ]]; then
      # traffic_to_alerts.py prints its own alert count on stdout as the
      # last line (see its main()) -- read straight from that instead of
      # diffing alerts.jsonl's line count. That file is shared by every
      # detector in the system now (login/osquery/zeek/suricata/scans all
      # write to it concurrently), so an unrelated alert landing in the
      # same instant used to make an unrelated window's traffic look like
      # it had raised something.
      RAISED=$(python3 "$DIR/traffic_to_alerts.py" "$TSV" \
          --ioc-ips "$DIR/ioc_ips.txt" --bad-domains "$DIR/bad_domains.txt" \
          --pcap "$PCAP_FINAL") || { warn "traffic_to_alerts.py failed on $TSV (continuing)"; RAISED=0; }
      RAISED="${RAISED:-0}"
      if [[ "$RAISED" -gt 0 ]] 2>/dev/null; then
        mv -f "$PCAP_TMP" "$PCAP_FINAL"
        chmod 664 "$PCAP_FINAL" 2>/dev/null || true
        ok "Alert(s) raised this window -- kept the capture: $PCAP_FINAL"
      else
        rm -f "$PCAP_TMP"
      fi
    else
      rm -f "$PCAP_TMP"
    fi
    rm -f "$TSV"
  else
    rm -f "$PCAP_TMP"
  fi
done
