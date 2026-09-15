#!/usr/bin/env bash
# =====================================================================
#  cleanup_results.sh — retention cleanup for kali/results/
# =====================================================================
#  Raw scan output (nmap XML/gnmap/.nmap/.log, arp-scan raw dumps,
#  traffic TSVs) accumulates forever otherwise -- nothing ever deletes
#  it. Its value is already extracted into data/alerts.jsonl (the
#  permanent audit record) well before a file here is old enough to
#  hit the retention window, so it's safe to age these out.
#
#  This does NOT touch data/ (alerts.jsonl, port_state.json, etc.) --
#  only kali/results/, which is disposable raw scan output.
#
#  Usage:
#     ./cleanup_results.sh                   # deletes files older than 90 days
#     RETENTION_DAYS=30 ./cleanup_results.sh  # custom retention window
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

DAYS="${RETENTION_DAYS:-90}"
COUNT=$(find "$RESULTS_DIR" -type f -mtime "+$DAYS" | wc -l)

if [[ "$COUNT" -gt 0 ]]; then
  find "$RESULTS_DIR" -type f -mtime "+$DAYS" -delete
  ok "Deleted $COUNT file(s) older than $DAYS days from $RESULTS_DIR"
else
  log "No files older than $DAYS days in $RESULTS_DIR -- nothing to clean up."
fi
