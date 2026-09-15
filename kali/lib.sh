#!/usr/bin/env bash
# lib.sh — shared helpers for the Kali recon suite. Sourced by the scripts.
set -euo pipefail

# ---- paths ----------------------------------------------------------------
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGETS_FILE="${TARGETS_FILE:-$SUITE_DIR/targets.conf}"
RESULTS_DIR="${RESULTS_DIR:-$SUITE_DIR/results}"
STAMP="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RESULTS_DIR"
# The scheduled scan runs as root and can create RESULTS_DIR with a umask that
# leaves it group-read-only, which then blocks the (non-root) 'tee' calls an
# interactive run does for its .log files. Re-assert group-write + setgid
# every time something with permission to do so touches this directory, so
# it self-heals instead of staying locked out until someone chmods it by hand.
chmod g+rwX,g+s "$RESULTS_DIR" 2>/dev/null || true

# ---- colours (hacker green, matches the dashboard) ------------------------
if [[ -t 1 ]]; then
  G=$'\e[32m'; BG=$'\e[1;32m'; Y=$'\e[33m'; R=$'\e[31m'; DIM=$'\e[2m'; N=$'\e[0m'
else
  G=""; BG=""; Y=""; R=""; DIM=""; N=""
fi

log()  { echo "${BG}[*]${N} $*"; }
ok()   { echo "${G}[+]${N} $*"; }
warn() { echo "${Y}[!]${N} $*" >&2; }
err()  { echo "${R}[x]${N} $*" >&2; }

banner() {
  echo "${G}"
  echo "  ┌───────────────────────────────────────────────┐"
  printf "  │  %-45s│\n" "$1"
  echo "  └───────────────────────────────────────────────┘"
  echo "${N}"
}

# ---- preflight ------------------------------------------------------------
require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    err "Required tool '$1' not found. Install it:  sudo apt install $2"
    exit 1
  fi
}

# Authorization gate — refuse to run without explicit acknowledgement.
authorize() {
  if [[ "${SCAN_AUTHORIZED:-no}" != "yes" ]]; then
    warn "You must confirm you are authorized to scan these targets."
    warn "Only scan networks your organization owns and has approved IN WRITING."
    read -rp "Type 'yes' to confirm authorization: " ans
    [[ "$ans" == "yes" ]] || { err "Not authorized. Aborting."; exit 2; }
  fi
}

# Read non-comment, non-empty target lines into a space-separated string.
read_targets() {
  [[ -f "$TARGETS_FILE" ]] || { err "targets file not found: $TARGETS_FILE"; exit 1; }
  grep -vE '^\s*(#|$)' "$TARGETS_FILE" | sed 's/#.*//' | awk '{print $1}'
}

# ---- "an authorized scan is running right now" marker ---------------------
# 4b_traffic_monitor.sh (the continuous traffic watcher) checks this before
# raising port-scan / cleartext-protocol alerts. Without it, every scheduled
# or manual scan this suite runs shows up as its own "attack" -- this box's
# own nmap/zmap/arp-scan probes ARE, from the wire's point of view,
# indistinguishable from someone else's. One line per active scan (keyed by
# PID), so concurrent scans (the timer firing while someone also runs one by
# hand -- this has actually happened) don't clobber each other's marker.
SCAN_MARKER_FILE="$SUITE_DIR/../data/scan_in_progress"
SCAN_MARKER_LOCK="$SUITE_DIR/../data/scan_in_progress.lock"
# Last-ended timestamp -- lets suricata_to_alerts.py/zeek_to_alerts.py (see
# soc_core.py's scan_active()) keep suppressing IDS alerts for a short grace
# window after the marker above goes empty, since a scan's own already-sent
# NSE/HTTP traffic keeps generating responses on the wire for a few seconds
# after the process that sent it is gone (confirmed 2026-09-15: a crashed
# vuln scan's trailing traffic triggered a burst of self-inflicted "attack"
# alerts in the seconds right after its marker line was removed).
SCAN_LAST_ENDED_FILE="$SUITE_DIR/../data/scan_last_ended"

mark_scan_start() {
  mkdir -p "$(dirname "$SCAN_MARKER_FILE")"
  # Both files get created by whichever process (root's scheduled scan, or
  # a team member's manual run) happens to touch them first, using THAT
  # process's umask -- root's default umask leaves them group-read-only,
  # which then locks every other user out of ever opening them again
  # (only the owner or root can chmod a file, so once root creates one at
  # 0644, no non-root group member can self-heal it afterward the way
  # RESULTS_DIR does above). Confirmed: this broke a manual scan outright
  # ("Permission denied" opening the lock file) after the scheduled job
  # had run first. Touch + best-effort chmod here so whichever run creates
  # them for the first time leaves them group-writable for everyone after.
  touch "$SCAN_MARKER_FILE" "$SCAN_MARKER_LOCK" "$SCAN_LAST_ENDED_FILE" 2>/dev/null || true
  chmod g+rw "$SCAN_MARKER_FILE" "$SCAN_MARKER_LOCK" "$SCAN_LAST_ENDED_FILE" 2>/dev/null || true
  (
    flock -x 200
    echo "$$:$(date -Is):$(basename "$0")" >> "$SCAN_MARKER_FILE"
  ) 200>"$SCAN_MARKER_LOCK"
  trap mark_scan_end EXIT
}

mark_scan_end() {
  [[ -f "$SCAN_MARKER_FILE" ]] || return 0
  # Locked read-modify-write: without this, two scans ending at nearly the
  # same moment both read-then-overwrite this file using the SAME fixed tmp
  # filename, and whichever one's mv() loses the race can leave the OTHER
  # scan's already-finished PID line stuck in here forever (this has
  # actually happened, per the comment above on why this file is
  # PID-keyed). A stuck line means [[ -s "$SCAN_MARKER_FILE" ]] reads
  # non-empty forever, which silently suppresses Suricata/Zeek/
  # traffic-monitor alerts indefinitely -- not just during the scan that
  # left it behind, but every scan after it too.
  #
  # The '> tmp && mv tmp real' rewrite below creates a brand-new file, so
  # its permissions come from the CURRENT PROCESS's umask, not from
  # whatever mode the file had before. root's default umask (022) yields
  # 644 -- no group-write -- silently undoing mark_scan_start's chmod the
  # moment any scan ends, including scans that never touch these files as
  # root themselves (soc-scan.timer runs scheduled_scan.sh as root; the
  # very next *manual* scan's mark_scan_end then rewrites the file too,
  # and since a non-root user can't chmod a file root now owns, the lockout
  # persists until someone runs 'sudo chmod g+rw' by hand again). Confirmed
  # this exact cycle repeating 2026-09-15. Fix: explicitly chmod the tmp
  # file before the mv, every time, so every rewrite self-heals regardless
  # of who ran it or what their umask was.
  (
    flock -x 200
    grep -v "^$$:" "$SCAN_MARKER_FILE" > "${SCAN_MARKER_FILE}.tmp" 2>/dev/null || true
    chmod g+rw "${SCAN_MARKER_FILE}.tmp" 2>/dev/null || true
    mv -f "${SCAN_MARKER_FILE}.tmp" "$SCAN_MARKER_FILE" 2>/dev/null || true
    date -Is > "${SCAN_LAST_ENDED_FILE}.tmp" 2>/dev/null && chmod g+rw "${SCAN_LAST_ENDED_FILE}.tmp" 2>/dev/null && mv -f "${SCAN_LAST_ENDED_FILE}.tmp" "$SCAN_LAST_ENDED_FILE" 2>/dev/null || true
  ) 200>"$SCAN_MARKER_LOCK"
}
