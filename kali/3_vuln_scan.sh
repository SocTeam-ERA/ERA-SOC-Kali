#!/usr/bin/env bash
# =====================================================================
#  3_vuln_scan.sh — Vulnerability scan using nmap NSE 'vuln' scripts
# =====================================================================
#  Runs nmap's vulnerability NSE category against the targets, plus two
#  low-noise checks for common low-hanging-fruit misconfigurations that the
#  generic 'vuln' category sometimes misses: anonymous FTP login
#  (ftp-anon) and default web-app credentials (http-default-accounts).
#  Both stay completely silent unless they actually find something, so
#  they don't add noise on hosts where everything is fine. Optionally
#  uses 'vulners' (if installed) to map service versions to CVEs.
#
#  Also fingerprints every HTTP(S) service this scan finds with whatweb
#  (server/CMS/framework/version detection) and turns that into alerts too
#  -- see whatweb_to_alerts.py. Set SKIP_WHATWEB=1 to turn that part off.
#
#  Also checks every host for default/weak SNMP community strings
#  (snmp-brute, snmp-info over UDP/161 -- set SKIP_SNMP=1 to turn that
#  part off) and runs nikto against every HTTP(S) service found (web
#  vulnerability scan -- see nikto_to_alerts.py; set SKIP_NIKTO=1 to
#  turn that part off).
#
#  Usage:
#     ./3_vuln_scan.sh results/live_hosts_XXXX.txt
#     ./3_vuln_scan.sh 10.10.20.10
#
#  Output:
#     results/vuln_<stamp>.xml / .nmap
#
#  NOTE: 'vuln' scripts are noisier and can be intrusive against fragile
#  services (printers, legacy SCADA, etc.). Coordinate with IT and avoid
#  production-critical hosts during business hours.
# ---------------------------------------------------------------------
source "$(dirname "$0")/lib.sh"

require_tool nmap nmap
authorize
mark_scan_start
banner "VULNERABILITY SCAN"

if [[ $# -gt 0 && -f "$1" ]]; then
  RAW_TARGETS_FILE="$1"
elif [[ $# -gt 0 ]]; then
  RAW_TARGETS_FILE="$RESULTS_DIR/_rawtargets_${STAMP}.txt"
  printf '%s\n' "$@" > "$RAW_TARGETS_FILE"
else
  RAW_TARGETS_FILE="$RESULTS_DIR/_targets_${STAMP}.txt"
  read_targets > "$RAW_TARGETS_FILE"
fi

OUT="$RESULTS_DIR/vuln_${STAMP}"

# Build the script set. 'vulners' is optional (script may not be installed).
# ssl-enum-ciphers/ssl-cert check TLS posture (deprecated protocols, weak
# ciphers, expired/self-signed certs) -- nmap_to_alerts.py only turns their
# output into an alert when it actually shows a problem, not for every
# healthy HTTPS port.
SCRIPTS="vuln,ftp-anon,http-default-accounts,ssl-enum-ciphers,ssl-cert"
if nmap --script-help vulners >/dev/null 2>&1; then
  SCRIPTS="$SCRIPTS,vulners"
  log "vulners NSE available — CVE mapping enabled"
fi

warn "Vulnerability scripts can be intrusive. Scan approved hosts only."

# Expand whatever we were given (a file of IPs, a CIDR, a range, single
# hosts) into one IP per line, then run the heavy NSE scripts in small
# batches instead of one giant nmap invocation. A single nmap process
# running 'vuln'+'vulners' against 300+ hosts at once has been observed
# to crash nmap itself with an internal engine assertion
# ("nse_nsock.cc: Assertion `lua_status(L) == LUA_YIELD' failed", SIGABRT)
# -- a known NSE/nsock coroutine-scheduler bug under high script
# concurrency, not a bug in our scripts. Under 'set -e' that abort took
# the WHOLE scan down and lost every host, not just the one that
# triggered it. Batching means one crashed batch only costs that
# batch's hosts, and capping --max-parallelism makes the crash far less
# likely to begin with.
EXPANDED_TARGETS="$RESULTS_DIR/_expanded_${STAMP}.txt"
nmap -n -sL -iL "$RAW_TARGETS_FILE" 2>/dev/null \
    | awk '/^Nmap scan report/{print $NF}' | tr -d '()' > "$EXPANDED_TARGETS"

BATCH_SIZE="${VULN_SCAN_BATCH_SIZE:-20}"
MAX_PARALLELISM="${VULN_SCAN_MAX_PARALLELISM:-10}"
mapfile -t ALL_HOSTS < "$EXPANDED_TARGETS"
TOTAL_HOSTS=${#ALL_HOSTS[@]}
TOTAL_BATCHES=$(( (TOTAL_HOSTS + BATCH_SIZE - 1) / BATCH_SIZE ))
log "Running vuln scan against $TOTAL_HOSTS host(s) in $TOTAL_BATCHES batch(es) of $BATCH_SIZE (max-parallelism=$MAX_PARALLELISM)..."

BATCH_DIR="$RESULTS_DIR/_vulnbatches_${STAMP}"
mkdir -p "$BATCH_DIR"
FAILED_BATCHES=0
BATCH_XMLS=()
: > "${OUT}.log"
: > "${OUT}.nmap"

for ((i = 0; i < TOTAL_HOSTS; i += BATCH_SIZE)); do
  batch_num=$((i / BATCH_SIZE + 1))
  batch_file="$BATCH_DIR/batch_${batch_num}.txt"
  printf '%s\n' "${ALL_HOSTS[@]:i:BATCH_SIZE}" > "$batch_file"
  batch_out="$BATCH_DIR/vuln_${batch_num}"
  log "Batch $batch_num/$TOTAL_BATCHES ($(wc -l < "$batch_file") hosts)..."
  # shellcheck disable=SC2069
  if sudo /usr/local/sbin/soc-nmap -sV --script "$SCRIPTS" -T3 --max-parallelism "$MAX_PARALLELISM" \
       -oA "$batch_out" -iL "$batch_file" 2>&1 | tee -a "${OUT}.log"; then
    :
  else
    warn "Batch $batch_num crashed or errored -- skipping (hosts: $(tr '\n' ' ' < "$batch_file"))"
    FAILED_BATCHES=$((FAILED_BATCHES + 1))
  fi
  [[ -f "${batch_out}.xml" ]] && BATCH_XMLS+=("${batch_out}.xml")
  [[ -f "${batch_out}.nmap" ]] && cat "${batch_out}.nmap" >> "${OUT}.nmap"
done

if [[ ${#BATCH_XMLS[@]} -eq 0 ]]; then
  err "Every batch failed -- no results produced."
  exit 1
fi

# Merge all batch XML files into one combined report so downstream
# consumers (nmap_to_alerts.py, 0_run_all.sh, the WEB_TARGETS extraction
# below) keep seeing a single "${OUT}.xml", same contract as before
# batching existed.
python3 - "${OUT}.xml" "${BATCH_XMLS[@]}" <<'PY'
import sys
import xml.etree.ElementTree as ET

out_path, batch_paths = sys.argv[1], sys.argv[2:]
merged = None
for p in batch_paths:
    root = ET.parse(p).getroot()
    if merged is None:
        merged = root
        continue
    for host in root.findall("host"):
        merged.append(host)
ET.ElementTree(merged).write(out_path, encoding="UTF-8", xml_declaration=True)
PY

if [[ "$FAILED_BATCHES" -gt 0 ]]; then
  warn "$FAILED_BATCHES of $TOTAL_BATCHES batch(es) crashed and were skipped -- their hosts are missing from this scan. Re-run against just those hosts if you need full coverage."
fi

ok "Vuln scan complete -> ${OUT}.nmap"
# Quick highlight of anything the scripts flagged
echo
log "Flagged findings (grep of the report):"
# Note: this preview is just a quick eyeball scan -- for ssl-enum-ciphers/
# ssl-cert it can list healthy findings too (any TLS port mentions them).
# nmap_to_alerts.py applies the real filtering (only actual weak/expired
# findings become alerts).
grep -iE 'VULNERABLE|CVE-|State: LIKELY|ftp-anon|http-default-accounts|SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|self.signed' \
    "${OUT}.nmap" || echo "  (none reported)"

# --- extract every HTTP(S) service this scan found -----------------------
# Shared by whatweb and nikto below, so it runs once regardless of which
# (if either) of those is enabled.
WEB_TARGETS="$RESULTS_DIR/_web_targets_${STAMP}.txt"
python3 - "${OUT}.xml" > "$WEB_TARGETS" <<'PY'
import sys
import xml.etree.ElementTree as ET

tree = ET.parse(sys.argv[1])
for host in tree.getroot().findall("host"):
    addr_el = host.find("address[@addrtype='ipv4']")
    ip = addr_el.get("addr") if addr_el is not None else None
    if not ip:
        continue
    for port in host.findall("ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        if svc is None:
            continue
        name = (svc.get("name") or "").lower()
        tunnel = (svc.get("tunnel") or "").lower()
        if "http" not in name:
            continue
        pnum = port.get("portid")
        scheme = "https" if (tunnel == "ssl" or "https" in name or "ssl" in name) else "http"
        print(f"{scheme}://{ip}:{pnum}")
PY

# --- whatweb: fingerprint every HTTP(S) service this scan just found -----
if [[ "${SKIP_WHATWEB:-0}" != "1" ]] && command -v whatweb >/dev/null 2>&1; then
  if [[ -s "$WEB_TARGETS" ]]; then
    WEB_OUT="$RESULTS_DIR/whatweb_${STAMP}.json"
    log "Fingerprinting $(wc -l < "$WEB_TARGETS") web service(s) with whatweb..."
    whatweb --color=never -a 3 --log-json="$WEB_OUT" -i "$WEB_TARGETS" >/dev/null 2>&1 \
        || warn "whatweb returned nonzero (continuing)"
    if [[ -s "$WEB_OUT" ]] && command -v python3 >/dev/null 2>&1; then
      python3 "$SUITE_DIR/whatweb_to_alerts.py" "$WEB_OUT" || true
    fi
  else
    log "No HTTP(S) services found in this scan -- skipping whatweb."
  fi
fi

# --- SNMP: default/weak community strings (snmp-brute, snmp-info) --------
# UDP + a brute-force-style script, so this stays out of the scheduled
# job and lives here with the other manual/intrusive checks. Both scripts
# confirmed silent (no <script> output at all) when no community string
# works, same convention as ftp-anon/http-default-accounts -- so this is
# just another nmap XML fed through the same nmap_to_alerts.py path.
if [[ "${SKIP_SNMP:-0}" != "1" ]]; then
  SNMP_OUT="$RESULTS_DIR/snmp_${STAMP}"
  log "Checking for default/weak SNMP community strings (UDP/161)..."
  sudo /usr/local/sbin/soc-nmap -sU -p 161 --script snmp-brute,snmp-info --max-parallelism "$MAX_PARALLELISM" \
       -oA "$SNMP_OUT" -iL "$EXPANDED_TARGETS" >/dev/null 2>&1 || true
  if [[ -f "${SNMP_OUT}.xml" ]] && command -v python3 >/dev/null 2>&1; then
    python3 "$SUITE_DIR/nmap_to_alerts.py" "${SNMP_OUT}.xml" || true
  fi
fi

# --- nikto: web vulnerability scan of every HTTP(S) service found above --
if [[ "${SKIP_NIKTO:-0}" != "1" ]] && command -v nikto >/dev/null 2>&1; then
  if [[ -s "$WEB_TARGETS" ]]; then
    NIKTO_COMBINED="$RESULTS_DIR/nikto_${STAMP}.json"
    echo "[]" > "$NIKTO_COMBINED"
    log "Running nikto against $(wc -l < "$WEB_TARGETS") web service(s) (this can take a while)..."
    while IFS= read -r url; do
      [[ -z "$url" ]] && continue
      HOST_JSON="$RESULTS_DIR/_nikto_host_${STAMP}_$$.json"
      nikto -h "$url" -Format json -output "$HOST_JSON" \
            -maxtime 90s -nolookup -ask no -nointeractive \
            >/dev/null 2>&1 || true
      if [[ -s "$HOST_JSON" ]]; then
        python3 - "$NIKTO_COMBINED" "$HOST_JSON" <<'PY' || true
import json, sys
combined_path, host_path = sys.argv[1], sys.argv[2]
combined = json.loads(open(combined_path).read() or "[]")
host = json.loads(open(host_path).read() or "[]")
combined.extend(host)
open(combined_path, "w").write(json.dumps(combined))
PY
      fi
      rm -f "$HOST_JSON"
    done < "$WEB_TARGETS"
    if command -v python3 >/dev/null 2>&1; then
      python3 "$SUITE_DIR/nikto_to_alerts.py" "$NIKTO_COMBINED" || true
    fi
  else
    log "No HTTP(S) services found in this scan -- skipping nikto."
  fi
fi

echo "${OUT}.xml"
