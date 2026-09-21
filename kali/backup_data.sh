#!/usr/bin/env bash
# =====================================================================
#  backup_data.sh -- daily backup of the SOC's runtime data
# =====================================================================
#  The code lives in git; this saves what git does not: the alert history and
#  live feed, incidents, asset inventory (owners and notes), suppression and scan
#  state, and the versioned config. It is small (about 14 MB of data).
#
#  Left OUT on purpose: data/api_keys.json (secrets: reissue keys with
#  manage_api_keys.py after a restore), threat_intel/ (re-downloaded daily),
#  lock and temp files, __pycache__.
#
#  Where it goes:
#    local   $SOC_BACKUP_DIR (default ~/soc-backups), mode 700, newest 14 kept
#    remote  optional: SOC_BACKUP_REMOTE=user@host:/path  (rsync over ssh, key in
#            SOC_BACKUP_SSH_KEY). A copy on this same machine does not survive losing
#            it, so set a remote as soon as IT provides one. The archive holds internal
#            IPs and findings: set SOC_BACKUP_GPG_RECIPIENT=<key id> to encrypt it first.
#
#  Usage:
#    kali/backup_data.sh              run a backup now
#    kali/backup_data.sh --list       list the local backups
#    kali/backup_data.sh --restore FILE DIR   unpack a backup into DIR to inspect it
#                                             (never writes into the live data/)
#  Cron (installed by the user's crontab):  17 3 * * *
#
#  Writes data/backup_status.json; source_health.py raises an alert if no backup
#  succeeded for 26 hours.
# =====================================================================
set -uo pipefail

SUITE="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${SOC_DATA_DIR:-$SUITE/data}"
DEST="${SOC_BACKUP_DIR:-$HOME/soc-backups}"
KEEP="${SOC_BACKUP_KEEP:-14}"
STATUS="$DATA/backup_status.json"

case "${1:-}" in
  --list)
    ls -lh --time-style=long-iso "$DEST"/soc-backup-*.tar.gz* 2>/dev/null || echo "no backups in $DEST"
    exit 0 ;;
  --restore)
    [[ -n "${2:-}" && -n "${3:-}" ]] || { echo "usage: $0 --restore BACKUP_FILE TARGET_DIR"; exit 2; }
    [[ -f "$2" ]] || { echo "not found: $2"; exit 2; }
    [[ "$2" == *.gpg ]] && { echo "this backup is encrypted: gpg --decrypt '$2' > file.tar.gz first"; exit 2; }
    mkdir -p "$3" && tar -xzf "$2" -C "$3" && echo "unpacked into $3 (the live data/ was not touched)"
    exit $? ;;
esac

write_status() {   # write_status ok|fail "message" [file] [bytes] [remote]
  python3 - "$STATUS" "$1" "$2" "${3:-}" "${4:-0}" "${5:-none}" <<'PY'
import json, sys, os, tempfile
from datetime import datetime, timezone
path, result, msg, f, size, remote = sys.argv[1:7]
try: st = json.load(open(path))
except Exception: st = {}
now = datetime.now(timezone.utc).isoformat()
st.update(last_run=now, last_result=result, message=msg)
if result == "ok":
    st.update(last_ok=now, file=f, bytes=int(size), remote=remote)
fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
os.chmod(tmp, 0o664)
with os.fdopen(fd, "w") as fh: json.dump(st, fh, indent=2)
os.replace(tmp, path)
PY
}

if ! { mkdir -p "$DEST" && chmod 700 "$DEST"; } 2>/dev/null; then
  msg="cannot create the backup directory $DEST"; echo "[!] $msg" >&2; write_status fail "$msg"; exit 1
fi
exec 9>"$DEST/.lock"
flock -n 9 || { echo "another backup is running"; exit 0; }

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$DEST/soc-backup-$STAMP.tar.gz"
TMP="$OUT.partial"

# data/ (minus secrets and regenerable files) plus the versioned config
tar -czf "$TMP" -C "$SUITE" \
    --exclude='data/api_keys.json' --exclude='data/threat_intel' --exclude='*.lock' --exclude='.*.lock' \
    --exclude='*.tmp' --exclude='__pycache__' --exclude='data/backup_status.json' \
    data config 2>"$DEST/.tar.err"
rc=$?
if [[ $rc -gt 1 ]]; then      # 1 = a file changed while being read: fine on live logs
  rm -f "$TMP"; msg="tar failed (exit $rc): $(head -c 200 "$DEST/.tar.err")"
  echo "[!] $msg" >&2; write_status fail "$msg"; exit 1
fi

# integrity: the archive must read back completely, and hold the essentials
if ! tar -tzf "$TMP" >"$DEST/.list" 2>/dev/null || ! grep -q 'data/alerts.json$' "$DEST/.list" \
     || ! grep -q 'data/assets.json$' "$DEST/.list"; then
  rm -f "$TMP"; msg="verification failed: the archive is unreadable or missing alerts.json/assets.json"
  echo "[!] $msg" >&2; write_status fail "$msg"; exit 1
fi
mv "$TMP" "$OUT" && chmod 600 "$OUT"
( cd "$DEST" && sha256sum "$(basename "$OUT")" > "$OUT.sha256" ) && chmod 600 "$OUT.sha256"
FINAL="$OUT"

if [[ -n "${SOC_BACKUP_GPG_RECIPIENT:-}" ]]; then
  if gpg --batch --yes --trust-model always -r "$SOC_BACKUP_GPG_RECIPIENT" -o "$OUT.gpg" -e "$OUT" 2>/dev/null; then
    chmod 600 "$OUT.gpg"; FINAL="$OUT.gpg"
  else
    echo "[!] gpg encryption failed; the remote copy is skipped" >&2; SOC_BACKUP_REMOTE=""
  fi
fi

remote_state="none"
if [[ -n "${SOC_BACKUP_REMOTE:-}" ]]; then
  ssh_opt=(-o BatchMode=yes -o ConnectTimeout=15)
  [[ -n "${SOC_BACKUP_SSH_KEY:-}" ]] && ssh_opt+=(-i "$SOC_BACKUP_SSH_KEY" -o IdentitiesOnly=yes)
  if rsync -q -e "ssh ${ssh_opt[*]}" "$FINAL" "$FINAL.sha256" "$SOC_BACKUP_REMOTE/" 2>/dev/null \
     || rsync -q -e "ssh ${ssh_opt[*]}" "$FINAL" "$SOC_BACKUP_REMOTE/" 2>/dev/null; then
    remote_state="ok"
  else
    remote_state="failed"; echo "[!] remote copy to $SOC_BACKUP_REMOTE failed (the local backup is fine)" >&2
  fi
fi

# retention: newest $KEEP archives (each with its .sha256/.gpg companions)
ls -1t "$DEST"/soc-backup-*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while read -r old; do rm -f "$old" "$old.sha256" "$old.gpg"; done
[[ -n "$FINAL" && "$FINAL" == *.gpg ]] && rm -f "$OUT"   # keep only the encrypted copy when encrypting

size=$(stat -c %s "$FINAL")
write_status ok "backup completed" "$FINAL" "$size" "$remote_state"
echo "[*] backup ok: $FINAL ($(numfmt --to=iec "$size")), $(wc -l < "$DEST/.list") files, remote: $remote_state"
