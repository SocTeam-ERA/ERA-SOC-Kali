#!/usr/bin/env bash
# =====================================================================
#  install_all.sh -- install everything in deploy/ onto this machine
# =====================================================================
#  Run as root:   sudo bash /opt/sentinel-soc/deploy/install_all.sh [--force]
#
#  deploy/ is the source of truth for what the SOC needs outside this directory; this puts it in
#  place. Use it to rebuild the SOC on a fresh Kali (clone the repo to /opt/sentinel-soc first) and
#  after every change to a unit in deploy/. It can be re-run safely: it only rewrites files.
#
#    1. the soc group and the project's group ownership
#    2. /etc/sentinel-soc/*.env from deploy/env/*.example when missing (never overwritten)
#    3. the ntfy topic into a private drop-in (<unit>.service.d/ntfy.conf, mode 600) for every unit
#       that pushes to the phone. Taken from $NTFY_TOPIC, else from what is installed, else asked.
#    4. every soc-* unit, timer and non-secret drop-in from deploy/
#    5. the sudoers rule (checked with visudo first)
#    6. the user crontab, only when the user has none (otherwise the difference is shown)
#    7. daemon-reload, then enable and start every timer and every service that has an [Install]
#
#  Refuses to run if an installed unit was edited on this machine and the edit is not in deploy/:
#  installing would silently undo it. Bring the change into deploy/ first, or pass --force.
#  An installed unit that is merely an earlier committed version of deploy/'s copy (deploy/ moved on
#  since the last install) is not an edit: it is simply updated (deploy_drift.py reports it as outdated).
#
#    4b. the sensors' configuration from deploy/sensors/ (Zeek, Suricata, osquery), keeping each file's owner
#       and mode; the restarts needed are printed, not run
#
#  NOT done here (see docs/INSTRUCCIONES_ES.md): installing packages (zeek, suricata, osquery, aide,
#  nmap, python modules) and the data/ restore (kali/backup_data.sh --restore).
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0"; exit 1; }
SUITE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$SUITE/deploy"
UNITS=/etc/systemd/system
SOC_USER="${SOC_USER:-${SUDO_USER:-adelcueto}}"
FORCE=0; [[ "${1:-}" == "--force" ]] && FORCE=1

# The units that push critical alerts to the phone get the ntfy topic.
NTFY_SERVICES="soc-aide-check soc-check-updates soc-login soc-chkrootkit-forwarder soc-disk-check soc-ntfy-flush
  soc-scan soc-osquery-forwarder soc-traffic-monitor soc-vuln-scan soc-watchdog soc-zeek-forwarder
  soc-suricata-forwarder soc-vlan-segmentation soc-ad-inventory soc-ad-privileged soc-l2-watch soc-poisoner-canary soc-cert-expiry"

changed="$(cd "$SUITE/scripts" && python3 -c 'import deploy_drift as d
print(" ".join(n for k, n in d.drift(check_crontab=False, check_firewall=False) if k == "changed"))')"
if [[ -n "$changed" && $FORCE -eq 0 ]]; then
  echo "[!] edited on this machine but not in deploy/: $changed"
  echo "    Installing would undo those edits. Copy them into deploy/ and commit, or re-run with --force."
  exit 1
fi

getent group soc >/dev/null || groupadd soc
id -nG "$SOC_USER" | tr ' ' '\n' | grep -qx soc || usermod -aG soc "$SOC_USER"
chgrp -R soc "$SUITE"
find "$SUITE" -path "$SUITE/.git" -prune -o -type d -exec chmod g+rws {} +
echo "[1/7] group soc, $SOC_USER in it, $SUITE group-owned"

install -d -m 755 /etc/sentinel-soc
for ex in "$SRC"/env/*.env.example; do
  dst="/etc/sentinel-soc/$(basename "$ex" .example)"
  [[ -e "$dst" ]] && continue
  install -m 640 -g soc "$ex" "$dst"
  echo "      created $dst from the template: FILL IN the values from the password vault"
done
chmod 600 /etc/sentinel-soc/soc-api.env
echo "[2/7] /etc/sentinel-soc ready"

TOPIC="${NTFY_TOPIC:-}"
if [[ -z "$TOPIC" ]]; then
  TOPIC="$(cat "$UNITS"/soc-*.service.d/ntfy.conf "$UNITS"/soc-*.service 2>/dev/null \
           | sed -n 's/^Environment="\{0,1\}NTFY_TOPIC=\([^" ]*\).*/\1/p' | head -1 || true)"
fi
if [[ -z "$TOPIC" && -t 0 ]]; then
  read -rp "ntfy topic (from the password vault; empty = no phone alerts): " TOPIC
fi
if [[ -n "$TOPIC" ]]; then
  for svc in $NTFY_SERVICES; do
    install -d -m 755 "$UNITS/$svc.service.d"
    ( umask 077; printf '[Service]\nEnvironment=NTFY_TOPIC=%s\n' "$TOPIC" > "$UNITS/$svc.service.d/ntfy.conf" )
  done
  echo "[3/7] ntfy topic in private drop-ins for $(wc -w <<<"$NTFY_SERVICES") units"
else
  echo "[3/7] [!] no ntfy topic: critical alerts will NOT reach the phone. Re-run with NTFY_TOPIC=... to add it"
fi

n=0
for f in "$SRC"/soc-*.service "$SRC"/soc-*.timer; do
  install -m 644 "$f" "$UNITS/$(basename "$f")"; n=$((n + 1))
done
for d in "$SRC"/soc-*.d; do
  [[ -d "$d" ]] || continue
  install -d -m 755 "$UNITS/$(basename "$d")"
  for c in "$d"/*.conf; do install -m 644 "$c" "$UNITS/$(basename "$d")/$(basename "$c")"; done
done
echo "[4/7] $n units and their drop-ins installed"

# Sensor configuration (Zeek, Suricata, osquery): deploy/sensors/<absolute path> -> /<absolute path>.
# An existing file keeps its owner and mode. Nothing is restarted here: the commands are printed.
restart=()
while IFS= read -r -d '' f; do
  dst="/${f#"$SRC"/sensors/}"
  cmp -s "$f" "$dst" && continue
  if [[ -e "$dst" ]]; then
    install -m "$(stat -c %a "$dst")" -o "$(stat -c %U "$dst")" -g "$(stat -c %G "$dst")" "$f" "$dst"
  else
    install -D -m 644 "$f" "$dst"
  fi
  echo "      updated $dst"
  case "$dst" in
    /opt/zeek/*)      restart+=("sudo /opt/zeek/bin/zeekctl deploy") ;;
    /etc/suricata/*)  restart+=("sudo suricata -T -c /etc/suricata/suricata.yaml -q && sudo systemctl restart suricata") ;;
    /etc/osquery/*)   restart+=("sudo systemctl restart osqueryd") ;;
  esac
done < <(find "$SRC/sensors" -type f -print0 2>/dev/null | sort -z)
# Zeek's digest salt stays out of git (local.zeek loads it from here). Created once, never overwritten;
# it reuses the salt of the pre-2026-09-17 configuration when that copy is still on disk.
SALT_FILE=/opt/zeek/share/zeek/site/sentinel_salt.zeek
if [[ -d /opt/zeek/share/zeek/site && ! -e "$SALT_FILE" ]]; then
  salt="$(sed -n 's/^redef digest_salt = "\([^"]*\)";.*/\1/p' /opt/zeek/share/zeek/site/local.zeek.dpkg-old 2>/dev/null | head -1)"
  [[ -z "$salt" || "$salt" == "Please change this value." ]] && salt="$(openssl rand -hex 24)"
  ( umask 027; printf 'redef digest_salt = "%s";\n' "$salt" > "$SALT_FILE" )
  chgrp zeek "$SALT_FILE" 2>/dev/null || true
  echo "      created $SALT_FILE (the site's digest salt, not in git)"
fi
if (( ${#restart[@]} )); then
  echo "[4/7] sensor configuration updated. Apply it with (Zeek's restart leaves a gap of about a minute):"
  printf '%s\n' "${restart[@]}" | sort -u | sed 's/^/          /'
else
  echo "[4/7] sensor configuration already matches deploy/sensors/"
fi

for s in "$SRC"/sudoers/*; do
  visudo -cqf "$s" || { echo "[!] $s does not pass visudo; skipped"; continue; }
  install -m 440 "$s" "/etc/sudoers.d/$(basename "$s")"
done
echo "[5/7] sudoers rules installed"

if ! crontab -u "$SOC_USER" -l >/dev/null 2>&1; then
  crontab -u "$SOC_USER" "$SRC/crontab.txt"
  echo "[6/7] crontab installed for $SOC_USER"
elif ! diff <(crontab -u "$SOC_USER" -l) "$SRC/crontab.txt" >/dev/null; then
  echo "[6/7] [!] $SOC_USER already has a different crontab; left alone. Difference (< installed, > deploy/):"
  diff <(crontab -u "$SOC_USER" -l) "$SRC/crontab.txt" || true
else
  echo "[6/7] crontab already matches"
fi

systemctl daemon-reload
enable=()
for f in "$SRC"/soc-*.timer "$SRC"/soc-*.service; do
  grep -q '^\[Install\]' "$f" && enable+=("$(basename "$f")")
done
systemctl enable --now "${enable[@]}"
echo "[7/7] ${#enable[@]} timers and services enabled and started"
echo
echo "Running services keep their old settings until restarted. Check with:"
echo "    python3 $SUITE/scripts/deploy_drift.py"
echo "    sg soc -c 'python3 $SUITE/scripts/soc_selftest.py'"
