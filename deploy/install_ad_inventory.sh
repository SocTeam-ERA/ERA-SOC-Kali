#!/usr/bin/env bash
# =====================================================================
#  install_ad_inventory.sh -- install the daily Active Directory inventory
# =====================================================================
#  Run once, as root:   sudo bash /opt/sentinel-soc/deploy/install_ad_inventory.sh
#
#  Installs and starts:
#    soc-ad-inventory.timer   once a day (06:40) runs scripts/ad_inventory.py, which reads AD with the
#                             read-only account in /etc/sentinel-soc/ad-ldap.env
#    soc-ad-privileged.timer  every 15 minutes compares only the privileged groups (a new Domain Admin
#                             should not wait until tomorrow). Safe to re-run to add it to an older install.
#  An addition to a privileged group is a critical alert, pushed to the phone through ntfy. The ntfy
#  topic is a secret that lives only in the existing units under /etc/systemd/system, so it is copied
#  from soc-login.service into a private drop-in rather than written into this repository.
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0"; exit 1; }
SRC=/opt/sentinel-soc/deploy
UNITS=/etc/systemd/system

[[ -r /etc/sentinel-soc/ad-ldap.env ]] || { echo "Missing /etc/sentinel-soc/ad-ldap.env (see scripts/ad_inventory.py)"; exit 1; }
TOPIC_LINE="$(grep -h '^Environment=NTFY_TOPIC=' "$UNITS/soc-login.service" | head -1 || true)"
[[ -n "$TOPIC_LINE" ]] || echo "[!] no NTFY_TOPIC found in soc-login.service: alerts will not be pushed to the phone"

for u in soc-ad-inventory.service soc-ad-inventory.timer soc-ad-privileged.service soc-ad-privileged.timer; do
  install -m 644 "$SRC/$u" "$UNITS/$u"
  echo "[1/3] installed $u"
done
if [[ -n "$TOPIC_LINE" ]]; then
  for svc in soc-ad-inventory soc-ad-privileged; do
    mkdir -p "$UNITS/$svc.service.d"
    printf '[Service]\n%s\n' "$TOPIC_LINE" > "$UNITS/$svc.service.d/ntfy.conf"
    chmod 600 "$UNITS/$svc.service.d/ntfy.conf"
  done
  echo "[2/3] ntfy topic copied into private drop-ins (mode 600)"
fi
systemctl daemon-reload
systemctl enable --now soc-ad-inventory.timer soc-ad-privileged.timer
echo "[3/3] started. Next full inventory: $(systemctl show soc-ad-inventory.timer -p NextElapseUSecRealtime --value)"
