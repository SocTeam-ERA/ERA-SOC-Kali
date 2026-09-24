#!/usr/bin/env bash
# =====================================================================
#  install_l2_watch.sh -- install the two broadcast-attack detectors
# =====================================================================
#  Run once, as root:   sudo bash /opt/sentinel-soc/deploy/install_l2_watch.sh
#
#  Installs and starts:
#    soc-l2-watch.service        follows Zeek's dhcp.log / conn.log: rogue DHCP server, rogue IPv6 router
#    soc-poisoner-canary.timer   every 10 min asks every network for a made-up name (LLMNR / NBT-NS);
#                                only a poisoner such as Responder answers
#  Both raise critical alerts, which are pushed to the phone through ntfy. The ntfy topic is a secret
#  that lives only on this machine (soc-login's ntfy.conf drop-in, or the unit itself on older installs), so it is copied from there
#  into a private drop-in for each new unit rather than written into this repository.
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0"; exit 1; }
SRC=/opt/sentinel-soc/deploy
UNITS=/etc/systemd/system

TOPIC_LINE="$(grep -hs '^Environment=NTFY_TOPIC=' "$UNITS/soc-login.service.d/ntfy.conf" "$UNITS/soc-login.service" | head -1 || true)"
[[ -n "$TOPIC_LINE" ]] || echo "[!] no NTFY_TOPIC found in soc-login.service: alerts will not be pushed to the phone"

for u in soc-l2-watch.service soc-poisoner-canary.service soc-poisoner-canary.timer; do
  install -m 644 "$SRC/$u" "$UNITS/$u"
  echo "[1/3] installed $u"
done
if [[ -n "$TOPIC_LINE" ]]; then
  for svc in soc-l2-watch soc-poisoner-canary; do
    mkdir -p "$UNITS/$svc.service.d"
    printf '[Service]\n%s\n' "$TOPIC_LINE" > "$UNITS/$svc.service.d/ntfy.conf"
    chmod 600 "$UNITS/$svc.service.d/ntfy.conf"
  done
  echo "[2/3] ntfy topic copied into private drop-ins (mode 600)"
fi
systemctl daemon-reload
systemctl enable --now soc-l2-watch.service soc-poisoner-canary.timer
echo "[3/3] started. First start of soc-l2-watch learns the trusted DHCP servers / IPv6 router from the Zeek history"
echo "      (about 30 seconds), then raises ONE normal alert listing what it learned -- please read it."
systemctl is-active soc-l2-watch.service soc-poisoner-canary.timer
