#!/usr/bin/env bash
# =====================================================================
#  install_login_banner.sh -- show a legal warning before anyone logs in (Lynis BANN-7126 / BANN-7130)
# =====================================================================
#  Install:    sudo bash /opt/sentinel-soc/deploy/install_login_banner.sh
#  Take out:   sudo bash /opt/sentinel-soc/deploy/install_login_banner.sh --remove
#
#  The wording lives in deploy/login_banner.txt. It is a DRAFT: have IT or whoever handles legal matters at
#  ERA approve it (or replace it with the company's standard notice), edit that file, and run this script
#  again -- it is safe to repeat.
#
#  What it does:
#    /etc/issue                          the notice on the local console / RDP login (original saved once
#                                        as /etc/issue.pre-banner)
#    /etc/issue.net                      the notice SSH shows before the password prompt (original saved
#                                        once as /etc/issue.net.pre-banner)
#    /etc/ssh/sshd_config.d/98-banner.conf   `Banner /etc/issue.net`; checked with `sshd -t` before SSH is
#                                        reloaded, and removed again if the check fails
#  A reload keeps existing SSH sessions open. Keep this one open until you have tested a NEW login.
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0"; exit 1; }
SRC=/opt/sentinel-soc/deploy/login_banner.txt
DROPIN=/etc/ssh/sshd_config.d/98-banner.conf

reload_ssh() { systemctl reload ssh 2>/dev/null || systemctl reload sshd; }

if [[ "${1:-}" == "--remove" ]]; then
  rm -f "$DROPIN"
  [[ -f /etc/issue.pre-banner ]] && cp -p /etc/issue.pre-banner /etc/issue
  [[ -f /etc/issue.net.pre-banner ]] && cp -p /etc/issue.net.pre-banner /etc/issue.net
  sshd -t && reload_ssh
  echo "banner removed (original /etc/issue and /etc/issue.net restored)"
  exit 0
fi

[[ -s "$SRC" ]] || { echo "missing or empty $SRC"; exit 1; }
[[ -f /etc/issue.pre-banner ]] || cp -p /etc/issue /etc/issue.pre-banner
[[ -f /etc/issue.net.pre-banner ]] || cp -p /etc/issue.net /etc/issue.net.pre-banner
install -m 644 "$SRC" /etc/issue
install -m 644 "$SRC" /etc/issue.net
echo "[1/3] wrote /etc/issue and /etc/issue.net"

printf '# Legal notice shown before login (see /opt/sentinel-soc/deploy/install_login_banner.sh)\nBanner /etc/issue.net\n' > "$DROPIN"
chmod 644 "$DROPIN"
if ! sshd -t; then
  rm -f "$DROPIN"
  echo "[!] sshd rejected the configuration; the SSH drop-in was removed and SSH was NOT reloaded"
  exit 1
fi
echo "[2/3] SSH configuration is valid"
reload_ssh
echo "[3/3] SSH reloaded. Existing sessions stay open."
echo
echo "Test from ANOTHER terminal (you should see the notice before the password prompt):"
echo "    ssh -o PreferredAuthentications=none -o StrictHostKeyChecking=no $(logname 2>/dev/null || echo USER)@127.0.0.1"
