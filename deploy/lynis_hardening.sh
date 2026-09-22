#!/usr/bin/env bash
# =====================================================================
#  lynis_hardening.sh — apply the safe, low-risk findings from the
#  daily Lynis audit (systemd's lynis.service, /var/log/lynis-report.dat)
# =====================================================================
#  Usage: sudo bash /opt/sentinel-soc/deploy/lynis_hardening.sh
#
#  Covers only findings that are unambiguous wins on THIS appliance:
#    - install a handful of small, standard hardening/maintenance tools
#    - purge the one already-removed package's leftover config
#    - purge atftpd (a TFTP *server*; disabled today, but Lynis'
#      own reasoning is to remove it so it can never be turned on by
#      accident -- tftp-hpa, the TFTP *client*, is left alone: it is a
#      normal Kali tool this project's later pentesting phase will use)
#    - blacklist 4 kernel network protocols nothing here uses
#      (dccp, sctp, rds, tipc) -- standard hardening, smaller attack surface
#    - enable process accounting (extra forensic trail, fits a SOC box)
#    - tell Lynis that every eth interface being promiscuous is expected
#      (Zeek/Suricata/tshark all need it to see all traffic), so its
#      daily report stops repeating a warning about something intentional
#
#  Deliberately NOT here (real trade-offs; a person should decide, not a
#  script) -- see docs/PENDIENTES_2026-09-16_ES.md for the full list:
#    - GRUB bootloader password (could lock out recovery mode)
#    - moving SSH off port 22 (obscurity, not security; complicates access)
#    - a legal login banner (needs actual approved wording)
#    - restricting compilers to root (this box will build/compile
#      pentesting tools once Etapa 2 resumes)
#    - disabling USB/firewire storage (the Flipper/Pineapple hardware
#      planned for Etapa 2 needs USB)
#    - password-aging/complexity policy in /etc/login.defs (changes the
#      operator's own login experience)
#    - AIDE's checksum algorithm (would need another --reinit-aide)
# ---------------------------------------------------------------------
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run this with sudo." >&2
  exit 1
fi

echo "[1/5] Installing standard hardening/maintenance packages..."
apt-get install -y libpam-tmpdir apt-listbugs needrestart debsums apt-show-versions

echo "[2/5] Purging removed-but-not-cleaned-up package configs..."
mapfile -t leftover < <(dpkg -l | awk '$1=="rc"{print $2}')
if [[ ${#leftover[@]} -gt 0 ]]; then
  dpkg --purge "${leftover[@]}"
else
  echo "      none found."
fi
if dpkg -l atftpd 2>/dev/null | grep -q "^ii"; then
  apt-get purge -y atftpd
else
  echo "      atftpd already absent."
fi

echo "[3/5] Blacklisting unused kernel network protocols (dccp, sctp, rds, tipc)..."
cat > /etc/modprobe.d/90-sentinel-soc-disable-protocols.conf <<'EOF'
# Sentinel SOC hardening (Lynis NETW-3200): these protocols are not used by
# anything on this appliance. Blacklisting them shrinks the kernel's
# attack surface without affecting normal networking (TCP/UDP/ICMP).
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
EOF

echo "[4/5] Enabling process accounting..."
apt-get install -y acct
systemctl enable --now acct.service 2>/dev/null || true

echo "[5/5] Telling Lynis that promiscuous NICs on this box are expected..."
if [[ -f /etc/lynis/custom.prf ]]; then
  echo "      /etc/lynis/custom.prf already exists -- leaving it alone. Add this by hand if missing:"
  echo "        skip-test=NETW-3015"
else
  cat > /etc/lynis/custom.prf <<'EOF'
# Sentinel SOC: every eth interface runs in promiscuous mode on purpose
# (Zeek, Suricata and the live traffic monitor all need to see every
# packet, not just ones addressed to this box). NETW-3015 flags that as
# a warning on every single daily run; skip it here instead of getting
# the same explained finding forever.
skip-test=NETW-3015
EOF
fi

echo
echo "Done. Re-run 'sudo lynis audit system' any time to see the updated report."
