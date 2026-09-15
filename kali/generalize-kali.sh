#!/usr/bin/env bash
# =====================================================================
#  generalize-kali.sh — Prepare the Kali appliance to become a clean image
# =====================================================================
#  Run this LAST, right before you capture/export the disk to an image
#  (VHDX for Hyper-V, qcow2 for KVM). It removes machine-specific identity
#  so every VM cloned from the image is unique and clean — the Linux
#  equivalent of Windows "sysprep".
#
#  ⚠  After running this, DO NOT reboot this machine normally and keep using
#     it — it is meant to be powered off and captured. Rebooting regenerates
#     the identity you just cleared (which is fine, but then re-run this
#     before the real capture).
#
#  Usage:  sudo ./generalize-kali.sh
#          GENERALIZE_CONFIRMED=yes sudo ./generalize-kali.sh   # skip the prompt (automation)
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "Run with sudo"; exit 1; }

# This is the most destructive script in the project -- SSH host keys, shell
# history, and the REAL alert history (data/alerts.json + alerts.jsonl) all
# get permanently deleted below, with no backup. Every other risky action in
# this project (lib.sh's authorize(), seed_demo_data.py --fresh) requires an
# explicit confirmation first; this one never did. Match that pattern here,
# and warn extra hard if the live SOC services look like they're still
# running on this box -- that's a strong sign this is the production
# appliance, not a template being prepped for imaging.
if [[ "${GENERALIZE_CONFIRMED:-no}" != "yes" ]]; then
  echo "[!] This will PERMANENTLY DELETE, with no backup:"
  echo "      - SSH host keys (/etc/ssh/ssh_host_*)"
  echo "      - shell history (root + every user)"
  echo "      - the real alert history (data/alerts.json, data/alerts.jsonl)"
  echo "      - everything in kali/results/"
  echo "      - /tmp, /var/tmp, and all logs under /var/log"
  if systemctl is-active --quiet soc-scan.timer 2>/dev/null || \
     systemctl is-active --quiet soc-login.service 2>/dev/null; then
    echo "[!!] soc-scan.timer / soc-login.service are ACTIVE on this box right"
    echo "     now -- that looks like the LIVE production appliance, not a"
    echo "     template being prepped for imaging. Only continue if you are"
    echo "     certain this is the machine you meant to wipe."
  fi
  read -rp "Type 'yes' to confirm: " ans
  [[ "$ans" == "yes" ]] || { echo "[x] Not confirmed. Aborting."; exit 2; }
fi

echo "[*] Generalizing this Kali for imaging..."

# 1. package caches and logs
apt-get clean || true
find /var/log -type f -exec truncate -s 0 {} \; 2>/dev/null || true
rm -rf /tmp/* /var/tmp/* 2>/dev/null || true

# 2. shell history (root + all users)
rm -f /root/.bash_history 2>/dev/null || true
for home in /home/*; do rm -f "$home/.bash_history" 2>/dev/null || true; done
history -c 2>/dev/null || true

# 3. SSH host keys — MUST be regenerated per machine (otherwise all clones
#    share the same key = security problem)
rm -f /etc/ssh/ssh_host_* 2>/dev/null || true
echo "[*] SSH host keys removed (regenerate on first boot)."

# 4. machine-id — unique per machine; empty it so systemd regenerates it
truncate -s 0 /etc/machine-id 2>/dev/null || true
rm -f /var/lib/dbus/machine-id 2>/dev/null || true
ln -sf /etc/machine-id /var/lib/dbus/machine-id 2>/dev/null || true

# 5. network: don't bake a fixed IP into the image; leave it on DHCP for
#    first boot, then set the static IP after deploy.
#    (We only warn; edit /etc/network/interfaces or netplan by hand if fixed.)
echo "[*] Reminder: make sure no fixed IP / MAC is hard-coded (use DHCP in the image)."

# 6. clear the SOC scan results / demo data so the image ships empty
rm -f /opt/sentinel-soc/data/alerts.json /opt/sentinel-soc/data/alerts.jsonl 2>/dev/null || true
rm -rf /opt/sentinel-soc/kali/results/* 2>/dev/null || true

# 7. clear apt lists (smaller image)
rm -rf /var/lib/apt/lists/* 2>/dev/null || true

# 8. zero free space so the dynamic disk compacts well (optional, slow)
if [[ "${ZEROFILL:-0}" == "1" ]]; then
  echo "[*] Zero-filling free space (this makes the VHDX/qcow2 much smaller)..."
  dd if=/dev/zero of=/zero.fill bs=1M 2>/dev/null || true
  rm -f /zero.fill
  sync
fi

echo "[*] Done. Power off now and capture/convert the disk to your image format."
echo "    Hyper-V:  qemu-img convert -O vhdx <disk>.raw kali-soc.vhdx"
echo "    KVM:      qemu-img convert -O qcow2 <disk>.raw kali-soc.qcow2"
