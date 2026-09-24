#!/usr/bin/env bash
# =====================================================================
#  install_packages.sh -- install the software the SOC needs on a FRESH Kali
# =====================================================================
#  Run as root on a new VM, before install_all.sh (see docs/REBUILD_EN.md for the whole order):
#      sudo bash /opt/sentinel-soc/deploy/install_packages.sh
#
#    1. the two extra APT repositories (Zeek from openSUSE, osquery) with their public keys,
#       from deploy/apt/ (copied from the working machine, so the rebuild does not depend on the
#       vendors' key URLs still being where they were)
#    2. apt-get update, then every package in deploy/packages.txt
#    3. the SOC user in the groups the tools need (wireshark for tshark, zeek for its logs)
#
#  Safe to re-run: apt skips what is installed. It installs nothing that is not in packages.txt and
#  never removes anything. On the running SOC it has nothing to do.
# ---------------------------------------------------------------------
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0"; exit 1; }
SRC="$(cd "$(dirname "$0")" && pwd)"
SOC_USER="${SOC_USER:-${SUDO_USER:-adelcueto}}"

install -d -m 755 /etc/apt/keyrings
for k in "$SRC"/apt/keyrings/*; do install -m 644 "$k" "/etc/apt/keyrings/$(basename "$k")"; done
for s in "$SRC"/apt/sources.list.d/*; do install -m 644 "$s" "/etc/apt/sources.list.d/$(basename "$s")"; done
echo "[1/3] extra repositories: $(ls "$SRC"/apt/sources.list.d | tr '\n' ' ')"

mapfile -t pkgs < <(sed -e 's/#.*//' -e 's/[[:space:]]*$//' "$SRC/packages.txt" | grep -v '^$')
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}"
echo "[2/3] ${#pkgs[@]} packages installed or already present"

for g in wireshark zeek; do
  getent group "$g" >/dev/null && usermod -aG "$g" "$SOC_USER"
done
echo "[3/3] $SOC_USER added to wireshark and zeek"
echo
echo "Next: sudo bash $SRC/install_all.sh   (then the rest of docs/REBUILD_EN.md)"
