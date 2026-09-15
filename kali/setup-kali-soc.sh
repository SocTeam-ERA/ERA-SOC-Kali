#!/usr/bin/env bash
# =====================================================================
#  setup-kali-soc.sh — Provision a Kali host as the SOC scanning appliance
# =====================================================================
#  Run this ONCE on the laptop to customize Kali, and run the SAME script
#  later inside the fresh Kali VM on the server. Because the customization
#  is a script (not hand-clicking), both machines end up identical — this
#  is what makes the image reproducible.
#
#  It is IDEMPOTENT: safe to run more than once.
#
#  Usage:
#     sudo ./setup-kali-soc.sh
#     sudo ./setup-kali-soc.sh --headless   # also removes desktop bloat (for a server VM)
#
#  What it does:
#     * Updates the system
#     * Installs the scanning toolset (nmap, zmap, tshark, masscan, ...)
#     * Configures tshark for non-root capture
#     * Deploys the Sentinel SOC project to /opt/sentinel-soc
#     * Enables time sync (critical for trustworthy alert timestamps)
#     * Prints a verification report
#
#  It does NOT run any scan and does NOT open the network. Authorization
#  and scope are handled separately (see the authorization form).
# ---------------------------------------------------------------------
set -euo pipefail

HEADLESS=0
[[ "${1:-}" == "--headless" ]] && HEADLESS=1

# --- must be root -----------------------------------------------------
if [[ $EUID -ne 0 ]]; then echo "Run with sudo: sudo $0" >&2; exit 1; fi

# --- who is the real (non-root) operator? -----------------------------
TARGET_USER="${SUDO_USER:-$(logname 2>/dev/null || echo kali)}"
echo "[*] Operator user: $TARGET_USER"

export DEBIAN_FRONTEND=noninteractive
INSTALL_DIR="/opt/sentinel-soc"
LOG="/var/log/soc-setup.log"
say(){ echo -e "[*] $*" | tee -a "$LOG"; }

say "=== Sentinel SOC — Kali provisioning  $(date -u) ==="

# --- 1. system update -------------------------------------------------
say "Updating package lists and upgrading (this can take a while)..."
apt-get update -y
apt-get full-upgrade -y

# --- 2. scanning + support toolset -----------------------------------
say "Installing the scanning toolset..."
PKGS=(
  nmap ndiff            # port/service/vuln scanning
  zmap                  # fast internal-range discovery
  masscan               # alternative fast scanner
  netdiscover arp-scan  # layer-2 host discovery
  tshark tcpdump        # passive traffic capture (Stage 2 module)
  whatweb               # web fingerprinting
  dnsutils              # dig/host
  net-tools iproute2    # ip / ifconfig / route
  ncat                  # netcat (egress tests)
  jq curl wget git      # tooling
  tmux                  # keep long scans running over SSH (detach/reattach)
  lsof                  # inspect open files/sockets
  python3 python3-pip python3-venv   # runs the detectors + converters
)
apt-get install -y "${PKGS[@]}"

# --- 3. tshark: allow non-root capture -------------------------------
say "Configuring tshark for non-root capture..."
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
dpkg-reconfigure -f noninteractive wireshark-common || true
if getent group wireshark >/dev/null; then
  usermod -aG wireshark "$TARGET_USER" || true
  say "  added $TARGET_USER to the 'wireshark' group (re-login to take effect)."
fi
# let dumpcap capture without full root
command -v dumpcap >/dev/null && setcap cap_net_raw,cap_net_admin+eip "$(command -v dumpcap)" || true

# --- 4. deploy the Sentinel SOC project ------------------------------
say "Deploying the SOC project to $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
# If this script sits inside the project (kali/), copy the whole project up one level.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
if [[ -d "$PROJECT_ROOT/scripts" && -d "$PROJECT_ROOT/kali" ]]; then
  cp -r "$PROJECT_ROOT/." "$INSTALL_DIR/"
  say "  copied project from $PROJECT_ROOT"
else
  say "  NOTE: project files not found next to the script; copy them into $INSTALL_DIR manually."
fi
chown -R "$TARGET_USER":"$TARGET_USER" "$INSTALL_DIR"
find "$INSTALL_DIR" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true
find "$INSTALL_DIR" -name '*.py' -exec chmod +x {} \; 2>/dev/null || true

# Python deps for the detectors (currently stdlib-only; venv kept for future libs)
if [[ -d "$INSTALL_DIR/scripts" ]]; then
  say "  detectors use the Python standard library (no pip packages required today)."
fi

# --- 4.5 SSH server + role-based team accounts ----------------------
# Kali ships openssh-server installed but DISABLED by default. The team
# needs to log in to run scans and check connectivity, so we enable it
# and set it to start on boot — this state is carried into the image.
say "Enabling the SSH server for team access..."
apt-get install -y openssh-server
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config   # no root over SSH
systemctl enable --now ssh
say "  SSH server ENABLED on port 22 (starts on boot)."
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 22/tcp || true; say "  ufw: allowed tcp/22."
fi

# Shared project group: the whole team can read/edit the project files,
# independent of root. Admins get sudo; devs do NOT (least privilege).
groupadd -f soc
if [[ -d "$INSTALL_DIR" ]]; then
  chgrp -R soc "$INSTALL_DIR" 2>/dev/null || true
  chmod -R g+rwX "$INSTALL_DIR" 2>/dev/null || true
  find "$INSTALL_DIR" -type d -exec chmod g+s {} \; 2>/dev/null || true   # new files inherit group
fi

# Accounts are defined in  kali/team-users.conf  as   username:role
#   admin -> full sudo (manages the box, runs privileged scans)
#   dev   -> NO sudo / NO root (software + connectivity testing only)
# A public key in kali/team_keys/<user>.pub enables key login; otherwise a
# random temporary password is set and MUST be changed on first login.
TEAM_FILE="$SCRIPT_DIR/team-users.conf"
[[ -f "$TEAM_FILE" ]] || TEAM_FILE="$SCRIPT_DIR/team-users.txt"   # backward compatible
KEYS_DIR="$SCRIPT_DIR/team_keys"
ACCOUNT_SUMMARY=""
if [[ -f "$TEAM_FILE" ]]; then
  say "Provisioning team accounts from $(basename "$TEAM_FILE") ..."
  while IFS= read -r line; do
    line="${line%%#*}"; line="$(echo "$line" | tr -d '[:space:]')"
    [[ -z "$line" ]] && continue
    u="${line%%:*}"; role="${line#*:}"
    [[ "$role" == "$u" || -z "$role" ]] && role="dev"     # default = dev (no root)
    if ! id "$u" &>/dev/null; then
      useradd -m -s /bin/bash "$u"; say "  created '$u' (role: $role)"
    else
      say "  '$u' exists (role: $role)"
    fi
    usermod -aG soc "$u" 2>/dev/null || true
    if [[ "$role" == "admin" ]]; then
      usermod -aG sudo "$u" 2>/dev/null || true
      usermod -aG wireshark "$u" 2>/dev/null || true       # admins may capture traffic
    else
      gpasswd -d "$u" sudo 2>/dev/null || true              # ENFORCE no root for dev
      gpasswd -d "$u" wireshark 2>/dev/null || true
    fi
    if [[ -f "$KEYS_DIR/$u.pub" ]]; then
      install -d -m700 -o "$u" -g "$u" "/home/$u/.ssh"
      touch "/home/$u/.ssh/authorized_keys"
      grep -qxf "$KEYS_DIR/$u.pub" "/home/$u/.ssh/authorized_keys" 2>/dev/null || \
        cat "$KEYS_DIR/$u.pub" >> "/home/$u/.ssh/authorized_keys"
      chown -R "$u":"$u" "/home/$u/.ssh"; chmod 600 "/home/$u/.ssh/authorized_keys"
      say "    key installed for '$u' (key-based login)"
      ACCOUNT_SUMMARY+=$'\n'"    $u  [$role]  -> SSH key login"
    else
      # `head -c 12` closing early after its 12 bytes sends tr a SIGPIPE, so
      # the pipeline exits 141 under pipefail -- and set -e would then kill
      # this whole script mid-provisioning, right here, for the first user
      # without an SSH key on file. Disable pipefail just for this one known
      # -benign case (the output is still captured correctly either way).
      set +o pipefail
      TMPPW="$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 12)"
      set -o pipefail
      echo "$u:$TMPPW" | chpasswd
      chage -d 0 "$u" 2>/dev/null || true                   # force change at first login
      say "    temporary password set for '$u' (change forced on first login)"
      ACCOUNT_SUMMARY+=$'\n'"    $u  [$role]  -> temp password: $TMPPW   (must change at first login)"
    fi
  done < "$TEAM_FILE"
else
  say "No team-users.conf found — SSH is on, but no accounts created yet (see the guide)."
fi

# --- 5. zmap internal blocklist --------------------------------------
say "Setting up zmap for internal scanning..."
if [[ -f "$INSTALL_DIR/kali/zmap-blocklist.conf" ]]; then
  say "  custom blocklist present: $INSTALL_DIR/kali/zmap-blocklist.conf"
  say "  (use it with:  zmap -b $INSTALL_DIR/kali/zmap-blocklist.conf ... )"
  say "  reminder: the DEFAULT /etc/zmap/blocklist.conf blocks RFC1918 — do not use it for internal scans."
fi

# --- 6. time sync (trustworthy timestamps) ---------------------------
say "Enabling time synchronization..."
if systemctl list-unit-files | grep -q systemd-timesyncd; then
  timedatectl set-ntp true || true
  systemctl enable --now systemd-timesyncd || true
fi
timedatectl 2>/dev/null | sed 's/^/    /' || true

# --- 7. optional: strip desktop for a headless server VM -------------
if [[ $HEADLESS -eq 1 ]]; then
  say "--headless: removing desktop environment (server VM mode)..."
  apt-get remove -y kali-desktop-xfce xfce4 '^lightdm' 2>/dev/null || true
  systemctl set-default multi-user.target || true
  apt-get autoremove -y || true
fi

# --- 8. housekeeping --------------------------------------------------
apt-get autoremove -y
apt-get clean

# --- 9. verification report ------------------------------------------
say ""
say "=== VERIFICATION ==="
for t in nmap zmap tshark masscan netdiscover arp-scan python3 dig; do
  if command -v "$t" >/dev/null; then
    ver="$("$t" --version 2>&1 | head -n1)"
    printf "    [OK]   %-12s %s\n" "$t" "$ver" | tee -a "$LOG"
  else
    printf "    [MISS] %-12s not found\n" "$t" | tee -a "$LOG"
  fi
done
# SSH server status (teammates connect here)
if systemctl is-active ssh >/dev/null 2>&1; then
  printf "    [OK]   %-12s enabled & running (port 22)\n" "ssh-server" | tee -a "$LOG"
else
  printf "    [WARN] %-12s not running\n" "ssh-server" | tee -a "$LOG"
fi
# Account summary -> CONSOLE ONLY (never written to the log/image, since it
# may contain temporary passwords). Hand these to each person privately.
if [[ -n "$ACCOUNT_SUMMARY" ]]; then
  echo ""
  echo "=== TEAM ACCOUNTS (give privately; temp passwords change on first login) ==="
  echo "$ACCOUNT_SUMMARY"
  echo "==========================================================================="
fi
say ""
say "Project at: $INSTALL_DIR"
say "Done. Log: $LOG"
say "Next: harden the host (see the guide), then generalize + image for the server."
