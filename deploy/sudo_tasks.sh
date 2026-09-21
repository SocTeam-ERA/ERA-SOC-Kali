#!/usr/bin/env bash
# =====================================================================
#  sudo_tasks.sh -- the changes that need root and cannot be done by the
#  SOC platform itself. Safe to run more than once.
# =====================================================================
#    sudo bash /opt/sentinel-soc/deploy/sudo_tasks.sh              # AIDE exclusions only (seconds)
#    sudo bash /opt/sentinel-soc/deploy/sudo_tasks.sh --reinit-aide # ...and rebuild the AIDE database (~30 min)
#
#  What it does:
#   1. Adds the noisy paths below to AIDE's exclusions (/etc/aide/aide.conf.d/90_sentinel_soc),
#      after backing that file up, and validates the result with `aide --config-check`
#      (it restores the backup if the config no longer validates).
#   2. With --reinit-aide, copies the current database aside and runs `aide --init`.
#      An exclusion does not remove files already recorded in the database, so this
#      is what makes it take full effect. It also accepts the system's CURRENT state
#      as the new baseline, so only do it when the machine is in a state you trust.
#      Observed here: `aide --init` writes straight to aide.db (not aide.db.new).
#
#  Excluded paths, and why:
#    /var/lib/apt, /var/lib/PackageKit, /var/lib/rpm, /var/lib/command-not-found
#        package-manager state that changes on every apt run
#    /var/lib/aide/aide.db.new          AIDE's own scratch file
#    /opt/sentinel-soc/.*/__pycache__   Python bytecode regenerated when project code runs
#        (the source files themselves are still checked)
#
#  Interim suppression rules in config/suppressions.json (aide-package-manager-paths and
#  aide-project-bytecode) hide the same noise until this has been applied; they can be
#  removed afterwards.
# =====================================================================
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "This needs root: sudo bash $0 $*"; exit 1; }
CONF=/etc/aide/aide.conf.d/90_sentinel_soc
MAIN=/etc/aide/aide.conf
DB=/var/lib/aide/aide.db
STAMP="$(date +%Y%m%d%H%M%S)"
EXCLUSIONS=(
  '!/var/lib/apt'
  '!/var/lib/PackageKit'
  '!/var/lib/rpm'
  '!/var/lib/command-not-found'
  '!/var/lib/aide/aide.db.new'
  '!/opt/sentinel-soc/.*/__pycache__'
)

[[ -f "$CONF" ]] || { echo "Not found: $CONF"; exit 1; }
cp -a "$CONF" "$CONF.bak.$STAMP"
echo "[1/2] backup: $CONF.bak.$STAMP"

added=0
for line in "${EXCLUSIONS[@]}"; do
  if grep -qxF -- "$line" "$CONF"; then
    echo "      already present: $line"
  else
    printf '%s\n' "$line" >> "$CONF"
    echo "      added: $line"
    added=$((added + 1))
  fi
done

if aide --config="$MAIN" --config-check >/dev/null 2>&1; then
  echo "[1/2] AIDE configuration is valid ($added line(s) added)."
else
  cp -a "$CONF.bak.$STAMP" "$CONF"
  echo "[!] AIDE rejected the configuration; the backup was restored. Nothing changed."
  exit 1
fi

if [[ "${1:-}" == "--reinit-aide" ]]; then
  [[ -f "$DB" ]] && cp -a "$DB" "$DB.pre-reinit.$STAMP" && echo "[2/2] database copy: $DB.pre-reinit.$STAMP"
  echo "[2/2] running aide --init (about 30 minutes; safe to leave running)..."
  time aide --config="$MAIN" --init
  ls -la --time-style=full-iso "$DB" "$DB.new" 2>/dev/null || true
  echo "[2/2] done. If aide.db is not newer than the copy above, look for aide.db.new and move it over aide.db."
else
  echo "[2/2] skipped (add --reinit-aide to rebuild the database so the exclusions fully apply)."
fi
