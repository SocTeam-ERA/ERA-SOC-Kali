# Sentinel SOC — Kali appliance

This repository (github.com/SocTeam-ERA/ERA-SOC-Kali) is the Kali side of the SOC: detectors,
forwarders, scans and the read API that the platform backend polls. The backend, frontend and
assets service live in a separate repository, SocTeam-ERA/ERA-SOC; the contract between the two is
`SOC-Back/docs/kali/` there. Never push this repository to ERA-SOC.

## deploy/ is the source of truth for everything outside this directory

Everything the SOC needs outside `/opt/sentinel-soc` lives in `deploy/`, and `deploy/install_all.sh`
puts it in place. That is how the SOC is rebuilt if this VM is lost.

- systemd units and timers: `deploy/soc-*.service`, `deploy/soc-*.timer`
- non-secret drop-ins: `deploy/soc-*.d/*.conf`
- the user crontab: `deploy/crontab.txt`
- sudoers rules: `deploy/sudoers/`
- templates for the secret env files: `deploy/env/*.env.example`

When adding or changing a unit, timer, drop-in, cron line or sudoers rule:

1. Write it in `deploy/` first. Never edit `/etc/systemd/system` or the crontab directly.
2. Install it with `sudo bash deploy/install_all.sh`. Installing needs sudo, so the user runs it.
3. Commit, then push.

`scripts/deploy_drift.py` compares `deploy/` with the machine. `soc_selftest.py` runs it daily and
raises an alert when something was installed or edited without reaching `deploy/`.

## Secrets never go in git

- The ntfy topic (`NTFY_TOPIC`) acts as a password. It goes only in private drop-ins
  (`/etc/systemd/system/<unit>.service.d/ntfy.conf`, mode 600), which `install_all.sh` writes.
  A unit in `deploy/` must not carry an `Environment=NTFY_TOPIC=` line; `deploy_drift.py`
  reports one as `secret`.
- `/etc/sentinel-soc/*.env` (LDAP password, API settings), `data/api_keys.json` and SSH keys
  stay on the machine and in the team's password vault.
- `data/` and `kali/results/` are runtime data. `kali/backup_data.sh` backs them up, not git.

## Before committing

    sg soc -c 'python3 scripts/soc_selftest.py'    # must pass
    python3 scripts/deploy_drift.py                 # must say "deploy/ matches this machine"
