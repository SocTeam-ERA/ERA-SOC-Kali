# Rebuilding the Kali SOC appliance from scratch

What to do if the Kali VM is lost. Everything the SOC needs outside its data is in the repository
(SocTeam-ERA/ERA-SOC-Kali); the data comes from the nightly backup; the secrets come from the team's
password vault.

*Written 2026-09-24. Keep it current: when something new has to be done by hand on a fresh machine,
add the step here.*

## What comes from where

| What | Where it lives | Restored by |
|---|---|---|
| Code (detectors, API, scans) | the repository | `git clone` |
| Packages and their APT repositories | `deploy/packages.txt`, `deploy/apt/` | `deploy/install_packages.sh` |
| systemd units, timers, drop-ins, crontab, sudoers, root helpers (`soc-nmap`) | `deploy/` | `deploy/install_all.sh` |
| Zeek, Suricata and osquery configuration | `deploy/sensors/` | `deploy/install_all.sh` |
| Firewall rules | `deploy/firewall/ufw-status.txt` | by hand (step 6) |
| Data: alerts, incidents, inventories, states, watchlists, GeoLite databases | `data/` (nightly backup, today on the same VM) | step 7 |
| Secrets: ntfy topic, API keys, LDAP password, TLS keys | password vault | by hand (step 5) |

The daily self-test (`deploy_drift.py`) reports anything installed or changed on the machine that is
not in the repository, so this recipe does not go stale unnoticed.

## Steps

1. **New VM.** Install Kali (rolling), hostname `kali2`, with the six network interfaces in the same
   order as before: eth0 Floor (10.69.0.40/16), eth1 Management, eth2 Wiping, eth3 Printers, eth4 Office,
   eth5 Guest WiFi. Zeek and Suricata are bound to those names (`deploy/sensors/`). Create the SOC user
   `adelcueto` with sudo.

2. **Code.**
   ```bash
   sudo git clone git@github.com:SocTeam-ERA/ERA-SOC-Kali.git /opt/sentinel-soc
   sudo chown -R adelcueto /opt/sentinel-soc
   ```
   (The Kali's deploy key `id_ed25519_sentinel_github` is in the vault; any team member's access works too.)

3. **Packages.** `sudo bash /opt/sentinel-soc/deploy/install_packages.sh`

4. **Everything else in deploy/.** `sudo bash /opt/sentinel-soc/deploy/install_all.sh`
   It asks for the ntfy topic if none is installed yet (from the vault).

5. **Secrets** (from the vault), then restart what uses them:
   - `/etc/sentinel-soc/soc-api.env` and `/etc/sentinel-soc/ad-ldap.env`: `install_all.sh` created them
     from `deploy/env/*.example`; fill in the values.
   - The API's TLS certificate: either restore `/etc/sentinel-soc/tls/` from the vault, or run
     `sudo bash deploy/make_api_cert.sh`. **A new CA means the platform backend needs the new `ca.pem`**
     (`KALI_API_CA_CERT`), so restoring is simpler.
   - API keys are **not** in the backup (`data/api_keys.json` is left out on purpose): issue new ones with
     `python3 scripts/manage_api_keys.py`, and give the platform backend its new key (`KALI_API_TOKEN` in
     Dokploy).

6. **Firewall.** Recreate the rules listed in `deploy/firewall/ufw-status.txt` with `ufw allow ...` (one per
   line, with the same comments), then `sudo ufw enable`. They are not applied automatically on purpose.
   Check with `python3 scripts/deploy_drift.py`: no `firewall` line.

7. **Data.** Copy the latest `soc-backup-*.tar.gz` back (from wherever it was kept off the VM), unpack it
   with `kali/backup_data.sh --restore <file> /tmp/restore` (it never writes into the live `data/`), stop the
   SOC services, copy the unpacked `data/` into `/opt/sentinel-soc/data/`, and start them again. The threat
   feeds are downloaded again the next night. Until the off-VM copy exists (improvements/002), the data is
   lost with the VM, and the SOC then starts from empty baselines.

8. **Start the sensors.** `sudo /opt/zeek/bin/zeekctl deploy`; `sudo systemctl restart suricata osqueryd`;
   `sudo bash deploy/sudo_tasks.sh --reinit-aide` (a new AIDE baseline of the fresh system).

9. **Check.**
   ```bash
   python3 /opt/sentinel-soc/scripts/deploy_drift.py        # "deploy/ matches this machine"
   sg soc -c 'python3 /opt/sentinel-soc/scripts/soc_selftest.py'
   ```
   Then confirm with whoever runs the platform backend that new alerts reach the dashboard.
