# 003: Automated provisioning of a fresh Kali (packages and sensor configuration)

- **Status:** Done (2026-09-24): sensor configuration in `deploy/sensors/` (68cf7ee); packages in `deploy/packages.txt`
  and `deploy/install_packages.sh`, with drift detection and the full order in `docs/REBUILD_EN.md`. Still manual:
  recreating the firewall rules and the network interfaces of the VM.
- **Proposed:** 2026-09-23 by Arturo
- **Effort:** medium

## Problem

`deploy/install_all.sh` installs the systemd units, drop-ins, crontab and sudoers rules, but it assumes the
software is already on the machine. Rebuilding the SOC on a fresh Kali today still needs manual steps that
are written down nowhere complete:

- **Sensors and their configuration**, all outside this repository:
  - Zeek in `/opt/zeek`, configured by `/opt/zeek/share/zeek/site/local.zeek`
  - Suricata, configured by `/etc/suricata/suricata.yaml`, plus its ruleset
  - osquery in `/opt/osquery`, configured by `/etc/osquery/osquery.conf`
  - AIDE, with the SOC exclusions in `/etc/aide/aide.conf.d/90_sentinel_soc`. `deploy/sudo_tasks.sh`
    writes those.
  - chkrootkit
- **Python modules** the code now imports: `geoip2`, `impacket`, `ldap3` and `yara`.
- **The MaxMind GeoLite2 databases** kept current by `geoipupdate`.

`kali/setup-kali-soc.sh` was written for this, but it is out of date. It installs the scanning tools
(nmap, zmap, tshark, arp-scan, whatweb) but none of the sensors above. It says the detectors use only
the standard library, and it copies the project instead of cloning it from git.

## Proposal

Bring provisioning up to date in two parts:

1. **Update `kali/setup-kali-soc.sh`**, or replace it with `deploy/provision.sh`, so it installs every
   package the SOC uses, including the sensors and the Python modules, and clones this repository into
   `/opt/sentinel-soc`.
2. **Version the sensor configuration.** Put the SOC's own changes in `deploy/sensors/`: `local.zeek`, the
   Suricata settings that differ from the default, `osquery.conf`, and the AIDE exclusions. Have
   `install_all.sh` put them in place. Extend `scripts/deploy_drift.py` to compare them, so the daily
   self-test catches a config edited on the machine and not in git.

The full rebuild would then be: provision, clone, `install_all.sh`, fill in the secrets, restore `data/`.

## What it takes

- Record exactly which packages and versions are installed today (`dpkg -l`, `pip list`), and how Zeek and
  osquery were installed, since both live under `/opt` and did not come from Kali's repositories.
- Separate the SOC's changes to `suricata.yaml` from the defaults, because the full file is very large.
- A test rebuild on a throwaway VM. This is the only real proof that it works.

## Risks and open questions

- Sensor configs may contain internal network ranges. That is fine in a private repository, but they
  must not contain credentials.
- Zeek and osquery versions change their config formats, so the rebuild should pin the versions in use.
- A test VM needs a network position similar to production for Zeek and Suricata to see traffic.
