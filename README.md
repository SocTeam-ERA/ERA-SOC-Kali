# Sentinel // SOC  🛡️

A small **Splunk / LetsDefend-style Security Operations Center** for internal
monitoring: a black-and-green "hacker" dashboard fed by Python detectors and a
Kali/nmap network-scanning suite.

| I want to… | Go to |
|------------|-------|
| **Run it on my computer today (Español)** | [`docs/QUICKSTART_LOCAL_ES.md`](docs/QUICKSTART_LOCAL_ES.md) |
| See what everything is and how to deploy it (**Español**) | [`docs/INSTRUCCIONES_ES.md`](docs/INSTRUCCIONES_ES.md) |
| Same, in **English** | [`docs/INSTRUCTIONS_EN.md`](docs/INSTRUCTIONS_EN.md) |
| zmap + tshark modules (ES/EN) | [`docs/MODULOS_zmap_tshark_ES.md`](docs/MODULOS_zmap_tshark_ES.md) |
| Open the dashboard | `dashboard/sentinel_soc.html` |
| Run the detectors | `scripts/` |
| Scan the network from Kali | `kali/` |
| Future improvements proposed for review | [`improvements/`](improvements/README.md) |

> **Dashboard data:** served over HTTP it reads the real `data/alerts.json` (badge: *FEED · alerts.json*); double-clicked it shows in-browser demo data (*FEED LIVE · demo*). See the quickstart.

## 30-second demo
```bash
cd scripts
python3 seed_demo_data.py --fresh --count 44   # sample alerts
python3 login_monitor.py --demo                # brute-force demo
python3 phishing_detector.py --demo            # phishing email demo
python3 malware_detector.py --demo             # EICAR malware demo
# then open ../dashboard/sentinel_soc.html
```

## Components
- **`scripts/`** — `port_scanner.py`, `login_monitor.py`, `phishing_detector.py`,
  `malware_detector.py`, all writing a common alert schema via `soc_core.py`.
- **`kali/`** — `0_run_all.sh` orchestrates host discovery → port/service scan →
  vuln scan (nmap NSE) and imports findings into the dashboard feed.
- **`dashboard/sentinel_soc.html`** — the live console (KPIs, 12-hour histogram,
  by-type / top-IP panels, filterable event stream, alert detail drawer).

## Deployment on the Kali appliance

This repository is the Kali side of the SOC. The backend, frontend and assets service live in
[SocTeam-ERA/ERA-SOC](https://github.com/SocTeam-ERA/ERA-SOC); the backend polls this appliance's API.

- **`deploy/`** is the source of truth for everything outside this directory: the 48 systemd units and
  timers, their non-secret drop-ins, the user crontab (`crontab.txt`), the sudoers rule and templates for
  the secret env files (`env/*.env.example`).
- **`deploy/install_all.sh`** (run with sudo) installs all of it, on a fresh Kali or after changing a unit.
  It refuses to run if an installed unit was edited on the machine and the edit is not in `deploy/`.
- **`scripts/deploy_drift.py`** compares `deploy/` with the machine. The daily self-test runs it and raises
  an alert when something is installed or edited without reaching `deploy/`.
- New units, timers or cron lines are written in `deploy/` first, never directly in `/etc/systemd/system`.
  See [`CLAUDE.md`](CLAUDE.md) for the full workflow.

**Secrets are never committed.** The ntfy topic lives only in private drop-ins
(`/etc/systemd/system/<unit>.service.d/ntfy.conf`, mode 600). `/etc/sentinel-soc/*.env`,
`data/api_keys.json` and SSH keys stay on the machine and in the team's password vault.

### 2026-09-23: ntfy topic moved to private drop-ins

`install_all.sh` was run on the live appliance. The ntfy topic had been written into 14 installed units
with mode 644, so any local user could read it and use it to read or forge alerts. The units no longer carry
it; it is in 18 `ntfy.conf` drop-ins with mode 600, and the services receive the same value. Afterwards:
no unit carries the topic, no `soc-*` unit failed, `deploy_drift.py` reports no drift and the self-test
passed 328/328. No service was restarted.

**Expected AIDE alert:** the check on 2026-09-24 at 05:00 reports changes under `/etc/systemd/system`
(`soc-*` units and `soc-*.service.d/` directories) because of this change. Resolve it with the note
"ntfy topic moved to private drop-ins", but first confirm it lists no other files: AIDE groups every
change of the day into one alert.

> ⚖️ **Defensive / internal-audit use only.** Scan and analyse only company
> infrastructure you are authorized **in writing** to test.
