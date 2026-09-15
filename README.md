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

> ⚖️ **Defensive / internal-audit use only.** Scan and analyse only company
> infrastructure you are authorized **in writing** to test.
