# SOC Project — Sentinel // SOC
### English guide for the team

This document explains **what was built**, **how it is organized**, and **how to deploy it** on the company Ubuntu server. It is written so it can be handed straight to the two developers on the team.

> **Language:** all code, the dashboard UI, and alert messages are in **English** (as requested). This guide and its Spanish version (`INSTRUCCIONES_ES.md`) describe the same content.

---

## 1. What this project is

A **mini-SOC** (Security Operations Center) in the style of **Splunk / LetsDefend**: one central console where you and your teammates monitor the company's security alerts in real time, from your own computers.

It detects and displays five event types:

| Type | What it detects | Script |
|------|-----------------|--------|
| **intrusion** | Domain logins, brute force, access from unknown IPs | `login_monitor.py` |
| **port_scan** | Open ports / exposed services on IPs and subnets | `port_scanner.py` |
| **phishing** | Malicious emails (phishing / malware) via headers, links, attachments | `phishing_detector.py` |
| **malware** | Malicious files by hash (IOC), signatures, heuristics | `malware_detector.py` |
| **vuln** | Network vulnerabilities found with nmap from Kali | `kali/` suite |

Every alert carries: **exact time, type, severity (normal / medium / critical), source IP, hostname, and user** (when it can be determined).

---

## 2. Architecture (how it fits together)

```
        KALI LINUX (Arturo)                 UBUNTU SERVER (Dell R730/R740)
   ┌───────────────────────┐          ┌────────────────────────────────────────┐
   │  kali/ (nmap scanning)│  results │  scripts/  (Python detectors)            │
   │  discovers hosts,     │─────────▶│    port_scanner.py                       │
   │  ports and vulns      │  alerts  │    login_monitor.py                      │
   └───────────────────────┘          │    phishing_detector.py                  │
                                       │    malware_detector.py                   │
                                       │            │                             │
                                       │            ▼   emit_alert()              │
                                       │      soc_core.py  ── writes ──▶          │
                                       │            │                             │
                                       │            ▼                             │
                                       │   data/alerts.json  (common feed)        │
                                       │            │                             │
                                       │            ▼                             │
                                       │   dashboard/  (Splunk-style web) ◀───────┼─── you + teammates
                                       └────────────────────────────────────────┘        (browser)
```

**The key piece is `soc_core.py`.** Every script calls the same `emit_alert(...)` function, so all alerts end up in **one common JSON schema**. That means:

- The dashboard always reads the same file (`data/alerts.json`).
- Later you can swap the storage layer (PostgreSQL, or forward to **Wazuh / Elastic**, the real open-source "Splunks") **without touching the detectors**.

---

## 3. File layout

```
soc-project/
├── dashboard/
│   └── sentinel_soc.html      # The console (open in a browser)
├── scripts/                   # Python detectors (run on the Ubuntu server)
│   ├── soc_core.py            # Shared library: alert schema + storage
│   ├── port_scanner.py        # Port / IP scanner
│   ├── login_monitor.py       # Login / intrusion monitor
│   ├── phishing_detector.py   # Phishing email analyser
│   ├── malware_detector.py    # Malware / IOC scanner
│   └── seed_demo_data.py      # Generates demo data
├── kali/                      # Network scan suite (run on Kali)
│   ├── targets.conf           # Authorized scope (subnets/VLANs)
│   ├── lib.sh                 # Shared helpers
│   ├── 0_run_all.sh           # Runs the FULL workflow + report
│   ├── 1_host_discovery.sh    # Discover live hosts
│   ├── 2_port_service_scan.sh # Port + service scan
│   ├── 3_vuln_scan.sh         # Vulnerability scan (NSE)
│   └── nmap_to_alerts.py      # Convert nmap results → dashboard alerts
├── data/
│   ├── alerts.json            # Feed the dashboard reads (auto-generated)
│   ├── alerts.jsonl           # Full history (append-only)
│   └── ioc_hashes.txt         # Known-bad hash list
└── docs/
    ├── INSTRUCCIONES_ES.md    # Spanish guide
    └── INSTRUCTIONS_EN.md     # This guide
```

---

## 4. Quick test (any machine with Python 3)

```bash
cd soc-project/scripts

# Generate ~44 sample alerts (all types and severities)
python3 seed_demo_data.py --fresh --count 44

# Try each detector in demo mode:
python3 login_monitor.py --demo         # simulates a brute-force attack
python3 phishing_detector.py --demo      # analyses a sample phishing email
python3 malware_detector.py --demo       # creates + scans the EICAR test file
python3 port_scanner.py 127.0.0.1 --ports 1-1024
```

Then open `dashboard/sentinel_soc.html` in a browser.

> **About the prototype:** the delivered dashboard generates its own sample data in the browser so it can be demoed to managers **with no server required**. In production, replace the `generateAlerts()` function with a poll of `data/alerts.json` (a comment marks the spot in the `<script>` section). The field names are identical, so it is a small change.

---

## 5. Each detector in detail (for the developers)

### `port_scanner.py`
Scans TCP ports of a single IP, several IPs, or a whole subnet (CIDR) and raises one alert per open port. Severity depends on the service:
- **critical:** Telnet, SMB (445), RDP (3389), FTP, exposed databases, Redis, Mongo…
- **medium:** SSH, SMTP, LDAP, admin ports…
- **normal:** HTTP/HTTPS.

```bash
python3 port_scanner.py 10.10.20.0/24 --top-ports
python3 port_scanner.py 10.10.20.10 --ports 1-1024 --baseline 22,443
```
`--baseline` = list of "approved" ports; any open port **not** in the baseline is escalated one severity level (useful to catch unauthorized changes).

### `login_monitor.py`
Reads authentication logs and detects:
- Brute force (many failures from one IP in a short window) → **medium/critical**
- Successful login right after many failures → **critical** (compromise pattern)
- Login from a new/unknown IP → escalated
- Normal login → **normal**

```bash
# On the Ubuntu server, following the live SSH log:
sudo python3 login_monitor.py --auth-log /var/log/auth.log --follow --known-ips known_ips.txt

# Analysing a Windows Security-log CSV export (time,event_id,user,ip,host):
python3 login_monitor.py --windows-csv security_export.csv
```
Supported Windows events: **4624** (logon success) and **4625** (logon failure).

### `phishing_detector.py`
Analyses `.eml` (RFC-822) emails **statically** (no link-clicking, nothing executed). It checks:
- **SPF / DKIM / DMARC** authentication in the headers.
- **From vs Reply-To vs Return-Path** domain mismatches.
- Links: raw-IP URLs, shorteners, punycode, `@`-trick, link text that doesn't match the real destination.
- Dangerous attachments (`.exe`, `.scr`, `.js`, `.hta`…), double extensions (`invoice.pdf.exe`), macro-enabled Office.
- Classic phishing language (urgency, credentials, payments).

It produces a score → severity (≥8 critical, 4–7 medium, 1–3 normal).

```bash
python3 phishing_detector.py suspicious.eml
```

### `malware_detector.py`
Scans files or folders (**executes nothing**):
- **Hash** MD5/SHA1/SHA256 against the IOC list (`data/ioc_hashes.txt`).
- Simple signatures (EICAR, PowerShell download cradle, macro Shell exec…).
- Real file type by magic bytes (catches a `.pdf` that is actually an executable).
- High entropy (packed/encrypted file).

```bash
python3 malware_detector.py /path/to/quarantine/
```
Feed `data/ioc_hashes.txt` from threat-intel sources (AbuseCH, MISP, etc.).

---

## 6. The Kali suite (vulnerability scanning)

This part is run **by Arturo from Kali**. **Only scan the IPs/subnets/VLANs that IT authorizes in writing.**

1. Edit `kali/targets.conf` with the subnets you are given (grouped by VLAN).
2. Run the whole workflow:

```bash
cd soc-project/kali
chmod +x *.sh
sudo ./0_run_all.sh            # discovery → ports → vulns → report
# or faster:
FAST=1 sudo ./0_run_all.sh
```

It produces, under `kali/results/`:
- `live_hosts_*.txt` — live hosts
- `services_*.nmap` — ports and services
- `vuln_*.nmap` — vulnerabilities (nmap NSE)
- `REPORT_*.txt` — **human-readable summary for IT and managers** ← this is the one for the project report

It also auto-imports the findings into the dashboard via `nmap_to_alerts.py`, so open ports and vulnerabilities appear alongside every other alert.

You can also run the steps individually:
```bash
sudo ./1_host_discovery.sh 10.10.20.0/24
sudo ./2_port_service_scan.sh results/live_hosts_XXXX.txt
sudo ./3_vuln_scan.sh results/live_hosts_XXXX.txt
python3 nmap_to_alerts.py results/vuln_XXXX.xml --baseline 22,443
```

Requirements on Kali: `nmap` (pre-installed). Optional: the `vulners` NSE script to map versions to CVEs.

---

## 7. Running it 24/7 on the Ubuntu server

Since the dashboard must run permanently on a Dell R730/R740, run the detectors as **systemd services**.

### 7.1 Prepare the server
```bash
sudo apt update && sudo apt install -y python3 python3-pip nmap
sudo useradd -r -s /bin/false soc          # service account
sudo mkdir -p /opt/soc-project
sudo cp -r soc-project/* /opt/soc-project/
sudo chown -R soc:soc /opt/soc-project
```

### 7.2 Serve the dashboard (simple, with nginx)
```bash
sudo apt install -y nginx
sudo cp /opt/soc-project/dashboard/sentinel_soc.html /var/www/html/index.html
sudo ln -s /opt/soc-project/data /var/www/html/data
```
The team then browses to `http://SERVER-IP/`.
(In production, put it behind HTTPS and a login — see section 8.)

### 7.3 Service for the login monitor (example)
File `/etc/systemd/system/soc-login.service`:
```ini
[Unit]
Description=SOC login/intrusion monitor
After=network.target

[Service]
User=soc
WorkingDirectory=/opt/soc-project/scripts
ExecStart=/usr/bin/python3 login_monitor.py --auth-log /var/log/auth.log --follow --known-ips /opt/soc-project/scripts/known_ips.txt
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now soc-login.service
sudo systemctl status soc-login.service
```

### 7.4 Periodic scans with cron
```bash
sudo crontab -e
# Port scan every hour:
0 * * * * cd /opt/soc-project/scripts && /usr/bin/python3 port_scanner.py --targets /opt/soc-project/scripts/subnets.txt --top-ports
```

---

## 8. Roadmap / recommended next steps (for the IT + managers report)

This deliverable is a **solid, working foundation**. For real production, recommend in the report:

1. **Dashboard authentication** (per-user login, HTTPS) — today it is read-only.
2. **A database** (PostgreSQL or SQLite) instead of `alerts.json`, or better, **integrate Wazuh or the Elastic Stack** as the engine behind it and use this dashboard as the visualization layer. Wazuh already ships Windows/Linux agents, correlation, and compliance.
3. **Endpoint agents** to collect logs from every machine (not just the server).
4. **Real threat-intel feeds** for `ioc_hashes.txt` (MISP, AbuseCH).
5. **Notifications** (email / Teams / Slack) when a `critical` fires.
6. **Retention and backup** of `alerts.jsonl` for audit.

### Project goal
The purpose is a **report on what the company needs to improve its security**. The Kali scans (`REPORT_*.txt`) deliver exactly that: ports to close, insecure services (exposed Telnet/SMB/RDP), and CVE vulnerabilities to patch. That report is what goes to the meeting with IT and the managers.

---

## 9. Important reminder (ethics & authorization)

These tools are **defensive / internal-audit** tools. Scanning networks or analysing email is done **only** on company infrastructure and **with written authorization** from IT / management. Keep that approval on file — the Kali scripts even require an authorization confirmation before running.
