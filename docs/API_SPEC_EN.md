# Sentinel SOC Kali API: specification

The Kali appliance's own REST API (`scripts/soc_api.py`, service `soc-api`). The platform backend
(SocTeam-ERA/ERA-SOC, `SOC-Back/common/kali_poll.py`) pulls alerts from it. The endpoints in this
document are what a backend proxy (`/api/kali/*`) can expose to the dashboard.

This file is the source of truth for the contract. ERA-SOC should link here rather than keep copies of
the Kali code, and when the API changes, this file changes in the same commit.

*Updated 2026-09-24.*

---

## 1. Connection

| | |
|---|---|
| Base URL | `https://10.69.0.40:8443` (HTTPS, `soc-api-tls.service`) or `http://10.69.0.40:8080` (plain, to be closed, see §9). Same API and data on both |
| Auth | `Authorization: Bearer <token>` on every `/api/*` path except `/api/health` |
| Format | JSON (`application/json`), UTF-8. A pcap download is `application/vnd.tcpdump.pcap` |
| Times | ISO-8601 in UTC with offset (`2026-09-24T15:47:38.123+00:00`). Query parameters also accept epoch milliseconds |
| CORS | Off unless `SOC_API_CORS` is set. The browser should not call this API directly (§8) |

### Keys and roles

Every key belongs to a user and has a role. Keys are managed with `scripts/manage_api_keys.py` on the Kali.

| Role | Can do |
|---|---|
| `read` | Every `GET` |
| `write` | Every `GET`, plus the `POST` and `DELETE` endpoints in §4 |

Every write is recorded under the **key's user**. The API never accepts a user name sent by the client,
so a backend acting for an analyst should put the analyst's name in the note or comment,
e.g. `"[jdoe] false positive: IT maintenance"`.

### Errors

Every error is JSON: `{"error": "<message>", "hint": "<optional>"}`.

| Code | Meaning |
|---|---|
| 400 | Invalid parameter or body |
| 401 | Missing or unknown key |
| 403 | Read-only key on a write endpoint |
| 404 | Unknown path or object |
| 413 | Body larger than 64 KB |
| 429 | Too many searches running (at most 2 at a time) |
| 504 | Search took too long |

---

## 2. The alert object

```jsonc
{
  "id": "a192a03e-70d0-4c3d-9f75-3c6bbef3e82c",   // stable, unique: the dedupe key
  "timestamp": "2026-09-23T11:32:27.104729+00:00", // when the detector raised it
  "type": "intrusion",          // port_scan | intrusion | phishing | malware | vuln
  "severity": "medium",         // normal | medium | critical
  "title": "Windows host not in the domain: DESKTOP-SUKLCOQ (10.69.11.94)",
  "description": "…",
  "detector": "ad_inventory",   // which Kali component raised it (GET /api/detections lists them)
  "source_ip": "10.69.11.94",   // may be null
  "hostname": "DESKTOP-SUKLCOQ",// may be null
  "user": null,                 // may be null
  "status": "open",             // open | acknowledged | resolved
  "status_updated": "…",        // only after a status change
  "status_actor": "jdoe",       // who changed it (the API key's user, or "auto-aging", "selftest"…)
  "status_note": "…",           // why; absent when the last change had no note
  "test": true,                 // only on synthetic alerts: keep them out of real views. The detectors
                                // manual_test, test and debug_test are always synthetic too
  "details": { … }              // free-form, see below
}
```

**Severity.** `critical` is also pushed to the on-call phone. `medium` means a person should look at it.
`normal` is informational. The platform maps `normal` to `low`, and its default triage view shows `medium`
and up, so anything a person must see is raised as at least `medium`.

### `details`: the fields a consumer can rely on

Not from the Kali: `details.corroborated` (several detectors, same IP, same window), `details.threat` (the backend's hosting heuristic) and `details.kali_id` / `ingest_via` are added by the platform backend (ERA-SOC `common/`), never sent by this API.

`details` is free-form: each detector adds its own keys. These ones are common to many detectors and
have a stable shape:

| Key | Shape | Meaning |
|---|---|---|
| `entities` | `[{"type": "ip\|mac\|host\|user", "value": "…", "role": "source\|destination"}]` | Everything the alert is about. These are the keys for `/api/entities/<type:value>` |
| `identity` | `{"as_of", "computers": [{name, in_domain, ou, os, build, enabled, last_logon, os_support, os_support_ends, ip}], "users": [{sam, name, ou, enabled, last_logon, privileged_groups}]}` | Who and what the alert is about, according to Active Directory. Present only when something matched. `in_domain: false` means a Windows machine AD does not know |
| `mitre` | `[{"technique", "name", "tactics": [...], "basis": "observed\|exposure"}]` | MITRE ATT&CK tags |
| `incident_id`, `incident_number` | string, int | The incident this alert belongs to (§3.3) |
| `geo` | `{country_code, country, city?, lat?, lon?, precision: "city"\|"country"}` | For public IPs only (`geoip_enrich.py`). No ASN or organisation here: when known, the organisation is in `anonymizer.org` |
| `anonymizer`, `anonymizer_ip` | `{tor, datacenter, anonymized, type, org?}` (`type`: e.g. `tor`, `vpn`, `hosting`, `unknown`), and the IP it describes | Tor, VPN or hosting source (`proxy_check.py`) |
| `threat_intel` | `{"ip_matches": [{indicator, feed, role}], "kev": [{cve, …}]}` | Threat-feed hit, or a CVE in CISA KEV |
| `pcap` | path on the Kali | A packet capture exists: download it with `GET /api/alerts/<id>/pcap` |
| `source_role` | `actor\|asset` | Whether `source_ip` is the attacker (`actor`) or the scanned or affected machine (`asset`) |
| `source_is_self` | `true` | The source is the Kali itself (its own scans) |
| `group_key`, `batch_id` | strings | Grouping of similar alerts, and of alerts raised in the same burst |
| `change`, `previous_title` | strings | Why a state-tracking detector fired (`added`, `removed`, `new_device`, …) |

---

## 3. Read endpoints (`GET`, any key)

### 3.1 Alerts

| Path | Parameters | Returns |
|---|---|---|
| `/api/health` (no auth) | none | `{"status": "ok", "alerts": <n>, "time"}` |
| `/api/summary` | none | `{total, by_severity, by_type, by_status}` |
| `/api/alerts` | `severity`, `type`, `detector`, `status`, `since`, `status_since`, `limit` (default 100, max 1000) | `{"count", "alerts": [alert…]}` |
| `/api/alerts/<id>` | none | One alert, or 404 |
| `/api/alerts/<id>/pcap` | none | The capture file (`Content-Disposition: attachment`), or 404. Only files inside the Kali's capture directory are served |
| `/api/hosts` | same filters as `/api/alerts` | Alerts grouped by host |

Details on the `/api/alerts` parameters:

- **`since`** filters by `timestamp` (`>=`). Results are newest first.
- **`status_since`** filters by `status_updated` (`>=`): only alerts whose status changed at or after that
  instant. These results are **oldest change first**, so a poller can advance its watermark to the last
  `status_updated` it received.
- The feed holds the latest **5,000** alerts. Older ones stay in the Kali's history, but they are no longer
  served here and their status can no longer change.

### 3.2 Investigation

| Path | Parameters | Returns |
|---|---|---|
| `/api/entities` | `type` (`ip\|mac\|host\|user`), `limit` (default 50, max 200) | `{"count", "entities": [{key, type, value, risk, risk_level, open_alerts: {critical, medium, normal}, incidents_open, last_seen}]}`, riskiest first |
| `/api/entities/<type:value>` | none | The entity plus `asset`, `incidents`, `techniques`, `timeline` |
| `/api/entities/<type:value>/graph` | none | `{"nodes": [{id, kind, label, …}], "edges": [{from, to, label}]}` |
| `/api/activity` | `category`, `actor`, `since`, `limit` (default 100, max 500) | `{"count", "categories", "activity": [{at, actor, action, summary, ref, category}]}`. Categories: `alert_status`, `asset_annotation`, `incident`, `playbook_run`, `suppression`, `watchlist`, `alert_aging` |
| `/api/search/sources` | none | Searchable sources, limits, syntax and examples |
| `/api/search` | `source` (`alerts`, `suricata`, `zeek:<log>`), `q`, `since` (e.g. `6h`), `limit`, `timeout` | Matching raw records, newest first, plus what ended the search (limit, time or size) |

In a graph, `kind` is one of `incident`, `alert`, `ip`, `mac`, `host`, `user`. `alert` nodes also carry
`severity`, `detector`, `status` and `timestamp`. A node's `id` is unique within the graph.

The search syntax is: `word`, `field:value`, `field~text`, `field:10.0.0.0/8`, and `-term` to exclude.
Regular expressions are not accepted.

### 3.3 Incidents

Incidents are opened by the Kali's correlation rules (`GET /api/detections` lists them) when related
alerts line up. **The Kali owns them**: the platform reads them rather than keeping a copy.

| Path | Parameters | Returns |
|---|---|---|
| `/api/incidents` | `status` (`new\|active\|closed`), `severity`, `limit` (default 100, max 500) | `{"count", "incidents": [incident without comments, + comment_count]}` |
| `/api/incidents/<id or number>` | none | The incident, with `comments`, its `alerts` and `alerts_not_in_feed` |
| `/api/incidents/<id or number>/graph` | none | Graph, same shape as the entity graph |

Incident fields: `id`, `number`, `title`, `severity` (`medium\|critical`), `status`, `classification`
(`true_positive\|false_positive\|benign\|undetermined` or `null`), `owner`, `rule_id`, `rule_name`,
`entities`, `alert_ids`, `alert_count`, `mitre`, `created`, `updated`, `first_alert_at`, `last_alert_at`,
`comments`.

### 3.4 Health, coverage and reports

| Path | Returns |
|---|---|
| `/api/metrics` | Alert and incident counts, time to acknowledge and to resolve (MTTA/MTTR), riskiest entities |
| `/api/sources` | `{"checked", "sources": [{id, name, kind, max_age_minutes, status, last_event, age_minutes, since}]}`: has each data source produced data recently? |
| `/api/detections` | Every detector (alerts in the last 7 and 30 days, last alert, MITRE, settings), the MITRE coverage and the correlation rules |
| `/api/mitre` | Coverage matrix: covered, limited or gap per technique, and which missing data source would close each gap |
| `/api/reports` | Saved weekly reports: `[{date, json, markdown}]` |
| `/api/reports/weekly` | `date` (optional; without it, a live report), `format=markdown` (optional) |
| `/api/self` | `{hostname, addresses: [{ip, interface}]}`: the Kali's own addresses |

### 3.5 Assets, tuning and automation

| Path | Returns |
|---|---|
| `/api/assets` | `vlan` (optional). Devices seen on the network (ARP scan), keyed by MAC: `ip`, `vendor`, `cidr`, `first_seen`, `last_seen`, `seen_count`, `owner`, `notes`, `authorized`, `scan_facts` (OS, Windows build, SMB signing), `software` |
| `/api/suppressions` | `{"count", "rules": [{id, source, reason, added_by, added, expires, expired, allow_critical, match, hits_total, hits_24h}], "errors"}` |
| `/api/watchlists` | `{"watchlists": [{name, description, used_by, count, entries}]}`. The names are `trusted_ips`, `bad_ips`, `bad_domains`, `bad_hashes`, `dhcp_servers`, `ra_sources`, `sensitive_vlans`, `untrusted_vlans`, `on_leave_accounts` (AD accounts of people away: any sign-in is a critical alert) |
| `/api/watchlists/<name>` | One list |
| `/api/playbooks` | Automatic responses: `{playbooks: [{id, name, enabled, dry_run, cooldown_minutes, trigger, actions, last_run, runs_24h, errors_24h}], errors, dry_run_all}` |
| `/api/playbooks/runs` | `limit` (default 50, max 200). Recent runs |

### 3.6 Active Directory

From the daily AD inventory (`scripts/ad_inventory.py`, 06:40; privileged groups every 15 minutes). No
LDAP call per request. Every path answers 404 `no Active Directory inventory yet` until the first
inventory exists. A computer's or user's `status` is `active`, `stale` (enabled, but no sign-in for 90
days) or `disabled`; the alerts use the same rules.

| Path | Parameters | Returns |
|---|---|---|
| `/api/ad/summary` | none | `as_of`, `server`, `mode`, `computers` and `users` (`total`, `active`, `stale`, `disabled`), `privileged` (`{group: [{sam, display, status, last_logon}]}`), `windows_support` (`unsupported` and `ending_soon`: active computers), `not_in_domain` (`[{name, ip, last_seen, mac}]`: Windows machines on the network that AD does not know), `risks` (the domain weaknesses: `[{id, severity, title, description, accounts}]`), `domain_policy` (`min_length`, `lockout_threshold`, `max_age_days`, `history`) |
| `/api/ad/computers` | `status`, `ou` (prefix, e.g. `Calgary/Accounting`), `support` (`unsupported\|ending_soon\|supported`), `q` (name, DNS, OS or OU) | `{"count", "computers": [{name, dns, os, os_version, build, enabled, last_logon, created, ou, support: {release, track, ends, status, days_left}, status, network: {ip, last_seen, mac} or null}]}`. `network` is where the Kali's scan last saw the machine |
| `/api/ad/users` | `status`, `ou`, `q` (account or display name), `privileged=1` | `{"count", "users": [{sam, display, enabled, last_logon, created, ou, status, privileged_groups}]}` |
| `/api/ad/history` | `days` (default 90, max 730) | `{"count", "days": [{date, computers, users, privileged, privileged_accounts, os_unsupported, os_ending_soon, not_in_domain, risks, risks_by_severity}]}`, oldest first: for trend charts |

`last_logon` is AD's `lastLogonTimestamp`, which AD updates only every 9 to 14 days. Treat it as approximate.

---

## 4. Write endpoints (`write` key)

| Method and path | Body | Effect |
|---|---|---|
| `POST /api/alerts/<id>/status` | `{"status": "open\|acknowledged\|resolved", "note": "…"}` | Triage status. Records `status_actor` (the key's user), `status_updated` and `status_note`. Returns the updated alert. 404 if the alert is no longer in the feed |
| `POST /api/incidents/<id or number>` | any of `status`, `classification`, `owner`, `comment` | Updates the incident. A comment is attributed to the key's user |
| `POST /api/assets/<mac>/notes` | any of `owner`, `notes`, `authorized` (bool) | Annotates a device already seen on the network |
| `POST /api/suppressions/preview` | `{"alert_id", "scope": "similar\|host\|broad"}` or `{"match"}`, plus `days` | How many past alerts the rule would have hidden. Creates nothing |
| `POST /api/suppressions` | `{"reason", "alert_id", "scope"}` or `{"reason", "match"}`, plus `expires_days` (default 30, max 365) and `resolve_existing` | Creates a rule. Rules always expire and never hide critical alerts |
| `DELETE /api/suppressions/<id>` | none | Removes a rule created through the API |
| `POST /api/watchlists/<name>` | `{"entry": "…"}` | Adds an entry, which is validated per list (IP, CIDR, domain, hash…) |
| `DELETE /api/watchlists/<name>?entry=…` | none | Removes an entry |

Every write also appears in `GET /api/activity`.

---

## 5. Keeping the platform in sync

### 5.1 New alerts (the backend's current poller)

```
GET /api/alerts?since=<newest timestamp already stored>&limit=1000
```

- Use `id` as the dedupe key. Results are newest first.
- If a page is full (1,000 alerts), go back to the oldest `timestamp` on it for the next call, so no gap is left.
- An alert with `"test": true` goes to the test lane.

### 5.2 Status changes, Kali to platform

```
GET /api/alerts?status_since=<last status_updated received>&limit=1000
```

- For each alert returned, update **only** `status` and the `status_updated`, `status_actor` and
  `status_note` fields, then keep the last `status_updated` as the next watermark.
- This covers changes made on the Kali: automatic aging, the self-test, suppressions that resolve existing
  alerts, and anyone using the Kali's own tools.

### 5.3 Status changes, platform to Kali

When an analyst changes an alert that came from the Kali (the platform keeps its id in
`details.kali_id`):

```
POST /api/alerts/<kali_id>/status   {"status": "resolved", "note": "[jdoe] <reason>"}
```

This needs a `write` key for the backend. **Avoid loops:** a status the poller received from the Kali
(§5.2) must not be posted back to the Kali. A change posted to the Kali comes back through §5.2 with
`status_actor` equal to the backend key's user; since the status is already the same, applying it again
changes nothing.

---

## 6. Suggested mapping for a backend proxy

To serve these endpoints to the dashboard without exposing the Kali key in the browser, a backend proxy
can gate them by platform role:

| Platform role | Kali endpoints |
|---|---|
| viewer | Every `GET` in §3 except `/api/search`, `/api/alerts/<id>/pcap` and `/api/ad/users` (staff names and account status) |
| analyst | Everything above, plus search, pcap download and the §4 writes on alerts, incidents and asset notes |
| admin | Everything, including suppressions and watchlists |

The backend holds one read key and one write key and records the analyst in its own audit log.
Search and pcap download are expensive or sensitive, so they should be logged on the backend side too.

---

## 7. Detectors (`detector`)

`GET /api/detections` is the live list. As of this writing:

`suricata`, `zeek`, `traffic_capture`, `kali_scan`, `port_scanner`, `arp_discovery`, `l2_watch`,
`login_monitor`, `osquery`, `aide`, `chkrootkit`, `vlan_segmentation`, `ad_inventory`,
`malware_detector`, `phishing_detector`, `nikto`, `whatweb`, `correlation` (incidents),
`service_watchdog`, `source_health`, `disk_space_check`, `system_updates`, `soc_doctor`,
`code_freshness`, `selftest`.

The detectors from `service_watchdog` onward watch the Kali itself.

---

## 8. Changes since the copy in ERA-SOC (`SOC-Back/docs/kali/API_SPEC_EN.md`)

- The old copy said "GET only, one shared token". Today there are per-user keys with `read` and `write`
  roles, and write endpoints (§4).
- New since that copy: `status_since`, `status_actor`, `status_note`, pcap download, incidents and their
  graph, entities and their graph, activity, search, suppressions, watchlists, playbooks, metrics,
  sources, detections, the MITRE matrix, reports, and assets.
- New keys in `details`: `identity` (Active Directory), `entities`, `incident_id`, `threat_intel`,
  `source_role`, `source_is_self`.

---

## 9. HTTPS, and access only from the backend

**In place (2026-09-24):**
- `https://10.69.0.40:8443` serves the same API over TLS 1.2+.
- The certificate is signed by a small private CA made on the Kali (`deploy/make_api_cert.sh`). It is
  valid for `kali2`, `kali2.era.local`, `10.69.0.40` and `127.0.0.1`.
- **The backend trusts the CA file**, not the certificate itself: `/etc/sentinel-soc/tls/ca.pem`. That
  file is public and safe to copy. Renewing the API certificate (`make_api_cert.sh --renew`, every 825 days)
  then needs no change on the backend.
- The keys never leave the Kali.
- `scripts/cert_expiry.py` (daily, `soc-cert-expiry.timer`) alerts at 30 days before expiry (medium) and 7 days
  (critical, pushed to the phone), for `api.pem`, `ca.pem` and the certificate the HTTPS API actually serves.

**Switch-over, without stopping the alert flow:**
1. The Kali serves both: 8080 (HTTP) and 8443 (HTTPS). *(done)*
2. The backend puts `ca.pem` in its `kali-ca/` directory and sets `KALI_API_CA_CERT=/kali-ca/ca.pem` and
   `KALI_API_URL=https://10.69.0.40:8443` in Dokploy, then redeploys.
3. Check that the backend polls 8443 (the Kali journal: `journalctl -u soc-api-tls`) and that new alerts
   still reach the dashboard.
4. Only then: close 8080, and let the firewall accept 8443 from `10.69.0.80` (the backend) and the Kali
   itself only.
