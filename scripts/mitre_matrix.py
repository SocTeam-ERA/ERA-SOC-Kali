#!/usr/bin/env python3
"""
mitre_matrix.py -- the ATT&CK coverage matrix (GET /api/mitre).

Sentinel's "MITRE ATT&CK" blade and Splunk's ES "Security Posture" answer one question for a
security manager: which attacker techniques would we notice, and which would we not? This does the
same for this appliance, and adds the part that makes it useful for planning: for every technique we
do NOT cover, or cover only partly, it says which missing data source is the reason.

Three statuses per technique:
  covered  a detector here can tag it, and it has the data it needs to see it.
  limited  a detector exists but is starved: it sees only this appliance (a login monitor that
           watches Kali's own SSH, not the domain controllers) or only broadcast traffic (no mirror
           port). The technique is on the map, but an attack elsewhere on the network would pass.
  gap      no detector, and the entry says what data would be needed to build one.

The catalog of gaps is a curated list of the techniques that matter most for a Windows domain with
Microsoft 365, NOT all of ATT&CK (which has hundreds and mostly does not apply here), so the coverage
percentage is "of the techniques we chose to track". Adding one is one row in GAPS.

The data-source keys map onto the request sent to IT (docs/IT_REQUEST_2026-09-23_EN.md):
  span (request A), dc_events (B), dns_logs / firewall_logs / m365 (C), endpoint (optional, later).

Read-only: derives everything from mitre_tags.py and the alert history.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Set

import mitre_tags

TACTICS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
           "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
           "Command and Control", "Exfiltration", "Impact"]

# What each missing data source is, which IT request it belongs to, and what it unlocks.
DATA_SOURCES: Dict[str, Dict[str, str]] = {
    "span": {"label": "Mirror (SPAN) port", "request": "A",
             "why": "Without a mirror port Kali sees only broadcast and multicast, not the conversations between machines."},
    "dc_events": {"label": "Domain controller Windows event logs", "request": "B",
                  "why": "Account attacks are recorded as events on the domain controller, not on the network."},
    "dns_logs": {"label": "DNS server query logs", "request": "C",
                 "why": "Shows which internal machine asked for a malicious or tunnelled name."},
    "firewall_logs": {"label": "Firewall / VPN logs", "request": "C",
                      "why": "Shows outside scanning, blocked traffic and remote-access logins."},
    "m365": {"label": "Microsoft 365 / Entra sign-in and audit logs", "request": "C",
             "why": "Shows password attacks and mailbox abuse against cloud accounts."},
    "endpoint": {"label": "Endpoint telemetry (Sysmon / osquery on PCs and servers)", "request": "optional",
                 "why": "Process, registry and file activity on machines other than this appliance."},
}

# Techniques the detectors already tag, whose data is incomplete today. technique -> data sources.
LIMITED_BY: Dict[str, List[str]] = {
    "T1046": ["span"], "T1040": ["span"], "T1071": ["span"], "T1071.004": ["span", "dns_logs"],
    "T1090.003": ["span"], "T1190": ["span"], "T1498": ["span"],
    "T1110": ["dc_events"], "T1110.001": ["dc_events"], "T1078": ["dc_events"],
    "T1566": ["m365"],
    "T1053.003": ["endpoint"], "T1543.002": ["endpoint"], "T1548.001": ["endpoint"], "T1098": ["endpoint"],
    "T1098.004": ["endpoint"], "T1574.006": ["endpoint"],
}

# Techniques with no detector yet: id -> (name, tactics, data sources needed, what it would look for).
GAPS: Dict[str, tuple] = {
    "T1595":     ("Active Scanning", ["Reconnaissance"], ["firewall_logs"],
                  "Repeated probes from outside addresses at the firewall."),
    "T1133":     ("External Remote Services", ["Initial Access", "Persistence"], ["firewall_logs"],
                  "VPN or remote-access logins from unusual countries or hours."),
    "T1078.004": ("Cloud Accounts", ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"], ["m365"],
                  "Impossible-travel and risky sign-ins to Microsoft 365."),
    "T1059.001": ("PowerShell", ["Execution"], ["endpoint"],
                  "Encoded or download-and-run PowerShell on Windows machines."),
    "T1053.005": ("Scheduled Task", ["Execution", "Persistence", "Privilege Escalation"], ["dc_events", "endpoint"],
                  "New scheduled tasks on Windows (event 4698)."),
    "T1136.002": ("Domain Account", ["Persistence"], ["dc_events"],
                  "A domain account created outside normal provisioning (event 4720)."),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["Persistence", "Privilege Escalation"], ["endpoint"],
                  "New autorun entries on Windows machines."),
    "T1484":     ("Domain or Tenant Policy Modification", ["Defense Evasion", "Privilege Escalation"], ["dc_events"],
                  "Group Policy changed by an unexpected account (event 5136)."),
    "T1070.001": ("Clear Windows Event Logs", ["Defense Evasion"], ["dc_events", "endpoint"],
                  "The security log cleared (event 1102), a classic sign of an attacker covering tracks."),
    "T1562.001": ("Disable or Modify Tools", ["Defense Evasion"], ["endpoint"],
                  "Antivirus or endpoint agent stopped on a machine."),
    "T1550.002": ("Pass the Hash", ["Defense Evasion", "Lateral Movement"], ["dc_events"],
                  "NTLM logons that do not match how the account normally signs in."),
    "T1110.003": ("Password Spraying", ["Credential Access"], ["dc_events", "m365"],
                  "One source failing against many accounts (events 4625 / 4771, Entra sign-ins)."),
    "T1558.003": ("Kerberoasting", ["Credential Access"], ["dc_events"],
                  "Bursts of service-ticket requests with weak encryption (event 4769)."),
    "T1003.006": ("DCSync", ["Credential Access"], ["dc_events"],
                  "Directory replication requested by something that is not a domain controller (event 4662)."),
    "T1003.001": ("LSASS Memory", ["Credential Access"], ["endpoint"],
                  "A process reading the memory of the Windows credential process."),
    "T1528":     ("Steal Application Access Token", ["Credential Access"], ["m365"],
                  "Suspicious OAuth consent grants in Microsoft 365."),
    "T1621":     ("Multi-Factor Authentication Request Generation", ["Credential Access"], ["m365"],
                  "A flood of MFA prompts against one user (MFA fatigue)."),
    "T1018":     ("Remote System Discovery", ["Discovery"], ["span"],
                  "One internal machine sweeping others."),
    "T1087.002": ("Domain Account", ["Discovery"], ["dc_events", "endpoint"],
                  "Bulk directory queries listing accounts and groups."),
    "T1135":     ("Network Share Discovery", ["Discovery"], ["span"],
                  "One machine enumerating the file shares of many others."),
    "T1210":     ("Exploitation of Remote Services", ["Lateral Movement"], ["span"],
                  "Exploit signatures between internal machines."),
    "T1570":     ("Lateral Tool Transfer", ["Lateral Movement"], ["span"],
                  "Executables copied between machines over SMB."),
    "T1114.003": ("Email Forwarding Rule", ["Collection"], ["m365"],
                  "A hidden inbox rule forwarding mail outside the company."),
    "T1572":     ("Protocol Tunneling", ["Command and Control"], ["span", "dns_logs"],
                  "Long or random-looking DNS names, unusual tunnelled traffic."),
    "T1048":     ("Exfiltration Over Alternative Protocol", ["Exfiltration"], ["span", "firewall_logs"],
                  "Large transfers over DNS, ICMP or uncommon ports."),
    "T1041":     ("Exfiltration Over C2 Channel", ["Exfiltration"], ["span"],
                  "Large outbound volume to one external address."),
    "T1567":     ("Exfiltration Over Web Service", ["Exfiltration"], ["firewall_logs", "m365"],
                  "Uploads to personal cloud storage."),
    "T1486":     ("Data Encrypted for Impact", ["Impact"], ["endpoint", "span"],
                  "Mass file renames or SMB writes typical of ransomware."),
}


def _alerts_30d() -> Counter:
    import soc_views
    cutoff = time.time() - 30 * 86400
    seen: Counter = Counter()
    for r in soc_views._history():
        if r["t"] >= cutoff:
            for t in r["mitre"]:
                seen[t["technique"]] += 1
    return seen


def _technique(tid: str, name: str, status: str, **extra: Any) -> Dict[str, Any]:
    return {"technique": tid, "name": name, "status": status, **extra}


def matrix() -> Dict[str, Any]:
    cov = mitre_tags.coverage_map()
    seen = _alerts_30d()
    bases: Dict[str, Set[str]] = defaultdict(set)
    for _det, _rx, techs in mitre_tags._TITLE_RULES:
        for tid, basis in techs:
            bases[tid].add(basis)
    for _rx, techs in mitre_tags._AIDE_PATH_RULES:
        for tid, basis in techs:
            bases[tid].add(basis)
    for tid in mitre_tags._PORT_TECHNIQUES.values():
        bases[tid].add("exposure")

    by_tactic: Dict[str, List[Dict[str, Any]]] = {t: [] for t in TACTICS}
    unique: Dict[str, Dict[str, Any]] = {}

    for tid, detectors in sorted(cov.items()):
        name, tactics = mitre_tags.TECHNIQUES[tid]
        limited = LIMITED_BY.get(tid, [])
        entry = _technique(
            tid, name, "limited" if limited else "covered", detectors=detectors,
            evidence=("observed" if "observed" in bases[tid] else "exposure"),
            alerts_30d=seen[tid], limited_by=limited)
        unique[tid] = entry
        for tac in tactics:
            by_tactic.setdefault(tac, []).append(entry)

    for tid, (name, tactics, needs, looks_for) in sorted(GAPS.items()):
        if tid in cov:               # a detector was added since this row was written: it is no longer a gap
            continue
        entry = _technique(tid, name, "gap", detectors=[], alerts_30d=0, needs=needs, would_detect=looks_for)
        unique[tid] = entry
        for tac in tactics:
            by_tactic.setdefault(tac, []).append(entry)

    order = {"covered": 0, "limited": 1, "gap": 2}
    tactics_out = []
    for tac in TACTICS:
        rows = sorted(by_tactic.get(tac, []), key=lambda e: (order[e["status"]], e["technique"]))
        tactics_out.append({"tactic": tac, "count": len(rows),
                            "covered": sum(1 for e in rows if e["status"] == "covered"),
                            "limited": sum(1 for e in rows if e["status"] == "limited"),
                            "gap": sum(1 for e in rows if e["status"] == "gap"),
                            "techniques": rows})

    # what each data source would unlock: gaps that need it, and limited techniques it would complete
    sources_out = []
    for key, meta in DATA_SOURCES.items():
        gaps = sorted(t for t, e in unique.items() if e["status"] == "gap" and key in e["needs"])
        limited = sorted(t for t, e in unique.items() if e["status"] == "limited" and key in e["limited_by"])
        sources_out.append({"key": key, **meta, "would_add": gaps, "would_complete": limited,
                            "techniques_affected": len(gaps) + len(limited)})
    sources_out.sort(key=lambda s: -s["techniques_affected"])

    counts = Counter(e["status"] for e in unique.values())
    total = len(unique)
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "scope_note": ("Tracks a curated set of techniques relevant to a Windows domain with Microsoft 365, "
                       "not all of MITRE ATT&CK. 'limited' means a detector exists but cannot see the whole "
                       "network yet (see data_sources)."),
        "summary": {
            "techniques_tracked": total,
            "covered": counts["covered"], "limited": counts["limited"], "gap": counts["gap"],
            "with_alerts_30d": sum(1 for e in unique.values() if e["alerts_30d"] > 0),
            "covered_pct": round(100 * counts["covered"] / total) if total else 0,
            "covered_or_limited_pct": round(100 * (counts["covered"] + counts["limited"]) / total) if total else 0,
        },
        "data_sources": sources_out,
        "tactics": tactics_out,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(matrix()["summary"], indent=2))
