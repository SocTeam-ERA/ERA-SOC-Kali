#!/usr/bin/env python3
"""
mitre_tags.py -- MITRE ATT&CK tags for alerts.

emit_alert() (soc_core.py) calls tag(record) and stores the result under
details["mitre"], a list of:

    {"technique": "T1110.001", "name": "Password Guessing",
     "tactics": ["Credential Access"], "basis": "observed"}

basis says how strong the link is:
  observed  the alert is direct evidence of the behavior (a brute-force
            burst, a scan seen on the wire, a rogue device appearing).
  exposure  the alert shows a condition that enables the technique but not
            that anyone used it (a newly opened RDP port, cleartext Telnet).

Only mappings that are defensible are listed. Alerts with no honest ATT&CK
equivalent (expired certificates, capture loss, VLAN gaps, disk space...) get
no tag rather than a stretched one. To add a mapping: add the technique to
TECHNIQUES if it is new, then add a row to _TITLE_RULES.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# id -> (name, tactics)
TECHNIQUES: Dict[str, tuple] = {
    "T1040":     ("Network Sniffing", ["Credential Access", "Discovery"]),
    "T1046":     ("Network Service Discovery", ["Discovery"]),
    "T1053.003": ("Cron", ["Execution", "Persistence", "Privilege Escalation"]),
    "T1071":     ("Application Layer Protocol", ["Command and Control"]),
    "T1071.004": ("DNS", ["Command and Control"]),
    "T1078":     ("Valid Accounts", ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]),
    "T1090.003": ("Multi-hop Proxy", ["Command and Control"]),
    "T1098":     ("Account Manipulation", ["Persistence", "Privilege Escalation"]),
    "T1098.004": ("SSH Authorized Keys", ["Persistence", "Privilege Escalation"]),
    "T1110":     ("Brute Force", ["Credential Access"]),
    "T1110.001": ("Password Guessing", ["Credential Access"]),
    "T1190":     ("Exploit Public-Facing Application", ["Initial Access"]),
    "T1200":     ("Hardware Additions", ["Initial Access"]),
    "T1498":     ("Network Denial of Service", ["Impact"]),
    "T1543.002": ("Systemd Service", ["Persistence", "Privilege Escalation"]),
    "T1548.001": ("Setuid and Setgid", ["Privilege Escalation", "Defense Evasion"]),
    "T1566":     ("Phishing", ["Initial Access"]),
    "T1574.006": ("Dynamic Linker Hijacking", ["Persistence", "Privilege Escalation", "Defense Evasion"]),
    "T1021.001": ("Remote Desktop Protocol", ["Lateral Movement"]),
    "T1021.002": ("SMB/Windows Admin Shares", ["Lateral Movement"]),
    "T1021.004": ("SSH", ["Lateral Movement"]),
    "T1021.005": ("VNC", ["Lateral Movement"]),
    "T1021.006": ("Windows Remote Management", ["Lateral Movement"]),
}

# (detector, title regex, [(technique, basis), ...]); detector None = any.
_TITLE_RULES: List[tuple] = [
    ("arp_discovery",  r"^New device on VLAN",                      [("T1200", "observed")]),
    ("login_monitor",  r"^Brute-force:",                            [("T1110", "observed")]),
    ("login_monitor",  r"^Failed login from unknown IP",            [("T1110.001", "observed")]),
    ("login_monitor",  r"^Successful login after \d+ failures",     [("T1110", "observed"), ("T1078", "observed")]),
    ("login_monitor",  r"^Login from NEW IP",                       [("T1078", "observed")]),
    ("zeek",           r"^SSH::Password_Guessing",                  [("T1110.001", "observed")]),
    ("traffic_capture", r"^Port scan on the wire",                  [("T1046", "observed")]),
    ("traffic_capture", r"^Cleartext protocol",                     [("T1040", "exposure")]),
    ("traffic_capture", r"^Traffic to/from known-bad IP",           [("T1071", "observed")]),
    ("traffic_capture", r"^Suspicious DNS query",                   [("T1071.004", "observed")]),
    ("suricata",       r"^ET SCAN\b",                               [("T1046", "observed")]),
    ("suricata",       r"^ET (EXPLOIT|WEB_SERVER|WEB_SPECIFIC_APPS)\b", [("T1190", "observed")]),
    ("suricata",       r"Tor Usage",                                [("T1090.003", "observed")]),
    ("suricata",       r"^LOCAL (DDoS|possible outbound DDoS)",     [("T1498", "observed")]),
    ("chkrootkit",     r"^Unrecognized packet sniffer",             [("T1040", "observed")]),
    ("osquery",        r"^setuid/setgid binary",                    [("T1548.001", "observed")]),
    ("osquery",        r"^Scheduled task:",                         [("T1053.003", "observed")]),
    ("phishing_detector", r"^Phishing indicators",                  [("T1566", "observed")]),
]
_TITLE_RULES = [(d, re.compile(rx), t) for d, rx, t in _TITLE_RULES]

# AIDE: only paths where a change means something specific. Anything else
# (Zeek/PowerShell install dirs, package churn) is left untagged.
_AIDE_PATH_RULES = [
    (re.compile(r"^/(etc/cron|var/spool/cron)"),                      [("T1053.003", "observed")]),
    (re.compile(r"^/(etc|lib|usr/lib)/systemd/"),                     [("T1543.002", "observed")]),
    (re.compile(r"(^|/)\.ssh/authorized_keys"),                       [("T1098.004", "observed")]),
    (re.compile(r"^/etc/(passwd|shadow|group|gshadow|sudoers)\b"),    [("T1098", "observed")]),
    (re.compile(r"^/etc/ld\.so\.(preload|conf)"),                     [("T1574.006", "observed")]),
]
_AIDE_TITLE = re.compile(r"^File integrity: (\S+)")

# Remote-access ports: a newly opened one is attack surface for lateral movement.
_PORT_TECHNIQUES = {
    ("tcp", 22): "T1021.004", ("tcp", 3389): "T1021.001", ("tcp", 5900): "T1021.005",
    ("tcp", 445): "T1021.002", ("tcp", 5985): "T1021.006", ("tcp", 5986): "T1021.006",
}
_NEW_PORT_TITLE = re.compile(r"^(NEW open port|Open port) ")


def _entry(technique: str, basis: str) -> Dict[str, Any]:
    name, tactics = TECHNIQUES[technique]
    return {"technique": technique, "name": name, "tactics": list(tactics), "basis": basis}


def tag(record: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the ATT&CK tags for an alert record (empty list if none apply)."""
    title = record.get("title") or ""
    detector = record.get("detector") or ""
    found: List[tuple] = []

    for det, rx, techs in _TITLE_RULES:
        if (det is None or det == detector) and rx.search(title):
            found.extend(techs)

    if detector == "aide":
        m = _AIDE_TITLE.match(title)
        if m:
            for rx, techs in _AIDE_PATH_RULES:
                if rx.search(m.group(1)):
                    found.extend(techs)

    if detector in ("kali_scan", "port_scanner") and _NEW_PORT_TITLE.match(title):
        d = record.get("details") or {}
        tid: Optional[str] = _PORT_TECHNIQUES.get((d.get("proto"), d.get("port")))
        if tid:
            found.append((tid, "exposure"))

    out, seen = [], set()
    for technique, basis in found:
        if technique not in seen:
            seen.add(technique)
            out.append(_entry(technique, basis))
    return out


def coverage_map() -> Dict[str, List[str]]:
    """technique id -> sorted detectors that can produce a tag for it."""
    out: Dict[str, set] = {}
    for det, _rx, techs in _TITLE_RULES:
        for t, _basis in techs:
            out.setdefault(t, set()).add(det or "*")
    for _rx, techs in _AIDE_PATH_RULES:
        for t, _basis in techs:
            out.setdefault(t, set()).add("aide")
    for tid in _PORT_TECHNIQUES.values():
        out.setdefault(tid, set()).update({"kali_scan", "port_scanner"})
    return {t: sorted(d) for t, d in out.items()}
