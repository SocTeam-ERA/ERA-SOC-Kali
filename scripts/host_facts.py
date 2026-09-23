#!/usr/bin/env python3
"""
host_facts.py
-------------
What each 4-hourly nmap scan already learns about a host and used to throw away.

The service scan runs `-O` (operating system) and `-sC` (nmap's default scripts), and
on Windows machines those return a lot: the exact build number and the computer and
domain names (rdp-ntlm-info), whether SMB signing is required (smb2-security-mode),
the NetBIOS name (nbstat). nmap_to_alerts.py read none of it -- it only looked at open
ports and vulnerability scripts -- so it was collected every 4 hours, 286 hosts at a
time, and discarded. Measured 2026-09-23 on one scan: 281 of 286 hosts had an OS guess,
50 had RDP NTLM info, 23 reported SMB signing, and 12 of those 23 did not require it.

This module only reads the XML the scan already produced; it sends nothing to any host.
It does two things with it:
  * extract(): the facts, kept in the asset inventory (soc_core.record_asset_scan_facts);
  * findings(): two things worth an alert -- SMB signing not required (a machine that will
    accept a relayed NTLM authentication), and a Windows build that is past its end of
    support (no more security fixes).

Honest limits, stated in the alerts too: nmap's OS guess is approximate and is only stored,
never alerted on; a Windows build number from RDP is exact but says nothing about whether an
extended-support contract covers it; and a build shared by a client and a server edition
(Windows 10 1607 and Server 2016, 1809 and Server 2019, ...) is skipped rather than guessed.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

# Windows build -> (name, date support ended for the LATEST-ending edition). Using the last
# edition to lose support (Enterprise/Education, or the Server SKU's extended support) means
# a finding never fires for a machine that some edition still covers. Dates follow Microsoft's
# lifecycle pages; verify before quoting one to management. Builds shared with a supported
# Windows Server release are left out on purpose (14393, 17763, 20348).
_WINDOWS: Dict[str, tuple] = {
    "5.1.2600":   ("Windows XP", "2014-04-08"),
    "5.2.3790":   ("Windows Server 2003", "2015-07-14"),
    "6.0.6002":   ("Windows Vista / Server 2008", "2020-01-14"),
    "6.1.7601":   ("Windows 7 / Server 2008 R2", "2023-01-10"),
    "6.2.9200":   ("Windows 8 / Server 2012", "2023-10-10"),
    "6.3.9600":   ("Windows 8.1 / Server 2012 R2", "2023-10-10"),
    "10.0.10240": ("Windows 10 1507", "2017-05-09"),
    "10.0.10586": ("Windows 10 1511", "2018-10-09"),
    "10.0.15063": ("Windows 10 1703", "2019-10-08"),
    "10.0.16299": ("Windows 10 1709", "2020-10-13"),
    "10.0.17134": ("Windows 10 1803", "2021-05-11"),
    "10.0.18362": ("Windows 10 1903", "2020-12-08"),
    "10.0.18363": ("Windows 10 1909", "2022-05-10"),
    "10.0.19041": ("Windows 10 2004", "2021-12-14"),
    "10.0.19042": ("Windows 10 20H2", "2023-05-09"),
    "10.0.19043": ("Windows 10 21H1", "2022-12-13"),
    "10.0.19044": ("Windows 10 21H2", "2024-06-11"),
    "10.0.19045": ("Windows 10 22H2", "2025-10-14"),
    "10.0.22000": ("Windows 11 21H2", "2024-10-08"),
    "10.0.22621": ("Windows 11 22H2", "2025-10-14"),
    "10.0.22631": ("Windows 11 23H2", "2026-11-10"),
}


def windows_support(product_version: Optional[str], today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """{"label", "ended", "severity"} when this Windows build is past end of support, else None
    (still supported, ambiguous, or a build this table does not know). A build whose support
    ended more than a year ago is `medium`; one that ended within the last year is `normal`."""
    m = re.match(r"^(\d+\.\d+\.\d+)", str(product_version or ""))
    entry = _WINDOWS.get(m.group(1)) if m else None
    if not entry:
        return None
    label, ended = entry
    ended_on = date.fromisoformat(ended)
    today = today or date.today()
    if ended_on >= today:
        return None
    return {"label": label, "ended": ended, "severity": "medium" if (today - ended_on).days > 365 else "normal"}


def parse_smb_signing(output: str) -> Optional[str]:
    """'required' | 'not_required' from an smb2-security-mode / smb-security-mode script output."""
    low = (output or "").lower()
    if "signing enabled and required" in low or "message_signing: required" in low:
        return "required"
    if "enabled but not required" in low or "message_signing: disabled" in low or "message_signing: supported" in low:
        return "not_required"
    return None


def extract(xml_path: Path) -> Dict[str, Dict[str, Any]]:
    """{ip: facts} for every host in an nmap XML that yielded at least one of them."""
    out: Dict[str, Dict[str, Any]] = {}
    try:
        root = ET.parse(xml_path).getroot()
    except (ET.ParseError, OSError):
        return out
    for host in root.findall("host"):
        addr = host.find("address[@addrtype='ipv4']")
        if addr is None:
            continue
        facts: Dict[str, Any] = {}
        match = host.find("os/osmatch")
        if match is not None and match.get("name"):
            facts["os"] = {"name": match.get("name"), "accuracy": int(match.get("accuracy") or 0)}
        for script in host.iter("script"):
            sid, output = script.get("id"), script.get("output") or ""
            if sid == "rdp-ntlm-info":
                elems = {e.get("key"): (e.text or "") for e in script.findall("elem")}
                win = {k: elems[k] for k in ("Product_Version", "NetBIOS_Computer_Name", "DNS_Computer_Name",
                                              "DNS_Domain_Name", "NetBIOS_Domain_Name") if elems.get(k)}
                if win:
                    facts["windows"] = win
            elif sid in ("smb2-security-mode", "smb-security-mode") and "smb_signing" not in facts:
                signing = parse_smb_signing(output)
                if signing:
                    facts["smb_signing"] = signing
            elif sid == "nbstat":
                m = re.search(r"NetBIOS name:\s*([^,\s]+)", output)
                if m:
                    facts["netbios_name"] = m.group(1)
        if facts:
            out[addr.get("addr")] = facts
    return out


def findings(facts_by_ip: Dict[str, Dict[str, Any]], hostnames: Dict[str, Optional[str]],
             today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Alert kwargs (plus `_key`, as nmap_to_alerts.parse_xml() builds them) for what deserves one."""
    out: List[Dict[str, Any]] = []
    for ip, f in sorted(facts_by_ip.items()):
        name = (f.get("windows") or {}).get("DNS_Computer_Name") or (f.get("windows") or {}).get("NetBIOS_Computer_Name") \
            or f.get("netbios_name") or hostnames.get(ip)
        if f.get("smb_signing") == "not_required":
            out.append(dict(
                type="vuln", severity="normal", title=f"SMB signing not required on {ip}",
                source_ip=ip, hostname=name, detector="kali_scan",
                description=("This machine accepts SMB connections without requiring message signing, so a relayed NTLM "
                             "authentication (NTLM relay) could be accepted by it. Common as the default on Windows "
                             "workstations and file servers; domain controllers normally require signing. Consider "
                             "requiring it by group policy."),
                details={"script": "smb2-security-mode", "smb_signing": "not_required"},
                _key=f"{ip}:smb-signing"))
        win = f.get("windows") or {}
        support = windows_support(win.get("Product_Version"), today)
        if support:
            out.append(dict(
                type="vuln", severity=support["severity"],
                title=f"Unsupported Windows on {ip}: {support['label']} (build {win['Product_Version']})",
                source_ip=ip, hostname=name, detector="kali_scan",
                description=(f"{support['label']} stopped receiving security updates on {support['ended']} (the last "
                             "edition to lose support; earlier for some). The build number is read from the machine itself "
                             "over RDP, so it is exact -- but a paid Extended Security Updates contract, if the machine has "
                             "one, would still cover it."),
                details={"script": "rdp-ntlm-info", "product_version": win["Product_Version"],
                         "support_ended": support["ended"], "computer_name": name},
                _key=f"{ip}:windows-support"))
    return out
