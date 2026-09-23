#!/usr/bin/env python3
"""
ad_identity.py
--------------
Who and what an alert is about, according to Active Directory: soc_core.emit_alert() calls
identity() for every alert and stores the answer under details["identity"], so the dashboard
(and the backend it is forwarded to) can show "Chantelle-PC -- Calgary/Accounting, Windows 10
22H2, unsupported" or "jidris -- James Idris, Calgary/IT, Domain Admins" instead of a bare
address or login name.

Sources, all local files (no LDAP call per alert):
  * data/ad_inventory.json -- written daily by ad_inventory.py; cached here until it changes;
  * data/assets.json        -- the NetBIOS name the network scan learned for each IP
                               (scan_facts, see host_facts.py), to go from an IP to a computer.

Resolution, from the alert's details.entities (alert_context.py):
  * ip   -> NetBIOS name from the scan -> AD computer; if the scan names a Windows machine AD
            does not know, it is reported as {"name", "in_domain": false};
  * host -> AD computer by name, DNS name or first label;
  * user -> AD user by sAMAccountName (or DOMAIN\\user, user@domain) -- except for detectors
            that watch this appliance itself (their users are local Linux accounts that may
            merely share a name with someone in AD).
Nothing found (no inventory yet, a non-Windows device, an external IP) means no identity key.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import soc_core

# Detectors whose user and host fields describe this Kali appliance, not the domain.
LOCAL_DETECTORS = {"login_monitor", "osquery", "aide", "chkrootkit", "service_watchdog", "disk_space_check",
                   "soc_doctor", "source_health", "system_updates", "selftest"}
MAX_EACH = 5   # an alert about a /24 sweep must not carry 250 identities

_cache: Dict[str, Any] = {"sig": None, "idx": None}


def _sig(*paths) -> tuple:
    out = []
    for p in paths:
        try:
            st = p.stat()
            out.append((st.st_mtime_ns, st.st_size))
        except OSError:
            out.append(None)
    return tuple(out)


def _index() -> Optional[Dict[str, Any]]:
    inv_path, assets_path = soc_core.DATA_DIR / "ad_inventory.json", soc_core.DATA_DIR / "assets.json"
    sig = _sig(inv_path, assets_path)
    if sig[0] is None:
        return None
    if _cache["sig"] == sig:
        return _cache["idx"]
    try:
        inv = json.loads(inv_path.read_text())
    except (OSError, ValueError):
        return None
    comps = inv.get("computers", {})
    by_name: Dict[str, str] = {}
    for key, c in comps.items():
        by_name[key.upper()] = key
        if c.get("dns"):
            by_name[str(c["dns"]).upper()] = key
    priv: Dict[str, List[str]] = {}
    for group, members in (inv.get("privileged") or {}).items():
        for m in members:
            priv.setdefault(m.lower(), []).append(group)
    ip_name: Dict[str, str] = {}
    for rec in soc_core.load_assets().values():
        sf = rec.get("scan_facts") or {}
        name = (sf.get("windows") or {}).get("NetBIOS_Computer_Name") or sf.get("netbios_name")
        if name and rec.get("ip"):
            ip_name[rec["ip"]] = str(name).upper()
    idx = {"computers": comps, "by_name": by_name, "users": inv.get("users", {}), "priv": priv,
           "ip_name": ip_name, "generated": inv.get("generated")}
    _cache.update(sig=sig, idx=idx)
    return idx


def _computer(idx: Dict[str, Any], key: str) -> Dict[str, Any]:
    c = idx["computers"][key]
    s = c.get("support") or {}
    out = {"name": c["name"], "in_domain": True, "ou": c.get("ou") or None, "os": c.get("os"),
           "build": c.get("build"), "enabled": c.get("enabled"), "last_logon": c.get("last_logon")}
    if s:
        out["os_support"] = s.get("status")
        out["os_support_ends"] = s.get("ends")
    return out


def _user(idx: Dict[str, Any], key: str) -> Dict[str, Any]:
    u = idx["users"][key]
    return {"sam": u["sam"], "name": u.get("display"), "ou": u.get("ou") or None, "enabled": u.get("enabled"),
            "last_logon": u.get("last_logon"), "privileged_groups": idx["priv"].get(key, [])}


def find_computer(idx: Dict[str, Any], name: str) -> Optional[str]:
    n = str(name or "").strip().upper().rstrip(".")
    return idx["by_name"].get(n) or idx["by_name"].get(n.split(".")[0])


def identity(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    idx = _index()
    if not idx:
        return None
    local = (record.get("detector") or "") in LOCAL_DETECTORS
    ents = (record.get("details") or {}).get("entities") or []
    computers: Dict[str, Dict[str, Any]] = {}
    users: Dict[str, Dict[str, Any]] = {}
    for e in ents:
        kind, value = e.get("type"), str(e.get("value") or "")
        if kind == "ip" and not local:
            name = idx["ip_name"].get(value)
            if not name:
                continue
            key = find_computer(idx, name)
            if key:
                computers.setdefault(key, {**_computer(idx, key), "ip": value})
            else:
                computers.setdefault(name, {"name": name, "in_domain": False, "ip": value})
        elif kind == "host" and not local:
            key = find_computer(idx, value)
            if key:
                computers.setdefault(key, _computer(idx, key))
        elif kind == "user" and not local:
            sam = value.split("\\")[-1].split("@")[0].lower()
            if sam in idx["users"]:
                users.setdefault(sam, _user(idx, sam))
    if not computers and not users:
        return None
    out: Dict[str, Any] = {"as_of": idx["generated"]}
    if computers:
        out["computers"] = list(computers.values())[:MAX_EACH]
    if users:
        out["users"] = list(users.values())[:MAX_EACH]
    return out
