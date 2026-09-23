#!/usr/bin/env python3
"""
ad_changes.py
-------------
Changes to the parts of Active Directory that let an attacker control every machine or keep
control quietly. Read with the SOC's read-only account every 15 minutes (the quick check of
ad_inventory.py --privileged-only) and at the daily inventory; compared with the last reading:

  * Group Policy objects created, deleted or modified (versionNumber moves on every edit), and
    GPO links added to / removed from an OU or the domain. Editing or linking a GPO is how
    ransomware is pushed to every PC at once (T1484.001).
  * Domain trusts added, removed or changed (T1484.002).
  * The permissions on AdminSDHolder -- the template AD copies onto every admin account each
    hour; a new entry there is a durable, hidden backdoor to all of them.
  * The permissions on the domain object itself, and in particular who holds the replication
    rights that let an account copy every password hash from a DC ("DCSync", T1003.006).

Permissions are compared as the set of access-control entries (parsed with impacket), not by
whenChanged: the domain object's whenChanged moves every day for unrelated reasons.

The first reading is the baseline; it raises one informational alert listing who can DCSync
(expected: the DCs, the admin groups and the Microsoft 365 sync account MSOL_*).
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, List, Optional, Tuple

GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
FULL_CONTROL = 0xF01FF
WRITE_DACL = 0x40000
WRITE_OWNER = 0x80000
CONTROL_ACCESS = 0x100                                       # extended rights

WELL_KNOWN = {"S-1-5-18": "SYSTEM", "S-1-5-9": "Enterprise Domain Controllers", "S-1-1-0": "Everyone",
              "S-1-5-11": "Authenticated Users", "S-1-5-10": "SELF", "S-1-3-0": "Creator Owner",
              "S-1-5-32-544": "Administrators", "S-1-5-32-554": "Pre-Windows 2000 Compatible Access",
              "S-1-5-32-548": "Account Operators", "S-1-5-32-560": "Windows Authorization Access Group",
              "S-1-5-32-561": "Terminal Server License Servers", "S-1-5-32-557": "Incoming Forest Trust Builders",
              "S-1-5-32-551": "Backup Operators"}
# Domain RIDs that hold replication / full control on the domain object by default
DEFAULT_RIDS = {"498", "512", "516", "519", "521"}           # Enterprise RODCs, Domain Admins, DCs, Enterprise Admins, RODCs

_GPLINK = re.compile(r"\[LDAP://cn=(\{[0-9a-f-]+\}),[^;\]]*;(\d)\]", re.I)


# --------------------------------------------------------------------------- #
#  Reading
# --------------------------------------------------------------------------- #

def _first(v):
    return (v[0] if v else None) if isinstance(v, list) else v


def parse_aces(raw: bytes) -> List[str]:
    """DACL of a raw nTSecurityDescriptor -> sorted 'TYPE|SID|MASK|OBJECTTYPE' strings (inherited ones kept)."""
    from impacket.ldap import ldaptypes
    from impacket.uuid import bin_to_string
    if not raw:
        return []
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
    out = []
    for ace in (sd["Dacl"].aces if sd["Dacl"] else []):
        body = ace["Ace"]
        obj = ""
        if "OBJECT" in ace["TypeName"] and body["Flags"] & 0x1:
            obj = bin_to_string(body["ObjectType"]).lower()
        out.append(f"{ace['TypeName'].replace('_ACE', '')}|{body['Sid'].formatCanonical()}|{body['Mask']['Mask']:#x}|{obj}")
    return sorted(set(out))


def dcsync_holders(aces: List[str]) -> List[str]:
    """SIDs allowed to replicate secrets from the domain, or to grant themselves that right."""
    sids = set()
    for a in aces:
        typ, sid, mask, obj = a.split("|")
        if not typ.startswith("ACCESS_ALLOWED"):
            continue
        m = int(mask, 16)
        if ((m & CONTROL_ACCESS and obj in ("", GET_CHANGES_ALL)) or (m & FULL_CONTROL) == FULL_CONTROL
                or m & (WRITE_DACL | WRITE_OWNER)):
            sids.add(sid)
    return sorted(sids)


def is_default_holder(sid: str) -> bool:
    return sid in ("S-1-5-18", "S-1-5-9", "S-1-5-32-544") or sid.rsplit("-", 1)[-1] in DEFAULT_RIDS


def parse_gplink(value: str) -> List[str]:
    """'[LDAP://cn={GUID},cn=policies,...;0][...]' -> ['{GUID}', ...] (disabled links, option 1 or 3, marked '!')."""
    return [(g.upper() if opt in ("0", "2") else "!" + g.upper()) for g, opt in _GPLINK.findall(value or "")]


def read_change_data(conn, base: str, search: Callable[[Any, str, str, List[str]], List[Dict[str, Any]]]) -> Dict[str, Any]:
    from ldap3 import BASE
    from ldap3.protocol.microsoft import security_descriptor_control

    gpos = {}
    for g in search(conn, f"CN=Policies,CN=System,{base}", "(objectClass=groupPolicyContainer)",
                    ["cn", "displayName", "versionNumber", "flags"]):
        guid = str(_first(g.get("cn")) or "").upper()
        if guid:
            gpos[guid] = {"name": str(_first(g.get("displayName")) or guid),
                          "version": int(_first(g.get("versionNumber")) or 0), "flags": int(_first(g.get("flags")) or 0)}
    links = {str(_first(o.get("distinguishedName"))): parse_gplink(str(_first(o.get("gPLink")) or ""))
             for o in search(conn, base, "(gPLink=*)", ["distinguishedName", "gPLink"])}
    trusts = {str(_first(t.get("name"))): {"direction": int(_first(t.get("trustDirection")) or 0),
                                           "type": int(_first(t.get("trustType")) or 0),
                                           "attributes": int(_first(t.get("trustAttributes")) or 0)}
              for t in search(conn, f"CN=System,{base}", "(objectClass=trustedDomain)",
                              ["name", "trustDirection", "trustType", "trustAttributes"])}
    acl = {}
    for key, dn in (("adminsdholder", f"CN=AdminSDHolder,CN=System,{base}"), ("domain", base)):
        conn.search(dn, "(objectClass=*)", BASE, attributes=["nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04))   # DACL only: readable without privilege
        raw = conn.response[0]["raw_attributes"].get("nTSecurityDescriptor", [b""])[0] if conn.response else b""
        acl[key] = parse_aces(raw)
    return {"gpos": gpos, "links": links, "trusts": trusts, "acl": acl, "dcsync": dcsync_holders(acl["domain"])}


def resolve_sids(conn, base: str, sids: List[str]) -> Dict[str, str]:
    """SID -> sAMAccountName (or a well-known name); unknown SIDs map to themselves."""
    out = {}
    for sid in sids:
        if sid in WELL_KNOWN:
            out[sid] = WELL_KNOWN[sid]
            continue
        try:
            conn.search(base, f"(objectSid={sid})", attributes=["sAMAccountName"])
            out[sid] = str(conn.entries[0].sAMAccountName) if conn.entries else sid
        except Exception:  # noqa: BLE001
            out[sid] = sid
    return out


# --------------------------------------------------------------------------- #
#  Comparing (pure)
# --------------------------------------------------------------------------- #

def change_alerts(before: Optional[Dict[str, Any]], now: Dict[str, Any], names: Dict[str, str],
                  detector: str = "ad_inventory") -> List[Dict[str, Any]]:
    """Alert kwargs for what changed between two readings. `names` maps SIDs to account names for display."""
    out: List[Dict[str, Any]] = []
    nm = lambda sid: names.get(sid, sid)  # noqa: E731

    def add(severity, title, description, **details):
        out.append(dict(type="intrusion", severity=severity, title=title, description=description,
                        detector=detector, details={**details, "source": "active_directory"}))

    if not before:
        extra = [s for s in now["dcsync"] if not is_default_holder(s)]
        add("normal", "AD change monitoring started (baseline)",
            (f"Recorded {len(now['gpos'])} GPOs, GPO links on {len(now['links'])} containers, {len(now['trusts'])} "
             "domain trust(s) and the permissions of the domain and AdminSDHolder. From now on any change raises an "
             "alert. Accounts other than the DCs and admin groups that can replicate all password hashes (DCSync) "
             f"-- confirm each is expected (the Microsoft 365 sync account MSOL_* is): "
             f"{', '.join(nm(s) for s in extra) or 'none'}."),
            dcsync_non_default=[nm(s) for s in extra])
        return out

    bg, ng = before.get("gpos", {}), now["gpos"]
    for guid in sorted(set(ng) - set(bg)):
        add("medium", f"New GPO created: {ng[guid]['name']}",
            "A Group Policy object was created. Confirm it was made on purpose and review its settings before it is linked.",
            gpo=ng[guid]["name"], guid=guid, change="created")
    for guid in sorted(set(bg) - set(ng)):
        add("medium", f"GPO deleted: {bg[guid]['name']}", "A Group Policy object was deleted.",
            gpo=bg[guid]["name"], guid=guid, change="deleted")
    for guid in sorted(set(bg) & set(ng)):
        if bg[guid]["version"] != ng[guid]["version"] or bg[guid]["flags"] != ng[guid]["flags"]:
            dc = "Domain Controllers" in ng[guid]["name"]
            add("critical" if dc else "medium", f"GPO modified: {ng[guid]['name']}",
                ("The settings of this Group Policy object changed (version "
                 f"{bg[guid]['version']} -> {ng[guid]['version']}, flags {bg[guid]['flags']} -> {ng[guid]['flags']}). "
                 "Every computer it applies to will pick the change up within about 90 minutes. If nobody in IT made "
                 "this change, treat it as an attack in progress: attackers edit GPOs to run their program on every PC."),
                gpo=ng[guid]["name"], guid=guid, change="modified",
                version_before=bg[guid]["version"], version_after=ng[guid]["version"])

    gname = lambda g: ng.get(g.lstrip("!"), bg.get(g.lstrip("!"), {"name": g})).get("name")  # noqa: E731
    bl, nl = before.get("links", {}), now["links"]
    for dn in sorted(set(bl) | set(nl)):
        old, new = set(bl.get(dn, [])), set(nl.get(dn, []))
        for g in sorted(new - old):
            if "!" + g in old or g.lstrip("!") in old:
                verb = "disabled" if g.startswith("!") else "enabled"
                add("medium", f"GPO link {verb}: {gname(g)} on {dn}", f"The link of this GPO on {dn} was {verb}.",
                    gpo=gname(g), container=dn, change=f"link_{verb}")
            else:
                add("medium", f"GPO linked: {gname(g)} on {dn}",
                    f"The GPO now applies to everything under {dn}. Confirm this was intended.",
                    gpo=gname(g), container=dn, change="linked")
        for g in sorted(old - new):
            if "!" + g in new or g.lstrip("!") in new:
                continue   # reported as enabled/disabled above
            add("normal", f"GPO unlinked: {gname(g)} from {dn}", f"The GPO no longer applies under {dn}.",
                gpo=gname(g), container=dn, change="unlinked")

    bt, nt = before.get("trusts", {}), now["trusts"]
    for t in sorted(set(nt) - set(bt)):
        add("critical", f"New domain trust: {t}",
            ("A trust with another domain was created. It lets accounts of that domain be granted access here; "
             "attackers add one to keep a way back in. Confirm with the domain admin immediately."),
            trust=t, change="added", **nt[t])
    for t in sorted(set(bt) - set(nt)):
        add("normal", f"Domain trust removed: {t}", "A trust with another domain was removed.", trust=t, change="removed")
    for t in sorted(set(bt) & set(nt)):
        if bt[t] != nt[t]:
            add("medium", f"Domain trust changed: {t}", f"Trust settings changed: {bt[t]} -> {nt[t]}.",
                trust=t, change="changed")

    b_acl, n_acl = before.get("acl", {}), now["acl"]
    if b_acl.get("adminsdholder") is not None and b_acl["adminsdholder"] != n_acl["adminsdholder"]:
        added = sorted(set(n_acl["adminsdholder"]) - set(b_acl["adminsdholder"]))
        add("critical", "AdminSDHolder permissions changed",
            ("The permission template AD copies onto every admin account changed. A new entry here gives its holder "
             "lasting control over all admins, and is a known persistence technique. New entries: "
             + ("; ".join(f"{nm(a.split('|')[1])} {a.split('|')[2]}" for a in added) or "none (entries removed)") + "."),
            added=added, change="acl")
    new_dcsync = sorted(set(now["dcsync"]) - set(before.get("dcsync", [])))
    if new_dcsync:
        add("critical", f"DCSync rights granted: {', '.join(nm(s) for s in new_dcsync)}",
            ("These accounts can now replicate every password hash in the domain from a domain controller (DCSync), "
             "or grant themselves that right. Unless this is a new domain controller or sync server, the domain is "
             "compromised."), accounts=[nm(s) for s in new_dcsync], change="dcsync")
    elif b_acl.get("domain") is not None and b_acl["domain"] != n_acl["domain"]:
        added = sorted(set(n_acl["domain"]) - set(b_acl["domain"]))
        removed = sorted(set(b_acl["domain"]) - set(n_acl["domain"]))
        add("medium", "Permissions on the domain object changed",
            (f"{len(added)} permission entries added and {len(removed)} removed on the domain object itself. None of "
             "them grants replication rights. Added: "
             + ("; ".join(f"{nm(a.split('|')[1])} {a.split('|')[2]}" for a in added[:10]) or "none") + "."),
            added=added, removed=removed, change="acl")
    return out


def check(conn, base: str, before: Optional[Dict[str, Any]], search, detector: str = "ad_inventory") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Read, resolve the SIDs worth naming, compare. Returns (alert kwargs, new reading)."""
    now = read_change_data(conn, base, search)
    sids = set(now["dcsync"])
    for key in ("adminsdholder", "domain"):
        for a in set(now["acl"][key]) - set(((before or {}).get("acl") or {}).get(key, [])):
            sids.add(a.split("|")[1])
    names = resolve_sids(conn, base, sorted(sids)) if (not before or sids - set((before or {}).get("dcsync", []))) else {}
    return change_alerts(before, now, names, detector), now
