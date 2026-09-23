#!/usr/bin/env python3
"""
ad_inventory.py
---------------
A daily read-only look at Active Directory: the one inventory in this company that is
authoritative, because every PC and account is added to it by an administrator.

Until now the SOC only learned about Windows machines from the outside -- nmap's OS guess
and the build number a PC gives out over RDP (scripts/host_facts.py). That is a guess about
the servicing family at best, and on 2026-09-23 it was doubted, then confirmed only by asking
AD. This asks AD directly, once a day, and keeps the answer in data/ad_inventory.json:

  * every computer object: OS name and exact build (operatingSystem / operatingSystemVersion,
    which the machine itself keeps up to date), enabled or not, last sign-in, OU;
  * every user account: enabled or not, last sign-in, OU (no other personal data);
  * the members (recursive) of the privileged groups.

and alerts (detector "ad_inventory") on:
  * someone added to a privileged group (critical) or removed from one (normal);
  * a new computer or user account in AD (normal: the delegated admin should recognise it);
  * a computer whose Windows version no longer gets security updates, from AD's exact build
    and edition (vuln, normal / medium after a year);
  * a Windows version that loses support within WARN_DAYS, once per release and date;
  * enabled computers and user accounts that have not signed in for STALE_DAYS (one summary
    alert when new ones join the list);
  * a Windows machine the network scan found that is NOT in the domain (medium): nobody
    joined it, so nobody manages or patches it;
  * the AD read failing, and recovering;
  * (not an alert) one line per day of headline numbers in data/ad_history.jsonl, for trends;
  * the domain weaknesses of scripts/ad_risks.py (Kerberoastable accounts, no lockout, missing
    LAPS...), when one appears or gains accounts, and a note when one is fixed.

`--privileged-only` (soc-ad-privileged.timer, every 15 minutes) re-reads only the privileged
groups and the change-sensitive objects of scripts/ad_changes.py (GPOs and their links, trusts,
AdminSDHolder and domain permissions / DCSync rights), so a new Domain Admin or an edited GPO is
noticed within minutes rather than the next morning.

The first run records the privileged members, computers and users as the baseline (one
informational alert lists the privileged members to review) and only reports current risks.

Connection: settings in /etc/sentinel-soc/ad-ldap.env (root:soc 640; never in git):
    AD_LDAP_SERVERS=10.69.0.14,10.69.0.15   tried in order
    AD_LDAP_USER=svc-soc-ldap@era.local     a plain Domain Users account: reading these
                                            attributes needs no privilege
    AD_LDAP_PASSWORD=...
    AD_BASE_DN=DC=era,DC=local
    AD_LDAP_MODE=ntlm | ldaps               default ntlm
    AD_NTLM_DOMAIN=ERA                      default: first label of the UPN's domain
    AD_LDAP_CA_FILE=/path/ca.pem            ldaps only: verify the DC certificate against it
`ntlm` binds on 389 with NTLM, so the password never crosses the wire, but the replies are
not encrypted. It is the interim mode: as of 2026-09-23 the DCs have no certificate, so 636
resets the handshake and StartTLS answers "unavailable". Once IT installs one, switch to
`ldaps` (simple bind inside TLS) and point AD_LDAP_CA_FILE at the internal CA.

Usage:
    python3 ad_inventory.py              # read AD, write the inventory, raise alerts
    python3 ad_inventory.py --dry-run    # read AD and print what WOULD be alerted; saves nothing
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from datetime import date, datetime, timedelta, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ad_changes  # noqa: E402
import ad_risks  # noqa: E402
import soc_core  # noqa: E402
from soc_core import Alert, diff_state_lock, emit_alert  # noqa: E402

ENV_FILE = Path(os.environ.get("SOC_AD_ENV", "/etc/sentinel-soc/ad-ldap.env"))
CONFIG_FILE = Path(__file__).resolve().parent.parent / "config" / "ad_inventory.json"
INVENTORY_FILE = soc_core.DATA_DIR / "ad_inventory.json"
STATE_FILE = soc_core.DATA_DIR / "ad_inventory_state.json"
# One line per day with the headline numbers, for the dashboard's trend charts.
HISTORY_FILE = soc_core.DATA_DIR / "ad_history.jsonl"
DETECTOR = "ad_inventory"

STALE_DAYS = int(os.environ.get("SOC_AD_STALE_DAYS", "90"))
WARN_DAYS = int(os.environ.get("SOC_AD_WARN_DAYS", "45"))
# More new objects than this in one run is a re-baseline (state lost, OU restructure), not news:
# one summary alert instead of one per object.
MAX_INDIVIDUAL_NEW = 20

PRIVILEGED_GROUPS = ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators",
                     "Account Operators", "Backup Operators", "Server Operators", "Print Operators",
                     "DnsAdmins", "Group Policy Creator Owners")
# Objects that never sign in by design, so "stale" means nothing for them.
NEVER_SIGN_IN = {"AZUREADSSOACC", "KRBTGT", "GUEST", "DEFAULTACCOUNT", "WDAGUTILITYACCOUNT"}

UAC_DISABLED = 0x2

# --------------------------------------------------------------------------- #
#  Windows lifecycle, by build. Dates follow Microsoft's lifecycle pages; verify one
#  before quoting it to management.
# --------------------------------------------------------------------------- #
# Client build -> (release, end for Home/Pro/Pro Education/Pro for Workstations,
#                  end for Enterprise/Education)
_CLIENT: Dict[int, Tuple[str, str, str]] = {
    7601:  ("Windows 7", "2020-01-14", "2020-01-14"),
    9600:  ("Windows 8.1", "2023-01-10", "2023-01-10"),
    10240: ("Windows 10 1507", "2017-05-09", "2017-05-09"),
    14393: ("Windows 10 1607", "2018-04-10", "2019-04-09"),
    15063: ("Windows 10 1703", "2018-10-09", "2019-10-08"),
    16299: ("Windows 10 1709", "2019-04-09", "2020-10-13"),
    17134: ("Windows 10 1803", "2019-11-12", "2021-05-11"),
    17763: ("Windows 10 1809", "2020-11-10", "2021-05-11"),
    18363: ("Windows 10 1909", "2021-05-11", "2022-05-10"),
    19041: ("Windows 10 2004", "2021-12-14", "2021-12-14"),
    19042: ("Windows 10 20H2", "2022-05-10", "2023-05-09"),
    19043: ("Windows 10 21H1", "2022-12-13", "2022-12-13"),
    19044: ("Windows 10 21H2", "2023-06-13", "2024-06-11"),
    19045: ("Windows 10 22H2", "2025-10-14", "2025-10-14"),
    22000: ("Windows 11 21H2", "2023-10-10", "2024-10-08"),
    22621: ("Windows 11 22H2", "2024-10-08", "2025-10-14"),
    22631: ("Windows 11 23H2", "2025-11-11", "2026-11-10"),
    26100: ("Windows 11 24H2", "2026-10-13", "2027-10-12"),
    26200: ("Windows 11 25H2", "2027-10-12", "2028-10-10"),
}
# Server build -> (release, end of extended support)
_SERVER: Dict[int, Tuple[str, str]] = {
    7601:  ("Windows Server 2008 R2", "2020-01-14"),
    9200:  ("Windows Server 2012", "2023-10-10"),
    9600:  ("Windows Server 2012 R2", "2023-10-10"),
    14393: ("Windows Server 2016", "2027-01-12"),
    17763: ("Windows Server 2019", "2029-01-09"),
    20348: ("Windows Server 2022", "2031-10-14"),
    26100: ("Windows Server 2025", "2034-10-10"),
}


def parse_build(os_version: Optional[str]) -> Optional[int]:
    """AD writes operatingSystemVersion as '10.0 (26100)'."""
    m = re.search(r"\((\d+)\)", str(os_version or ""))
    return int(m.group(1)) if m else None


def os_support(os_name: Optional[str], os_version: Optional[str], today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """{"release", "track", "ends", "status", "days_left"} for a Windows computer object, or None when
    it is not Windows, the build is unknown, or it is an LTSC/LTSB edition (own, much longer lifecycle).
    status: "unsupported" | "ending_soon" (within WARN_DAYS) | "supported"."""
    name = str(os_name or "")
    build = parse_build(os_version)
    if not name.startswith("Windows") or build is None or re.search(r"LTS[BC]", name):
        return None
    if "Server" in name:
        entry = _SERVER.get(build)
        if not entry:
            return None
        release, ends, track = entry[0], entry[1], "Server"
    else:
        entry = _CLIENT.get(build)
        if not entry:
            return None
        long_track = "Enterprise" in name or ("Education" in name and "Pro Education" not in name)
        release = entry[0]
        ends = entry[2] if long_track else entry[1]
        track = "Enterprise/Education" if long_track else "Home/Pro"
    today = today or date.today()
    days_left = (date.fromisoformat(ends) - today).days
    status = "unsupported" if days_left < 0 else "ending_soon" if days_left <= WARN_DAYS else "supported"
    return {"release": release, "track": track, "ends": ends, "status": status, "days_left": days_left}


# --------------------------------------------------------------------------- #
#  Reading AD
# --------------------------------------------------------------------------- #

def load_config(path: Path = ENV_FILE) -> Dict[str, str]:
    cfg: Dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    missing = [k for k in ("AD_LDAP_SERVERS", "AD_LDAP_USER", "AD_LDAP_PASSWORD", "AD_BASE_DN") if not cfg.get(k)]
    if missing:
        raise ValueError(f"{path}: missing {', '.join(missing)}")
    return cfg


def connect(cfg: Dict[str, str]):
    """(connection, server) for the first DC that accepts the bind."""
    import ssl
    from ldap3 import NTLM, SIMPLE, Connection, Server, Tls
    from ldap3.core.exceptions import LDAPException

    mode = cfg.get("AD_LDAP_MODE", "ntlm").lower()
    user = cfg["AD_LDAP_USER"]
    if mode == "ntlm":
        domain = cfg.get("AD_NTLM_DOMAIN") or user.split("@")[-1].split(".")[0].upper()
        user, auth = f"{domain}\\{user.split('@')[0]}", NTLM
    elif mode == "ldaps":
        auth = SIMPLE
    else:
        raise ValueError(f"AD_LDAP_MODE must be ntlm or ldaps, not {mode!r}")
    errors = []
    for host in [h.strip() for h in cfg["AD_LDAP_SERVERS"].split(",") if h.strip()]:
        if mode == "ldaps":
            ca = cfg.get("AD_LDAP_CA_FILE")
            tls = Tls(validate=ssl.CERT_REQUIRED if ca else ssl.CERT_NONE, ca_certs_file=ca or None)
            server = Server(host, port=636, use_ssl=True, tls=tls, connect_timeout=10)
        else:
            server = Server(host, port=389, connect_timeout=10)
        try:
            conn = Connection(server, user=user, password=cfg["AD_LDAP_PASSWORD"], authentication=auth,
                              receive_timeout=60, raise_exceptions=False)
            if conn.bind():
                return conn, host
            errors.append(f"{host}: bind refused ({conn.result.get('description')})")
        except LDAPException as e:
            errors.append(f"{host}: {type(e).__name__}: {e}")
    raise ConnectionError("; ".join(errors) or "no AD_LDAP_SERVERS")


def _iso(value) -> Optional[str]:
    """LDAP time (already a datetime via the schema) -> ISO string; 'never' (1601) -> None."""
    if isinstance(value, datetime) and value.year > 1601:
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()
    return None


def _ou(dn: str) -> str:
    """'CN=PC1,OU=Accounting,OU=Calgary,DC=era,DC=local' -> 'Calgary/Accounting'."""
    parts = [p[3:] for p in re.split(r"(?<!\\),", dn or "") if p.upper().startswith("OU=")]
    return "/".join(reversed(parts))


def _search(conn, base: str, flt: str, attrs: List[str]) -> List[Dict[str, Any]]:
    from ldap3 import SUBTREE
    rows = conn.extend.standard.paged_search(base, flt, SUBTREE, attributes=attrs, paged_size=500, generator=False)
    return [r["attributes"] for r in rows if r.get("type") == "searchResEntry"]


def _first(v):
    return (v[0] if v else None) if isinstance(v, list) else v


def read_ad(conn, base: str, host: str, mode: str, today: Optional[date] = None) -> Dict[str, Any]:
    computers: Dict[str, Any] = {}
    for a in _search(conn, base, "(objectClass=computer)",
                     ["name", "dNSHostName", "operatingSystem", "operatingSystemVersion", "lastLogonTimestamp",
                      "userAccountControl", "whenCreated", "distinguishedName"]):
        name = str(_first(a.get("name")) or "").upper()
        if not name:
            continue
        os_name, os_ver = _first(a.get("operatingSystem")), _first(a.get("operatingSystemVersion"))
        computers[name] = {
            "name": name, "dns": _first(a.get("dNSHostName")), "os": os_name, "os_version": os_ver,
            "build": parse_build(os_ver), "enabled": not int(_first(a.get("userAccountControl")) or 0) & UAC_DISABLED,
            "last_logon": _iso(a.get("lastLogonTimestamp")), "created": _iso(a.get("whenCreated")),
            "ou": _ou(str(_first(a.get("distinguishedName")) or "")),
            "support": os_support(os_name, os_ver, today),
        }
    users: Dict[str, Any] = {}
    for a in _search(conn, base, "(&(objectCategory=person)(objectClass=user))",
                     ["sAMAccountName", "displayName", "userAccountControl", "lastLogonTimestamp", "whenCreated",
                      "distinguishedName"]):
        sam = str(_first(a.get("sAMAccountName")) or "")
        if not sam:
            continue
        users[sam.lower()] = {
            "sam": sam, "display": _first(a.get("displayName")),
            "enabled": not int(_first(a.get("userAccountControl")) or 0) & UAC_DISABLED,
            "last_logon": _iso(a.get("lastLogonTimestamp")), "created": _iso(a.get("whenCreated")),
            "ou": _ou(str(_first(a.get("distinguishedName")) or "")),
        }
    privileged = read_privileged(conn, base)
    risk_data = ad_risks.read_risk_data(conn, base, _search)
    all_privileged = {m for members in privileged.values() for m in members}
    return {"generated": datetime.now(timezone.utc).isoformat(), "server": host, "mode": mode,
            "computers": computers, "users": users, "privileged": privileged,
            "risks": ad_risks.risk_findings(risk_data, all_privileged, today or date.today()),
            "domain_policy": risk_data["policy"]}


def read_privileged(conn, base: str) -> Dict[str, List[str]]:
    """{group: [sAMAccountName...]} -- recursive membership of each privileged group that exists."""
    privileged: Dict[str, List[str]] = {}
    for group in PRIVILEGED_GROUPS:
        found = _search(conn, base, f"(&(objectClass=group)(sAMAccountName={group}))", ["distinguishedName"])
        if not found:
            continue
        dn = str(_first(found[0].get("distinguishedName")))
        dn_escaped = dn.replace("\\", "\\5c").replace("(", "\\28").replace(")", "\\29").replace("*", "\\2a")
        members = _search(conn, base, f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={dn_escaped}))",
                          ["sAMAccountName"])
        privileged[group] = sorted({str(_first(m.get("sAMAccountName"))) for m in members if m.get("sAMAccountName")},
                                   key=str.lower)
    return privileged


# --------------------------------------------------------------------------- #
#  What deserves an alert (pure: snapshot + previous state in, alerts + new state out)
# --------------------------------------------------------------------------- #

def network_windows_hosts() -> Dict[str, str]:
    """{NETBIOS NAME: ip} of the Windows machines the periodic nmap scan identified by name
    (scan_facts from scripts/host_facts.py on the asset records)."""
    out: Dict[str, str] = {}
    for rec in soc_core.load_assets().values():
        sf = rec.get("scan_facts") or {}
        name = (sf.get("windows") or {}).get("NetBIOS_Computer_Name") or sf.get("netbios_name")
        if name and rec.get("ip"):
            out[str(name).upper()] = rec["ip"]
    return out


def _days_since(iso: Optional[str], today: date) -> Optional[int]:
    if not iso:
        return None
    return (today - datetime.fromisoformat(iso).date()).days


def _is_stale(obj: Dict[str, Any], today: date) -> bool:
    if not obj.get("enabled"):
        return False
    since = _days_since(obj.get("last_logon"), today)
    if since is None:  # never signed in: stale only once it has existed long enough to have done so
        since = _days_since(obj.get("created"), today)
    return since is not None and since > STALE_DAYS


def _names(items: List[str], limit: int = 25) -> str:
    return ", ".join(items[:limit]) + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def privileged_changes(before: Dict[str, List[str]], now: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """Alert kwargs for additions (critical) and removals (normal) between two readings of the privileged groups.
    A group absent from `before` (first time it was readable) has nothing to compare against."""
    out: List[Dict[str, Any]] = []
    for group, members in now.items():
        if group not in before:
            continue
        old = set(before[group])
        for sam in sorted(set(members) - old, key=str.lower):
            out.append(dict(
                type="intrusion", severity="critical", title=f"Added to {group}: {sam}", user=sam, detector=DETECTOR,
                description=(f"{sam} became a member of the privileged group {group} (directly or through a nested "
                             "group) since the previous check. If nobody made this change on purpose, treat it as a "
                             "compromise of the domain."),
                details={"group": group, "change": "added", "members": members}))
        for sam in sorted(old - set(members), key=str.lower):
            out.append(dict(type="intrusion", severity="normal", title=f"Removed from {group}: {sam}", user=sam,
                            detector=DETECTOR, description=f"{sam} is no longer a member of {group}.",
                            details={"group": group, "change": "removed", "members": members}))
    return out


def evaluate(snap: Dict[str, Any], state: Dict[str, Any], network_hosts: Dict[str, str], today: date,
             ignore_not_in_domain: List[str] = ()) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """(alert kwargs, new state)."""
    alerts: List[Dict[str, Any]] = []
    first_run = not state.get("computers")
    comps, users, priv = snap["computers"], snap["users"], snap["privileged"]

    def add(**kw):
        kw.setdefault("detector", DETECTOR)
        alerts.append(kw)

    # ---- privileged groups -------------------------------------------------------------
    if first_run:
        lines = [f"{g} ({len(m)}): {', '.join(m) or '-'}" for g, m in priv.items()]
        add(type="intrusion", severity="normal", title="AD privileged group members recorded (baseline)",
            description=("First AD inventory: these are the current members of the privileged groups. From now on any "
                         "addition raises a critical alert. Review that every name is expected.\n" + "\n".join(lines)),
            details={"privileged": priv})
    else:
        alerts.extend(privileged_changes(state.get("privileged", {}), priv))

    # ---- new computers and users -----------------------------------------------------------
    if not first_run:
        for kind, current, before, noun in (("computer", comps, state.get("computers", []), "computer"),
                                            ("user", users, state.get("users", []), "user account")):
            new = sorted(set(current) - set(before))
            if len(new) > MAX_INDIVIDUAL_NEW:
                add(type="intrusion", severity="normal", title=f"{len(new)} new {noun}s in AD",
                    description=f"Too many to list one by one (state reset or reorganisation?): {_names(new)}",
                    details={"kind": kind, "new": new})
                continue
            for key in new:
                o = current[key]
                label = o["name"] if kind == "computer" else o["sam"]
                extra = f" ({o.get('display')})" if kind == "user" and o.get("display") else ""
                add(type="intrusion", severity="normal", title=f"New {noun} in AD: {label}{extra}",
                    hostname=o.get("dns") if kind == "computer" else None,
                    user=o["sam"] if kind == "user" else None,
                    description=(f"A {noun} was created in Active Directory (OU {o.get('ou') or '-'}, created "
                                 f"{o.get('created') or 'unknown'}). Confirm it was added on purpose."),
                    details={"kind": kind, "name": label, "ou": o.get("ou"), "created": o.get("created")})

    # ---- Windows support ----------------------------------------------------------------------
    alerted_unsupported = dict(state.get("unsupported", {}))
    now_unsupported: Dict[str, int] = {}
    ending: Dict[str, List[str]] = {}
    for name, c in sorted(comps.items()):
        s = c.get("support")
        if not s or not c.get("enabled") or _is_stale(c, today):
            continue
        if s["status"] == "unsupported":
            now_unsupported[name] = c["build"]
            if alerted_unsupported.get(name) == c["build"]:
                continue
            overdue = -s["days_left"]
            add(type="vuln", severity="medium" if overdue > 365 else "normal",
                title=f"Unsupported Windows (per AD) on {name}: {s['release']} {s['track']}",
                hostname=c.get("dns") or name, source_ip=network_hosts.get(name),
                description=(f"Active Directory reports {c['os']} build {c['build']} ({s['release']}). The "
                             f"{s['track']} editions of that release stopped receiving security updates on {s['ends']}. "
                             "Upgrade it, or record why it is covered (paid Extended Security Updates)."),
                details={"computer": name, "os": c["os"], "build": c["build"], "support_ended": s["ends"],
                         "ou": c.get("ou"), "source": "active_directory"})
        elif s["status"] == "ending_soon":
            ending.setdefault(f"{s['release']}|{s['track']}|{s['ends']}", []).append(name)
    alerted_ending = set(state.get("ending_soon", []))
    for key, names in sorted(ending.items()):
        if key in alerted_ending:
            continue
        release, track, ends = key.split("|")
        days = (date.fromisoformat(ends) - today).days
        add(type="vuln", severity="medium" if days <= 14 else "normal",
            title=f"{len(names)} computer(s) lose Windows support on {ends}: {release} {track}",
            description=(f"{release} ({track} editions) stops receiving security updates on {ends}, in {days} days. "
                         f"Upgrade these before then: {_names(names)}"),
            details={"release": release, "track": track, "ends": ends, "computers": names})

    # ---- stale objects ---------------------------------------------------------------------------
    stale: Dict[str, List[str]] = {}
    for kind, objs in (("computers", comps), ("users", users)):
        stale[kind] = sorted(k for k, o in objs.items() if k.upper() not in NEVER_SIGN_IN and _is_stale(o, today))
        new_stale = sorted(set(stale[kind]) - set(state.get(f"stale_{kind}", [])))
        if new_stale:
            shown = [comps[k]["name"] if kind == "computers" else users[k]["sam"] for k in new_stale]
            add(type="vuln", severity="normal",
                title=f"{len(new_stale)} enabled {kind[:-1]} account(s) unused for {STALE_DAYS}+ days in AD",
                description=(f"These are enabled in AD but have not signed in for more than {STALE_DAYS} days "
                             f"({len(stale[kind])} in total now): {_names(shown)}. Unused enabled accounts are a "
                             "favourite of attackers because nobody notices them being used. Disable the ones that "
                             "are no longer needed. (AD updates last sign-in only every 9-14 days, so treat the "
                             "date as approximate.)"),
                details={"kind": kind, "new": shown, "total": len(stale[kind])})

    # ---- Windows machines on the network that are not in the domain -------------------------------
    alerted_nid = set(state.get("not_in_domain", []))
    not_in_domain = []
    for name, ip in sorted(network_hosts.items()):
        if name in comps or any(fnmatch(name, p.upper()) for p in ignore_not_in_domain):
            continue
        not_in_domain.append(name)
        if name in alerted_nid:
            continue
        add(type="intrusion", severity="medium", title=f"Windows host not in the domain: {name} ({ip})",
            hostname=name, source_ip=ip,
            description=(f"The network scan found a Windows machine named {name} at {ip}, but there is no computer "
                         "with that name in Active Directory. Nobody joined it, so group policy, patching and "
                         "domain monitoring do not reach it. Find its owner; if it belongs, join it or document it "
                         "(config/ad_inventory.json not_in_domain_ignore)."),
            details={"computer": name, "ip": ip})

    # ---- domain weaknesses (ad_risks.py): alert when a weakness appears or gains accounts, note when it is fixed ----
    before_risks: Dict[str, List[str]] = state.get("risks", {})
    now_risks = {r["id"]: r["accounts"] for r in snap.get("risks", [])}
    for r in snap.get("risks", []):
        gained = sorted(set(r["accounts"]) - set(before_risks.get(r["id"], [])), key=str.lower)
        if not gained:
            continue
        add(type="vuln", severity=r["severity"], title=f"{r['title']}: {_names(r['accounts'], 8)}",
            user=r["accounts"][0] if len(r["accounts"]) == 1 else None,
            description=r["description"] + (f" New since the last check: {_names(gained)}." if r["id"] in before_risks else ""),
            details={"check": r["id"], "accounts": r["accounts"], "new": gained, "source": "active_directory"})
    for rid in sorted(set(before_risks) - set(now_risks)):
        add(type="vuln", severity="normal", title=f"AD weakness fixed: {rid.replace('_', ' ')}",
            description=f"The '{rid}' check no longer finds anything (was: {_names(before_risks[rid])}).",
            details={"check": rid, "change": "fixed"})

    new_state = {
        "computers": sorted(comps), "users": sorted(users), "privileged": priv, "risks": now_risks,
        "unsupported": now_unsupported,
        "ending_soon": sorted(alerted_ending | set(ending)),
        "stale_computers": stale["computers"], "stale_users": stale["users"],
        "not_in_domain": not_in_domain,
        "last_error": None, "updated": snap["generated"],
    }
    return alerts, new_state


def daily_counts(snap: Dict[str, Any], state: Dict[str, Any], today: date) -> Dict[str, Any]:
    """The headline numbers of one inventory, as a line of data/ad_history.jsonl."""
    comps, users = snap["computers"].values(), snap["users"].values()
    live = [c for c in comps if c.get("enabled") and not _is_stale(c, today)]
    risks = snap.get("risks", [])
    return {
        "date": today.isoformat(),
        "computers": {"total": len(snap["computers"]), "active": len(live),
                      "stale": len(state.get("stale_computers", [])),
                      "disabled": sum(1 for c in comps if not c.get("enabled"))},
        "users": {"total": len(snap["users"]), "enabled": sum(1 for u in users if u.get("enabled")),
                  "stale": len(state.get("stale_users", [])),
                  "disabled": sum(1 for u in users if not u.get("enabled"))},
        "privileged": {g: len(m) for g, m in snap.get("privileged", {}).items()},
        "privileged_accounts": len({m.lower() for ms in snap.get("privileged", {}).values() for m in ms}),
        "os_unsupported": len(state.get("unsupported", {})),
        "os_ending_soon": sum(1 for c in live if (c.get("support") or {}).get("status") == "ending_soon"),
        "not_in_domain": len(state.get("not_in_domain", [])),
        "risks": {r["id"]: len(r["accounts"]) for r in risks},
        "risks_by_severity": {sev: sum(1 for r in risks if r["severity"] == sev) for sev in ("critical", "medium", "normal")},
    }


def record_history(line: Dict[str, Any]) -> None:
    """Append today's line to data/ad_history.jsonl, replacing an earlier line for the same date (a re-run)."""
    try:
        kept = [l for l in HISTORY_FILE.read_text().splitlines() if l.strip() and json.loads(l).get("date") != line["date"]]
    except (OSError, ValueError):
        kept = []
    kept.append(json.dumps(line, sort_keys=True))
    fd, tmp = tempfile.mkstemp(dir=str(HISTORY_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(kept) + "\n")
        os.replace(tmp, HISTORY_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# --------------------------------------------------------------------------- #
#  Run
# --------------------------------------------------------------------------- #

def _load_json(path: Path, default):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _save_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(obj, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _failure(state: Dict[str, Any], error: str, dry_run: bool) -> int:
    print(f"[!] ad_inventory: cannot read Active Directory: {error}", file=sys.stderr)
    if not dry_run and not state.get("last_error"):
        emit_alert(Alert(type="vuln", severity="medium", title="AD inventory cannot read Active Directory",
                         detector=DETECTOR,
                         description=("The daily Active Directory read failed, so new admins, new computers and "
                                      f"unsupported Windows are not being checked. Error: {error}"),
                         details={"error": error}))
    if not dry_run:
        _save_json(STATE_FILE, {**state, "last_error": error})
    return 1


def run(dry_run: bool = False) -> int:
    today = date.today()
    with diff_state_lock(STATE_FILE):
        state = _load_json(STATE_FILE, {})
        try:
            cfg = load_config()
            conn, host = connect(cfg)
            try:
                snap = read_ad(conn, cfg["AD_BASE_DN"], host, cfg.get("AD_LDAP_MODE", "ntlm").lower(), today)
                change_kw, changes = ad_changes.check(conn, cfg["AD_BASE_DN"], state.get("changes"), _search, DETECTOR)
            finally:
                conn.unbind()
        except Exception as e:  # noqa: BLE001 -- any failure is reported the same way
            return _failure(state, f"{type(e).__name__}: {e}", dry_run)

        before = len(state.get("computers", []))
        if not snap["computers"] or (before and len(snap["computers"]) < before / 2):
            return _failure(state, f"read looks incomplete: {len(snap['computers'])} computers (was {before})", dry_run)

        ignore = _load_json(CONFIG_FILE, {}).get("not_in_domain_ignore", [])
        alerts, new_state = evaluate(snap, state, network_windows_hosts(), today, ignore)
        alerts += change_kw
        new_state["changes"] = changes

        if dry_run:
            print(f"[dry-run] {host} ({snap['mode']}): {len(snap['computers'])} computers, {len(snap['users'])} users")
            for a in alerts:
                print(f"  {a['severity']:8} {a['title']}")
            return 0

        if state.get("last_error"):
            emit_alert(Alert(type="vuln", severity="normal", title="AD inventory reading Active Directory again",
                             detector=DETECTOR, description="The daily Active Directory read works again.",
                             details={"previous_error": state["last_error"]}))
        for kw in alerts:
            emit_alert(Alert(**kw), echo=False)
        _save_json(INVENTORY_FILE, snap)
        record_history(daily_counts(snap, new_state, today))
        _save_json(STATE_FILE, new_state)
        print(f"[*] ad_inventory: {host} ({snap['mode']}): {len(snap['computers'])} computers, "
              f"{len(snap['users'])} users, {len(alerts)} alert(s)")
    return 0


def run_privileged(dry_run: bool = False) -> int:
    """The quick check (every 15 minutes, soc-ad-privileged.timer): only the privileged groups, compared with
    the last reading. A new Domain Admin should not wait for tomorrow's full inventory to be noticed. Does
    nothing until the full inventory has recorded a baseline."""
    with diff_state_lock(STATE_FILE):
        state = _load_json(STATE_FILE, {})
        if not state.get("privileged"):
            print("[*] ad_inventory --privileged-only: no baseline yet (run the full inventory first)")
            return 0
        try:
            cfg = load_config()
            conn, host = connect(cfg)
            try:
                priv = read_privileged(conn, cfg["AD_BASE_DN"])
                change_kw, changes = ad_changes.check(conn, cfg["AD_BASE_DN"], state.get("changes"), _search, DETECTOR)
            finally:
                conn.unbind()
        except Exception as e:  # noqa: BLE001
            return _failure(state, f"{type(e).__name__}: {e}", dry_run)
        if not priv:
            return _failure(state, "no privileged group was readable", dry_run)
        alerts = privileged_changes(state["privileged"], priv) + change_kw
        if dry_run:
            for a in alerts:
                print(f"  {a['severity']:8} {a['title']}")
            return 0
        if state.get("last_error"):
            emit_alert(Alert(type="vuln", severity="normal", title="AD inventory reading Active Directory again",
                             detector=DETECTOR, description="The Active Directory read works again.",
                             details={"previous_error": state["last_error"]}))
        for kw in alerts:
            emit_alert(Alert(**kw), echo=False)
        _save_json(STATE_FILE, {**state, "privileged": {**state["privileged"], **priv}, "changes": changes,
                                "last_error": None})
        if alerts:
            print(f"[*] ad_inventory --privileged-only: {len(alerts)} change(s)")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="print what would be alerted; save nothing")
    ap.add_argument("--privileged-only", action="store_true",
                    help="the 15-minute check: privileged groups, GPOs, trusts and domain permissions only")
    args = ap.parse_args()
    raise SystemExit(run_privileged(args.dry_run) if args.privileged_only else run(args.dry_run))
