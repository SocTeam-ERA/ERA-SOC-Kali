#!/usr/bin/env python3
"""
ad_views.py
-----------
Read-only views of the daily Active Directory inventory for the API (GET /api/ad/*), so the platform
can show an AD page and join its own asset inventory to AD without an LDAP connection of its own.

Everything comes from files ad_inventory.py already writes. Nothing here talks to AD:
  data/ad_inventory.json        the latest reading (computers, users, privileged groups, risks, policy)
  data/ad_inventory_state.json  what that reading concluded (stale, unsupported, not in the domain)
  data/ad_history.jsonl         one line of headline numbers per day
  data/assets.json              where the network scan last saw each Windows machine (by NetBIOS name)

Status of a computer or user, the same rules as the alerts:
  disabled   the account is disabled in AD
  stale      enabled, but no sign-in for ad_inventory.STALE_DAYS (or never, and created longer ago)
  active     everything else
"""
from __future__ import annotations

import json
from datetime import date, datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import soc_core

STATUSES = ("active", "stale", "disabled")


def _load(name: str, default):
    try:
        return json.loads((soc_core.DATA_DIR / name).read_text())
    except (OSError, ValueError):
        return default


def inventory() -> Optional[Dict[str, Any]]:
    inv = _load("ad_inventory.json", None)
    return inv if isinstance(inv, dict) and inv.get("computers") is not None else None


def _status(obj: Dict[str, Any], today: date) -> str:
    import ad_inventory
    if not obj.get("enabled"):
        return "disabled"
    return "stale" if ad_inventory._is_stale(obj, today) else "active"


def _network_sightings() -> Dict[str, Dict[str, Any]]:
    """{NETBIOS NAME: {"ip", "last_seen", "mac"}} from the network scan."""
    out: Dict[str, Dict[str, Any]] = {}
    for rec in soc_core.load_assets().values():
        sf = rec.get("scan_facts") or {}
        name = str((sf.get("windows") or {}).get("NetBIOS_Computer_Name") or sf.get("netbios_name") or "").upper()
        if name and (name not in out or (rec.get("last_seen") or "") > (out[name].get("last_seen") or "")):
            out[name] = {"ip": rec.get("ip"), "last_seen": rec.get("last_seen"), "mac": rec.get("mac")}
    return out


def _match(q: Optional[str], *fields) -> bool:
    return not q or any(q.lower() in str(f or "").lower() for f in fields)


def computers(status: Optional[str] = None, ou: Optional[str] = None, q: Optional[str] = None,
              support: Optional[str] = None, today: Optional[date] = None) -> Optional[List[Dict[str, Any]]]:
    """Every computer object with its status and where the network last saw it. Filters: status (active,
    stale, disabled), ou (prefix, e.g. "Calgary/Accounting"), support (unsupported, ending_soon,
    supported), q (text in name, DNS name, OS or OU). None when there is no inventory yet."""
    inv = inventory()
    if inv is None:
        return None
    today = today or date.today()
    seen = _network_sightings()
    rows = []
    for name, c in sorted(inv["computers"].items()):
        st = _status(c, today)
        sup = c.get("support") or {}
        if status and st != status:
            continue
        if ou and not str(c.get("ou") or "").lower().startswith(ou.lower()):
            continue
        if support and sup.get("status") != support:
            continue
        if not _match(q, name, c.get("dns"), c.get("os"), c.get("ou")):
            continue
        rows.append({**{k: c.get(k) for k in ("name", "dns", "os", "os_version", "build", "enabled",
                                              "last_logon", "created", "ou", "support")},
                     "status": st, "network": seen.get(name)})
    return rows


def users(status: Optional[str] = None, ou: Optional[str] = None, q: Optional[str] = None,
          privileged: bool = False, today: Optional[date] = None) -> Optional[List[Dict[str, Any]]]:
    """Every user account with its status and privileged groups. Filters: status, ou, q (text in the
    account or display name), privileged (only members of a privileged group)."""
    inv = inventory()
    if inv is None:
        return None
    today = today or date.today()
    groups: Dict[str, List[str]] = {}
    for g, members in (inv.get("privileged") or {}).items():
        for m in members:
            groups.setdefault(m.lower(), []).append(g)
    rows = []
    for key, u in sorted(inv["users"].items()):
        st = _status(u, today)
        pg = groups.get(key, [])
        if status and st != status:
            continue
        if privileged and not pg:
            continue
        if ou and not str(u.get("ou") or "").lower().startswith(ou.lower()):
            continue
        if not _match(q, u.get("sam"), u.get("display")):
            continue
        rows.append({**{k: u.get(k) for k in ("sam", "display", "enabled", "last_logon", "created", "ou")},
                     "status": st, "privileged_groups": pg})
    return rows


def summary(today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """The AD page's header: counts by status, privileged groups with their members, Windows support,
    machines outside the domain, open domain weaknesses and the password policy."""
    inv = inventory()
    if inv is None:
        return None
    today = today or date.today()
    state = _load("ad_inventory_state.json", {})
    comps, usrs = computers(today=today) or [], users(today=today) or []
    by_user = {u["sam"].lower(): u for u in usrs}
    count = lambda rows: {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}  # noqa: E731
    support: Dict[str, List[str]] = {"unsupported": [], "ending_soon": []}
    for c in comps:
        s = (c.get("support") or {}).get("status")
        if c["status"] == "active" and s in support:
            support[s].append(c["name"])
    seen = _network_sightings()
    return {
        "as_of": inv.get("generated"), "server": inv.get("server"), "mode": inv.get("mode"),
        "computers": {"total": len(comps), **count(comps)},
        "users": {"total": len(usrs), **count(usrs)},
        "privileged": {g: [{"sam": m, "display": (by_user.get(m.lower()) or {}).get("display"),
                            "status": (by_user.get(m.lower()) or {}).get("status"),
                            "last_logon": (by_user.get(m.lower()) or {}).get("last_logon")} for m in members]
                       for g, members in (inv.get("privileged") or {}).items()},
        "windows_support": support,
        "not_in_domain": [{"name": n, **(seen.get(n) or {})} for n in state.get("not_in_domain", [])],
        "risks": inv.get("risks", []),
        "domain_policy": inv.get("domain_policy"),
    }


def history(days: int = 90) -> List[Dict[str, Any]]:
    """The daily headline numbers (data/ad_history.jsonl) for the last `days` days, oldest first."""
    cutoff = (datetime.now(timezone.utc).date() - timedelta(days=max(days, 1))).isoformat()
    out = []
    try:
        lines = (soc_core.DATA_DIR / "ad_history.jsonl").read_text().splitlines()
    except OSError:
        return out
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("date", "") >= cutoff:
            out.append(row)
    return sorted(out, key=lambda r: r["date"])
