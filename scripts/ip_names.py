#!/usr/bin/env python3
"""
ip_names.py -- which Active Directory computer is at which IP address (data/ip_names.json).

ad_identity.py can only say "this alert is about CHANTELLE-PC" when it knows the machine behind an IP,
and the scan learned that for only a few of them (RDP/NetBIOS answers): 63 of 518 known addresses
mapped to an AD computer, so most alerts carried no identity. Two more sources, both already on the
network or on this appliance:

  dhcp   the host name the DHCP server saw (Zeek dhcp.log, kept on each asset as dhcp_hostname);
         observed recently, so it is trusted like the scan's name;
  dns    the address the domain's DNS holds for each AD computer (resolved through the domain
         controllers this appliance already uses). Registered by the machine itself, so it covers most
         of the domain, but a record can be stale after DHCP churn, so a DNS-only match is used only when

           * the computer is enabled and signed in to the domain within the last 90 days;
           * its name resolves to ONE address, or, for a multi-homed machine, the address is one the
             SOC saw in the last 2 days;
           * no other AD computer resolves to the same address; and
           * the asset at that address has not been named as something else by the scan or DHCP.

Entries carry "via" so the dashboard and analysts can tell an observed name from an inferred one.
Refreshed hourly by service_watchdog.py; read-only apart from data/ip_names.json.

    python3 ip_names.py            rebuild now and print the counts
"""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import os
import socket
import sys
import tempfile
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soc_core  # noqa: E402

FILE_NAME = "ip_names.json"
DEFAULT_DOMAIN = os.environ.get("SOC_AD_DOMAIN", "era.local")
ACTIVE_DAYS = 90            # same rule as ad_inventory / host_facts
SEEN_DAYS = 2               # a multi-homed machine's address must have been seen this recently
REFRESH_SECONDS = 3600
LOOKUP_WORKERS = 16
LOOKUP_DEADLINE = 25        # seconds for the whole pass: never hold the watchdog


def _path() -> Path:
    return soc_core.DATA_DIR / FILE_NAME


def _dns_lookup(fqdn: str) -> List[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(fqdn, None, socket.AF_INET)})
    except OSError:
        return []


def _usable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_loopback or a.is_link_local or a.is_unspecified or a.is_multicast)


def _ts(v: Any) -> Optional[datetime]:
    try:
        d = datetime.fromisoformat(str(v))
    except (ValueError, TypeError):
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def build(inventory: Dict[str, Any], assets: Dict[str, Dict[str, Any]],
          lookup: Callable[[str], List[str]] = _dns_lookup, now: Optional[datetime] = None) -> Dict[str, Any]:
    """{"generated", "ips": {ip: {"name", "via"}}, "stats"} from the AD inventory and the asset table."""
    now = now or datetime.now(timezone.utc)
    comps: Dict[str, Dict[str, Any]] = inventory.get("computers") or {}
    by_name = {}
    for key, c in comps.items():
        by_name[key.upper()] = key
        if c.get("dns"):
            by_name[str(c["dns"]).split(".")[0].upper()] = key

    # what the scan and DHCP observed at each address, and when the address was last seen
    observed: Dict[str, str] = {}
    last_seen: Dict[str, datetime] = {}
    out: Dict[str, Dict[str, str]] = {}
    for rec in assets.values():
        ip = rec.get("ip")
        if not ip:
            continue
        ls = _ts(rec.get("last_seen"))
        if ls and (ip not in last_seen or ls > last_seen[ip]):
            last_seen[ip] = ls
        sf = rec.get("scan_facts") or {}
        scan_name = (sf.get("windows") or {}).get("NetBIOS_Computer_Name") or sf.get("netbios_name")
        dhcp_name = rec.get("dhcp_hostname")
        for n in (scan_name, dhcp_name):
            if n:
                observed[ip] = str(n).split(".")[0].upper()
        key = by_name.get(str(dhcp_name).split(".")[0].upper()) if dhcp_name else None
        if key and _usable(ip):
            out[ip] = {"name": key, "via": "dhcp"}

    cutoff = now - timedelta(days=ACTIVE_DAYS)
    candidates = {}
    for key, c in comps.items():
        last = _ts(c.get("last_logon"))
        if c.get("enabled") and last and last >= cutoff:
            candidates[key] = c.get("dns") or f"{key.lower()}.{DEFAULT_DOMAIN}"

    resolved: Dict[str, List[str]] = {}
    with cf.ThreadPoolExecutor(LOOKUP_WORKERS) as ex:
        futures = {ex.submit(lookup, fq): key for key, fq in candidates.items()}
        try:
            for f in cf.as_completed(futures, timeout=LOOKUP_DEADLINE):
                try:
                    resolved[futures[f]] = [ip for ip in f.result() if _usable(ip)]
                except Exception:
                    resolved[futures[f]] = []
        except cf.TimeoutError:
            pass                       # what did not answer in time is simply not mapped this hour

    owners: Dict[str, set] = defaultdict(set)
    for key, ips in resolved.items():
        for ip in ips:
            owners[ip].add(key)
    skipped = defaultdict(int)
    for key, ips in resolved.items():
        for ip in ips:
            if ip in out:
                continue                                    # DHCP saw it: observed beats inferred
            if len(owners[ip]) > 1:
                skipped["address shared by several AD computers"] += 1
            elif ip in observed and by_name.get(observed[ip]) != key:
                skipped["the scan/DHCP named a different machine there"] += 1
            elif len(ips) > 1 and not (ip in last_seen and now - last_seen[ip] <= timedelta(days=SEEN_DAYS)):
                skipped["multi-homed machine, address not seen recently"] += 1
            else:
                out[ip] = {"name": key, "via": "dns"}
    return {"generated": now.isoformat(), "ips": out,
            "stats": {"ad_computers": len(comps), "looked_up": len(candidates), "resolved": sum(1 for v in resolved.values() if v),
                      "mapped": len(out), "via_dhcp": sum(1 for v in out.values() if v["via"] == "dhcp"),
                      "via_dns": sum(1 for v in out.values() if v["via"] == "dns"), "skipped": dict(skipped)}}


def _write(data: Dict[str, Any]) -> None:
    p = _path()
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.chmod(tmp, 0o664)
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def refresh(force: bool = False) -> Optional[Dict[str, Any]]:
    """Rebuild data/ip_names.json when it is older than REFRESH_SECONDS (or `force`). None when it was
    fresh, or when there is no AD inventory to build from yet."""
    p = _path()
    if not force:
        try:
            if time.time() - p.stat().st_mtime < REFRESH_SECONDS:
                return None
        except OSError:
            pass
    try:
        inventory = json.loads((soc_core.DATA_DIR / "ad_inventory.json").read_text())
    except (OSError, ValueError):
        return None
    data = build(inventory, soc_core.load_assets())
    _write(data)
    return data


if __name__ == "__main__":
    d = refresh(force=True)
    print(json.dumps(d["stats"], indent=2) if d else "no AD inventory yet (data/ad_inventory.json)")
