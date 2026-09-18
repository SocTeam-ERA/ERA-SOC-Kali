#!/usr/bin/env python3
"""
threat_intel.py -- match alerts against public threat-intelligence feeds.

Feeds (refreshed daily by kali/refresh_tor.sh; or run --refresh by hand):
  abuse.ch Feodo Tracker   IPs of botnet command-and-control servers
  CISA KEV                 CVEs known to be exploited in the wild
plus the local, hand-kept kali/ioc_ips.txt.

emit_alert() calls enrich(record); on a hit the alert gets
details["threat_intel"]:
    {"ip_matches": [{"indicator": "1.2.3.4", "feed": "feodotracker", "role": "destination"}],
     "kev": [{"cve": "CVE-2024-1234", "name": "...", "vendor": "...", "product": "...",
              "added": "2026-01-01", "due": "2026-01-22", "ransomware": false}]}
It never changes severity; correlation rules and the UI decide what a match means.

Feed data lives in data/threat_intel/. A failed download keeps the previous
copy, and a feed that comes back implausibly empty is rejected.

    python3 threat_intel.py --refresh    download feeds, rebuild the merged IOC list
    python3 threat_intel.py --status     show what is loaded and how old it is
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soc_core  # noqa: E402

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIN_ENTRIES = 500          # the real catalog has well over 1000
MAX_FEED_BYTES = 20_000_000

TI_DIR = soc_core.DATA_DIR / "threat_intel"
FEODO_FILE = TI_DIR / "feodo_ips.txt"
KEV_FILE = TI_DIR / "kev.json"
META_FILE = TI_DIR / "meta.json"
MERGED_IOC_FILE = TI_DIR / "ioc_ips_merged.txt"
STATIC_IOC_FILE = Path(__file__).resolve().parent.parent / "kali" / "ioc_ips.txt"

_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_cache: Dict[str, Any] = {"sig": None, "feodo": set(), "static": set(), "kev": {}}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)   # inherits data/'s setgid + group
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        os.chown(tmp, -1, path.parent.stat().st_gid)   # keep group 'soc' even without setgid
    except PermissionError:
        pass
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sentinel-soc-threat-intel/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read(MAX_FEED_BYTES + 1)
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed larger than expected")
    return data


def _parse_ip_list(text: str) -> set:
    ips = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            ips.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return ips


def _load_meta() -> Dict[str, Any]:
    try:
        return json.loads(META_FILE.read_text())
    except (OSError, ValueError):
        return {}


def refresh() -> Dict[str, Any]:
    """Download both feeds. Returns {feed: {"ok": bool, ...}}; keeps old data on failure."""
    meta = _load_meta()
    result: Dict[str, Any] = {}

    try:
        text = _fetch(FEODO_URL).decode("utf-8", "replace")
        ips = _parse_ip_list(text)
        if "Feodo" not in text:
            raise ValueError("response does not look like the Feodo blocklist")
        _atomic_write(FEODO_FILE, "\n".join(sorted(ips)) + ("\n" if ips else ""))
        meta["feodo"] = {"fetched": _now(), "count": len(ips)}
        result["feodo"] = {"ok": True, "count": len(ips)}
    except Exception as e:  # network, format, disk: keep the previous copy
        result["feodo"] = {"ok": False, "error": str(e)}

    try:
        data = json.loads(_fetch(KEV_URL))
        vulns = data["vulnerabilities"]
        if not isinstance(vulns, list) or len(vulns) < KEV_MIN_ENTRIES:
            raise ValueError(f"only {len(vulns) if isinstance(vulns, list) else 'no'} entries -- refusing to replace")
        slim = {v["cveID"].upper(): {
                    "name": v.get("vulnerabilityName"), "vendor": v.get("vendorProject"),
                    "product": v.get("product"), "added": v.get("dateAdded"), "due": v.get("dueDate"),
                    "ransomware": str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"}
                for v in vulns if v.get("cveID")}
        _atomic_write(KEV_FILE, json.dumps(slim))
        meta["kev"] = {"fetched": _now(), "count": len(slim), "catalog_version": data.get("catalogVersion")}
        result["kev"] = {"ok": True, "count": len(slim)}
    except Exception as e:
        result["kev"] = {"ok": False, "error": str(e)}

    _atomic_write(META_FILE, json.dumps(meta, indent=2))
    _write_merged()
    return result


def _read_static() -> set:
    try:
        return _parse_ip_list(STATIC_IOC_FILE.read_text())
    except OSError:
        return set()


def _write_merged() -> None:
    """One IP-per-line list (local + Feodo) for the traffic monitor's IOC check."""
    try:
        feodo = _parse_ip_list(FEODO_FILE.read_text())
    except OSError:
        feodo = set()
    merged = sorted(_read_static() | feodo)
    _atomic_write(MERGED_IOC_FILE, "# generated by threat_intel.py -- local IOCs + Feodo Tracker\n"
                  + "\n".join(merged) + "\n")


def _load() -> Dict[str, Any]:
    sig = []
    for p in (FEODO_FILE, KEV_FILE, STATIC_IOC_FILE):
        try:
            st = p.stat()
            sig.append((st.st_mtime_ns, st.st_size))
        except OSError:
            sig.append(None)
    sig = tuple(sig)
    if _cache["sig"] != sig:
        try:
            feodo = _parse_ip_list(FEODO_FILE.read_text())
        except OSError:
            feodo = set()
        try:
            kev = json.loads(KEV_FILE.read_text())
        except (OSError, ValueError):
            kev = {}
        _cache.update(sig=sig, feodo=feodo, static=_read_static(), kev=kev)
    return _cache


def enrich(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Threat-intel matches for an alert record, or None."""
    ti = _load()
    details = record.get("details") or {}

    ip_matches, seen = [], set()
    ips = [(e["value"], e.get("role", "")) for e in details.get("entities", []) if e.get("type") == "ip"]
    if not ips and record.get("source_ip"):
        ips = [(record["source_ip"], "source")]
    for ip, role in ips:
        for feed, members in (("feodotracker", ti["feodo"]), ("local_ioc", ti["static"])):
            if ip in members and (ip, feed) not in seen:
                seen.add((ip, feed))
                ip_matches.append({"indicator": ip, "feed": feed, "role": role})

    kev = []
    text = " ".join(str(x) for x in (record.get("title"), record.get("description"),
                                      details.get("signature"), details.get("msg")) if x)
    for cve in dict.fromkeys(c.upper() for c in _CVE.findall(text)):
        entry = ti["kev"].get(cve)
        if entry:
            kev.append({"cve": cve, **entry})

    if not ip_matches and not kev:
        return None
    out: Dict[str, Any] = {}
    if ip_matches:
        out["ip_matches"] = ip_matches
    if kev:
        out["kev"] = kev
    return out


def _status() -> int:
    meta = _load_meta()
    for feed in ("feodo", "kev"):
        m = meta.get(feed)
        print(f"{feed}: " + (f"{m['count']} entries, fetched {m['fetched']}" if m else "never fetched"))
    ti = _load()
    print(f"loaded: {len(ti['feodo'])} Feodo IPs, {len(ti['static'])} local IOC IPs, {len(ti['kev'])} KEV CVEs")
    return 0


if __name__ == "__main__":
    if "--refresh" in sys.argv:
        res = refresh()
        for feed, r in res.items():
            print(f"{feed}: " + (f"ok, {r['count']} entries" if r["ok"] else f"FAILED ({r['error']}) -- kept previous copy"))
        sys.exit(0 if all(r["ok"] for r in res.values()) else 1)
    sys.exit(_status())
