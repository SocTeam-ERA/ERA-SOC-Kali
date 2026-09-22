#!/usr/bin/env python3
"""
soc_views.py -- read-only aggregations behind the API's investigation pages:
entities with a risk score, metrics, the detection catalog and source health.

Nothing here writes anything; every function derives its answer from the live
snapshot, alerts.jsonl, the incident store and the config files.
"""
from __future__ import annotations

import json
import re
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import median
from typing import Any, Dict, List, Optional

import alert_context
import correlate
import mitre_tags
import soc_core
import suppressions

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "kali"))


def _tunables() -> Dict[str, Dict[str, Any]]:
    """Live threshold/config values read straight from each detector module's own
    constants, not copied by hand -- so this stays correct when someone tunes an
    env var or edits a default, instead of silently drifting like a hand-written
    doc would. Any module that fails to import (missing optional dependency,
    wrong cwd) is just left out rather than breaking the whole catalog."""
    out: Dict[str, Dict[str, Any]] = {}
    try:
        import nmap_to_alerts as m
        out["kali_scan"] = {
            "new_high_risk_port_severity": "medium (remote-access/file-share/database ports)",
            "high_risk_ports": sorted(m.HIGH_RISK_PORTS),
            "bulk_alert_after_ports": m.HOST_BULK_THRESHOLD,
            "vuln_finding_gone_after_hours": m.VULN_GONE_HOURS,
        }
    except Exception:
        pass
    try:
        import arp_to_alerts as m
        out["arp_discovery"] = {"bulk_alert_after_devices": m.ARP_BULK_THRESHOLD}
    except Exception:
        pass
    try:
        import aide_to_alerts as m
        out["aide"] = {
            "critical_path_prefixes": list(m.CRITICAL_PREFIXES),
            "medium_path_prefixes": list(m.MEDIUM_PREFIXES),
            "bulk_alert_after_files": m.AIDE_BULK_THRESHOLD,
        }
    except Exception:
        pass
    # login_monitor's brute-force threshold/window are CLI flags (soc-login.service runs
    # with no override, so these are its --threshold/--window defaults, not live constants).
    out["login_monitor"] = {"brute_force_threshold": "5 failed logins", "brute_force_window_seconds": 120}
    try:
        import login_monitor as m
        out["login_monitor"]["new_ip_cooldown_hours"] = m.NEW_IP_COOLDOWN / 3600
    except Exception:
        pass
    return out

# ---- risk ------------------------------------------------------------------ #
# An entity's risk is the sum of its unresolved alerts' points, each halving
# every 3 days, plus a bonus per open incident, capped at 100.
POINTS = {"critical": 20.0, "medium": 5.0, "normal": 0.0}
HALF_LIFE_DAYS = 3.0
INCIDENT_BONUS = {"critical": 25.0, "medium": 10.0}
_MAC = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")


def _epoch(ts: Any) -> float:
    try:
        dt = datetime.fromisoformat(str(ts))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _risk_level(score: float) -> str:
    return "high" if score >= 60 else "medium" if score >= 25 else "low" if score > 0 else "none"


def _entities_of(alert: Dict[str, Any]) -> List[Dict[str, str]]:
    ents = (alert.get("details") or {}).get("entities")
    return ents if ents is not None else alert_context.entities(alert)


_asset_cache: Dict[str, Any] = {"sig": None, "by_mac": {}, "by_ip": {}, "mac_ips": {}}


def _assets() -> Dict[str, Any]:
    """Asset lookups by MAC and by IP, rebuilt only when assets.json changes."""
    try:
        st = (soc_core.DATA_DIR / "assets.json").stat()
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        return _asset_cache
    if _asset_cache["sig"] != sig:
        by_mac, by_ip, mac_ips = {}, {}, defaultdict(list)
        for rec in soc_core.load_assets().values():
            m = _MAC.match(str(rec.get("mac") or ""))
            if m:
                by_mac[m.group(0).lower()] = rec
            if rec.get("ip"):
                by_ip[rec["ip"]] = rec
                if m:
                    mac_ips[m.group(0).lower()].append(rec["ip"])
        _asset_cache.update(sig=sig, by_mac=by_mac, by_ip=by_ip, mac_ips=mac_ips)
    return _asset_cache


def _mac_ips() -> Dict[str, List[str]]:
    return _assets()["mac_ips"]


def canonical(key: str) -> str:
    """ip:X becomes mac:M when the asset inventory knows that IP's MAC."""
    kind, _, value = key.partition(":")
    if kind == "ip":
        mac = alert_context._ip_to_mac().get(value)
        if mac:
            return f"mac:{mac}"
    return key


_index_cache: Dict[str, Any] = {"sig": None, "index": {}}


def _entity_index() -> Dict[str, Dict[str, Any]]:
    """canonical entity key -> {"alerts": [...], "source_alerts": [...]}; cached per snapshot version."""
    try:
        st = soc_core.ALERTS_SNAPSHOT.stat()
        sig = (st.st_mtime_ns, st.st_size, time.time() // 30)
    except OSError:
        return {}
    if _index_cache["sig"] == sig:
        return _index_cache["index"]
    index: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"alerts": [], "source_alerts": []})
    ignore = correlate._self_ips()
    for a in soc_core._load_snapshot():
        seen_all, seen_src = set(), set()
        for e in _entities_of(a):
            key = f"{e['type']}:{e['value']}"
            if key in ignore or e["type"] not in ("ip", "mac", "host", "user"):
                continue
            ck = canonical(key)
            if ck not in seen_all:
                seen_all.add(ck)
                index[ck]["alerts"].append(a)
            if e.get("role") == "source" and ck not in seen_src:
                seen_src.add(ck)
                index[ck]["source_alerts"].append(a)
    _index_cache.update(sig=sig, index=index)
    return index


def _score(alerts: List[Dict[str, Any]], incidents: List[Dict[str, Any]], now: float) -> float:
    total = 0.0
    for a in alerts:
        if a.get("status", "open") == "resolved":
            continue
        age_days = max(0.0, (now - _epoch(a.get("timestamp"))) / 86400)
        total += POINTS.get(a.get("severity"), 0.0) * 0.5 ** (age_days / HALF_LIFE_DAYS)
    for inc in incidents:
        if inc["status"] != "closed":
            total += INCIDENT_BONUS.get(inc["severity"], 0.0)
    return round(min(100.0, total), 1)


def _incidents_for(key: str, incidents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [inc for inc in incidents
            if key in {canonical(f"{e['type']}:{e['value']}") for e in inc["entities"]}]


def _asset_for(key: str) -> Optional[Dict[str, Any]]:
    kind, _, value = key.partition(":")
    cache = _assets()
    return cache["by_mac"].get(value) if kind == "mac" else cache["by_ip"].get(value) if kind == "ip" else None


def _summary(key: str, data: Dict[str, Any], incidents: List[Dict[str, Any]], now: float) -> Dict[str, Any]:
    kind, _, value = key.partition(":")
    mine = _incidents_for(key, incidents)
    alerts = data["source_alerts"]
    counts = Counter(a.get("severity") for a in data["alerts"] if a.get("status", "open") != "resolved")
    score = _score(alerts, mine, now)
    out: Dict[str, Any] = {
        "key": key, "type": kind, "value": value,
        "risk": score, "risk_level": _risk_level(score),
        "open_alerts": {"critical": counts["critical"], "medium": counts["medium"], "normal": counts["normal"]},
        "incidents_open": sum(1 for i in mine if i["status"] != "closed"),
        "last_seen": max((a.get("timestamp", "") for a in data["alerts"]), default=None),
    }
    if kind == "mac":
        out["ips"] = _mac_ips().get(value, [])
        asset = _asset_for(key)
        if asset:
            out["vendor"], out["owner"], out["vlan"] = asset.get("vendor"), asset.get("owner"), asset.get("cidr")
    return out


def entities(kind: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Entities ranked by risk (highest first)."""
    now = time.time()
    incidents = correlate.list_incidents()
    rows = [_summary(k, v, incidents, now) for k, v in _entity_index().items()
            if not kind or k.startswith(kind + ":")]
    rows.sort(key=lambda r: (r["risk"], r["last_seen"] or ""), reverse=True)
    return rows[:limit]


def entity_detail(ref: str) -> Optional[Dict[str, Any]]:
    """One entity's page: summary, asset record, incidents, techniques and its alert timeline."""
    key = canonical(ref)
    data = _entity_index().get(key)
    if data is None:
        return None
    now = time.time()
    incidents = correlate.list_incidents()
    out = _summary(key, data, incidents, now)
    alerts = sorted(data["alerts"], key=lambda a: a.get("timestamp", ""), reverse=True)
    techs: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        for t in (a.get("details") or {}).get("mitre", []):
            cur = techs.setdefault(t["technique"], {**t, "count": 0})
            cur["count"] += 1
    out.update(asset=_asset_for(key), incidents=_incidents_for(key, incidents),
               techniques=sorted(techs.values(), key=lambda t: -t["count"]),
               timeline=alerts[:200], alert_count=len(alerts))
    return out


# ---- history-based aggregates (alerts.jsonl, cached) ------------------------ #
_hist_cache: Dict[str, Any] = {"sig": None, "rows": []}


def _history() -> List[Dict[str, Any]]:
    try:
        st = soc_core.ALERTS_LOG.stat()
    except OSError:
        return []
    sig = (st.st_mtime_ns, st.st_size)
    if _hist_cache["sig"] != sig:
        rows = []
        with soc_core.ALERTS_LOG.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                rows.append({"t": _epoch(r.get("timestamp")), "detector": r.get("detector"),
                             "severity": r.get("severity"), "mitre": (r.get("details") or {}).get("mitre", [])})
        _hist_cache.update(sig=sig, rows=rows)
    return _hist_cache["rows"]


def metrics() -> Dict[str, Any]:
    now = time.time()
    hist = _history()
    snap = soc_core._load_snapshot()
    days = 14
    per_day: Dict[str, Counter] = {}
    for i in range(days):
        d = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        per_day[d] = Counter()
    week = now - 7 * 86400
    detectors, tactics = Counter(), Counter()
    for r in hist:
        d = datetime.fromtimestamp(r["t"], tz=timezone.utc).strftime("%Y-%m-%d")
        if d in per_day:
            per_day[d][r["severity"]] += 1
        if r["t"] >= week:
            detectors[r["detector"]] += 1
            for t in r["mitre"]:
                for tac in t.get("tactics", []):
                    tactics[tac] += 1
    open_alerts = [a for a in snap if a.get("status", "open") == "open"]
    incs = correlate.list_incidents()
    audit: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    try:
        for line in correlate.INCIDENT_LOG.read_text().splitlines():
            r = json.loads(line)
            audit[r["incident_id"]].append(r)
    except (OSError, ValueError):
        pass
    ack_minutes, close_minutes = [], []
    for inc in incs:
        created = _epoch(inc["created"])
        human = [ev for ev in audit.get(inc["id"], [])
                 if ev["action"] == "updated" and ev["actor"] != "correlation"
                 and (ev.get("changes") or {}).get("status")]
        if human:
            ack_minutes.append((_epoch(human[0]["at"]) - created) / 60)
        closed = [ev for ev in human if ev["changes"]["status"][1] == "closed"]
        if closed:
            close_minutes.append((_epoch(closed[-1]["at"]) - created) / 60)
    sources = Counter(s["status"] for s in _sources().get("sources", []))
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "alerts": {
            "in_feed": len(snap),
            "open": len(open_alerts),
            "open_by_severity": dict(Counter(a.get("severity") for a in open_alerts)),
            "per_day_utc": [{"date": d, "critical": c["critical"], "medium": c["medium"], "normal": c["normal"]}
                            for d, c in sorted(per_day.items())],
            "top_detectors_7d": [{"detector": d, "count": n} for d, n in detectors.most_common(8)],
            "mitre_tactics_7d": [{"tactic": t, "count": n} for t, n in tactics.most_common()],
        },
        "incidents": {
            "open_by_status": dict(Counter(i["status"] for i in incs if i["status"] != "closed")),
            "open_by_severity": dict(Counter(i["severity"] for i in incs if i["status"] != "closed")),
            "closed_total": sum(1 for i in incs if i["status"] == "closed"),
            "mtta_minutes_median": round(median(ack_minutes), 1) if ack_minutes else None,
            "mttr_minutes_median": round(median(close_minutes), 1) if close_minutes else None,
        },
        "top_risk_entities": entities(limit=5),
        "sources": dict(sources),
    }


# ---- catalog ---------------------------------------------------------------- #
DETECTORS = {
    "kali_scan": ("Scheduled network scan", "Open-port changes and vulnerabilities found by nmap on every VLAN."),
    "port_scanner": ("Manual port scan", "Unexpected open ports found by a manual scan."),
    "arp_discovery": ("ARP discovery", "New devices appearing on any VLAN."),
    "aide": ("File integrity (AIDE)", "Changes to files on this appliance."),
    "login_monitor": ("Login monitor", "Brute force, unknown-IP and post-failure logins on SSH."),
    "suricata": ("Suricata IDS", "Network intrusion signatures (scans, exploits, Tor, DDoS)."),
    "zeek": ("Zeek network analysis", "Zeek notices such as SSH password guessing and invalid TLS certificates."),
    "traffic_capture": ("Live traffic monitor", "Port scans on the wire, cleartext protocols, known-bad IPs and DNS."),
    "osquery": ("osquery", "New scheduled tasks and setuid binaries on this appliance."),
    "chkrootkit": ("chkrootkit", "Rootkit indicators such as unrecognized packet sniffers."),
    "vlan_segmentation": ("VLAN segmentation test", "VLAN pairs that can reach each other."),
    "malware_detector": ("Malware detector", "Suspicious files by hash, YARA and heuristics."),
    "phishing_detector": ("Phishing detector", "Phishing indicators in email."),
    "nikto": ("Nikto", "Web server findings."),
    "whatweb": ("WhatWeb", "Web technology fingerprints."),
    "service_watchdog": ("Service watchdog", "This platform's own services being down."),
    "source_health": ("Data source health", "A data source that stopped producing data."),
    "disk_space_check": ("Disk space", "Disk usage of this appliance."),
    "system_updates": ("System updates", "Pending package updates."),
    "soc_doctor": ("Pipeline health check", "Permission and scan-marker problems."),
    "correlation": ("Correlation engine", "Incidents opened from related alerts."),
}


def _sources() -> Dict[str, Any]:
    try:
        return json.loads((soc_core.DATA_DIR / "source_health.json").read_text())
    except (OSError, ValueError):
        return {"checked": None, "sources": []}


def sources() -> Dict[str, Any]:
    return _sources()


def detections() -> Dict[str, Any]:
    now = time.time()
    hist = _history()
    c7, c30 = Counter(), Counter()
    tech30: Counter = Counter()
    sev30: Dict[str, Counter] = defaultdict(Counter)
    last_seen: Dict[str, float] = {}
    for r in hist:
        last_seen[r["detector"]] = max(last_seen.get(r["detector"], 0.0), r["t"])
        if r["t"] >= now - 30 * 86400:
            c30[r["detector"]] += 1
            sev30[r["detector"]][r["severity"]] += 1
            for t in r["mitre"]:
                tech30[t["technique"]] += 1
            if r["t"] >= now - 7 * 86400:
                c7[r["detector"]] += 1
    det_mitre = mitre_tags.detector_techniques()
    tunables = _tunables()
    detectors = [{"id": k, "name": v[0], "description": v[1], "alerts_7d": c7[k], "alerts_30d": c30[k],
                 "by_severity_30d": dict(sev30[k]),
                 "last_alert_at": (datetime.fromtimestamp(last_seen[k], tz=timezone.utc).isoformat()
                                   if k in last_seen else None),
                 "mitre": det_mitre.get(k, []),
                 "tunables": tunables.get(k, {})}
                for k, v in DETECTORS.items()]
    cov = mitre_tags.coverage_map()
    by_tactic: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for tid, dets in cov.items():
        name, tactics = mitre_tags.TECHNIQUES[tid]
        for tac in tactics:
            by_tactic[tac].append({"technique": tid, "name": name, "detectors": dets, "alerts_30d": tech30[tid]})
    incs = correlate.list_incidents()
    per_rule = Counter(i["rule_id"] for i in incs)
    rules, _, rule_errors = correlate.load_rules()
    sup_rules, sup_errors = suppressions.load_rules()
    sup_hits: Counter = Counter()
    try:
        for line in (soc_core.SUPPRESSED_LOG).read_text().splitlines():
            try:
                sup_hits[json.loads(line).get("suppressed_by")] += 1
            except ValueError:
                continue
    except OSError:
        pass
    return {
        "detectors": detectors,
        "mitre_coverage": [{"tactic": t, "techniques": sorted(v, key=lambda x: x["technique"])}
                           for t, v in sorted(by_tactic.items())],
        "correlation_rules": [{"id": r["id"], "name": r["name"], "type": r["type"], "severity": r["severity"],
                               "enabled": r["enabled"], "incidents": per_rule[r["id"]]} for r in rules],
        "correlation_errors": rule_errors,
        "suppression_rules": [{"id": r["id"], "reason": r["reason"], "match": r["raw"].get("match"),
                               "allow_critical": r["allow_critical"], "source": r["source"],
                               "expires": r["expires"].isoformat() if r["expires"] else None,
                               "expired": suppressions.is_expired(r), "hits_total": sup_hits[r["id"]]}
                              for r in sup_rules],
        "suppression_errors": sup_errors,
    }
