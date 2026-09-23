#!/usr/bin/env python3
"""
weekly_report.py -- the weekly executive security report (GET /api/reports/weekly).

Splunk ES and Sentinel both ship a scheduled "security posture" report for management: what happened
this week compared with last week, what is still open, how well the team responded, and where the
blind spots are. This builds the same from data this appliance already keeps. It is meant to be read
by someone who does not use the dashboard, so it says what each number means and ends with what needs
a decision.

  build()        the report as a dict (JSON for the API and for the dashboard)
  to_markdown()  the same content as text, ready to paste into an e-mail or a document
  save()         writes data/reports/weekly_<date>.json and .md (weekly_digest.py calls it every Monday)

The window is a rolling 7 days ending now, compared with the 7 days before it. Times are shown in
Calgary time (the analysts' zone); the stored data stays UTC. Read-only apart from save().

    python3 weekly_report.py             print this week's report
    python3 weekly_report.py --save      also write it under data/reports/
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from zoneinfo import ZoneInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soc_core  # noqa: E402

LOCAL_TZ = ZoneInfo("America/Edmonton")
REPORT_DIR = soc_core.DATA_DIR / "reports"
SEVERITIES = ("critical", "medium", "normal")
_RANDOM_MAC_HINT = "locally administered"


def _epoch(ts: Any) -> float:
    try:
        dt = datetime.fromisoformat(str(ts))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (ValueError, TypeError):
        return 0.0


def _local(epoch: float, fmt: str = "%a %b %d %H:%M") -> str:
    return datetime.fromtimestamp(epoch, tz=LOCAL_TZ).strftime(fmt)


def _read_history(since_epoch: float) -> List[Dict[str, Any]]:
    """Real alerts (no tests, no 'RESOLVED' notices) newer than `since_epoch`, from the live
    history and its rotated predecessor, so a week that spans a rotation is not truncated."""
    out: List[Dict[str, Any]] = []
    for path in (Path(str(soc_core.ALERTS_LOG) + ".1"), soc_core.ALERTS_LOG):
        try:
            fh = path.open(encoding="utf-8")
        except OSError:
            continue
        with fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                if r.get("test") or str(r.get("title", "")).startswith("RESOLVED"):
                    continue
                t = _epoch(r.get("timestamp"))
                if t >= since_epoch:
                    r["_t"] = t
                    out.append(r)
    return out


def _is_random_mac(a: Dict[str, Any]) -> bool:
    return bool((a.get("details") or {}).get("locally_administered")) or _RANDOM_MAC_HINT in str(a.get("title", "")).lower()


def _collapse(rows: List[Dict[str, Any]], status_of: Dict[str, str], limit: int = 15) -> List[Dict[str, Any]]:
    """One line per (detector, kind of alert, day): a single event such as a hardening script
    changing 235 files raises 235 alerts, and a report that lists them all hides everything else.
    The kind is the title up to its first ':'."""
    groups: Dict[tuple, Dict[str, Any]] = {}
    for r in rows:                                         # `rows` arrive newest first
        title = str(r.get("title", ""))
        key = (r.get("detector"), title.split(":")[0], _local(r["_t"], "%Y-%m-%d"))
        g = groups.get(key)
        if g is None:
            g = groups[key] = {"at": datetime.fromtimestamp(r["_t"], tz=timezone.utc).isoformat(), "title": title,
                           "source_ip": r.get("source_ip"), "detector": r.get("detector"),
                           "status": status_of.get(r.get("id"), "unknown"), "count": 1, "statuses": Counter()}
            g["statuses"][g["status"]] += 1
        else:
            g["count"] += 1
            g["statuses"][status_of.get(r.get("id"), "unknown")] += 1
    out = []
    for g in list(groups.values())[:limit]:
        st = g.pop("statuses")
        if g["count"] > 1:
            g["title"] = f"{g['title'].split(':')[0]}: {g['count']} similar alerts (latest: {g['title']})"
            g["status"] = ", ".join(f"{n} {k}" for k, n in st.most_common())
        out.append(g)
    return out


def _dominant(rows: List[Dict[str, Any]], names: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """A detector that produced most of the week's alerts, and whether it was one burst: totals that
    come from a single event (a package update, a hardening run) overstate real activity."""
    if not rows:
        return None
    det, n = Counter(r.get("detector") for r in rows).most_common(1)[0]
    if n < 100 or n / len(rows) < 0.5:
        return None
    hours = Counter(int(r["_t"] // 3600) for r in rows if r.get("detector") == det)
    hour, in_hour = hours.most_common(1)[0]
    return {"detector": det, "name": names.get(det, det), "count": n, "share_pct": round(100 * n / len(rows)),
            "single_burst": in_hour / n >= 0.5, "peak_hour": _local(hour * 3600, "%a %b %d %H:00"), "peak_hour_count": in_hour}


def _delta(now: int, before: int) -> Dict[str, Any]:
    return {"now": now, "before": before, "change": now - before,
            "change_pct": round(100 * (now - before) / before) if before else None}


def build(now: Optional[float] = None, days: int = 7) -> Dict[str, Any]:
    import mitre_matrix
    import soc_activity
    import soc_views

    now = now or datetime.now(timezone.utc).timestamp()
    start, prev_start = now - days * 86400, now - 2 * days * 86400
    rows = _read_history(prev_start)
    this = [r for r in rows if r["_t"] >= start]
    before = [r for r in rows if r["_t"] < start]

    snap = [a for a in soc_core._load_snapshot() if not a.get("test")]
    status_of = {a.get("id"): a.get("status", "open") for a in snap}
    open_now = [a for a in snap if a.get("status", "open") == "open"]
    stale_open = [a for a in open_now if _epoch(a.get("timestamp")) < start and a.get("severity") in ("critical", "medium")]

    # --- alerts ---------------------------------------------------------------------------------
    sev_now, sev_before = Counter(r.get("severity") for r in this), Counter(r.get("severity") for r in before)
    detectors = Counter(r.get("detector") for r in this)
    tactics, techniques = Counter(), Counter()
    for r in this:
        for t in (r.get("details") or {}).get("mitre", []):
            techniques[(t["technique"], t["name"])] += 1
            for tac in t.get("tactics", []):
                tactics[tac] += 1
    critical = sorted((r for r in this if r.get("severity") == "critical"), key=lambda r: -r["_t"])
    names = {k: v[0] for k, v in soc_views.DETECTORS.items()}
    dominant = _dominant(this, names)
    hosts = Counter(r.get("source_ip") for r in this if r.get("severity") in ("critical", "medium") and r.get("source_ip"))

    # --- incidents --------------------------------------------------------------------------------
    import correlate
    incs = correlate.list_incidents()
    inc_new = [i for i in incs if _epoch(i.get("created")) >= start]
    metrics = soc_views.metrics()["incidents"]

    # --- vulnerabilities and exposure -----------------------------------------------------------
    vulns = [a for a in open_now if a.get("type") == "vuln"]
    vuln_top = sorted((a for a in vulns if a.get("severity") in ("critical", "medium")),
                      key=lambda a: (a.get("severity") != "critical", str(a.get("title"))))
    unsupported = sorted({a.get("source_ip") for a in open_now if str(a.get("title", "")).startswith("Unsupported Windows")})
    smb = sorted({a.get("source_ip") for a in open_now if str(a.get("title", "")).startswith("SMB signing not required")})

    # --- devices ----------------------------------------------------------------------------------
    new_dev = [r for r in this if r.get("detector") == "arp_discovery" and "New device" in str(r.get("title", ""))]
    assets = soc_core.load_assets()

    # --- analyst work -----------------------------------------------------------------------------
    activity = soc_activity.feed(since=f"{days}d", limit=500)
    by_cat = Counter(a["category"] for a in activity)
    by_actor = Counter(a["actor"] for a in activity)

    # --- data sources and coverage ----------------------------------------------------------------
    src = soc_views.sources().get("sources", [])
    unhealthy = [{"id": s["id"], "name": s.get("name"), "status": s["status"], "age_minutes": s.get("age_minutes")}
                 for s in src if s.get("status") not in ("healthy", "unknown")]
    outages = [r for r in this if r.get("detector") == "source_health" and "RESOLVED" not in str(r.get("title", ""))
               and r.get("severity") != "normal"]
    cov = mitre_matrix.matrix()

    attention: List[str] = []
    if dominant and dominant["single_burst"]:
        attention.append(f"{dominant['name']} produced {dominant['share_pct']}% of this week's alerts ({dominant['count']:,}), "
                         f"{dominant['peak_hour_count']:,} of them in one hour ({dominant['peak_hour']}). That is one event, "
                         "not a week of activity, so the totals below overstate what happened.")
    crit_open = sum(1 for a in open_now if a.get("severity") == "critical")
    if crit_open:
        attention.append(f"{crit_open} critical alert(s) are still open and need an owner.")
    if stale_open:
        attention.append(f"{len(stale_open)} medium/critical alert(s) have been open for more than {days} days.")
    if unhealthy:
        attention.append("Data source(s) not healthy: " + ", ".join(s["id"] for s in unhealthy) + ".")
    if cov["summary"]["limited"] or cov["summary"]["gap"]:
        top = cov["data_sources"][0]
        attention.append(f"Detection is limited by missing data, most of all '{top['label']}' "
                         f"(request {top['request']} to IT): it would improve {top['techniques_affected']} technique(s).")

    return {
        "generated": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
        "period": {"start": datetime.fromtimestamp(start, tz=timezone.utc).isoformat(),
                   "end": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(), "days": days,
                   "label": f"{_local(start, '%b %d')} to {_local(now, '%b %d, %Y')} (Calgary time)"},
        "alerts": {
            "new": _delta(len(this), len(before)),
            "by_severity": {s: _delta(sev_now[s], sev_before[s]) for s in SEVERITIES},
            "open_now": {"total": len(open_now), **{s: sum(1 for a in open_now if a.get("severity") == s) for s in SEVERITIES}},
            "open_older_than_period": len(stale_open),
            "top_detectors": [{"detector": d, "name": names.get(d, d), "count": n} for d, n in detectors.most_common(6)],
            "dominated_by": dominant,
            "top_tactics": [{"tactic": t, "count": n} for t, n in tactics.most_common(6)],
            "top_techniques": [{"technique": k[0], "name": k[1], "count": n} for k, n in techniques.most_common(6)],
            "critical": _collapse(critical, status_of),
            "critical_total": len(critical),
            "busiest_hosts": [{"source_ip": ip, "count": n} for ip, n in hosts.most_common(5)],
        },
        "incidents": {
            "opened": len(inc_new),
            "open_now": sum(1 for i in incs if i.get("status") != "closed"),
            "median_minutes_to_acknowledge": metrics.get("mtta_minutes_median"),
            "median_minutes_to_close": metrics.get("mttr_minutes_median"),
        },
        "exposure": {
            "open_vulnerabilities": len(vulns),
            "open_vulnerabilities_by_severity": {s: sum(1 for a in vulns if a.get("severity") == s) for s in SEVERITIES},
            "top_vulnerabilities": [{"source_ip": a.get("source_ip") or "Kali appliance", "severity": a.get("severity"), "title": a.get("title")}
                                    for a in vuln_top[:10]],
            "unsupported_windows_hosts": unsupported,
            "smb_signing_not_required_hosts": smb,
        },
        "devices": {"known": len(assets), "new_this_period": len(new_dev),
                    "new_randomized_wifi": sum(1 for a in new_dev if _is_random_mac(a))},
        "analyst_activity": {"actions": len(activity), "actions_capped": len(activity) >= 500, "by_category": dict(by_cat), "by_actor": dict(by_actor)},
        "data_sources": {"total": len(src), "not_healthy": unhealthy, "outage_alerts_this_period": len(outages)},
        "coverage": {"summary": cov["summary"],
                     "biggest_blind_spots": [{"label": s["label"], "request": s["request"], "techniques": s["techniques_affected"]}
                                             for s in cov["data_sources"][:3]]},
        "attention": attention,
    }


def _chg(d: Dict[str, Any]) -> str:
    if d["change"] == 0:
        return f"same as the week before ({d['before']:,})"
    if d["before"] == 0:
        return "none the week before"
    return f"{'up' if d['change'] > 0 else 'down'} {abs(d['change_pct'])}% from {d['before']:,} the week before"


def _minutes(m: Optional[float]) -> str:
    if m is None:
        return "no data yet"
    return f"{m:.0f} min" if m < 120 else f"{m / 60:.1f} h"


def to_markdown(r: Dict[str, Any]) -> str:
    a, inc, ex = r["alerts"], r["incidents"], r["exposure"]
    L: List[str] = [f"# Sentinel SOC weekly report", f"**{r['period']['label']}**", ""]

    L += ["## Needs attention"]
    L += [f"- {x}" for x in r["attention"]] or ["- Nothing urgent this week."]

    L += ["", "## The week in numbers",
          f"- **New alerts:** {a['new']['now']:,} ({_chg(a['new'])}).",
          f"  - Critical {a['by_severity']['critical']['now']:,} ({_chg(a['by_severity']['critical'])}).",
          f"  - Medium {a['by_severity']['medium']['now']:,} ({_chg(a['by_severity']['medium'])}).",
          f"  - Normal {a['by_severity']['normal']['now']:,} ({_chg(a['by_severity']['normal'])}).",
          f"- **Open right now:** {a['open_now']['total']} "
          f"(critical {a['open_now']['critical']}, medium {a['open_now']['medium']}, normal {a['open_now']['normal']}); "
          f"{a['open_older_than_period']} medium/critical have been open longer than a week.",
          f"- **Incidents:** {inc['opened']} opened, {inc['open_now']} open. Median time to acknowledge: "
          f"{_minutes(inc['median_minutes_to_acknowledge'])}; to close: {_minutes(inc['median_minutes_to_close'])}.",
          f"- **Devices:** {r['devices']['known']} known; {r['devices']['new_this_period']} new this week "
          f"({r['devices']['new_randomized_wifi']} of them phones or laptops using a randomized Wi-Fi address).",
          f"- **Analyst work:** {'at least ' if r['analyst_activity']['actions_capped'] else ''}{r['analyst_activity']['actions']} recorded actions "
          f"(status changes, suppressions, watchlist edits, playbook runs)."]

    L += ["", "## Critical alerts this week"]
    if a["critical"]:
        L += [f"{a['critical_total']:,} alert(s), grouped by kind and day so one event is one line:"]
        for c in a["critical"]:
            when = _local(_epoch(c["at"]))
            L.append(f"- {when} · {c['source_ip'] or 'this appliance'} · {c['title']} · *{c['status']}*")
    else:
        L.append("None.")

    L += ["", "## Where the alerts came from"]
    L += [f"- {d['name']}: {d['count']:,}" for d in a["top_detectors"]] or ["- No alerts."]
    if a["top_tactics"]:
        L += ["", "Attacker behavior seen (MITRE ATT&CK tactics): " + ", ".join(f"{t['tactic']} ({t['count']})" for t in a["top_tactics"]) + "."]
    if a["busiest_hosts"]:
        L += ["", "Machines with the most medium/critical alerts: " + ", ".join(f"{h['source_ip']} ({h['count']})" for h in a["busiest_hosts"]) + "."]

    L += ["", "## Known weaknesses still open",
          f"- {ex['open_vulnerabilities']} open vulnerability findings "
          f"(critical {ex['open_vulnerabilities_by_severity']['critical']}, medium {ex['open_vulnerabilities_by_severity']['medium']}, "
          f"normal {ex['open_vulnerabilities_by_severity']['normal']}).",
          f"- {len(ex['unsupported_windows_hosts'])} machine(s) run Windows that no longer receives security updates.",
          f"- {len(ex['smb_signing_not_required_hosts'])} machine(s) do not require SMB signing (exposed to credential relay)."]
    for v in ex["top_vulnerabilities"]:
        L.append(f"  - [{v['severity']}] {v['source_ip']}: {v['title']}")

    ds = r["data_sources"]
    L += ["", "## Monitoring health",
          (f"- All {ds['total']} data sources are reporting." if not ds["not_healthy"] else
           f"- {len(ds['not_healthy'])} of {ds['total']} data sources are not healthy: "
           + ", ".join(f"{s['id']} ({s['status']})" for s in ds["not_healthy"]) + "."),
          f"- Data-source outage alerts this week: {ds['outage_alerts_this_period']}."]

    cv = r["coverage"]["summary"]
    L += ["", "## Detection coverage (MITRE ATT&CK)",
          f"Of {cv['techniques_tracked']} tracked attacker techniques: {cv['covered']} are fully covered, "
          f"{cv['limited']} are covered only partly because a data source is missing, and {cv['gap']} have no detection yet.",
          "Largest blind spots, by missing data source:"]
    L += [f"- {b['label']} (request {b['request']}): affects {b['techniques']} technique(s)" for b in r["coverage"]["biggest_blind_spots"]]
    L += ["", f"_Generated {_local(_epoch(r['generated']), '%Y-%m-%d %H:%M')} Calgary time by the Sentinel SOC._"]
    return "\n".join(L) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def save(report: Optional[Dict[str, Any]] = None) -> Path:
    """Write the report as JSON and Markdown named after the day it covers up to (Calgary date);
    running it twice on the same day replaces that day's file."""
    report = report or build()
    stem = f"weekly_{_local(_epoch(report['generated']), '%Y-%m-%d')}"
    _atomic_write(REPORT_DIR / f"{stem}.json", json.dumps(report, indent=2))
    _atomic_write(REPORT_DIR / f"{stem}.md", to_markdown(report))
    return REPORT_DIR / f"{stem}.md"


_NAME = re.compile(r"^weekly_(\d{4}-\d{2}-\d{2})\.json$")


def list_reports(limit: int = 26) -> List[Dict[str, Any]]:
    """Saved reports, newest first (26 = half a year of weeklies)."""
    try:
        names = sorted((p.name for p in REPORT_DIR.iterdir() if _NAME.match(p.name)), reverse=True)
    except OSError:
        return []
    return [{"date": _NAME.match(n).group(1), "json": n, "markdown": n[:-5] + ".md"} for n in names[:limit]]


def load_saved(date: str) -> Optional[Dict[str, Any]]:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        return None
    try:
        return json.loads((REPORT_DIR / f"weekly_{date}.json").read_text())
    except (OSError, ValueError):
        return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Weekly executive security report")
    ap.add_argument("--save", action="store_true", help="also write data/reports/weekly_<date>.{json,md}")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    args = ap.parse_args()
    rep = build()
    print(json.dumps(rep, indent=2) if args.json else to_markdown(rep))
    if args.save:
        print(f"[*] saved {save(rep)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
