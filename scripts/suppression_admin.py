#!/usr/bin/env python3
"""
suppression_admin.py -- create and remove suppression rules from the dashboard.

Rules made here live in data/suppressions_dashboard.json (runtime state, not in
git); the versioned, hand-edited rules stay in config/suppressions.json and are
read-only from the API. Both are evaluated by suppressions.py.

Guard rails, because a suppression is a blind spot someone chose:
  * A rule made here always expires (default 30 days, at most 365).
  * It can never hide critical alerts; that needs allow_critical in the config file.
  * It must name a detector and one more narrowing criterion, so "hide every
    medium alert" cannot be created by accident.
  * Clients never send regular expressions (a bad one could stall alert
    processing). Rules are built from an alert with a preset, or from plain
    fields: detector, type, severity, source_ip, title_contains, title_template, details.
  * Every create/delete is appended to data/suppressions_log.jsonl with the actor.
  * preview() says how many alerts a rule would hide before it is created.
"""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import alert_context
import alert_match
import soc_core
import suppressions

DEFAULT_DAYS, MAX_DAYS = 30, 365
MAX_RULES = 200
MIN_REASON, MAX_REASON = 5, 500
_ALLOWED_KEYS = {"detector", "type", "severity", "source_ip", "title_contains", "title_template", "details"}
_NARROWING = ("details", "source_ip", "title_contains", "title_template")
_LOCK = soc_core.DATA_DIR / ".suppressions.lock"
_LOG = soc_core.DATA_DIR / "suppressions_log.jsonl"


def _find_alert(alert_id: str) -> Dict[str, Any]:
    for a in soc_core._load_snapshot():
        if a.get("id") == alert_id:
            return a
    raise ValueError(f"alert not found in the live feed: {alert_id}")


def match_from_alert(alert: Dict[str, Any], scope: str) -> Dict[str, Any]:
    """Build a rule from an alert.
    similar  same title with any IP/MAC (numbers such as ports stay exact)
    host     `similar`, but only from this alert's source IP
    broad    every alert of this detector with the same group_key: numbers are
             blanked there, so e.g. one port stands for all ports. Check the preview."""
    if scope not in ("similar", "host", "broad"):
        raise ValueError("scope must be 'similar', 'host' or 'broad'")
    if alert.get("severity") == "critical":
        raise ValueError("critical alerts cannot be suppressed from the dashboard; "
                         "add a rule with allow_critical to config/suppressions.json if you really need to")
    det = alert.get("detector")
    if not det:
        raise ValueError("this alert has no detector, so a safe rule cannot be built from it")
    if scope == "broad":
        key = (alert.get("details") or {}).get("group_key") or alert_context.group_key(alert)
        return {"detector": det, "details": {"group_key": key}}
    match: Dict[str, Any] = {"detector": det, "title_template": alert_match.template_from_title(alert.get("title") or "")}
    if scope == "host":
        if not alert.get("source_ip"):
            raise ValueError("this alert has no source IP; use scope 'similar'")
        match["source_ip"] = alert["source_ip"]
    return match


def _validate_match(match: Any) -> Dict[str, Any]:
    if not isinstance(match, dict):
        raise ValueError("match must be an object")
    unknown = set(match) - _ALLOWED_KEYS
    if unknown:
        raise ValueError(f"match key(s) {sorted(unknown)} are not allowed from the dashboard "
                         f"(allowed: {sorted(_ALLOWED_KEYS)})")
    if not isinstance(match.get("detector"), str) or not match["detector"].strip():
        raise ValueError("match must include a detector")
    if not any(k in match for k in _NARROWING):
        raise ValueError("match must also narrow the rule with details, source_ip, title_contains or title_template")
    sev = match.get("severity")
    if sev is not None:
        sevs = [sev] if isinstance(sev, str) else sev
        if not isinstance(sevs, list) or "critical" in sevs:
            raise ValueError("a dashboard rule cannot target critical alerts")
    alert_match.compile_match(match)          # raises ValueError on anything malformed
    return match


def _is_critical(record: Dict[str, Any]) -> bool:
    return record.get("severity") == "critical"


def preview(match: Dict[str, Any], days: int = 30) -> Dict[str, Any]:
    """How many alerts this match would have hidden (never counts critical ones)."""
    cm = alert_match.compile_match(_validate_match(match))

    def hits(rec: Dict[str, Any]) -> bool:
        if _is_critical(rec):
            return False
        d = rec.get("details") or {}
        if "group_key" not in d:
            rec = {**rec, "details": {**d, "group_key": alert_context.group_key(rec)}}
        return alert_match.matches(cm, rec)

    feed = [a for a in soc_core._load_snapshot() if a.get("status", "open") == "open" and hits(a)]
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    hist, sample = 0, []
    try:
        with soc_core.ALERTS_LOG.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("timestamp", "") >= cutoff and hits(rec):
                    hist += 1
                    if len(sample) < 5 and rec.get("title") not in sample:
                        sample.append(rec.get("title"))
    except OSError:
        pass
    return {"feed_open": len(feed), "history_days": days, "history_count": hist, "sample_titles": sample}


def _read_rules() -> List[Dict[str, Any]]:
    try:
        return json.loads(suppressions.DASHBOARD_FILE.read_text()).get("rules", [])
    except (OSError, ValueError):
        return []


def _write_rules(rules: List[Dict[str, Any]]) -> None:
    path = suppressions.DASHBOARD_FILE
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"rules": rules}, f, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _audit(actor: str, action: str, rule: Dict[str, Any]) -> None:
    with _LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "actor": actor,
                             "action": action, "rule": rule}) + "\n")


def create_rule(actor: str, reason: str, match: Optional[Dict[str, Any]] = None,
                alert_id: Optional[str] = None, scope: str = "similar",
                expires_days: int = DEFAULT_DAYS, resolve_existing: bool = False) -> Dict[str, Any]:
    reason = (reason or "").strip() if isinstance(reason, str) else ""
    if not MIN_REASON <= len(reason) <= MAX_REASON:
        raise ValueError(f"reason is required ({MIN_REASON}-{MAX_REASON} characters): say why this is safe to ignore")
    if isinstance(expires_days, bool) or not isinstance(expires_days, int) or not 1 <= expires_days <= MAX_DAYS:
        raise ValueError(f"expires_days must be an integer between 1 and {MAX_DAYS}")
    if (match is None) == (alert_id is None):
        raise ValueError("send either 'alert_id' (with 'scope') or 'match', not both")
    if alert_id is not None:
        match = match_from_alert(_find_alert(alert_id), scope)
    match = _validate_match(match)

    with _LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            rules = _read_rules()
            if len(rules) >= MAX_RULES:
                raise ValueError(f"too many dashboard rules ({MAX_RULES}); delete some first")
            n = max((int(r["id"].split("-")[-1]) for r in rules if r.get("id", "").startswith("ui-")
                     and r["id"].split("-")[-1].isdigit()), default=0) + 1
            today = datetime.now(timezone.utc).date()
            rule = {"id": f"ui-{n:03d}", "reason": reason, "added_by": actor, "added": today.isoformat(),
                    "expires": (today + timedelta(days=expires_days)).isoformat(), "match": match}
            rules.append(rule)
            _write_rules(rules)
            _audit(actor, "created", rule)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)

    resolved = 0
    if resolve_existing:
        cm = alert_match.compile_match(match)
        for a in soc_core._load_snapshot():
            if a.get("status", "open") != "open" or _is_critical(a):
                continue
            rec = a if "group_key" in (a.get("details") or {}) else \
                {**a, "details": {**(a.get("details") or {}), "group_key": alert_context.group_key(a)}}
            if alert_match.matches(cm, rec):
                try:
                    soc_core.set_alert_status(a["id"], "resolved", actor=actor,
                                              note=f"Suppression rule {rule['id']} created: {reason}")
                    resolved += 1
                except ValueError:
                    continue
    return {"rule": rule, "resolved_existing": resolved}


def delete_rule(rule_id: str, actor: str) -> Dict[str, Any]:
    with _LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            rules = _read_rules()
            target = next((r for r in rules if r.get("id") == rule_id), None)
            if target is None:
                cfg, _ = suppressions.load_rules()
                if any(r["id"] == rule_id for r in cfg):
                    raise ValueError(f"rule {rule_id} is defined in config/suppressions.json; edit that file to remove it")
                raise ValueError(f"rule not found: {rule_id}")
            _write_rules([r for r in rules if r is not target])
            _audit(actor, "deleted", target)
            return target
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


def list_detail() -> Dict[str, Any]:
    rules, errors = suppressions.load_rules()
    now = datetime.now(timezone.utc)
    hits_total: Dict[str, int] = {}
    hits_24h: Dict[str, int] = {}
    cutoff = (now - timedelta(hours=24)).isoformat()
    try:
        with soc_core.SUPPRESSED_LOG.open(encoding="utf-8") as fh:
            for line in fh:
                try:
                    r = json.loads(line)
                except ValueError:
                    continue
                rid = r.get("suppressed_by")
                hits_total[rid] = hits_total.get(rid, 0) + 1
                if r.get("timestamp", "") >= cutoff:
                    hits_24h[rid] = hits_24h.get(rid, 0) + 1
    except OSError:
        pass
    out = []
    for r in rules:
        raw = r["raw"]
        out.append({"id": r["id"], "source": r["source"], "reason": r["reason"], "added_by": raw.get("added_by"),
                    "added": raw.get("added"), "expires": r["expires"].isoformat() if r["expires"] else None,
                    "expired": suppressions.is_expired(r), "allow_critical": r["allow_critical"],
                    "match": raw["match"], "hits_total": hits_total.get(r["id"], 0),
                    "hits_24h": hits_24h.get(r["id"], 0)})
    return {"count": len(out), "rules": out, "errors": errors}
