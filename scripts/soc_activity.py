#!/usr/bin/env python3
"""
soc_activity.py
----------------
A single, chronological "who did what, when" feed across every audit log this
project writes on its own (GET /api/activity) -- Splunk's Audit Trail / Sentinel's
Activity Log, for an appliance that otherwise keeps one separate log file per
subsystem: alert status changes, incidents, suppressions, watchlists, playbook
runs, asset annotations, and auto-aging closures. An analyst asking "what
changed in the last hour" had to check 7 files by hand, each in a different
shape; this just merges and normalizes them into one feed.

Read-only: never writes to any of the 7 logs, only tails them. Each source's
own file stays the source of truth and keeps its native schema, carried
verbatim under "raw" for anything category-specific a caller still needs.
"""
from __future__ import annotations

import json
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import log_search
import soc_core

DATA_DIR = soc_core.DATA_DIR

# Reading the last this-many lines of each source is enough for an activity
# feed (most recent first); a source that somehow wrote more than this between
# two calls just has its oldest entries skipped this once -- they're still in
# the file itself, nothing is lost, only a very old page of this specific feed.
MAX_LINES_PER_SOURCE = 5000


def _tail_jsonl(path: Path, n: int = MAX_LINES_PER_SOURCE) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out: deque = deque(maxlen=n)
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue  # one malformed line never breaks the whole source
    return list(out)


def _fmt_alert_status(e: Dict[str, Any]) -> Dict[str, Any]:
    note = f" ({e['note']})" if e.get("note") else ""
    return {
        "at": e.get("timestamp"), "actor": e.get("actor") or "unknown", "action": e.get("new_status") or "",
        "summary": f"set alert {str(e.get('alert_id', ''))[:8]} to {e.get('new_status')}"
                   f" (was {e.get('old_status')}){note}",
        "ref": e.get("alert_id"),
    }


def _fmt_asset_annotation(e: Dict[str, Any]) -> Dict[str, Any]:
    changed = e.get("changed") or []
    fields = ", ".join(changed) if isinstance(changed, list) else str(changed)
    return {
        "at": e.get("timestamp"), "actor": e.get("actor") or "unknown", "action": "annotated",
        "summary": f"annotated asset {e.get('mac')}" + (f" ({fields})" if fields else ""),
        "ref": e.get("mac"),
    }


def _fmt_incident(e: Dict[str, Any]) -> Dict[str, Any]:
    changes = e.get("changes") or {}
    detail = (", ".join(f"{k}={v}" for k, v in changes.items() if k != "alert_ids")
              if isinstance(changes, dict) else "")
    return {
        "at": e.get("at"), "actor": e.get("actor") or "unknown", "action": e.get("action") or "",
        "summary": f"{e.get('action')} incident {str(e.get('incident_id', ''))[:8]}" + (f" ({detail})" if detail else ""),
        "ref": e.get("incident_id"),
    }


def _fmt_playbook_run(e: Dict[str, Any]) -> Dict[str, Any]:
    acts = e.get("actions") or []
    acts_summary = ", ".join(f"{a.get('type')}={a.get('status')}" for a in acts) if isinstance(acts, list) else ""
    return {
        "at": e.get("at"), "actor": f"playbook:{e.get('playbook')}", "action": e.get("status") or "",
        "summary": (f"playbook {e.get('playbook')} {e.get('status')} for alert "
                    f"{str(e.get('alert_id', ''))[:8]} ({e.get('title')})" + (f" [{acts_summary}]" if acts_summary else "")),
        "ref": e.get("alert_id"),
    }


def _fmt_suppression(e: Dict[str, Any]) -> Dict[str, Any]:
    rule = e.get("rule")
    rid = rule.get("id") if isinstance(rule, dict) else rule
    return {
        "at": e.get("at"), "actor": e.get("actor") or "unknown", "action": e.get("action") or "",
        "summary": f"{e.get('action')} suppression {rid}",
        "ref": rid,
    }


def _fmt_watchlist(e: Dict[str, Any]) -> Dict[str, Any]:
    verb = "to" if e.get("action") == "added" else "from"
    return {
        "at": e.get("at"), "actor": e.get("actor") or "unknown", "action": e.get("action") or "",
        "summary": f"{e.get('action')} {e.get('entry')!r} {verb} watchlist {e.get('watchlist')}",
        "ref": e.get("watchlist"),
    }


def _fmt_alert_aging(e: Dict[str, Any]) -> Dict[str, Any]:
    closed = e.get("closed") or {}
    total = sum(closed.values()) if isinstance(closed, dict) else 0
    by_rule = ", ".join(f"{k}={v}" for k, v in closed.items()) if isinstance(closed, dict) else ""
    return {
        "at": e.get("at"), "actor": "auto-aging", "action": "closed",
        "summary": f"auto-closed {total} stale informational alert(s)" + (f" ({by_rule})" if by_rule else ""),
        "ref": None,
    }


# (category name, log file, per-line formatter) -- one entry per audit trail this
# project already writes elsewhere; add a source here to fold it into the feed.
_SOURCES = (
    ("alert_status", DATA_DIR / "alert_status_log.jsonl", _fmt_alert_status),
    ("asset_annotation", DATA_DIR / "asset_annotation_log.jsonl", _fmt_asset_annotation),
    ("incident", DATA_DIR / "incident_log.jsonl", _fmt_incident),
    ("playbook_run", DATA_DIR / "playbook_log.jsonl", _fmt_playbook_run),
    ("suppression", DATA_DIR / "suppressions_log.jsonl", _fmt_suppression),
    ("watchlist", DATA_DIR / "watchlist_log.jsonl", _fmt_watchlist),
    ("alert_aging", DATA_DIR / "alert_aging_log.jsonl", _fmt_alert_aging),
)

CATEGORIES = tuple(name for name, _, _ in _SOURCES)


def feed(category: Optional[str] = None, actor: Optional[str] = None,
         since: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """The merged, normalized, most-recent-first activity feed. `since` uses the
    same relative-duration convention as /api/search (90s, 15m, 6h, 2d) --
    raises ValueError on a bad value, same as log_search.parse_since(). Every
    source already writes RFC3339 UTC timestamps, which sort correctly as
    plain text, so the actual filtering below stays a string comparison."""
    cutoff = None
    if since:
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=log_search.parse_since(since))).isoformat()
    rows: List[Dict[str, Any]] = []
    for name, path, fmt in _SOURCES:
        if category and category != name:
            continue
        for e in _tail_jsonl(path):
            try:
                row = fmt(e)
            except Exception:
                continue  # one malformed/unexpected-shape line never breaks the whole feed
            if not row.get("at"):
                continue
            if cutoff and row["at"] < cutoff:
                continue
            if actor and row.get("actor") != actor:
                continue
            row["category"] = name
            rows.append(row)
    rows.sort(key=lambda r: r["at"], reverse=True)
    return rows[:max(1, min(limit, 500))]
