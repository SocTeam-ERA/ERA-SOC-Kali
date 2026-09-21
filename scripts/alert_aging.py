#!/usr/bin/env python3
"""
alert_aging.py -- close informational change alerts nobody reviewed.

Some alerts only say "something changed" (a port appeared, a finding stopped being
seen, a phone joined). They matter when they are fresh; after a few days they are
just weight in the open queue and bury the alerts that need a person. Rules in
config/alert_aging.json (override: SOC_AGING_FILE) say which alerts are closed
after how many days:

  {"rules": [
    {"id": "port-changes", "after_days": 3,
     "note": "optional text for the status note",
     "match": {"detector": "kali_scan", "title_regex": "^NEW open port",
               "severity": ["normal", "medium"]}}
  ]}

match is the criteria block of alert_match.py; it must name a detector. Guard rails:
  * critical alerts are never aged (a rule that targets them is rejected);
  * only open alerts are touched, never acknowledged ones;
  * an alert linked to an incident (details.incident_id) is never aged;
  * each closure goes through set_alert_status, so it has a note, the actor
    "auto-aging" and a line in alert_status_log.jsonl;
  * at most 300 alerts per run; invalid rules are ignored.

The watchdog runs run_if_due() every couple of minutes; it acts at most once every
6 hours. By hand:
    python3 alert_aging.py --dry-run    list what would be closed
    python3 alert_aging.py --run        close it now
"""
from __future__ import annotations

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alert_match  # noqa: E402
import soc_core  # noqa: E402

RULES_FILE = Path(os.environ.get(
    "SOC_AGING_FILE", Path(__file__).resolve().parent.parent / "config" / "alert_aging.json"))
STATE_FILE = soc_core.DATA_DIR / "alert_aging_state.json"
LOG_FILE = soc_core.DATA_DIR / "alert_aging_log.jsonl"
INTERVAL_SECONDS = 6 * 3600
MAX_PER_RUN = 300
_RULE_KEYS = {"id", "after_days", "note", "match"}


def _compile(raw: Any, seen: set) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid.strip() or rid in seen:
        raise ValueError("missing or duplicate 'id'")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ValueError(f"unknown key(s) {sorted(unknown)}")
    days = raw.get("after_days")
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 90:
        raise ValueError("after_days must be an integer between 1 and 90")
    match = raw.get("match")
    if not isinstance(match, dict) or "detector" not in match:
        raise ValueError("match must name a detector")
    sev = match.get("severity")
    if sev is not None and "critical" in ([sev] if isinstance(sev, str) else sev):
        raise ValueError("critical alerts are never aged")
    note = raw.get("note")
    if note is not None and (not isinstance(note, str) or len(note) > 300):
        raise ValueError("note must be text of at most 300 characters")
    return {"id": rid, "seconds": days * 86400, "days": days, "note": note, "cm": alert_match.compile_match(match)}


def load_rules() -> Tuple[List[Dict[str, Any]], List[str]]:
    if not RULES_FILE.exists():
        return [], []
    rules, errors, seen = [], [], set()
    try:
        raw_rules = json.loads(RULES_FILE.read_text())["rules"]
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' must be a list")
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [], [f"{RULES_FILE.name}: cannot read rules ({e}) -- nothing is being aged"]
    for i, raw in enumerate(raw_rules):
        label = raw.get("id", f"#{i + 1}") if isinstance(raw, dict) else f"#{i + 1}"
        try:
            rules.append(_compile(raw, seen))
            seen.add(rules[-1]["id"])
        except ValueError as e:
            errors.append(f"rule {label}: {e} -- ignored")
    return rules, errors


def _epoch(ts: Any) -> float:
    try:
        dt = datetime.fromisoformat(str(ts))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return time.time()


def candidates() -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
    """(alert, rule) pairs that are due to be closed, oldest first."""
    rules, _ = load_rules()
    now = time.time()
    out = []
    for a in soc_core._load_snapshot():
        if a.get("status", "open") != "open" or a.get("severity") == "critical":
            continue
        if (a.get("details") or {}).get("incident_id"):
            continue
        for rule in rules:
            if now - _epoch(a.get("timestamp")) >= rule["seconds"] and alert_match.matches(rule["cm"], a):
                out.append((a, rule))
                break
    out.sort(key=lambda p: p[0].get("timestamp", ""))
    return out


def run(dry_run: bool = False) -> Dict[str, Any]:
    due = candidates()
    closed: Dict[str, int] = {}
    n = 0
    if not dry_run:
        for a, rule in due[:MAX_PER_RUN]:
            note = rule["note"] or (f"Auto-closed by rule '{rule['id']}': an informational alert left open "
                                    f"more than {rule['days']} days without review.")
            try:
                soc_core.set_alert_status(a["id"], "resolved", note=note, actor="auto-aging")
            except ValueError:
                continue
            closed[rule["id"]] = closed.get(rule["id"], 0) + 1
            n += 1
        if n:
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "closed": closed}) + "\n")
    else:
        for _, rule in due:
            closed[rule["id"]] = closed.get(rule["id"], 0) + 1
    return {"due": len(due), "closed": n, "by_rule": closed, "capped": len(due) > MAX_PER_RUN and not dry_run}


def run_if_due() -> None:
    try:
        last = json.loads(STATE_FILE.read_text()).get("last_run", 0)
    except (OSError, ValueError):
        last = 0
    if time.time() - last < INTERVAL_SECONDS:
        return
    run()
    STATE_FILE.write_text(json.dumps({"last_run": time.time()}))
    try:
        os.chmod(STATE_FILE, 0o664)
    except OSError:
        pass


if __name__ == "__main__":
    args = sys.argv[1:]
    rules, errors = load_rules()
    for e in errors:
        print(f"[!] {e}", file=sys.stderr)
    if "--run" in args or "--dry-run" in args:
        dry = "--dry-run" in args
        res = run(dry_run=dry)
        print(f"{'would close' if dry else 'closed'} {res['due'] if dry else res['closed']} alert(s): {res['by_rule']}"
              + (" (capped; the rest next run)" if res["capped"] else ""))
    else:
        print(f"{len(rules)} valid rule(s), {len(errors)} problem(s)")
        for r in rules:
            print(f"  {r['id']}: after {r['days']} day(s)")
    sys.exit(1 if errors else 0)
