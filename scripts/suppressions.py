#!/usr/bin/env python3
"""
suppressions.py -- known-benign alerts, declared in a file instead of in code.

Rules live in config/suppressions.json (override with SOC_SUPPRESSIONS_FILE):

    {"rules": [
      {"id": "sup-001",
       "reason": "Why this is safe to ignore (required)",
       "added_by": "alberto", "added": "2026-09-18",
       "expires": "2026-12-31",
       "allow_critical": false,
       "match": {
         "detector": "aide",
         "type": "intrusion",
         "severity": "medium",
         "source_ip": "10.201.0.0/16",
         "title_regex": "^File integrity: /opt/zeek/share",
         "details": {"port": 62078, "proto": "tcp"}
       }}
    ]}

match: every listed criterion must hold (AND) and at least one is required.
  detector, type      exact string
  severity            a string or a list of strings
  source_ip           one IP or a CIDR
  title_regex         re.search, case-insensitive
  details             each key must equal that key in the alert's details
Optional: expires (YYYY-MM-DD, UTC; the rule stops applying after that day),
added_by, added. allow_critical must be true for a rule to hide a critical alert.

A suppressed alert is NOT sent to the dashboard, the backend or ntfy, and is
NOT written to alerts.jsonl. It is appended, with "suppressed_by": <rule id>,
to data/alerts_suppressed.jsonl so nothing disappears without a trace.

Safety: a rule with an unknown key, a bad regex/date/CIDR, a duplicate id, a
missing reason or an empty match is rejected and ignored, so a typo can only
make a rule weaker, never wider. A broken file suppresses nothing.

CLI:
    python3 suppressions.py --check           validate the file, list rules
    python3 suppressions.py --dry-run [N]     how many of the last N alerts
                                              (default: all) each rule would hide
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("normal", "medium", "critical")
CONFIG_FILE = Path(os.environ.get(
    "SOC_SUPPRESSIONS_FILE",
    Path(__file__).resolve().parent.parent / "config" / "suppressions.json"))

_RULE_KEYS = {"id", "reason", "added_by", "added", "expires", "allow_critical", "match"}
_MATCH_KEYS = {"detector", "type", "severity", "source_ip", "title_regex", "details"}

_cache: Dict[str, Any] = {"sig": None, "rules": [], "errors": []}


def _parse_date(value: Any) -> date:
    return datetime.strptime(str(value), "%Y-%m-%d").date()


def _compile(raw: Any, seen: set) -> Dict[str, Any]:
    """Validate one rule. Raises ValueError with a readable message."""
    if not isinstance(raw, dict):
        raise ValueError("rule must be an object")
    rid = raw.get("id")
    if not isinstance(rid, str) or not rid.strip():
        raise ValueError("missing 'id'")
    if rid in seen:
        raise ValueError(f"duplicate id {rid!r}")
    unknown = set(raw) - _RULE_KEYS
    if unknown:
        raise ValueError(f"unknown key(s) {sorted(unknown)}")
    reason = raw.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError("missing 'reason' (say why this is safe to ignore)")
    match = raw.get("match")
    if not isinstance(match, dict) or not match:
        raise ValueError("'match' must list at least one criterion")
    unknown = set(match) - _MATCH_KEYS
    if unknown:
        raise ValueError(f"unknown match key(s) {sorted(unknown)}")

    rule: Dict[str, Any] = {"id": rid, "reason": reason, "raw": raw,
                            "allow_critical": bool(raw.get("allow_critical", False)),
                            "expires": None}
    if raw.get("expires") is not None:
        try:
            rule["expires"] = _parse_date(raw["expires"])
        except ValueError:
            raise ValueError(f"bad 'expires' {raw['expires']!r} (use YYYY-MM-DD)")

    for key in ("detector", "type"):
        if key in match and not isinstance(match[key], str):
            raise ValueError(f"match.{key} must be a string")
    if "severity" in match:
        sev = match["severity"]
        sevs = [sev] if isinstance(sev, str) else sev
        if not isinstance(sevs, list) or not sevs or any(s not in SEVERITIES for s in sevs):
            raise ValueError(f"match.severity must be one or more of {SEVERITIES}")
        rule["severities"] = set(sevs)
    if "source_ip" in match:
        try:
            rule["network"] = ipaddress.ip_network(str(match["source_ip"]), strict=False)
        except ValueError:
            raise ValueError(f"bad match.source_ip {match['source_ip']!r}")
    if "title_regex" in match:
        try:
            rule["title_re"] = re.compile(str(match["title_regex"]), re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"bad match.title_regex: {e}")
    if "details" in match:
        if not isinstance(match["details"], dict) or not match["details"]:
            raise ValueError("match.details must be a non-empty object")
        rule["details"] = match["details"]
    rule["match"] = match
    return rule


def load_rules(path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Return (valid rules, error messages). Cached until the file changes."""
    path = Path(path) if path else CONFIG_FILE
    try:
        st = path.stat()
        sig = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return [], []
    if _cache["sig"] == sig:
        return _cache["rules"], _cache["errors"]

    rules: List[Dict[str, Any]] = []
    errors: List[str] = []
    try:
        data = json.loads(path.read_text())
        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' must be a list")
    except (OSError, ValueError, KeyError, TypeError) as e:
        errors.append(f"{path.name}: cannot read rules ({e}) -- nothing is being suppressed")
        raw_rules = []
    seen: set = set()
    for i, raw in enumerate(raw_rules):
        label = raw.get("id", f"#{i + 1}") if isinstance(raw, dict) else f"#{i + 1}"
        try:
            rules.append(_compile(raw, seen))
            seen.add(rules[-1]["id"])
        except ValueError as e:
            errors.append(f"rule {label}: {e} -- ignored")
    _cache.update(sig=sig, rules=rules, errors=errors)
    for msg in errors:
        print(f"[suppressions] WARNING {msg}", file=sys.stderr)
    return rules, errors


def is_expired(rule: Dict[str, Any], today: Optional[date] = None) -> bool:
    exp = rule.get("expires")
    return exp is not None and (today or datetime.now(timezone.utc).date()) > exp


def _matches(rule: Dict[str, Any], record: Dict[str, Any]) -> bool:
    m = rule["match"]
    if "detector" in m and record.get("detector") != m["detector"]:
        return False
    if "type" in m and record.get("type") != m["type"]:
        return False
    if "severities" in rule and record.get("severity") not in rule["severities"]:
        return False
    if "network" in rule:
        try:
            if ipaddress.ip_address(record.get("source_ip") or "") not in rule["network"]:
                return False
        except ValueError:
            return False
    if "title_re" in rule and not rule["title_re"].search(record.get("title") or ""):
        return False
    if "details" in rule:
        details = record.get("details") or {}
        if any(k not in details or details[k] != v for k, v in rule["details"].items()):
            return False
    return True


def find_match(record: Dict[str, Any], rules: Optional[List[Dict[str, Any]]] = None
               ) -> Optional[Dict[str, Any]]:
    """First active rule that hides this alert record, or None."""
    if rules is None:
        rules, _ = load_rules()
    for rule in rules:
        if is_expired(rule):
            continue
        if record.get("severity") == "critical" and not rule["allow_critical"]:
            continue
        if _matches(rule, record):
            return rule
    return None


def _cli() -> int:
    args = sys.argv[1:]
    rules, errors = load_rules()
    if not args or args[0] == "--check":
        print(f"file: {CONFIG_FILE}" + ("" if CONFIG_FILE.exists() else "  (does not exist)"))
        for r in rules:
            state = "EXPIRED" if is_expired(r) else "active"
            exp = f", expires {r['expires']}" if r["expires"] else ""
            print(f"  [{state}] {r['id']}{exp} -- {r['reason']}")
        for e in errors:
            print(f"  [INVALID] {e}")
        print(f"{len(rules)} valid rule(s), {len(errors)} problem(s)")
        return 1 if errors else 0
    if args[0] == "--dry-run":
        log = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data")) / "alerts.jsonl"
        limit = int(args[1]) if len(args) > 1 else None
        try:
            lines = [ln for ln in log.read_text().splitlines() if ln.strip()]
        except OSError as e:
            print(f"cannot read {log}: {e}")
            return 1
        if limit:
            lines = lines[-limit:]
        hits = {r["id"]: 0 for r in rules}
        for ln in lines:
            rec = json.loads(ln)
            rule = find_match(rec, rules)
            if rule:
                hits[rule["id"]] += 1
        print(f"checked {len(lines)} alert(s) from {log.name}")
        for r in rules:
            print(f"  {r['id']}: would hide {hits[r['id']]}")
        for e in errors:
            print(f"  [INVALID] {e}")
        return 1 if errors else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(_cli())
