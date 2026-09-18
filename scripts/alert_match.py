#!/usr/bin/env python3
"""
alert_match.py -- the one definition of "does this alert match these criteria",
shared by suppressions.py (hide known-benign alerts) and correlate.py
(correlation rules).

A criteria block ("match") is an object; every listed key must hold (AND):
  detector, type   a string or a list of strings (any of)
  severity         a string or a list of strings
  source_ip        one IP or a CIDR
  title_regex      re.search, case-insensitive
  details          {key: value}; each key must equal that key in alert.details
  details_has      ["threat_intel.kev", ...]; dotted paths that must be present
                   and non-empty in alert.details

compile_match() raises ValueError with a readable message on anything unknown
or malformed, so callers can reject the whole rule instead of guessing.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List

SEVERITIES = ("normal", "medium", "critical")
MATCH_KEYS = {"detector", "type", "severity", "source_ip", "title_regex", "details", "details_has"}


def _as_str_list(value: Any, name: str) -> List[str]:
    items = [value] if isinstance(value, str) else value
    if not isinstance(items, list) or not items or any(not isinstance(i, str) for i in items):
        raise ValueError(f"match.{name} must be a string or a non-empty list of strings")
    return items


def compile_match(match: Any) -> Dict[str, Any]:
    if not isinstance(match, dict) or not match:
        raise ValueError("'match' must list at least one criterion")
    unknown = set(match) - MATCH_KEYS
    if unknown:
        raise ValueError(f"unknown match key(s) {sorted(unknown)}")
    cm: Dict[str, Any] = {"raw": match}
    for key in ("detector", "type"):
        if key in match:
            cm[key] = set(_as_str_list(match[key], key))
    if "severity" in match:
        sevs = _as_str_list(match["severity"], "severity")
        if any(s not in SEVERITIES for s in sevs):
            raise ValueError(f"match.severity must be one or more of {SEVERITIES}")
        cm["severity"] = set(sevs)
    if "source_ip" in match:
        try:
            cm["network"] = ipaddress.ip_network(str(match["source_ip"]), strict=False)
        except ValueError:
            raise ValueError(f"bad match.source_ip {match['source_ip']!r}")
    if "title_regex" in match:
        try:
            cm["title_re"] = re.compile(str(match["title_regex"]), re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"bad match.title_regex: {e}")
    if "details" in match:
        if not isinstance(match["details"], dict) or not match["details"]:
            raise ValueError("match.details must be a non-empty object")
        cm["details"] = match["details"]
    if "details_has" in match:
        cm["details_has"] = _as_str_list(match["details_has"], "details_has")
    return cm


def _dig(details: Dict[str, Any], path: str) -> Any:
    cur: Any = details
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def matches(cm: Dict[str, Any], record: Dict[str, Any]) -> bool:
    if "detector" in cm and record.get("detector") not in cm["detector"]:
        return False
    if "type" in cm and record.get("type") not in cm["type"]:
        return False
    if "severity" in cm and record.get("severity") not in cm["severity"]:
        return False
    if "network" in cm:
        try:
            if ipaddress.ip_address(record.get("source_ip") or "") not in cm["network"]:
                return False
        except ValueError:
            return False
    if "title_re" in cm and not cm["title_re"].search(record.get("title") or ""):
        return False
    details = record.get("details") or {}
    if "details" in cm and any(k not in details or details[k] != v for k, v in cm["details"].items()):
        return False
    if "details_has" in cm and any(not _dig(details, p) for p in cm["details_has"]):
        return False
    return True
