#!/usr/bin/env python3
"""
correlate.py -- turn related alerts into incidents (the Sentinel "incident" idea).

Rules live in config/correlation_rules.json (override: SOC_CORRELATION_FILE):

  {"ignore_entities": ["ip:10.69.0.1"],
   "rules": [
     {"id": "scan-then-exploit", "name": "Scan followed by exploit attempt",
      "severity": "critical", "type": "sequence", "window_minutes": 60,
      "steps": [ {match}, {match} ]},
     {"id": "multi-source-host", "name": "...", "severity": "medium",
      "type": "threshold", "window_minutes": 30, "count": 3, "distinct": "detector",
      "match": {match}},
     {"id": "ti-hit", "name": "...", "severity": "critical", "type": "single",
      "match": {match}}
   ]}

  {match}     the criteria block described in alert_match.py.
  sequence    the steps must occur in order, within window_minutes, about the
              same entity; the alert matching the last step completes it.
  threshold   `count` matching alerts about the same entity within the window;
              with "distinct": "detector"|"title" they must differ in that.
  single      one matching alert is enough.
  Optional per rule: enabled (default true), roles (default ["source"]: which
  entity roles count as "the same entity"), entity_types (default
  ["ip","mac","host"]).

Alerts share an entity when one of their entities (see alert_context.py) is
equal. This box's own IPs and anything in ignore_entities never count, or the
scanner itself would tie every alert together.

When a rule completes, an incident is opened (or the alert joins the open
incident of that rule that shares an entity). Incidents live in
data/incidents.json; every change is appended to data/incident_log.jsonl.
Opening one also raises a normal alert (detector "correlation") so it shows up
in the feed, the backend and ntfy like any other critical event.

Invalid rules are ignored, never guessed at. A crash here never loses an alert.

    python3 correlate.py --check        validate the rules file
    python3 correlate.py --replay [N]   run the last N historical alerts (default
                                        all) through the rules in a throwaway
                                        data dir and print the incidents that
                                        WOULD open. Sends nothing.
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alert_match  # noqa: E402
import soc_core  # noqa: E402

RULES_FILE = Path(os.environ.get(
    "SOC_CORRELATION_FILE", Path(__file__).resolve().parent.parent / "config" / "correlation_rules.json"))
DATA_DIR = soc_core.DATA_DIR
STATE_FILE = DATA_DIR / "correlation_state.json"
INCIDENTS_FILE = DATA_DIR / "incidents.json"
INCIDENT_LOG = DATA_DIR / "incident_log.jsonl"
LOCK_FILE = DATA_DIR / ".correlation.lock"

STATUSES = ("new", "active", "closed")
CLASSIFICATIONS = ("true_positive", "false_positive", "benign", "undetermined")
MAX_ALERTS_PER_INCIDENT = 500
MAX_COMMENT_LEN = 2000
_RULE_KEYS = {"id", "name", "severity", "type", "window_minutes", "steps", "match", "count",
              "distinct", "enabled", "roles", "entity_types"}
_ROLES = ("source", "destination")
_ENTITY_TYPES = ("ip", "mac", "host", "user")

_rules_cache: Dict[str, Any] = {"sig": None, "rules": [], "ignore": set(), "errors": []}
_self_cache: Dict[str, Any] = {"at": 0.0, "ips": set()}


# --------------------------------------------------------------------------- #
#  Rules
# --------------------------------------------------------------------------- #

def _compile_rule(raw: Any, seen: set) -> Dict[str, Any]:
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
    if not isinstance(raw.get("name"), str) or not raw["name"].strip():
        raise ValueError("missing 'name'")
    if raw.get("severity") not in ("medium", "critical"):
        raise ValueError("severity must be 'medium' or 'critical'")
    rtype = raw.get("type")
    rule: Dict[str, Any] = {"id": rid, "name": raw["name"], "severity": raw["severity"], "type": rtype,
                            "enabled": bool(raw.get("enabled", True)), "raw": raw}
    roles = raw.get("roles", ["source"])
    etypes = raw.get("entity_types", ["ip", "mac", "host"])
    if not isinstance(roles, list) or not roles or any(r not in _ROLES for r in roles):
        raise ValueError(f"roles must be a non-empty list of {_ROLES}")
    if not isinstance(etypes, list) or not etypes or any(t not in _ENTITY_TYPES for t in etypes):
        raise ValueError(f"entity_types must be a non-empty list of {_ENTITY_TYPES}")
    rule["roles"], rule["entity_types"] = set(roles), set(etypes)

    if rtype in ("sequence", "threshold"):
        w = raw.get("window_minutes")
        if not isinstance(w, int) or isinstance(w, bool) or not 1 <= w <= 1440:
            raise ValueError("window_minutes must be an integer between 1 and 1440")
        rule["window"] = w * 60
    if rtype == "sequence":
        steps = raw.get("steps")
        if not isinstance(steps, list) or len(steps) < 2:
            raise ValueError("a sequence needs at least 2 steps")
        rule["steps"] = [alert_match.compile_match(s) for s in steps]
    elif rtype == "threshold":
        cnt = raw.get("count")
        if not isinstance(cnt, int) or isinstance(cnt, bool) or cnt < 2:
            raise ValueError("count must be an integer >= 2")
        if raw.get("distinct") not in (None, "detector", "title"):
            raise ValueError("distinct must be 'detector' or 'title'")
        rule["count"], rule["distinct"] = cnt, raw.get("distinct")
        rule["steps"] = [alert_match.compile_match(raw.get("match"))]
    elif rtype == "single":
        rule["steps"] = [alert_match.compile_match(raw.get("match"))]
    else:
        raise ValueError("type must be 'sequence', 'threshold' or 'single'")
    return rule


def load_rules(path: Optional[Path] = None) -> Tuple[List[Dict[str, Any]], set, List[str]]:
    """(valid rules, ignored entity keys, error messages); cached until the file changes."""
    path = Path(path) if path else RULES_FILE
    try:
        st = path.stat()
        sig = (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return [], set(), []
    if _rules_cache["sig"] == sig:
        return _rules_cache["rules"], _rules_cache["ignore"], _rules_cache["errors"]
    rules: List[Dict[str, Any]] = []
    errors: List[str] = []
    ignore: set = set()
    raw_rules: Any = []
    try:
        data = json.loads(path.read_text())
        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' must be a list")
        ig = data.get("ignore_entities", [])
        if not isinstance(ig, list) or any(not isinstance(x, str) for x in ig):
            raise ValueError("'ignore_entities' must be a list of 'type:value' strings")
        ignore = set(ig)
    except (OSError, ValueError, KeyError, TypeError) as e:
        errors.append(f"{path.name}: cannot read rules ({e}) -- no correlation is running")
        raw_rules = []
    seen: set = set()
    for i, raw in enumerate(raw_rules):
        label = raw.get("id", f"#{i + 1}") if isinstance(raw, dict) else f"#{i + 1}"
        try:
            rules.append(_compile_rule(raw, seen))
            seen.add(rules[-1]["id"])
        except ValueError as e:
            errors.append(f"rule {label}: {e} -- ignored")
    _rules_cache.update(sig=sig, rules=rules, ignore=ignore, errors=errors)
    for msg in errors:
        print(f"[correlate] WARNING {msg}", file=sys.stderr)
    return rules, ignore, errors


def _self_ips() -> set:
    """This box's own IPv4 addresses ('ip:x.x.x.x'), refreshed every 5 minutes."""
    if time.time() - _self_cache["at"] > 300:
        ips = set()
        try:
            out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
            ips = {f"ip:{m}" for m in re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out)}
        except (OSError, subprocess.SubprocessError):
            pass
        _self_cache.update(at=time.time(), ips=ips)
    return _self_cache["ips"]


# --------------------------------------------------------------------------- #
#  Storage (locked, atomic)
# --------------------------------------------------------------------------- #

def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return default


def _write_json(path: Path, data: Any) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


class _Lock:
    def __enter__(self):
        self._fh = LOCK_FILE.open("a")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()


def _audit(incident_id: str, actor: str, action: str, changes: Dict[str, Any]) -> None:
    with INCIDENT_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "incident_id": incident_id,
                             "actor": actor, "action": action, "changes": changes}) + "\n")


def _load_store() -> Dict[str, Any]:
    store = _read_json(INCIDENTS_FILE, {})
    if not isinstance(store, dict) or "incidents" not in store:
        store = {"next_number": 1, "incidents": []}
    return store


# --------------------------------------------------------------------------- #
#  Engine
# --------------------------------------------------------------------------- #

def _epoch(record: Dict[str, Any]) -> float:
    try:
        dt = datetime.fromisoformat(record["timestamp"])
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (KeyError, ValueError, TypeError):
        return time.time()


def _keys(ents: List[List[str]], rule: Dict[str, Any], ignore: set) -> set:
    skip = ignore | _self_ips()
    return {f"{t}:{v}" for t, v, role in ents
            if role in rule["roles"] and t in rule["entity_types"] and f"{t}:{v}" not in skip}


def _event_from(record: Dict[str, Any], tags: List[str]) -> Dict[str, Any]:
    details = record.get("details") or {}
    return {"id": record["id"], "ts": _epoch(record), "detector": record.get("detector"),
            "severity": record.get("severity"), "title": record.get("title"),
            "shape": details.get("group_key", record.get("title")),
            "ents": [[e["type"], e["value"], e.get("role", "source")] for e in details.get("entities", [])],
            "mt": details.get("mitre", []), "m": tags}


def on_alert(record: Dict[str, Any]) -> Tuple[Optional[str], Optional[soc_core.Alert]]:
    """Evaluate the rules for a new alert record (called by emit_alert before the
    alert is stored). Returns (incident_id for this alert or None, a follow-up
    Alert to emit when a NEW incident was opened)."""
    if record.get("detector") == "correlation":
        return None, None
    rules, ignore, _ = load_rules()
    tags: List[str] = []
    for rule in rules:
        if rule["enabled"]:
            tags += [f"{rule['id']}:{i}" for i, cm in enumerate(rule["steps"]) if alert_match.matches(cm, record)]
    if not tags:
        return None, None

    event = _event_from(record, tags)
    horizon = max((r["window"] for r in rules if "window" in r), default=3600)
    incident_id: Optional[str] = None
    followup: Optional[soc_core.Alert] = None
    with _Lock():
        state = _read_json(STATE_FILE, {"events": []})
        events = [e for e in state.get("events", []) if event["ts"] - e["ts"] <= horizon]
        events.append(event)
        _write_json(STATE_FILE, {"events": events})
        for rule in rules:
            if not rule["enabled"]:
                continue
            mine = {t for t in tags if t.startswith(rule["id"] + ":")}
            if not mine:
                continue
            chain = _complete(rule, event, events, ignore)
            if not chain:
                continue
            inc, created = _open_or_update(rule, chain, event)
            if incident_id is None or created:
                incident_id = inc["id"]
            if created and followup is None:
                followup = _incident_alert(inc)
    return incident_id, followup


def _complete(rule: Dict[str, Any], event: Dict[str, Any], events: List[Dict[str, Any]],
              ignore: set) -> Optional[List[Dict[str, Any]]]:
    """Events that together satisfy the rule with `event` as the newest one, or None."""
    rid, kind = rule["id"], rule["type"]
    if kind == "single":
        return [event]
    mykeys = _keys(event["ents"], rule, ignore)
    if not mykeys:
        return None

    def related(e: Dict[str, Any], tag: str) -> bool:
        return (tag in e["m"] and e["id"] != event["id"] and 0 <= event["ts"] - e["ts"] <= rule["window"]
                and bool(_keys(e["ents"], rule, ignore) & mykeys))

    if kind == "sequence":
        last = f"{rid}:{len(rule['steps']) - 1}"
        if last not in event["m"]:
            return None
        chain = []
        for j in range(len(rule["steps"]) - 1):
            cands = [e for e in events if related(e, f"{rid}:{j}")]
            if not cands:
                return None
            chain.append(max(cands, key=lambda e: e["ts"]))
        return chain + [event]

    tag = f"{rid}:0"                                  # threshold
    group = [e for e in events if related(e, tag)] + [event]
    field = {"detector": "detector", "title": "shape"}.get(rule["distinct"])
    distinct = {e[field] for e in group} if field else {e["id"] for e in group}
    return group if len(distinct) >= rule["count"] else None


def _open_or_update(rule: Dict[str, Any], chain: List[Dict[str, Any]],
                    event: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """Attach the chain to the open incident of this rule sharing an entity, else open one."""
    ignore = _rules_cache["ignore"]
    keys = set()
    for e in chain:
        keys |= _keys(e["ents"], rule, ignore)
    store = _load_store()
    now = datetime.now(timezone.utc).isoformat()
    ids = [e["id"] for e in chain]
    techs = {t["technique"]: t for e in chain for t in e.get("mt", [])}
    ents = {f"{t}:{v}": {"type": t, "value": v} for e in chain for t, v, r in e["ents"]
            if f"{t}:{v}" not in (ignore | _self_ips())}

    for inc in store["incidents"]:
        if inc["rule_id"] == rule["id"] and inc["status"] != "closed" and \
                keys & {f"{x['type']}:{x['value']}" for x in inc["entities"]}:
            added = [i for i in ids if i not in inc["alert_ids"]]
            inc["alert_ids"] = (inc["alert_ids"] + added)[-MAX_ALERTS_PER_INCIDENT:]
            inc["alert_count"] = len(inc["alert_ids"])
            inc["updated"] = inc["last_alert_at"] = now
            known = {f"{x['type']}:{x['value']}" for x in inc["entities"]}
            inc["entities"] += [v for k, v in ents.items() if k not in known]
            have = {t["technique"] for t in inc["mitre"]}
            inc["mitre"] += [t for k, t in techs.items() if k not in have]
            if any(e["severity"] == "critical" for e in chain):
                inc["severity"] = "critical"
            if added:
                _write_json(INCIDENTS_FILE, store)
                _audit(inc["id"], "correlation", "alerts_added", {"alert_ids": added})
                _link_alerts([i for i in added if i != event["id"]], inc["id"])
            return inc, False

    number = store["next_number"]
    label = next((k.split(":", 1)[1] for k in sorted(keys)), "")
    sev = "critical" if rule["severity"] == "critical" or any(e["severity"] == "critical" for e in chain) else "medium"
    inc = {"id": str(uuid.uuid4()), "number": number,
           "title": f"{rule['name']} — {label}" if label else rule["name"],
           "severity": sev, "status": "new", "classification": None, "owner": None,
           "rule_id": rule["id"], "rule_name": rule["name"],
           "entities": list(ents.values()), "alert_ids": ids, "alert_count": len(ids),
           "mitre": list(techs.values()), "created": now, "updated": now,
           "first_alert_at": datetime.fromtimestamp(min(e["ts"] for e in chain), tz=timezone.utc).isoformat(),
           "last_alert_at": now, "comments": []}
    store["incidents"].insert(0, inc)
    store["next_number"] = number + 1
    _write_json(INCIDENTS_FILE, store)
    _audit(inc["id"], "correlation", "opened", {"rule": rule["id"], "alert_ids": ids})
    _link_alerts([i for i in ids if i != event["id"]], inc["id"])
    return inc, True


def _incident_alert(inc: Dict[str, Any]) -> soc_core.Alert:
    return soc_core.Alert(
        type="intrusion", severity=inc["severity"], detector="correlation",
        title=f"Incident #{inc['number']}: {inc['title']}",
        source_ip=next((e["value"] for e in inc["entities"] if e["type"] == "ip"), None),
        description=(f"Correlation rule '{inc['rule_name']}' matched {inc['alert_count']} related alert(s). "
                     "Open the incident to review them."),
        details={"incident_id": inc["id"], "incident_number": inc["number"], "rule_id": inc["rule_id"],
                 "mitre": inc["mitre"]})


def _link_alerts(alert_ids: List[str], incident_id: str) -> None:
    """Stamp details.incident_id on alerts already in the live snapshot."""
    if not alert_ids:
        return
    wanted = set(alert_ids)
    with soc_core.ALERTS_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            snapshot = soc_core._load_snapshot()
            changed = False
            for a in snapshot:
                if a.get("id") in wanted:
                    d = a.setdefault("details", {})
                    if d.get("incident_id") != incident_id:
                        d["incident_id"] = incident_id
                        changed = True
            if changed:
                _write_json(soc_core.ALERTS_SNAPSHOT, snapshot)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


# --------------------------------------------------------------------------- #
#  Incident operations (used by the API)
# --------------------------------------------------------------------------- #

def list_incidents(status: Optional[str] = None, severity: Optional[str] = None) -> List[Dict[str, Any]]:
    out = _load_store()["incidents"]
    if status:
        out = [i for i in out if i["status"] == status]
    if severity:
        out = [i for i in out if i["severity"] == severity]
    return out


def get_incident(ref: str) -> Optional[Dict[str, Any]]:
    for inc in _load_store()["incidents"]:
        if inc["id"] == ref or str(inc["number"]) == ref:
            return inc
    return None


def update_incident(ref: str, actor: str, status: Optional[str] = None, classification: Optional[str] = None,
                    owner: Optional[str] = None, comment: Optional[str] = None) -> Dict[str, Any]:
    """Change an incident. Raises ValueError (message says why) on bad input.
    owner="" clears the owner; closing needs a classification."""
    if status is not None and status not in STATUSES:
        raise ValueError(f"invalid status {status!r} (expected one of {STATUSES})")
    if classification is not None and classification not in CLASSIFICATIONS:
        raise ValueError(f"invalid classification {classification!r} (expected one of {CLASSIFICATIONS})")
    if owner is not None and (not isinstance(owner, str) or len(owner) > 100):
        raise ValueError("owner must be a string of at most 100 characters")
    if comment is not None and (not isinstance(comment, str) or not comment.strip() or len(comment) > MAX_COMMENT_LEN):
        raise ValueError(f"comment must be non-empty text of at most {MAX_COMMENT_LEN} characters")
    with _Lock():
        store = _load_store()
        inc = next((i for i in store["incidents"] if i["id"] == ref or str(i["number"]) == ref), None)
        if inc is None:
            raise ValueError(f"incident not found: {ref}")
        changes: Dict[str, Any] = {}
        new_class = classification if classification is not None else inc["classification"]
        if status == "closed" and not new_class:
            raise ValueError("closing an incident needs a classification "
                             f"({', '.join(CLASSIFICATIONS)})")
        if status is not None and status != inc["status"]:
            changes["status"] = [inc["status"], status]
            inc["status"] = status
        if classification is not None and classification != inc["classification"]:
            changes["classification"] = [inc["classification"], classification]
            inc["classification"] = classification
        if owner is not None and (owner or None) != inc["owner"]:
            changes["owner"] = [inc["owner"], owner or None]
            inc["owner"] = owner or None
        if comment is not None:
            inc["comments"].append({"at": datetime.now(timezone.utc).isoformat(), "by": actor, "text": comment.strip()})
            changes["comment"] = True
        if changes:
            inc["updated"] = datetime.now(timezone.utc).isoformat()
            _write_json(INCIDENTS_FILE, store)
            _audit(inc["id"], actor, "updated", changes)
        return inc


# --------------------------------------------------------------------------- #
#  CLI
# --------------------------------------------------------------------------- #

def _replay(limit: Optional[int]) -> int:
    """Run history through the rules in a throwaway data dir, with notifications off."""
    import shutil
    tmp = tempfile.mkdtemp(prefix="corr_replay_")
    try:
        real = soc_core.DATA_DIR
        for name in ("assets.json",):
            if (real / name).exists():
                shutil.copy(real / name, tmp)
        env = {k: v for k, v in os.environ.items() if k not in ("SOC_INGEST_URL", "NTFY_TOPIC")}
        env.update(SOC_DATA_DIR=tmp, SOC_REPLAY_SOURCE=str(real / "alerts.jsonl"),
                   SOC_REPLAY_LIMIT=str(limit or 0))
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), "--replay-inner"], env=env).returncode
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _replay_inner() -> int:
    import alert_context
    import threat_intel
    src = Path(os.environ["SOC_REPLAY_SOURCE"])
    limit = int(os.environ.get("SOC_REPLAY_LIMIT", "0")) or None
    rows = [json.loads(ln) for ln in src.read_text().splitlines() if ln.strip()]
    rows.sort(key=lambda r: r["timestamp"])
    if limit:
        rows = rows[-limit:]
    opened = 0
    for r in rows:
        alert_context.add_context(r)
        ti = threat_intel.enrich(r)
        if ti:
            r["details"]["threat_intel"] = ti
        _, follow = on_alert(r)
        if follow:
            opened += 1
    print(f"replayed {len(rows)} alert(s): {opened} incident(s) would have opened")
    for inc in _load_store()["incidents"][::-1]:
        print(f"  #{inc['number']} [{inc['severity']}] {inc['title']}  ({inc['alert_count']} alert(s), rule {inc['rule_id']})")
    return 0


def _cli() -> int:
    args = sys.argv[1:]
    if args and args[0] == "--replay-inner":
        return _replay_inner()
    if args and args[0] == "--replay":
        return _replay(int(args[1]) if len(args) > 1 else None)
    rules, ignore, errors = load_rules()
    print(f"file: {RULES_FILE}" + ("" if RULES_FILE.exists() else "  (does not exist)"))
    for r in rules:
        print(f"  [{'enabled' if r['enabled'] else 'disabled'}] {r['id']} ({r['type']}, {r['severity']}) -- {r['name']}")
    for e in errors:
        print(f"  [INVALID] {e}")
    print(f"{len(rules)} valid rule(s), {len(errors)} problem(s); ignoring {len(ignore)} configured + "
          f"{len(_self_ips())} own IP(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(_cli())
