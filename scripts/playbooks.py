#!/usr/bin/env python3
"""
playbooks.py -- automatic responses to alerts (a small SOAR).

Playbooks live in config/playbooks.json (override: SOC_PLAYBOOKS_FILE):

  {"playbooks": [
    {"id": "critical-incident-webhook",
     "name": "Tell the SOC channel about critical incidents",
     "enabled": true,
     "dry_run": false,
     "cooldown_minutes": 10,
     "trigger": {"match": {"detector": "correlation", "severity": "critical"}},
     "actions": [
       {"type": "webhook", "url_env": "SOC_WEBHOOK_URL", "format": "text"},
       {"type": "assign_incident", "owner": "on-call"},
       {"type": "comment_incident", "text": "Notified by playbook {playbook}."}
     ]}
  ]}

trigger.match is the criteria block from alert_match.py, tested against every alert
that reaches the feed (suppressed alerts never do). An incident opening is itself an
alert (detector "correlation", details.incident_id), so it can trigger playbooks too.

Actions, deliberately limited to things that cannot damage the network:
  webhook           POST to a URL kept OUT of git. url_env names a variable in the
                    process environment or in /etc/sentinel-soc/webhooks.env
                    (KEY=VALUE lines, mode 640, group soc). format "text" sends
                    {"text": msg, "content": msg} (Slack, Mattermost, Discord and
                    similar); "json" sends {"playbook", "alert", "incident"}.
                    https:// only, unless the action sets "allow_http": true.
  ntfy              a push through ntfy (needs NTFY_TOPIC), for any severity.
  assign_incident   set the owner of the alert's incident (only if it has none).
  comment_incident  add a comment to the alert's incident ({playbook} is replaced).
There is no "block IP" or "run command": Kali is a passive sensor, and blocking needs
the firewall plus a human decision. A webhook to the firewall's own automation, or a
ticket, is the right bridge for that.

Safety: a per-playbook cooldown (per entity), at most 60 action runs per 10 minutes
overall, a circuit breaker that pauses webhooks for 5 minutes after 3 failures in a
row, 5 s timeouts, dry_run per playbook (or SOC_PLAYBOOKS_DRY_RUN=1) to see what
would happen, and every run appended to data/playbook_log.jsonl. Invalid playbooks
are ignored. A failure here never loses or delays an alert beyond the timeouts.

    python3 playbooks.py --check          validate the file
    python3 playbooks.py --test ALERT_ID  show what would run for an alert in the feed (never executes)
    python3 playbooks.py --runs [N]       the last N runs
"""
from __future__ import annotations

import fcntl
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alert_match  # noqa: E402
import soc_core  # noqa: E402

PLAYBOOKS_FILE = Path(os.environ.get(
    "SOC_PLAYBOOKS_FILE", Path(__file__).resolve().parent.parent / "config" / "playbooks.json"))
WEBHOOKS_FILE = Path(os.environ.get("SOC_WEBHOOKS_FILE", "/etc/sentinel-soc/webhooks.env"))
DATA_DIR = soc_core.DATA_DIR
STATE_FILE = DATA_DIR / "playbook_state.json"
RUN_LOG = DATA_DIR / "playbook_log.jsonl"
LOCK_FILE = DATA_DIR / ".playbooks.lock"

RATE_LIMIT, RATE_WINDOW = 60, 600
BREAKER_FAILURES, BREAKER_PAUSE = 3, 300
HTTP_TIMEOUT = 5
_PB_KEYS = {"id", "name", "enabled", "dry_run", "cooldown_minutes", "trigger", "actions"}
_ACTIONS = {"webhook": {"type", "url_env", "format", "allow_http"}, "ntfy": {"type"},
            "assign_incident": {"type", "owner"}, "comment_incident": {"type", "text"}}
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]{2,60}$")

_cache: Dict[str, Any] = {"sig": None, "playbooks": [], "errors": []}


# --------------------------------------------------------------------------- #
#  Loading
# --------------------------------------------------------------------------- #

def _compile_action(raw: Any) -> Dict[str, Any]:
    if not isinstance(raw, dict) or raw.get("type") not in _ACTIONS:
        raise ValueError(f"action type must be one of {sorted(_ACTIONS)}")
    unknown = set(raw) - _ACTIONS[raw["type"]]
    if unknown:
        raise ValueError(f"unknown key(s) {sorted(unknown)} in a {raw['type']} action")
    t = raw["type"]
    if t == "webhook":
        if not isinstance(raw.get("url_env"), str) or not _ENV_NAME.match(raw["url_env"]):
            raise ValueError("webhook needs url_env, the NAME of a variable that holds the URL (e.g. SOC_WEBHOOK_URL)")
        if raw.get("format", "text") not in ("text", "json"):
            raise ValueError("webhook format must be 'text' or 'json'")
    if t == "assign_incident" and (not isinstance(raw.get("owner"), str) or not raw["owner"].strip()
                                   or len(raw["owner"]) > 100):
        raise ValueError("assign_incident needs an owner (up to 100 characters)")
    if t == "comment_incident" and (not isinstance(raw.get("text"), str) or not raw["text"].strip()
                                    or len(raw["text"]) > 500):
        raise ValueError("comment_incident needs text (up to 500 characters)")
    return dict(raw)


def _compile(raw: Any, seen: set) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError("playbook must be an object")
    pid = raw.get("id")
    if not isinstance(pid, str) or not pid.strip():
        raise ValueError("missing 'id'")
    if pid in seen:
        raise ValueError(f"duplicate id {pid!r}")
    unknown = set(raw) - _PB_KEYS
    if unknown:
        raise ValueError(f"unknown key(s) {sorted(unknown)}")
    if not isinstance(raw.get("name"), str) or not raw["name"].strip():
        raise ValueError("missing 'name'")
    cool = raw.get("cooldown_minutes", 10)
    if isinstance(cool, bool) or not isinstance(cool, int) or not 0 <= cool <= 1440:
        raise ValueError("cooldown_minutes must be an integer between 0 and 1440")
    trig = raw.get("trigger")
    if not isinstance(trig, dict) or set(trig) != {"match"}:
        raise ValueError("trigger must be {\"match\": {...}}")
    actions = raw.get("actions")
    if not isinstance(actions, list) or not actions or len(actions) > 5:
        raise ValueError("actions must be a list of 1 to 5 actions")
    return {"id": pid, "name": raw["name"], "enabled": bool(raw.get("enabled", False)),
            "dry_run": bool(raw.get("dry_run", False)), "cooldown": cool * 60,
            "cm": alert_match.compile_match(trig["match"]),
            "actions": [_compile_action(a) for a in actions], "raw": raw}


def load_playbooks() -> Tuple[List[Dict[str, Any]], List[str]]:
    try:
        st = PLAYBOOKS_FILE.stat()
        sig = (str(PLAYBOOKS_FILE), st.st_mtime_ns, st.st_size)
    except OSError:
        return [], []
    if _cache["sig"] == sig:
        return _cache["playbooks"], _cache["errors"]
    pbs, errors, seen = [], [], set()
    try:
        raw_list = json.loads(PLAYBOOKS_FILE.read_text())["playbooks"]
        if not isinstance(raw_list, list):
            raise ValueError("'playbooks' must be a list")
    except (OSError, ValueError, KeyError, TypeError) as e:
        raw_list, errors = [], [f"{PLAYBOOKS_FILE.name}: cannot read playbooks ({e}) -- no automation is running"]
    for i, raw in enumerate(raw_list):
        label = raw.get("id", f"#{i + 1}") if isinstance(raw, dict) else f"#{i + 1}"
        try:
            pbs.append(_compile(raw, seen))
            seen.add(pbs[-1]["id"])
        except ValueError as e:
            errors.append(f"playbook {label}: {e} -- ignored")
    _cache.update(sig=sig, playbooks=pbs, errors=errors)
    for msg in errors:
        print(f"[playbooks] WARNING {msg}", file=sys.stderr)
    return pbs, errors


# --------------------------------------------------------------------------- #
#  State
# --------------------------------------------------------------------------- #

class _Lock:
    def __enter__(self):
        self._fh = LOCK_FILE.open("a")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()


def _read_state() -> Dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _write_state(state: Dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(STATE_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _entity_key(record: Dict[str, Any]) -> str:
    d = record.get("details") or {}
    if d.get("incident_id"):
        return f"inc:{d['incident_id']}"
    for e in d.get("entities", []):
        return f"{e['type']}:{e['value']}"
    return record.get("source_ip") or d.get("group_key") or record.get("title", "")[:60]


# --------------------------------------------------------------------------- #
#  Actions
# --------------------------------------------------------------------------- #

def _secret(name: str) -> Optional[str]:
    if os.environ.get(name):
        return os.environ[name].strip()
    try:
        for line in WEBHOOKS_FILE.read_text().splitlines():
            k, _, v = line.partition("=")
            if k.strip() == name and v.strip():
                return v.strip().strip('"\'')
    except OSError:
        pass
    return None


def _message(record: Dict[str, Any]) -> str:
    d = record.get("details") or {}
    parts = [f"[{str(record.get('severity', '')).upper()}] {record.get('title', '')}"]
    if record.get("source_ip"):
        parts.append(f"source {record['source_ip']}")
    if d.get("incident_number"):
        parts.append(f"incident #{d['incident_number']}")
    if d.get("mitre"):
        parts.append("MITRE " + ", ".join(t["technique"] for t in d["mitre"][:4]))
    return " | ".join(parts)


def _post(url: str, payload: Dict[str, Any]) -> None:
    req = urllib.request.Request(url, data=json.dumps(payload, default=str).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
        if resp.status >= 300:
            raise RuntimeError(f"HTTP {resp.status}")


def _run_action(pb: Dict[str, Any], action: Dict[str, Any], record: Dict[str, Any],
                state: Dict[str, Any]) -> Tuple[str, str]:
    t = action["type"]
    incident_id = (record.get("details") or {}).get("incident_id")
    if t == "webhook":
        if state.get("breaker_until", 0) > time.time():
            return "skipped", "webhook circuit breaker is open after repeated failures"
        url = _secret(action["url_env"])
        if not url:
            return "error", f"{action['url_env']} is not set (environment or {WEBHOOKS_FILE})"
        if not url.startswith("https://") and not (action.get("allow_http") and url.startswith("http://")):
            return "error", "the webhook URL must start with https://"
        try:
            if action.get("format", "text") == "json":
                inc = None
                if incident_id:
                    import correlate
                    inc = correlate.get_incident(incident_id)
                _post(url, {"playbook": pb["id"], "alert": record, "incident": inc})
            else:
                msg = _message(record)
                _post(url, {"text": msg, "content": msg})
            state["failures"] = 0
            return "ok", "sent"
        except Exception as e:
            state["failures"] = state.get("failures", 0) + 1
            if state["failures"] >= BREAKER_FAILURES:
                state["breaker_until"] = time.time() + BREAKER_PAUSE
            return "error", f"{type(e).__name__}: {e}"[:200]
    if t == "ntfy":
        if not soc_core.NTFY_TOPIC:
            return "error", "NTFY_TOPIC is not set in this process"
        soc_core._ntfy_push(str(record.get("title", ""))[:250], _message(record))
        return "ok", "pushed"
    if t in ("assign_incident", "comment_incident"):
        if not incident_id:
            return "skipped", "this alert has no incident"
        import correlate
        actor = f"playbook:{pb['id']}"
        try:
            if t == "assign_incident":
                inc = correlate.get_incident(incident_id)
                if inc and inc.get("owner"):
                    return "skipped", f"incident already owned by {inc['owner']}"
                correlate.update_incident(incident_id, actor, owner=action["owner"])
                return "ok", f"assigned to {action['owner']}"
            correlate.update_incident(incident_id, actor, comment=action["text"].replace("{playbook}", pb["id"]))
            return "ok", "commented"
        except ValueError as e:
            return "error", str(e)
    return "error", "unknown action"


# --------------------------------------------------------------------------- #
#  Entry points
# --------------------------------------------------------------------------- #

def _log(entry: Dict[str, Any]) -> None:
    with RUN_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


def run_for_alert(record: Dict[str, Any], dry_run: bool = False) -> List[Dict[str, Any]]:
    """Run the playbooks that match this alert; returns one result per playbook that fired.
    With dry_run=True nothing is executed, throttled or logged (used by --test)."""
    pbs, _ = load_playbooks()
    matching = [p for p in pbs if p["enabled"] and alert_match.matches(p["cm"], record)]
    if not matching:
        return []
    force_dry = dry_run or os.environ.get("SOC_PLAYBOOKS_DRY_RUN") == "1"
    now = time.time()
    to_run: List[Dict[str, Any]] = []
    results: List[Dict[str, Any]] = []
    if dry_run:
        state: Dict[str, Any] = {}
        to_run = matching
    else:
        with _Lock():
            state = _read_state()
            cool = state.setdefault("cooldowns", {})
            recent = [t for t in state.get("recent", []) if now - t < RATE_WINDOW]
            for pb in matching:
                key = f"{pb['id']}|{_entity_key(record)}"
                if pb["cooldown"] and now - cool.get(key, 0) < pb["cooldown"]:
                    results.append({"playbook": pb["id"], "status": "cooldown", "actions": []})
                    continue
                if len(recent) + len(pb["actions"]) > RATE_LIMIT:
                    results.append({"playbook": pb["id"], "status": "rate_limited", "actions": []})
                    continue
                if not (force_dry or pb["dry_run"]):
                    cool[key] = now
                    recent += [now] * len(pb["actions"])
                to_run.append(pb)
            state["cooldowns"] = {k: v for k, v in cool.items() if now - v < 86400}
            state["recent"] = recent
            _write_state(state)

    for pb in to_run:
        acts = []
        for action in pb["actions"]:
            if force_dry or pb["dry_run"]:
                acts.append({"type": action["type"], "status": "dry_run", "detail": "not executed"})
            else:
                status, detail = _run_action(pb, action, record, state)
                acts.append({"type": action["type"], "status": status, "detail": detail})
        res = {"playbook": pb["id"], "status": "dry_run" if (force_dry or pb["dry_run"]) else "ran", "actions": acts}
        results.append(res)
        if not dry_run:
            _log({"at": datetime.now(timezone.utc).isoformat(), "alert_id": record.get("id"),
                  "title": record.get("title"), "incident_id": (record.get("details") or {}).get("incident_id"), **res})
    if not dry_run and to_run:
        with _Lock():                                 # keep the breaker counters the actions updated
            latest = _read_state()
            latest["failures"], latest["breaker_until"] = state.get("failures", 0), state.get("breaker_until", 0)
            _write_state(latest)
    return results


def recent_runs(limit: int = 50) -> List[Dict[str, Any]]:
    try:
        lines = RUN_LOG.read_text().splitlines()[-limit:]
    except OSError:
        return []
    out = []
    for ln in reversed(lines):
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def overview() -> Dict[str, Any]:
    pbs, errors = load_playbooks()
    runs = recent_runs(1000)
    cutoff = (datetime.now(timezone.utc)).timestamp() - 86400
    stats: Dict[str, Dict[str, Any]] = {}
    for r in runs:
        s = stats.setdefault(r["playbook"], {"last_run": None, "runs_24h": 0, "errors_24h": 0})
        s["last_run"] = s["last_run"] or r["at"]
        if datetime.fromisoformat(r["at"]).timestamp() >= cutoff:
            s["runs_24h"] += 1
            s["errors_24h"] += sum(1 for a in r["actions"] if a["status"] == "error")
    return {"playbooks": [{"id": p["id"], "name": p["name"], "enabled": p["enabled"], "dry_run": p["dry_run"],
                           "cooldown_minutes": p["cooldown"] // 60, "trigger": p["raw"]["trigger"]["match"],
                           "actions": [a["type"] for a in p["actions"]],
                           **stats.get(p["id"], {"last_run": None, "runs_24h": 0, "errors_24h": 0})} for p in pbs],
            "errors": errors, "dry_run_all": os.environ.get("SOC_PLAYBOOKS_DRY_RUN") == "1"}


def _cli() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--runs"]:
        for r in recent_runs(int(args[1]) if len(args) > 1 else 20):
            print(r["at"][:19], r["playbook"], r["status"], [(a["type"], a["status"]) for a in r["actions"]], r["title"][:50])
        return 0
    if args[:1] == ["--test"] and len(args) == 2:
        rec = next((a for a in soc_core._load_snapshot() if a.get("id") == args[1]), None)
        if rec is None:
            print("alert not found in the live feed")
            return 1
        res = run_for_alert(rec, dry_run=True)
        print(json.dumps(res, indent=2) if res else "no enabled playbook matches this alert")
        return 0
    pbs, errors = load_playbooks()
    print(f"file: {PLAYBOOKS_FILE}" + ("" if PLAYBOOKS_FILE.exists() else "  (does not exist)"))
    for p in pbs:
        print(f"  [{'enabled' if p['enabled'] else 'disabled'}{', dry-run' if p['dry_run'] else ''}] {p['id']} "
              f"-> {', '.join(a['type'] for a in p['actions'])}")
    for e in errors:
        print(f"  [INVALID] {e}")
    print(f"{len(pbs)} valid playbook(s), {len(errors)} problem(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(_cli())
