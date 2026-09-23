#!/usr/bin/env python3
"""
code_freshness.py
-----------------
Is each long-running service running the code that is on disk?

A service loads its Python once, at start. A fix committed afterwards does
nothing for it until somebody restarts it -- and restarting needs sudo, so it is
routinely forgotten. Nothing noticed: the doc notes are full of hand-written
"requires restarting service X to load the new code" reminders, and on
2026-09-22 the dhcp_to_assets.py fix (committed 11:07) only went live at 18:48,
when the administrator happened to run the restart commands.

For every service whose ExecStart is a script of this project, this compares the
newest modification time of that script and of every project module it imports
(found by parsing the imports, recursively) with the moment the service last
started. If something is newer, the service is running old code.

service_watchdog.py calls run() every 2 minutes: one normal-severity alert while
any service is stale (only for changes older than an hour, so it stays quiet
while someone is actively editing), resolved automatically once everything has
been restarted. soc_doctor.py lists them as warnings.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import tempfile
import os
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import soc_core

SUITE = Path(__file__).resolve().parent.parent
ROOTS = [SUITE / "scripts", SUITE / "kali"]
GRACE_SECONDS = 3600     # an edit from the last hour is probably still being worked on
CLOCK_SLACK = 2.0        # seconds: a file written in the same second the service started is not newer
STATE_FILE = soc_core.DATA_DIR / "code_freshness.json"


def local_imports(script: Path, roots: Iterable[Path] = ROOTS, _seen: Optional[Set[Path]] = None) -> Set[Path]:
    """`script` plus every project module it imports, directly or through another one."""
    seen = _seen if _seen is not None else set()
    if script in seen:
        return seen
    seen.add(script)
    if script.suffix != ".py":
        return seen
    try:
        tree = ast.parse(script.read_text(errors="ignore"))
    except (OSError, SyntaxError):
        return seen
    for node in ast.walk(tree):  # walk, not iter_child_nodes: imports inside functions load lazily but still load
        names: List[str] = []
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names = [node.module]
        for name in names:
            for root in roots:
                cand = root / (name.split(".")[0] + ".py")
                if cand.is_file():
                    local_imports(cand.resolve(), roots, seen)
    return seen


def newest_code(script: Path, roots: Iterable[Path] = ROOTS) -> Tuple[float, Path]:
    """(mtime, path) of the most recently modified file the service's code is made of."""
    best: Tuple[float, Path] = (0.0, script)
    for f in local_imports(script.resolve(), roots):
        try:
            m = f.stat().st_mtime
        except OSError:
            continue
        if m > best[0]:
            best = (m, f)
    return best


def is_stale(started: float, edited: float, now: float, grace: float = GRACE_SECONDS) -> bool:
    return edited > started + CLOCK_SLACK and now - edited >= grace


def _systemctl(unit: str, *props: str) -> str:
    try:
        return subprocess.run(["systemctl", "show", f"{unit}.service", *props, "--value"],
                              capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def service_script(unit: str) -> Optional[Path]:
    """The project script a unit runs, or None if it runs something else (osqueryd, suricata...)."""
    m = re.search(r"argv\[\]=([^;]*);", _systemctl(unit, "-p", "ExecStart"))
    for tok in (m.group(1).split() if m else []):
        if tok.startswith(str(SUITE)) and tok.endswith((".py", ".sh")):
            return Path(tok)
    return None


def service_started(unit: str) -> Optional[float]:
    if _systemctl(unit, "-p", "ActiveState") != "active":
        return None
    out = _systemctl(unit, "-p", "ActiveEnterTimestamp", "--timestamp=unix")
    try:
        return float(out.lstrip("@"))
    except ValueError:
        return None


def stale_services(units: Iterable[str], grace: float = GRACE_SECONDS) -> List[Dict[str, Any]]:
    now = time.time()
    out = []
    for unit in units:
        script, started = service_script(unit), service_started(unit)
        if script is None or started is None:
            continue
        edited, path = newest_code(script)
        if is_stale(started, edited, now, grace):
            out.append({"unit": unit, "started": started, "edited": edited,
                        "file": str(path.relative_to(SUITE)) if SUITE in path.parents else str(path)})
    return out


# --------------------------------------------------------------------------- #
#  Alert lifecycle (called by service_watchdog every 2 minutes)
# --------------------------------------------------------------------------- #

def _load() -> Dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save(state: Dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(STATE_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def run(units: Iterable[str]) -> List[Dict[str, Any]]:
    """One alert while any service is stale (a new one only when the set changes), resolved once none is."""
    stale = stale_services(units)
    state = _load()
    signature = sorted(s["unit"] for s in stale)
    if signature == state.get("units", []):
        return stale                          # nothing changed since the last look
    if state.get("alert_id"):                 # the situation changed: retire the old alert first
        try:
            soc_core.set_alert_status(
                state["alert_id"], "resolved", actor="code-freshness",
                note=("All services now run the current code." if not stale
                      else "The set of services running old code changed; a new alert follows."))
        except ValueError:
            pass                              # already gone from the snapshot cap
    alert_id = None
    if stale:
        lines = "; ".join(f"{s['unit']} (started before {s['file']} changed)" for s in stale)
        alert_id = soc_core.emit_alert(soc_core.Alert(
            type="intrusion", severity="normal", detector="code_freshness",
            title=f"{len(stale)} service(s) running older code than the files on disk",
            description=(f"{lines}. A service loads its code once, at start, so fixes committed since do nothing "
                         f"for it. Restart: sudo systemctl restart {' '.join(s['unit'] for s in stale)}"),
            details={"services": stale}), echo=False).get("id")
    _save({"units": signature, "alert_id": alert_id})
    return stale


if __name__ == "__main__":
    from service_watchdog import SERVICES
    rows = stale_services(SERVICES, grace=0)
    if not rows:
        print("Every service runs the code that is on disk.")
    for r in rows:
        print(f"  {r['unit']:26} started {time.strftime('%m-%d %H:%M', time.localtime(r['started']))}, "
              f"{r['file']} changed {time.strftime('%m-%d %H:%M', time.localtime(r['edited']))}")
