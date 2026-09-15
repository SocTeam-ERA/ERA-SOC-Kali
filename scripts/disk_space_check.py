#!/usr/bin/env python3
"""
disk_space_check.py
--------------------
Alerts before this appliance runs out of disk space, rather than after.
Nothing else in this project watches for that: Suricata's eve.json alone
grows at roughly 2.6GB/day on this box, on top of everything else
(nmap XML, .pcaps, osquery/Zeek logs) -- on a system meant to run
unattended forever, running out of space is a slow-motion but real
availability risk (services can't write their logs, alerts can silently
stop landing), and it's cheap to catch early.

Two thresholds, matching common convention:
    >= 80% used -> medium  ("plan a cleanup")
    >= 90% used -> critical ("act now")
State (data/disk_space_state.json) tracks the last level alerted so this
raises exactly one alert per threshold crossing (going up OR back down
below it), not a fresh one every time this runs while still above it.

Usage:
    python3 disk_space_check.py                    # checks / by default
    DISK_CHECK_PATH=/var python3 disk_space_check.py
"""
from __future__ import annotations
import json, os, shutil, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import Alert, emit_alert  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
STATE_FILE = DATA_DIR / "disk_space_state.json"
CHECK_PATH = os.environ.get("DISK_CHECK_PATH", "/")

MEDIUM_THRESHOLD = float(os.environ.get("DISK_MEDIUM_PCT", "80"))
CRITICAL_THRESHOLD = float(os.environ.get("DISK_CRITICAL_PCT", "90"))


def level_for(pct: float) -> str | None:
    if pct >= CRITICAL_THRESHOLD:
        return "critical"
    if pct >= MEDIUM_THRESHOLD:
        return "medium"
    return None


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(STATE_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def run() -> int:
    total, used, free = shutil.disk_usage(CHECK_PATH)
    pct = used / total * 100
    level = level_for(pct)

    state = load_state()
    last_level = state.get("level")

    if level == last_level:
        return 0  # no change to report

    if level is not None:
        emit_alert(Alert(
            type="vuln", severity=level,
            title=f"Disk space at {pct:.0f}% used on {CHECK_PATH}",
            detector="disk_space_check",
            description=(f"{CHECK_PATH} is at {pct:.1f}% used ({free / 1e9:.1f}GB free of "
                         f"{total / 1e9:.1f}GB). Suricata's eve.json alone grows fast on this "
                         "box -- review kali/results/ retention (cleanup_results.sh) and "
                         "/var/log/suricata/ if this keeps climbing."),
            details={"path": CHECK_PATH, "percent_used": round(pct, 1),
                     "free_bytes": free, "total_bytes": total, "level": level},
        ))
    elif last_level is not None:
        emit_alert(Alert(
            type="vuln", severity="normal",
            title=f"Disk space back to normal on {CHECK_PATH} ({pct:.0f}% used)",
            detector="disk_space_check",
            description=f"{CHECK_PATH} dropped back below {MEDIUM_THRESHOLD:.0f}% used.",
            details={"path": CHECK_PATH, "percent_used": round(pct, 1), "level": None},
        ))

    save_state({"level": level})
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
