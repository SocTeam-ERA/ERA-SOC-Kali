#!/usr/bin/env python3
"""
service_watchdog.py
--------------------
Checks that this project's own continuous systemd services are actually
running, and raises a SOC alert (critical, so it also pushes to ntfy) if
one isn't. This is the "who watches the watchers" piece: Restart=always on
each service already recovers ordinary crashes within seconds on its own,
but that doesn't help if a service hits systemd's StartLimitBurst and gives
up restarting, or if someone stops one by hand and forgets to bring it back
-- until now, nothing would ever notice either of those, on a system meant
to run unattended, permanently.

State (data/watchdog_state.json) tracks which services are currently
considered down, so a persistent outage raises exactly one alert when it
starts and one "recovered" alert when it ends -- not a fresh alert every
time this runs while the service is still down.

Usage:
    python3 service_watchdog.py          # one-shot check (for the timer)
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import Alert, emit_alert  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
STATE_FILE = DATA_DIR / "watchdog_state.json"

# The continuous/always-on units this project depends on. Deliberately NOT
# the oneshot timer-triggered jobs (soc-scan, soc-cleanup-results, etc.) --
# those are expected to be "inactive (dead)" between runs, so "is it
# active" isn't the right health check for them.
SERVICES = [
    "soc-api",
    "soc-login",
    "soc-osquery-forwarder",
    "soc-suricata-forwarder",
    "soc-traffic-monitor",
    "soc-zeek-forwarder",
    "soc-zeek-boot",
    "soc-dhcp-fingerprint",
    "osqueryd",
    "suricata",
]


def is_active(unit: str) -> bool:
    r = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True)
    return r.stdout.strip() == "active"


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
    state = load_state()
    changed = False

    for svc in SERVICES:
        up = is_active(svc)
        was_down = state.get(svc, False)

        if not up and not was_down:
            emit_alert(Alert(
                type="intrusion", severity="critical",
                title=f"Service down: {svc}",
                detector="service_watchdog",
                description=(f"systemctl reports '{svc}' is not active. Restart=always "
                             "should recover an ordinary crash within seconds on its own -- "
                             "this means it either hit systemd's restart limit and gave up, "
                             "or someone stopped it by hand. Check: "
                             f"systemctl status {svc}"),
                details={"service": svc, "change": "down"},
            ))
            state[svc] = True
            changed = True
        elif up and was_down:
            emit_alert(Alert(
                type="intrusion", severity="normal",
                title=f"Service recovered: {svc}",
                detector="service_watchdog",
                description=f"'{svc}' is active again.",
                details={"service": svc, "change": "recovered"},
            ))
            state[svc] = False
            changed = True

    if changed:
        save_state(state)

    # Also check that the data sources themselves are still producing data.
    # Kept separate from the service checks above: a failure here must never
    # stop the watchdog from doing its main job.
    try:
        import source_health
        source_health.run()
    except Exception as e:
        print(f"[watchdog] source health check failed: {e}", file=sys.stderr)

    # Close informational change alerts nobody reviewed (acts at most every 6 hours).
    try:
        import alert_aging
        alert_aging.run_if_due()
    except Exception as e:
        print(f"[watchdog] alert aging failed: {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
