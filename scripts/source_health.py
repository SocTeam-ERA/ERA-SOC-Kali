#!/usr/bin/env python3
"""
source_health.py -- is each data source still producing data? (Sentinel's
"data connector health".)

service_watchdog.py already checks that our own services are running. This
checks the other half: a service can be "active" while its input has gone
quiet (Suricata stopped writing eve.json, the scan timer stopped firing, the
threat-intel feeds stopped refreshing). Each source has a freshness limit;
past it the source is "stale".

Results go to data/source_health.json (served by the API as /api/sources).
A source turning stale raises one alert and one "recovered" alert when it comes
back, like service_watchdog. A source that cannot be read at all (permissions,
unit not installed) is "unknown" and never alerts.

Run by service_watchdog.py every 2 minutes; or by hand:
    python3 source_health.py            check now and print
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import Alert, DATA_DIR, emit_alert  # noqa: E402
import reader_health  # noqa: E402

STATE_FILE = DATA_DIR / "source_health.json"

# kind: file  = newest write to `path`;  timer = last time a systemd timer fired;
#       meta  = when the threat-intel feeds were last downloaded;
#       backup = the last successful run of kali/backup_data.sh.
SOURCES: List[Dict[str, Any]] = [
    {"id": "suricata", "name": "Suricata IDS log", "kind": "file",
     "path": "/var/log/suricata/eve.json", "max_age_min": 10},
    {"id": "zeek", "name": "Zeek network log", "kind": "file",
     "path": "/opt/zeek/logs/current/conn.log", "max_age_min": 15},
    {"id": "scan", "name": "Scheduled network scan", "kind": "timer",
     "unit": "soc-scan.timer", "max_age_min": 300},
    {"id": "aide", "name": "AIDE file-integrity check", "kind": "timer",
     "unit": "soc-aide-check.timer", "max_age_min": 26 * 60},
    {"id": "chkrootkit", "name": "chkrootkit check", "kind": "timer",
     "unit": "soc-chkrootkit-forwarder.timer", "max_age_min": 26 * 60},
    {"id": "vlan", "name": "VLAN segmentation test", "kind": "timer",
     "unit": "soc-vlan-segmentation.timer", "max_age_min": 26 * 60},
    {"id": "threat_intel", "name": "Threat-intel feeds", "kind": "meta", "max_age_min": 72 * 60},
    {"id": "backup", "name": "SOC data backup", "kind": "backup", "max_age_min": 26 * 60},
    # kind "reader": not "is data arriving" but "can the follower still parse it" (reader_health.py).
    # Zeek's format flipped from JSON to TSV on 2026-09-21 and these three read it blind for two days
    # while the log kept growing and every service stayed "active".
    {"id": "zeek_notice_parsing", "name": "Zeek notice forwarder (log parsing)", "kind": "reader",
     "reader": "zeek_to_alerts", "max_age_min": 0},
    {"id": "dhcp_parsing", "name": "DHCP hostname enrichment (log parsing)", "kind": "reader",
     "reader": "dhcp_to_assets", "max_age_min": 0},
    {"id": "software_parsing", "name": "Software fingerprint enrichment (log parsing)", "kind": "reader",
     "reader": "software_to_assets", "max_age_min": 0},
]


def _last_event(src: Dict[str, Any]) -> Optional[float]:
    """Epoch seconds of the source's latest activity, or None if unknowable."""
    kind = src["kind"]
    if kind == "file":
        try:
            return os.stat(src["path"]).st_mtime
        except OSError:
            return None
    if kind == "timer":
        try:
            out = subprocess.run(["systemctl", "show", src["unit"], "-p", "LastTriggerUSec",
                                  "--timestamp=unix", "--value"], capture_output=True, text=True, timeout=10).stdout.strip()
            return float(out.lstrip("@")) if out.startswith("@") and float(out.lstrip("@")) > 0 else None
        except (OSError, ValueError, subprocess.SubprocessError):
            return None
    if kind == "backup":
        try:
            return datetime.fromisoformat(json.loads((DATA_DIR / "backup_status.json").read_text())["last_ok"]).timestamp()
        except (OSError, ValueError, KeyError):
            return None
    if kind == "meta":
        try:
            meta = json.loads((DATA_DIR / "threat_intel" / "meta.json").read_text())
            return datetime.fromisoformat(meta["kev"]["fetched"]).timestamp()
        except (OSError, ValueError, KeyError):
            return None
    return None


def check() -> List[Dict[str, Any]]:
    now = time.time()
    out = []
    for src in SOURCES:
        rec = {"id": src["id"], "name": src["name"], "kind": src["kind"], "max_age_minutes": src["max_age_min"]}
        if src["kind"] == "reader":
            entry = reader_health.status(src["reader"])
            if entry is None:
                rec.update(status="unknown", last_event=None, age_minutes=None)  # follower never ran / not installed
            else:
                ok_at = entry.get("last_parsed_at")
                try:
                    age = round((now - datetime.fromisoformat(ok_at).timestamp()) / 60, 1) if ok_at else None
                except ValueError:
                    age = None
                rec.update(status="stale" if reader_health.is_unhealthy(entry) else "healthy",
                           last_event=ok_at, age_minutes=age, unparsable_in_a_row=int(entry.get("streak") or 0))
            out.append(rec)
            continue
        last = _last_event(src)
        if last is None:
            rec.update(status="unknown", last_event=None, age_minutes=None)
        else:
            age = (now - last) / 60
            rec.update(status="stale" if age > src["max_age_min"] else "healthy",
                       last_event=datetime.fromtimestamp(last, tz=timezone.utc).isoformat(),
                       age_minutes=round(age, 1))
        out.append(rec)
    return out


def _load_state() -> Dict[str, Any]:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def _save_state(state: Dict[str, Any]) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(STATE_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def run() -> List[Dict[str, Any]]:
    previous = {s["id"]: s for s in _load_state().get("sources", [])}
    current = check()
    now = datetime.now(timezone.utc).isoformat()
    for rec in current:
        was = previous.get(rec["id"], {}).get("status")
        rec["since"] = previous.get(rec["id"], {}).get("since", now) if was == rec["status"] else now
        if rec["status"] == "stale" and was != "stale" and rec["kind"] == "reader":
            emit_alert(Alert(
                type="intrusion", severity="medium", detector="source_health",
                title=f"Log reader cannot parse its input: {rec['name']}",
                description=(f"{rec['name']} has read {rec.get('unparsable_in_a_row')} lines in a row that it could not "
                             "parse, with none succeeding in between. The log is being written and the service is running, "
                             "so nothing else notices: this is what happened when Zeek switched from JSON to TSV logs "
                             "(2026-09-21) and its forwarders saw nothing for two days. Check the format of the log it "
                             "reads, and whether Zeek's configuration changed (a package upgrade can replace local.zeek)."),
                details={"source": rec["id"], "unparsable_in_a_row": rec.get("unparsable_in_a_row"),
                         "last_parsed_at": rec.get("last_event"), "change": "unparseable"}), echo=False)
        elif rec["status"] == "stale" and was != "stale":
            emit_alert(Alert(
                type="intrusion", severity="medium", detector="source_health",
                title=f"Data source silent: {rec['name']}",
                description=(f"No new data from '{rec['name']}' for {rec['age_minutes']:.0f} minutes "
                             f"(expected at least every {rec['max_age_minutes']}). The service may be "
                             "running while its input has stopped; detections from this source are blind."),
                details={"source": rec["id"], "age_minutes": rec["age_minutes"], "change": "stale"}), echo=False)
        elif rec["status"] == "healthy" and was == "stale":
            emit_alert(Alert(
                type="intrusion", severity="normal", detector="source_health",
                title=f"Data source recovered: {rec['name']}",
                description=(f"'{rec['name']}' is parsing its input again." if rec["kind"] == "reader"
                             else f"'{rec['name']}' is producing data again."),
                details={"source": rec["id"], "change": "recovered"}), echo=False)
    _save_state({"checked": now, "sources": current})
    return current


if __name__ == "__main__":
    for s in run():
        age = "n/a" if s["age_minutes"] is None else f"{s['age_minutes']:.0f} min ago"
        limit = "parse check" if s["kind"] == "reader" else f"limit {s['max_age_minutes']} min"
        print(f"  [{s['status']:7}] {s['name']:28} last data {age} ({limit})")
