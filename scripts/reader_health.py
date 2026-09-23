#!/usr/bin/env python3
"""
reader_health.py
----------------
Can each long-running log follower still PARSE what it reads?

source_health.py already notices a source that goes quiet. That is a different
failure from the one that hid for two days on 2026-09-21..23: Zeek kept writing
notices, the forwarder kept running and reading them, and every line failed to
parse (Zeek had switched from JSON to TSV). Nothing was quiet -- the log grew,
the service was "active", the process never crashed -- so no freshness or
liveness check could see it, and the alerts simply stopped coming.

The tell is a run of data lines that the reader could not parse with none that
parsed in between (ZeekTSVReader.unparsable_streak). A quiet hour has a streak of
zero; a healthy log has an occasional bad line and then a good one; a reader
facing a format it does not understand has a streak that only grows.

Each follower creates a Reporter and calls tick() per line; it rewrites its entry
in data/zeek_reader_stats.json at most once a minute (immediately when it flips
between healthy and unhealthy). source_health.py reads that file and raises the
alert. A separate small file, not source_health.json, because followers write it
continuously from their own processes and source_health rewrites its own.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import soc_core

STATS_FILE = soc_core.DATA_DIR / "zeek_reader_stats.json"
# This many unparsable data lines with none parsed in between means "broken", not "noisy".
UNHEALTHY_STREAK = 10
WRITE_EVERY_SECONDS = 60.0


def _read_all() -> Dict[str, Any]:
    try:
        data = json.loads(STATS_FILE.read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


class Reporter:
    """Publishes one follower's parse health. Cheap to call on every line."""

    def __init__(self, name: str, reader) -> None:
        self.name = name
        self.reader = reader
        self._last_write = 0.0
        self._flagged = False
        self.write()  # the entry exists from the moment the follower starts

    def tick(self) -> None:
        bad = self.reader.unparsable_streak >= UNHEALTHY_STREAK
        if bad != self._flagged or time.monotonic() - self._last_write >= WRITE_EVERY_SECONDS:
            self.write()

    def write(self) -> None:
        r = self.reader
        entry = {
            "parsed": r.parsed, "unparsable": r.unparsable, "streak": r.unparsable_streak,
            "last_parsed_at": (datetime.fromtimestamp(r.last_parsed, tz=timezone.utc).isoformat()
                               if r.last_parsed else None),
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        try:
            with soc_core.diff_state_lock(STATS_FILE):
                data = _read_all()
                if entry["last_parsed_at"] is None:  # keep the last success across a restart
                    entry["last_parsed_at"] = (data.get(self.name) or {}).get("last_parsed_at")
                data[self.name] = entry
                fd, tmp = tempfile.mkstemp(dir=str(STATS_FILE.parent), suffix=".tmp")
                os.chmod(tmp, 0o664)
                try:
                    with os.fdopen(fd, "w") as f:
                        json.dump(data, f, indent=2)
                    os.replace(tmp, STATS_FILE)
                finally:
                    if os.path.exists(tmp):
                        os.remove(tmp)
        except OSError:
            pass  # health reporting must never take the follower down
        self._last_write = time.monotonic()
        self._flagged = r.unparsable_streak >= UNHEALTHY_STREAK


def status(name: str) -> Optional[Dict[str, Any]]:
    """One follower's published entry, or None if it has never run."""
    entry = _read_all().get(name)
    return entry if isinstance(entry, dict) else None


def is_unhealthy(entry: Dict[str, Any]) -> bool:
    return int(entry.get("streak") or 0) >= UNHEALTHY_STREAK
