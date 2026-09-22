#!/usr/bin/env python3
"""
zeek_tsv.py
-----------
Parses Zeek's classic tab-separated log format (the `#separator`/`#fields`/
`#types` header block every zeekctl-managed log starts with -- dhcp.log,
software.log, conn.log, ... all use it; this project isn't running the
optional JSON-logs policy script).

Built for a `--follow` consumer (see soc_core.tail_follow()) that only ever
sees one line at a time, in order, forever -- not a whole open file it can
seek around in. That rules out the common approach of reading the header
once up front: Zeek only writes it once, right when the file is created,
and zeekctl rotates every log hourly by default, so a service that starts
mid-hour and tails from the end of the current file (as every --follow
detector in this project does, to skip stale history on startup) will never
see that hour's header naturally -- it only shows up again at the next
rotation. ZeekTSVReader stays a single long-lived object fed one line at a
time; it re-learns the column layout from each `#fields` line it happens to
see (whether that is the very first line of a one-shot whole-file read, or
the header for hour N+1 arriving out of an ongoing tail), and simply can't
parse data rows before the first header of its lifetime -- exactly the
up-to-an-hour blind spot `read_current_header()` below exists to close.

Confirmed 2026-09-22: kali/dhcp_to_assets.py had been running as a systemd
service since it was written, silently enriching zero assets the entire
time -- it called json.loads() on every line, but these logs are TSV, not
JSON (Zeek's JSON output is a separate, opt-in policy script this project
never loaded). json.JSONDecodeError was caught and swallowed as "not a
sighting", so the bug produced no errors, just a permanently empty result.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional

UNSET = "-"  # Zeek's placeholder for an empty/absent field (configurable via #unset_field,
             # but every log in this project uses the default)


class ZeekTSVReader:
    """Feed it lines one at a time, in file order; get back a dict per data row (field
    name -> value, or None for an unset field), or None for a line that carries no data
    (a header/comment line, or a data line seen before this reader's first header)."""

    def __init__(self) -> None:
        self._fields: Optional[list[str]] = None

    @property
    def ready(self) -> bool:
        """Whether a #fields header has been seen yet -- data rows are dropped until it has."""
        return self._fields is not None

    def feed(self, line: str) -> Optional[Dict[str, Optional[str]]]:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith("#fields\t"):
            self._fields = line.split("\t")[1:]
            return None
        if line.startswith("#"):
            return None  # #separator, #types, #open, #close, ...
        if self._fields is None:
            return None  # a data row with no header seen yet this run -- can't map it safely
        values = line.split("\t")
        if len(values) != len(self._fields):
            return None  # malformed/truncated line (e.g. a write caught mid-flush)
        return {name: (None if v == UNSET else v) for name, v in zip(self._fields, values)}


def read_current_header(path: Path) -> Optional[str]:
    """The `#fields` line of `path` as it stands right now, or None if the file doesn't
    exist yet or has none (empty/rotated away). A `--follow` consumer calls this once at
    startup, before it starts tailing from the end of the file, and feeds the result to
    its ZeekTSVReader -- otherwise it stays blind to that log until the next hourly
    rotation happens to hand it a fresh header on its own."""
    try:
        with path.open(errors="ignore") as fh:
            for line in fh:
                if line.startswith("#fields\t"):
                    return line.rstrip("\n")
                if not line.startswith("#") and line.strip():
                    return None  # already past the header block without finding one
    except OSError:
        return None
    return None
