#!/usr/bin/env python3
"""
zeek_tsv.py
-----------
One reader for both formats a Zeek log can be written in, so no consumer in
this project depends on which one Zeek happens to be configured for:

  * classic tab-separated (the `#separator`/`#fields`/`#types` header block
    every zeekctl-managed log starts with), and
  * one JSON object per line (Zeek's optional `policy/tuning/json-logs`).

Confirmed 2026-09-23: Zeek switched from JSON to TSV on 2026-09-21 at 16:02,
the first restart after a package upgrade on 09-17 replaced the customised
site/local.zeek (kept as local.zeek.dpkg-old) and lost its
`@load policy/tuning/json-logs`. Every reader here had been written for JSON,
so from that restart on they all failed the same silent way -- json.loads()
raised on a TSV line, the error was swallowed as "not an event", and nothing
was logged anywhere: zeek_to_alerts.py forwarded no Zeek notice for two days,
dhcp_to_assets.py enriched nothing, and log_search.py returned nothing for
Zeek data newer than that restart. A reader that accepts either format turns
that class of config drift from "blind for days" into "no effect".

Built for a `--follow` consumer (see soc_core.tail_follow()) that only ever
sees one line at a time, in order, forever -- not a whole open file it can
seek around in. That rules out the common approach of reading the header once
up front: Zeek writes it once per file, zeekctl rotates every log hourly, and
a service that starts mid-hour and tails from the end of the current file
never sees that hour's header. ZeekTSVReader stays one long-lived object fed
one line at a time; it re-learns the column layout from each `#fields` line it
happens to see (the first line of a whole-file read, or the header of the next
hour's file arriving out of an ongoing tail), and cannot parse TSV rows before
the first header of its lifetime -- the blind spot `read_header_lines()` closes
by priming it from the file's current header at startup. JSON lines carry
their own field names and need no header at all.
"""
from __future__ import annotations

import gzip
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

UNSET = "-"        # Zeek's placeholder for an absent field (`#unset_field`; the default in every log here)
EMPTY = "(empty)"  # Zeek's placeholder for an empty string / empty set (`#empty_field`)


def _convert(value: str, ztype: Optional[str]) -> Any:
    """One TSV cell as the Python value Zeek's JSON writer would have produced for it."""
    if value == UNSET:
        return None
    if ztype is None:
        return value
    if ztype.startswith(("set[", "vector[")):
        inner = ztype[ztype.index("[") + 1:-1]
        return [] if value == EMPTY else [_convert(v, inner) for v in value.split(",")]
    if value == EMPTY:
        return ""
    try:
        if ztype in ("count", "int", "port"):
            return int(value)
        if ztype in ("time", "interval", "double"):
            return float(value)
    except ValueError:
        return value
    if ztype == "bool":
        return value == "T"
    return value


class ZeekTSVReader:
    """Feed it lines one at a time, in file order; get back a dict per data row (field
    name -> value, None for an unset field), or None for a line that carries no data
    (a header/comment line, a malformed line, or a TSV row seen before this reader's
    first header). Values are typed from the `#types` header when one has been seen
    (ports and counts become ints, times floats, sets lists), and stay strings when
    it has not -- matching what the JSON form of the same log contains."""

    def __init__(self) -> None:
        self._fields: Optional[List[str]] = None
        self._types: Optional[List[str]] = None
        # Health counters (see reader_health.py). A DATA line that could not be parsed is not
        # noise: a stream where nothing parses is a broken reader, and the streak is what tells
        # that apart from a quiet log. Headers, comments and blank lines are not data and never count.
        self.parsed = 0
        self.unparsable = 0
        self.unparsable_streak = 0   # unparsable data lines since the last one that parsed
        self.last_parsed: Optional[float] = None   # time.time() of the last parsed row

    def _bad(self) -> None:
        self.unparsable += 1
        self.unparsable_streak += 1
        return None

    def _good(self, row: Dict[str, Any]) -> Dict[str, Any]:
        self.parsed += 1
        self.unparsable_streak = 0
        self.last_parsed = time.time()
        return row

    @property
    def ready(self) -> bool:
        """Whether a TSV `#fields` header has been seen yet (JSON lines never need one)."""
        return self._fields is not None

    def feed(self, line: str) -> Optional[Dict[str, Any]]:
        line = line.rstrip("\r\n")
        if not line:
            return None
        if line[0] == "{":  # JSON form: self-describing, no header needed
            try:
                obj = json.loads(line)
            except ValueError:
                return self._bad()
            return self._good(obj) if isinstance(obj, dict) else self._bad()
        if line.startswith("#fields\t"):
            self._fields = line.split("\t")[1:]
            self._types = None  # a new file's layout: drop the previous file's types until its own #types line
            return None
        if line.startswith("#types\t"):
            self._types = line.split("\t")[1:]
            return None
        if line[0] == "#":
            return None  # #separator, #set_separator, #empty_field, #unset_field, #path, #open, #close
        if self._fields is None:
            return self._bad()  # a TSV row with no header seen yet this run -- can't map it safely
        values = line.split("\t")
        if len(values) != len(self._fields):
            return self._bad()  # malformed/truncated line (e.g. a write caught mid-flush)
        types = self._types if self._types and len(self._types) == len(self._fields) else [None] * len(values)
        return self._good({name: _convert(v, t) for name, v, t in zip(self._fields, values, types)})


# The name most call sites want: it reads either format.
ZeekLogReader = ZeekTSVReader


def read_header_lines(path: Path) -> List[str]:
    """The `#fields` and `#types` lines of `path` as it stands right now (plain or .gz), or []
    if the file doesn't exist yet, is JSON, or has none. A `--follow` consumer feeds these to
    its ZeekTSVReader once at startup, before it starts tailing from the end of the file --
    otherwise it stays blind to that log until the next hourly rotation hands it a fresh header
    on its own."""
    found: List[str] = []
    try:
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", errors="ignore") as fh:
            for line in fh:
                if line.startswith(("#fields\t", "#types\t")):
                    found.append(line.rstrip("\n"))
                    if len(found) == 2:
                        break
                elif not line.startswith("#") and line.strip():
                    break  # already past the header block
    except OSError:
        return []
    return found


def read_current_header(path: Path) -> Optional[str]:
    """Just the `#fields` line (see read_header_lines), or None."""
    for line in read_header_lines(path):
        if line.startswith("#fields\t"):
            return line
    return None
