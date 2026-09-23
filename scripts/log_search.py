#!/usr/bin/env python3
"""
log_search.py -- search the raw data behind the alerts (Zeek logs, Suricata's
eve.json, the alert history), the Splunk-style "search bar".

Sources:
  alerts        data/alerts.jsonl (every alert ever raised)
  suricata      /var/log/suricata/eve.json (flows, dns, http, tls, alerts...)
  zeek:<log>    /opt/zeek/logs: the live log plus the hourly archives
                (zeek:conn, zeek:dns, zeek:http, zeek:ssl, zeek:notice ...)

Query (space-separated terms, ALL must hold; quote phrases):
  word            case-insensitive text anywhere in the record
  field:value     the field equals value ("id.orig_h:10.0.0.5", "event_type:alert")
  field~text      the field contains text
  field:10.0.0.0/8   the field is an IP inside that network
  -term           the record must NOT match the term
Shortcuts: src dst sport dport ip host (any of src/dst; any hostname field), plus
type and sig for suricata. A record's nested fields use dots ("alert.signature").
No regular expressions are accepted, on purpose.

Bounded by design: newest first, stops at `limit` results, `max_bytes` scanned or
`timeout` seconds, and says which one ended the search. The eve.json is tens of
GB, so it is only ever read from the end.

    python3 log_search.py --source zeek:dns --q 'query~example.com' --since 6h
    python3 log_search.py --source suricata --q 'type:alert src:10.201.0.0/16' --since 24h
"""
from __future__ import annotations

import argparse
import glob
import gzip
import ipaddress
import json
import os
import re
import resource
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

import zeek_tsv

_DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
ALERTS_LOG = _DATA_DIR / "alerts.jsonl"
EVE_FILE = Path(os.environ.get("SOC_EVE_FILE", "/var/log/suricata/eve.json"))
ZEEK_DIR = Path(os.environ.get("SOC_ZEEK_DIR", "/opt/zeek/logs"))

DEFAULT_SINCE, MAX_SINCE = 3600, 7 * 86400
DEFAULT_LIMIT, MAX_LIMIT = 100, 500
DEFAULT_TIMEOUT, MAX_TIMEOUT = 8.0, 15.0
DEFAULT_MAX_BYTES, MAX_BYTES = 400_000_000, 2_000_000_000
MAX_OUTPUT_BYTES = 3_000_000
MAX_VALUE_CHARS = 500
CHUNK = 1 << 20
_NAME = re.compile(r"^[a-z0-9_]{1,40}$")
_ZEEK_TS = re.compile(rb'^\{"ts":([0-9.]+)')            # JSON form
_ZEEK_TSV_TS = re.compile(rb'^([0-9]{9,11}\.[0-9]+)\t')       # classic TSV form: first column
_EVE_TS = re.compile(rb'^\{"timestamp":"([^"]+)"')
_DROP_KEYS = {"payload", "payload_printable", "packet", "packet_info"}

_ALIASES = {
    "zeek": {"src": ["id.orig_h"], "dst": ["id.resp_h"], "sport": ["id.orig_p"], "dport": ["id.resp_p"],
             "ip": ["id.orig_h", "id.resp_h"], "host": ["query", "host", "server_name"]},
    "suricata": {"src": ["src_ip"], "dst": ["dest_ip"], "sport": ["src_port"], "dport": ["dest_port"],
                 "ip": ["src_ip", "dest_ip"], "type": ["event_type"], "sig": ["alert.signature"],
                 "host": ["http.hostname", "dns.rrname", "tls.sni"]},
    "alerts": {"src": ["source_ip"], "ip": ["source_ip"]},
}


class Budget:
    def __init__(self, max_bytes: int, timeout: float):
        self.max_bytes, self.deadline = max_bytes, time.monotonic() + timeout
        self.bytes = self.lines = 0
        self.stopped = "complete"

    def spent(self) -> bool:
        if self.bytes >= self.max_bytes:
            self.stopped = "bytes"
        elif time.monotonic() > self.deadline:
            self.stopped = "time"
        return self.stopped != "complete"


# --------------------------------------------------------------------------- #
#  Query
# --------------------------------------------------------------------------- #

class Term:
    def __init__(self, kind: str, field: Optional[str], value: str, negate: bool):
        self.kind, self.field, self.negate = kind, field, negate      # kind: text | eq | contains | cidr
        self.value = value.lower()
        self.network = None
        if kind == "eq" and "/" in value:
            try:
                self.network, self.kind = ipaddress.ip_network(value, strict=False), "cidr"
            except ValueError:
                pass


def parse_query(q: str) -> List[Term]:
    try:
        tokens = shlex.split(q or "")
    except ValueError as e:
        raise ValueError(f"cannot parse the query ({e}); close your quotes") from None
    if len(tokens) > 20:
        raise ValueError("too many terms in the query (max 20)")
    terms = []
    for tok in tokens:
        neg = tok.startswith("-") and len(tok) > 1
        if neg:
            tok = tok[1:]
        m = re.match(r"^([A-Za-z0-9_.\-]+)(:|~)(.+)$", tok)
        if m:
            terms.append(Term("contains" if m.group(2) == "~" else "eq", m.group(1), m.group(3), neg))
        elif tok:
            terms.append(Term("text", None, tok, neg))
    return terms


def _lookup(rec: Dict[str, Any], path: str) -> Any:
    if path in rec:                                   # Zeek keys contain literal dots
        return rec[path]
    cur: Any = rec
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _values(rec: Dict[str, Any], family: str, field: str) -> List[Any]:
    out: List[Any] = []
    for path in _ALIASES.get(family, {}).get(field, [field]):
        v = _lookup(rec, path)
        out += v if isinstance(v, list) else [v]
    if family == "alerts" and field == "ip":
        out += [e.get("value") for e in (rec.get("details") or {}).get("entities", []) if e.get("type") == "ip"]
    return [v for v in out if v is not None]


def _term_ok(t: Term, rec: Dict[str, Any], family: str) -> bool:
    vals = _values(rec, family, t.field)
    if t.kind == "cidr":
        for v in vals:
            try:
                if ipaddress.ip_address(str(v)) in t.network:
                    return True
            except ValueError:
                continue
        return False
    strs = [str(v).lower() if not isinstance(v, bool) else str(v).lower() for v in vals]
    return any(s == t.value for s in strs) if t.kind == "eq" else any(t.value in s for s in strs)


def matches(terms: List[Term], line_lower: bytes, rec: Optional[Dict[str, Any]], family: str) -> bool:
    for t in terms:
        if t.kind == "text":
            ok = t.value.encode() in line_lower
        else:
            ok = rec is not None and _term_ok(t, rec, family)
        if ok == t.negate:
            return False
    return True


# --------------------------------------------------------------------------- #
#  Reading
# --------------------------------------------------------------------------- #

def _iso_to_epoch(s: str) -> Optional[float]:
    try:
        dt = datetime.fromisoformat(s)
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def _line_epoch(line: bytes, family: str) -> Optional[float]:
    """Cheap timestamp read from the start of a Zeek/Suricata line (alerts are parsed instead)."""
    if family == "zeek":
        m = _ZEEK_TS.match(line) or _ZEEK_TSV_TS.match(line)
        return float(m.group(1)) if m else None
    if family == "suricata":
        m = _EVE_TS.match(line)
        return _iso_to_epoch(m.group(1).decode()) if m else None
    return None


def _reverse_lines(path: Path, budget: Budget) -> Iterator[bytes]:
    with path.open("rb") as f:
        f.seek(0, 2)
        pos, buf = f.tell(), b""
        while pos > 0:
            if budget.spent():
                return
            step = min(CHUNK, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            budget.bytes += step
            parts = buf.split(b"\n")
            buf = parts[0]
            for ln in reversed(parts[1:]):
                if ln:
                    yield ln
        if buf:
            yield buf


def _zeek_archives(name: str, since: float) -> List[Path]:
    """Hourly archives for this log that can hold data newer than `since`, newest first."""
    found = []
    for p in glob.glob(str(ZEEK_DIR / "20??-??-??" / f"{name}.*.log.gz")):
        m = re.search(r"/(\d{4}-\d{2}-\d{2})/[a-z0-9_]+\.(\d{2}:\d{2}:\d{2})-(\d{2}:\d{2}:\d{2})\.log\.gz$", p)
        if not m:
            continue
        try:
            end = time.mktime(time.strptime(f"{m.group(1)} {m.group(3)}", "%Y-%m-%d %H:%M:%S"))
            if m.group(3) <= m.group(2):
                end += 86400
        except ValueError:
            continue
        if end >= since - 3600:
            found.append((end, Path(p)))
    return [p for _, p in sorted(found, reverse=True)]


def _zeek_log_names() -> List[str]:
    """Every Zeek log with data on disk: the live file, or an hourly archive of it. Zeek
    creates many logs (notice, software, weird, ...) only on their first event after each
    hourly rotation, so a log that is perfectly real is often absent from current/."""
    names = set()
    cur = ZEEK_DIR / "current"
    if cur.is_dir():
        names |= {p.stem for p in cur.glob("*.log")}
    for p in glob.glob(str(ZEEK_DIR / "20??-??-??" / "*.log.gz")):
        m = re.match(r"([a-z0-9_]+)\.\d{2}:\d{2}:\d{2}-\d{2}:\d{2}:\d{2}\.log\.gz$", os.path.basename(p))
        if m:
            names.add(m.group(1))
    return sorted(n for n in names if _NAME.match(n))


def available_sources() -> Dict[str, Any]:
    zeek = _zeek_log_names()
    return {"sources": ["alerts", "suricata"] + [f"zeek:{n}" for n in zeek],
            "defaults": {"since": "1h", "limit": DEFAULT_LIMIT, "timeout": DEFAULT_TIMEOUT},
            "limits": {"since": "7d", "limit": MAX_LIMIT, "timeout": MAX_TIMEOUT},
            "syntax": {"text": "word or \"quoted phrase\" anywhere in the record", "equals": "field:value",
                       "contains": "field~text", "network": "src:10.0.0.0/8", "exclude": "-term",
                       "shortcuts": "src dst sport dport ip host (+ type, sig for suricata)"},
            "examples": ["dst:8.8.8.8 dport:53", "query~example.com", "type:alert sig~Nmap -src:10.69.0.40",
                         "ip:10.201.5.155 \"login failed\""]}


# --------------------------------------------------------------------------- #
#  Search
# --------------------------------------------------------------------------- #

def parse_since(v: Any) -> float:
    if v is None or v == "":
        return DEFAULT_SINCE
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        secs = float(v)
    else:
        m = re.fullmatch(r"(\d+)\s*([smhd]?)", str(v).strip().lower())
        if not m:
            raise ValueError("since must look like 90s, 15m, 6h, 2d or a number of seconds")
        secs = int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    if not 1 <= secs <= MAX_SINCE:
        raise ValueError("since must be between 1 second and 7 days")
    return secs


def _clean(rec: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in rec.items():
        if k in _DROP_KEYS:
            continue
        out[k] = v[:MAX_VALUE_CHARS] + "..." if isinstance(v, str) and len(v) > MAX_VALUE_CHARS else v
    return out


def search(source: str, q: str = "", since: Any = None, limit: Any = None, timeout: Any = None,
           max_bytes: Any = None) -> Dict[str, Any]:
    started = time.monotonic()
    since_s = parse_since(since)
    limit = DEFAULT_LIMIT if limit is None else int(limit)
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_LIMIT}")
    timeout = DEFAULT_TIMEOUT if timeout is None else float(timeout)
    if not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError(f"timeout must be between 1 and {MAX_TIMEOUT} seconds")
    max_bytes = DEFAULT_MAX_BYTES if max_bytes is None else int(max_bytes)
    if not 1_000_000 <= max_bytes <= MAX_BYTES:
        raise ValueError("max_bytes out of range")
    terms = parse_query(q)
    if not terms:
        raise ValueError("write something to search for (see /api/search/sources for the syntax)")

    family, name = (source.split(":", 1) + [""])[:2] if ":" in source else (source, "")
    if family == "zeek":
        if not _NAME.match(name) or name not in _zeek_log_names():
            raise ValueError(f"unknown Zeek log {name!r}; see the source list")
    elif family not in ("alerts", "suricata") or name:
        raise ValueError("unknown source; use alerts, suricata or zeek:<log>")

    cutoff = time.time() - since_s
    budget = Budget(max_bytes, timeout)
    results: List[Tuple[float, Dict[str, Any]]] = []
    size = 0
    # Zeek may write a log as JSON or as classic TSV (it flipped on 2026-09-21, see zeek_tsv.py).
    # A TSV file names its columns only in its own header, so each file gets a reader primed
    # from that header; a JSON file needs none.
    zreader: List[Optional[zeek_tsv.ZeekTSVReader]] = [None]

    def use_zeek_file(path: Path) -> None:
        headers = zeek_tsv.read_header_lines(path)
        if headers:
            zreader[0] = zeek_tsv.ZeekTSVReader()
            for h in headers:
                zreader[0].feed(h)
        else:
            zreader[0] = None

    def consider(line: bytes) -> Optional[bool]:
        """True = collected, False = older than the window, None = no match."""
        nonlocal size
        budget.lines += 1
        ts = _line_epoch(line, family)
        if ts is not None and ts < cutoff:
            return False
        low = line.lower()
        if not all(t.value.encode() in low for t in terms if t.kind == "text" and not t.negate):
            return None
        if zreader[0] is not None and line[:1] != b"{":
            rec = zreader[0].feed(line.decode("utf-8", "replace"))
            if rec is None:
                return None          # a #header/#close line or a malformed row
        else:
            try:
                rec = json.loads(line)
            except ValueError:
                return None
        if family == "alerts":
            ts = _iso_to_epoch(str(rec.get("timestamp", "")))
            if ts is not None and ts < cutoff:
                return False
        if not matches(terms, low, rec, family):
            return None
        clean = _clean(rec)
        size += len(json.dumps(clean, default=str))
        results.append((ts or 0.0, clean))
        return True

    def scan_reverse(path: Path) -> bool:
        """Scan newest-first; returns True if the window start was reached."""
        older = 0
        for line in _reverse_lines(path, budget):
            r = consider(line)
            older = older + 1 if r is False else 0
            if older >= 50:
                return True
            if len(results) >= limit or size >= MAX_OUTPUT_BYTES:
                budget.stopped = "limit"
                return False
        return False

    if family == "alerts":
        if ALERTS_LOG.exists():
            scan_reverse(ALERTS_LOG)
    elif family == "suricata":
        if not EVE_FILE.exists():
            raise ValueError("Suricata's eve.json is not available on this machine")
        scan_reverse(EVE_FILE)
    else:
        current = ZEEK_DIR / "current" / f"{name}.log"
        use_zeek_file(current)
        reached = scan_reverse(current) if current.is_file() else False
        if not reached and budget.stopped == "complete":
            for arch in _zeek_archives(name, cutoff):
                if budget.spent() or len(results) >= limit:
                    break
                batch: List[Tuple[float, Dict[str, Any]]] = []
                mark = len(results)
                use_zeek_file(arch)
                try:
                    with gzip.open(arch, "rb") as fh:
                        for n, line in enumerate(fh):
                            budget.bytes += len(line)
                            if n % 2000 == 0 and budget.spent():
                                break
                            consider(line.rstrip(b"\n"))
                except (OSError, EOFError):
                    continue
                batch = results[mark:]
                results[mark:] = sorted(batch, key=lambda x: -x[0])      # newest first within the file
                if len(results) >= limit or size >= MAX_OUTPUT_BYTES:
                    budget.stopped = "limit"
                    break

    results.sort(key=lambda x: -x[0])
    rows = results[:limit]
    return {
        "source": source, "query": q, "since_seconds": int(since_s), "count": len(rows),
        "stopped": budget.stopped if budget.stopped != "complete" else ("limit" if len(results) >= limit else "complete"),
        "scanned_mb": round(budget.bytes / 1e6, 1), "scanned_lines": budget.lines,
        "elapsed_ms": int((time.monotonic() - started) * 1000),
        "results": [{"time": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts else None, "record": rec}
                    for ts, rec in rows],
    }


# --------------------------------------------------------------------------- #
#  Isolated execution (used by the API) and CLI
# --------------------------------------------------------------------------- #

def run_isolated(params: Dict[str, Any]) -> Dict[str, Any]:
    """Run search() in a child process with CPU and memory limits, so a heavy
    query cannot stall or bloat the API. Raises ValueError for bad input."""
    timeout = params.get("timeout") or DEFAULT_TIMEOUT
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise ValueError("timeout must be a number") from None

    def limits():
        cpu = int(min(max(timeout, 1), MAX_TIMEOUT)) + 5
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))

    try:
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--json", json.dumps(params)],
                              capture_output=True, text=True, timeout=min(max(timeout, 1), MAX_TIMEOUT) + 10,
                              preexec_fn=limits)
    except subprocess.TimeoutExpired:
        raise RuntimeError("the search took too long and was stopped") from None
    if proc.returncode == 2:
        raise ValueError(proc.stderr.strip() or "invalid search")
    if proc.returncode != 0:
        raise RuntimeError("the search failed")
    return json.loads(proc.stdout)


def _main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--source", default="alerts")
    ap.add_argument("--q", default="")
    ap.add_argument("--since")
    ap.add_argument("--limit")
    ap.add_argument("--timeout")
    ap.add_argument("--max-bytes")
    ap.add_argument("--json", help="all parameters as one JSON object (used by the API)")
    a = ap.parse_args()
    params = json.loads(a.json) if a.json else {"source": a.source, "q": a.q, "since": a.since, "limit": a.limit,
                                                 "timeout": a.timeout, "max_bytes": a.max_bytes}
    try:
        res = search(str(params.get("source", "alerts")), str(params.get("q", "")), params.get("since"),
                     params.get("limit"), params.get("timeout"), params.get("max_bytes"))
    except (ValueError, TypeError) as e:
        print(str(e), file=sys.stderr)
        return 2
    if a.json:
        json.dump(res, sys.stdout)
    else:
        print(f"{res['count']} result(s) from {res['source']} -- stopped: {res['stopped']}, "
              f"scanned {res['scanned_mb']} MB in {res['elapsed_ms']} ms")
        for r in res["results"]:
            # r["time"] is UTC (kept that way in the API/--json path above, the correct
            # convention for machine consumers); only this terminal-facing branch converts
            # it to the operator's local time zone, since a bare UTC timestamp on screen
            # reads as "now" to a human and led to real confusion (2026-09-22, Calgary).
            local = datetime.fromisoformat(r["time"]).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if r["time"] else "-"
            print(local, json.dumps(r["record"])[:220])
    return 0


if __name__ == "__main__":
    sys.exit(_main())
