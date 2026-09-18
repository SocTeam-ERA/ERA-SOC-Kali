#!/usr/bin/env python3
"""
archive_by_filter.py
---------------------
General-purpose alert archiving, for the cases archive_alerts.py's
age-based retention doesn't cover: sweeping out a specific detector's
historical noise (a bug that's since been fixed), or collapsing repeated
identical findings down to their most recent occurrence (a still-standing
issue that keeps re-alerting before a diff-state fix catches up).

Confirmed 2026-09-18 the hard way: several one-off scripts written during
today's noise cleanup each rebuilt data/alerts.json from data/alerts.jsonl
as their last step -- which silently reset every alert's status back to
"open", because alerts.jsonl is the immutable audit trail set_alert_status()
never touches (only the live snapshot and alert_status_log.jsonl get a
status change; see soc_core.set_alert_status()'s own docstring). That wiped
491 alerts a teammate had just resolved, twice, before anyone noticed. This
script loads the CURRENT snapshot first and overlays its status/
status_updated/status_note onto every surviving alert by id, so an archive
pass can never again discard triage work that happened after the snapshot
was last built -- regardless of which detector or filter you're running it
for.

Selection modes (combine at most one):
    --detector NAME              archive every alert from this detector
    --title-contains TEXT        archive every alert whose title contains TEXT
    --dedup-title                keep only the most recent alert per unique
                                  title, archive every earlier duplicate
                                  (optionally scoped with --detector too)

Usage:
    python3 archive_by_filter.py --detector aide
    python3 archive_by_filter.py --title-contains "Tor Checker Domain"
    python3 archive_by_filter.py --detector vlan_segmentation --dedup-title
    python3 archive_by_filter.py --detector kali_scan --type vuln --dedup-title
"""
from __future__ import annotations
import argparse, fcntl, gzip, json, os, sys, tempfile
from datetime import datetime
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent))
sys.path.insert(0, str(SCRIPTS))
from soc_core import ALERTS_LOCK, ALERTS_LOG, ALERTS_SNAPSHOT, DATA_DIR, MAX_SNAPSHOT  # noqa: E402

ARCHIVE_DIR = DATA_DIR / "archive"


def month_bucket(ts: str) -> str:
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m")
    except (ValueError, TypeError):
        return "unknown"


def _ensure_nl(line: str) -> str:
    return line if line.endswith("\n") else line + "\n"


def matches(rec: dict, args) -> bool:
    if args.detector and rec.get("detector") != args.detector:
        return False
    if args.type and rec.get("type") != args.type:
        return False
    if args.title_contains and args.title_contains not in rec.get("title", ""):
        return False
    return True


def run(args) -> int:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ARCHIVE_DIR, 0o2775)

    # Load the CURRENT live snapshot first -- this is the one source of
    # truth for "what's the real status of this alert right now", since
    # alerts.jsonl never reflects a status change. Anything still live
    # here gets its status/status_updated/status_note preserved verbatim
    # in the rebuilt snapshot below, no matter how old the alert is.
    try:
        live_by_id = {a["id"]: a for a in json.loads(ALERTS_SNAPSHOT.read_text())}
    except (OSError, json.JSONDecodeError):
        live_by_id = {}

    with ALERTS_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            size_at_start = ALERTS_LOG.stat().st_size
            with ALERTS_LOG.open("rb") as f:
                data = f.read(size_at_start)
            lines = data.decode("utf-8", errors="ignore").splitlines(keepends=True)

            # For --dedup-title: find the latest timestamp per title among
            # matching records, so only earlier duplicates get archived.
            latest_ts: dict[str, str] = {}
            if args.dedup_title:
                for line in lines:
                    s = line.strip()
                    if not s:
                        continue
                    try:
                        rec = json.loads(s)
                    except json.JSONDecodeError:
                        continue
                    if not matches(rec, args):
                        continue
                    t = rec.get("title", "")
                    ts = rec.get("timestamp", "")
                    if t not in latest_ts or ts > latest_ts[t]:
                        latest_ts[t] = ts

            keep_lines: list[str] = []
            by_bucket: dict[str, list[str]] = {}
            archived = 0
            for line in lines:
                s = line.strip()
                if not s:
                    continue
                nl = _ensure_nl(line)
                try:
                    rec = json.loads(s)
                except json.JSONDecodeError:
                    keep_lines.append(nl)
                    continue

                is_target = matches(rec, args)
                if is_target and args.dedup_title:
                    is_target = rec.get("timestamp") != latest_ts.get(rec.get("title", ""))

                if is_target:
                    by_bucket.setdefault(month_bucket(rec.get("timestamp", "")), []).append(nl)
                    archived += 1
                else:
                    keep_lines.append(nl)

            if archived == 0:
                print("[*] Nothing matched this filter -- nothing to archive.")
                return 0

            for bucket, bucket_lines in by_bucket.items():
                archive_path = ARCHIVE_DIR / f"alerts-{bucket}.jsonl.gz"
                mode = "ab" if archive_path.exists() else "wb"
                with gzip.open(archive_path, mode) as gz:
                    gz.write("".join(bucket_lines).encode("utf-8"))
                os.chmod(archive_path, 0o664)

            # Rewrite alerts.jsonl: kept lines, plus anything appended to
            # the real file after size_at_start was captured (a detector's
            # emit_alert() call landing mid-run) -- same pattern
            # archive_alerts.py already uses.
            fd, tmp = tempfile.mkstemp(dir=str(ALERTS_LOG.parent), suffix=".tmp")
            os.chmod(tmp, 0o664)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write("".join(keep_lines).encode("utf-8"))
                    with ALERTS_LOG.open("rb") as f:
                        f.seek(size_at_start)
                        out.write(f.read())
                os.replace(tmp, ALERTS_LOG)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)

            # Rebuild the snapshot from what's left, newest first -- but
            # overlay each surviving alert's REAL current status from the
            # live snapshot loaded at the top, so this can never revert
            # someone's triage work the way the one-off scripts did.
            remaining = [json.loads(l) for l in keep_lines if l.strip()]
            for rec in remaining:
                live = live_by_id.get(rec.get("id"))
                if live:
                    for field in ("status", "status_updated", "status_note"):
                        if field in live:
                            rec[field] = live[field]
            remaining.sort(key=lambda r: r.get("timestamp", ""), reverse=True)
            snapshot = remaining[:MAX_SNAPSHOT]

            fd, tmp = tempfile.mkstemp(dir=str(ALERTS_SNAPSHOT.parent), suffix=".tmp")
            os.chmod(tmp, 0o664)
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(snapshot, f, indent=2)
                os.replace(tmp, ALERTS_SNAPSHOT)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)

            print(f"[*] Archived {archived} alert(s) into {len(by_bucket)} monthly file(s) "
                  f"under {ARCHIVE_DIR}. {len(keep_lines)} alert(s) remain in {ALERTS_LOG}, "
                  f"snapshot rebuilt with {len(snapshot)} entries (statuses preserved from "
                  f"the live snapshot for every survivor).")
            return 0
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--detector", help="Only match alerts from this detector")
    ap.add_argument("--type", help="Only match alerts of this type (e.g. vuln, port_scan)")
    ap.add_argument("--title-contains", help="Only match alerts whose title contains this text")
    ap.add_argument("--dedup-title", action="store_true",
                     help="Keep only the most recent alert per unique title among matches, "
                          "archive every earlier duplicate")
    args = ap.parse_args()
    if not (args.detector or args.title_contains):
        ap.error("specify at least --detector or --title-contains")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
