#!/usr/bin/env python3
"""
archive_alerts.py
------------------
Retention/archival for data/alerts.jsonl.

alerts.jsonl is the permanent, append-only audit record (see the design
note in kali/cleanup_results.sh: kali/results/ is disposable raw scan
output, alerts.jsonl is not) -- so this never deletes anything. Instead,
alerts older than the retention window get moved out of the "hot" file
into monthly, gzip-compressed archive files under data/archive/ (e.g.
alerts-2026-03.jsonl.gz), keeping alerts.jsonl itself from growing without
bound while the full history stays on disk and readable (zcat / python)
indefinitely.

Confirmed 2026-09-15: alerts.jsonl was already 2.1MB / several thousand
alerts after only ~10 days of operation -- and that was BEFORE fixing the
vulnerability-alert repetition bug found the same day. A dashboard meant
to run 24/7 "for life" needs this from day one, not once the file has
become a visible problem.

Safe to run while detectors are actively appending: this only ever reads
up to the file's size at the moment it started, and re-appends (verbatim,
unmodified) anything written to the file after that point -- so a
detector's emit_alert() call landing mid-run can never be lost, even
though emit_alert()'s own jsonl append (soc_core.py) takes no lock of its
own. Uses the same ALERTS_LOCK emit_alert() uses for the snapshot file, so
a run of this script and a burst of concurrent alerts can't interleave
badly.

Usage:
    python3 archive_alerts.py                       # archive alerts older than 180 days
    ARCHIVE_AFTER_DAYS=90 python3 archive_alerts.py  # custom retention window
"""
from __future__ import annotations
import fcntl, gzip, json, os, sys, tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent))
sys.path.insert(0, str(SCRIPTS))
from soc_core import ALERTS_LOCK, ALERTS_LOG, DATA_DIR  # noqa: E402

ARCHIVE_DIR = DATA_DIR / "archive"
ARCHIVE_AFTER_DAYS = int(os.environ.get("ARCHIVE_AFTER_DAYS", "180"))


def _month_bucket(ts: str) -> str:
    try:
        dt = datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return "unknown"
    return dt.strftime("%Y-%m")


def _ensure_nl(line: str) -> str:
    return line if line.endswith("\n") else line + "\n"


def run() -> int:
    if not ALERTS_LOG.exists():
        print("[*] No alerts.jsonl -- nothing to archive.")
        return 0

    cutoff = (datetime.now(timezone.utc) - timedelta(days=ARCHIVE_AFTER_DAYS)).isoformat()
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ARCHIVE_DIR, 0o2775)  # setgid so files created here inherit the soc group

    with ALERTS_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            size_at_start = ALERTS_LOG.stat().st_size
            with ALERTS_LOG.open("rb") as f:
                data = f.read(size_at_start)
            lines = data.decode("utf-8", errors="ignore").splitlines(keepends=True)

            keep_lines: list[str] = []
            by_bucket: dict[str, list[str]] = {}
            archived = 0
            for line in lines:
                line_s = line.strip()
                if not line_s:
                    continue
                try:
                    rec = json.loads(line_s)
                except json.JSONDecodeError:
                    keep_lines.append(_ensure_nl(line))
                    continue
                ts = rec.get("timestamp", "")
                if ts and ts < cutoff:
                    by_bucket.setdefault(_month_bucket(ts), []).append(_ensure_nl(line))
                    archived += 1
                else:
                    keep_lines.append(_ensure_nl(line))

            if archived == 0:
                print(f"[*] No alerts older than {ARCHIVE_AFTER_DAYS} days -- nothing to archive.")
                return 0

            for bucket, bucket_lines in by_bucket.items():
                archive_path = ARCHIVE_DIR / f"alerts-{bucket}.jsonl.gz"
                mode = "ab" if archive_path.exists() else "wb"
                with gzip.open(archive_path, mode) as gz:
                    gz.write("".join(bucket_lines).encode("utf-8"))
                os.chmod(archive_path, 0o664)

            # Atomic rewrite of alerts.jsonl: kept (recent) lines, plus
            # anything appended to the real file after size_at_start was
            # captured -- a concurrent detector's write during this run
            # lands past that offset and gets copied through untouched.
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

            print(f"[*] Archived {archived} alert(s) older than {ARCHIVE_AFTER_DAYS} days "
                  f"into {len(by_bucket)} monthly file(s) under {ARCHIVE_DIR}. "
                  f"{len(keep_lines)} alert(s) remain in {ALERTS_LOG}.")
            return 0
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


if __name__ == "__main__":
    sys.exit(run())
