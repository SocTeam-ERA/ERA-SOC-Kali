#!/usr/bin/env python3
"""
weekly_digest.py
-----------------
Generates a human-readable summary of what changed in the SOC feed since
the last digest run: new findings by severity, vulnerabilities fixed
(RESOLVED alerts), new-device activity (split into genuinely new devices
vs. randomized Wi-Fi MACs -- see arp_to_alerts.py), and which hosts
currently carry the most open findings.

This exists because building today's specific findings (the pre-diff-state
port flood, the vulnerability repetition bug, the MAC-randomization noise)
all started the same way: someone manually writing one-off Python against
alerts.jsonl to spot a pattern. That's fine for a one-time investigation,
but a dashboard meant to run 24/7 "for life" needs this available as a
routine, repeatable report instead of requiring a fresh investigation
every time -- this reuses the same soc_core.group_by_host()/summarize()
this project already has.

State (data/digest_state.json) tracks only the timestamp of the last run,
so each digest covers exactly the period since the previous one. The very
first run (no prior state) covers the last 7 days.

Usage:
    python3 weekly_digest.py                  # writes data/digests/digest_<stamp>.txt, prints it too
    python3 weekly_digest.py --since-days 14   # ignore stored state, force a custom window
"""
from __future__ import annotations
import argparse, json, os, sys, tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent))
sys.path.insert(0, str(SCRIPTS))
from soc_core import ALERTS_LOG, DATA_DIR, group_by_host, summarize, _load_snapshot  # noqa: E402

DIGEST_STATE = DATA_DIR / "digest_state.json"
DIGEST_DIR = DATA_DIR / "digests"
DEFAULT_FIRST_RUN_DAYS = 7


def _load_digest_state() -> dict:
    try:
        return json.loads(DIGEST_STATE.read_text())
    except Exception:
        return {}


def _save_digest_state(now_iso: str) -> None:
    DIGEST_STATE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(DIGEST_STATE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"last_run": now_iso}, f, indent=2)
        os.replace(tmp, DIGEST_STATE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _read_since(cutoff_iso: str) -> list[dict]:
    """Read alerts.jsonl directly (not the capped snapshot) so a week's
    worth of alerts can't get silently truncated the way the live
    dashboard view is allowed to."""
    out = []
    if not ALERTS_LOG.exists():
        return out
    with ALERTS_LOG.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = rec.get("timestamp", "")
            if ts and ts >= cutoff_iso:
                out.append(rec)
    return out


def build_digest(cutoff_iso: str, now_iso: str) -> str:
    new_alerts = _read_since(cutoff_iso)

    sev_counts = Counter(a.get("severity", "normal") for a in new_alerts)
    resolved = [a for a in new_alerts if str(a.get("title", "")).startswith("RESOLVED")]
    real_findings = [a for a in new_alerts if not str(a.get("title", "")).startswith("RESOLVED")]

    def _is_randomized(a: dict) -> bool:
        # New alerts (arp_to_alerts.py, fixed 2026-09-15) carry this flag
        # directly; older alerts from before that fix don't have it, so
        # fall back to the vendor-lookup text that's always been there --
        # "Unknown: locally administered" is what a randomized MAC's
        # vendor lookup has always shown, fix or no fix.
        if a.get("details", {}).get("locally_administered"):
            return True
        return "locally administered" in a.get("title", "").lower()

    new_device_alerts = [a for a in real_findings if a.get("detector") == "arp_discovery"
                          and "New device" in a.get("title", "")]
    randomized = [a for a in new_device_alerts if _is_randomized(a)]
    genuine_new = [a for a in new_device_alerts if not _is_randomized(a)]

    top_critical = sorted(
        [a for a in real_findings if a.get("severity") == "critical"],
        key=lambda a: a.get("timestamp", ""), reverse=True,
    )[:10]

    live_snapshot = _load_snapshot()
    open_only = [a for a in live_snapshot if a.get("status", "open") == "open"]
    hosts = group_by_host(open_only)
    top_hosts = hosts[:10]

    live_summary = summarize()

    lines = []
    lines.append("=" * 72)
    lines.append(" SENTINEL SOC -- DIGEST")
    lines.append(f" Period: {cutoff_iso}  ->  {now_iso}")
    lines.append("=" * 72)

    lines.append("\n-- New findings this period --")
    lines.append(f"  critical: {sev_counts.get('critical', 0)}")
    lines.append(f"  medium:   {sev_counts.get('medium', 0)}")
    lines.append(f"  normal:   {sev_counts.get('normal', 0)}")
    lines.append(f"  total:    {len(real_findings)}  ({len(resolved)} of those were RESOLVED notices)")

    if top_critical:
        lines.append("\n-- Most recent critical findings (up to 10) --")
        for a in top_critical:
            lines.append(f"  {a.get('timestamp','')[:19]}  {a.get('source_ip') or '-':<15}  {a.get('title','')}")
    else:
        lines.append("\n-- Most recent critical findings --\n  none this period")

    lines.append("\n-- New devices --")
    lines.append(f"  genuinely new (real vendor MAC): {len(genuine_new)}")
    lines.append(f"  randomized Wi-Fi MAC (likely the same phones reconnecting): {len(randomized)}")
    if genuine_new:
        lines.append("  genuinely new devices this period:")
        for a in genuine_new[:10]:
            lines.append(f"    {a.get('timestamp','')[:19]}  {a.get('source_ip') or '-':<15}  {a.get('title','')}")

    lines.append("\n-- Current live feed snapshot (most recent alerts, capped) --")
    lines.append(f"  total: {live_summary['total']}")
    lines.append(f"  by severity: {live_summary['by_severity']}")
    lines.append(f"  by status:   {live_summary['by_status']}")

    lines.append("\n-- Hosts with the most OPEN findings right now (top 10) --")
    if top_hosts:
        for h in top_hosts:
            if h["total"] == 0:
                continue
            label = h["source_ip"] or "(no source IP)"
            lines.append(f"  {label:<16} critical={h['counts']['critical']:<3} "
                         f"medium={h['counts']['medium']:<3} total={h['total']:<4} "
                         f"hostname={h['hostname'] or '-'}")
    else:
        lines.append("  no open findings in the current snapshot")

    lines.append("\n" + "=" * 72)
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-days", type=float, default=None,
                    help="Ignore stored state; cover the last N days instead")
    args = ap.parse_args()

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    if args.since_days is not None:
        cutoff_iso = (now - timedelta(days=args.since_days)).isoformat()
    else:
        state = _load_digest_state()
        last_run = state.get("last_run")
        cutoff_iso = last_run or (now - timedelta(days=DEFAULT_FIRST_RUN_DAYS)).isoformat()

    report = build_digest(cutoff_iso, now_iso)
    print(report)

    DIGEST_DIR.mkdir(parents=True, exist_ok=True)
    stamp = now.strftime("%Y%m%d_%H%M%S")
    out_path = DIGEST_DIR / f"digest_{stamp}.txt"
    out_path.write_text(report)
    os.chmod(out_path, 0o664)
    print(f"\n[*] Written to {out_path}")

    if args.since_days is None:
        _save_digest_state(now_iso)

    return 0


if __name__ == "__main__":
    sys.exit(main())
