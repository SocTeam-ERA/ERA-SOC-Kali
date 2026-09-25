#!/usr/bin/env python3
"""
soc_doctor.py
-------------
On-demand health check for the whole Sentinel SOC pipeline -- checks for
every class of problem that has actually broken this project silently at
least once (a shared state file losing its group-write permission and
locking out the next scan, a stale scan_in_progress entry left behind by
a crashed process that suppresses Suricata/Zeek alerts forever, a
scheduled job quietly stalling) in one script instead of re-diagnosing
each one from scratch by hand, the way today's incidents were found.

This project runs 24/7 unattended -- nobody is necessarily watching the
terminal when something like this happens, so catching drift before it
causes a silent coverage gap matters more here than it would for
something actively supervised.

This is read-only: it never modifies anything, only reports. Pair it
with service_watchdog.py / disk_space_check.py (continuous, alerting)
for ongoing coverage; this is for "let's check everything right now."

Usage:
    python3 soc_doctor.py
"""
from __future__ import annotations
import grp, json, os, shutil, subprocess, sys, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent))
sys.path.insert(0, str(SCRIPTS))
from service_watchdog import SERVICES  # noqa: E402
from disk_space_check import MEDIUM_THRESHOLD, CRITICAL_THRESHOLD, CHECK_PATH  # noqa: E402
from soc_core import Alert, emit_alert  # noqa: E402

# Service/timer/disk problems already have their own continuous, alerting
# detectors (service_watchdog.py, disk_space_check.py) -- re-alerting them
# here would just duplicate those. Permission regressions and orphaned
# scan markers don't have anything else watching them, and both have
# actually caused real, silent problems today, so THOSE two categories
# also raise a real dashboard alert here (not just a line of stdout that
# nobody sees unless they're running this by hand at the right moment).
ALERTING_CATEGORIES = {"permissions", "scan_marker"}

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))

OK, WARN, FAIL = "[OK]  ", "[WARN]", "[FAIL]"
results: list[tuple[str, str]] = []


def check(level: str, message: str, category: str = "") -> None:
    results.append((level, message))
    print(f"{level} {message}")
    if level == FAIL and category in ALERTING_CATEGORIES:
        emit_alert(Alert(
            type="intrusion", severity="critical",
            title=f"soc_doctor: {message.split(':', 1)[0].strip()}",
            detector="soc_doctor",
            description=f"Pipeline health check found a real problem: {message}",
            details={"category": category},
        ), echo=False)


STATE_FILES = [
    "scan_in_progress", "scan_in_progress.lock", "scan_last_ended",
    "port_state.json", "port_state_manual.json",
    "udp_state.json", "udp_state_manual.json",
    "mac_state.json", "alerts.jsonl", "alerts.json",
    ".alerts_snapshot.lock", "alert_status_log.jsonl",
    # appended by every alert-emitting service AND by root jobs (AIDE, scans): a root-created 0644 copy
    # crashed soc-zeek-forwarder on 2026-09-25
    "alerts_suppressed.jsonl", "asset_annotation_log.jsonl", "assets.json", "correlation_state.json",
]


def check_permissions() -> None:
    try:
        soc_gid = grp.getgrnam("soc").gr_gid
    except KeyError:
        check(WARN, "group 'soc' does not exist on this system -- can't verify group ownership")
        soc_gid = None

    for name in STATE_FILES:
        p = DATA_DIR / name
        if not p.exists():
            continue  # not created yet -- fine, the first run that needs it will create it
        st = p.stat()
        mode = st.st_mode & 0o777
        group_writable = bool(mode & 0o020)
        right_group = (soc_gid is None) or (st.st_gid == soc_gid)
        if group_writable and right_group:
            check(OK, f"{name}: {oct(mode)}, group-writable")
        else:
            problems = []
            if not group_writable:
                problems.append("not group-writable")
            if not right_group:
                problems.append("wrong group owner")
            check(FAIL, f"{name}: {oct(mode)} -- {', '.join(problems)} "
                        f"(this is the exact bug class that broke manual scans earlier -- "
                        f"fix with: sudo chmod g+rw {p})")


def check_scan_marker() -> None:
    marker = DATA_DIR / "scan_in_progress"
    if not marker.exists() or marker.stat().st_size == 0:
        check(OK, "scan_in_progress: empty -- no scan currently marked active")
        return
    lines = [ln.strip() for ln in marker.read_text().splitlines() if ln.strip()]
    stale, alive = [], []
    for line in lines:
        pid_s = line.split(":", 1)[0]
        try:
            pid = int(pid_s)
        except ValueError:
            stale.append(line)
            continue
        try:
            os.kill(pid, 0)
            alive.append(line)
        except PermissionError:
            alive.append(line)  # exists, but owned by root (scheduled scans)
        except OSError:
            stale.append(line)
    if stale:
        check(FAIL, f"scan_in_progress has {len(stale)} STALE entry/entries (dead PID, never "
                    f"cleaned up) -- this silently suppresses Suricata/Zeek alerts forever until "
                    f"removed: {stale}")
    if alive:
        check(OK if not stale else WARN,
              f"scan_in_progress has {len(alive)} genuinely active scan(s): {alive}")


def check_code_freshness() -> None:
    import code_freshness
    stale = code_freshness.stale_services(SERVICES, grace=0)
    if not stale:
        check(OK, "services: every one runs the code that is on disk")
    for r in stale:
        check(WARN, f"{r['unit']}: running older code -- {r['file']} changed "
                    f"{time.strftime('%m-%d %H:%M', time.localtime(r['edited']))}, service started "
                    f"{time.strftime('%m-%d %H:%M', time.localtime(r['started']))} "
                    f"(sudo systemctl restart {r['unit']})")


def check_services() -> None:
    for svc in SERVICES:
        try:
            out = subprocess.run(["systemctl", "is-active", svc],
                                  capture_output=True, text=True, timeout=5)
            state = out.stdout.strip()
        except Exception as e:
            check(WARN, f"{svc}: could not check ({e})")
            continue
        check(OK if state == "active" else FAIL, f"{svc}: {state}")


TIMERS = ["soc-watchdog.timer", "soc-disk-check.timer", "soc-ntfy-flush.timer",
          "soc-scan.timer", "soc-archive-alerts.timer",
          "soc-suricata-ruleset-update.timer", "soc-aide-check.timer",
          "soc-cleanup-results.timer", "soc-tor-refresh.timer", "soc-check-updates.timer",
          "soc-chkrootkit-forwarder.timer", "soc-vuln-scan.timer", "soc-vlan-segmentation.timer"]


def check_timers() -> None:
    for t in TIMERS:
        try:
            out = subprocess.run(["systemctl", "is-enabled", t],
                                  capture_output=True, text=True, timeout=5)
            state = out.stdout.strip()
        except Exception as e:
            check(WARN, f"{t}: could not check ({e})")
            continue
        check(OK if state == "enabled" else FAIL, f"{t}: {state}")


def check_geoip() -> None:
    """Alert geolocation used to be a silent no-op for two weeks because its database was never installed."""
    try:
        import geoip_enrich
        st = geoip_enrich.status()
    except Exception as e:  # noqa: BLE001
        check(WARN, f"geolocation: could not check ({type(e).__name__}: {e})")
        return
    if not st["available"]:
        check(WARN, f"geolocation: no GeoLite2 database ({st['country']['path']}, {st['city']['path']}), so alerts "
                    "carry no location")
        return
    age = lambda d: (datetime.now(timezone.utc).date() - datetime.fromisoformat(d["built"]).date()).days if d["built"] else None
    cn, ct = st["country"], st["city"]
    if not cn["available"]:
        check(WARN, f"geolocation: only the City database (built {ct['built']}) is available; no Country database")
    elif age(cn) is not None and age(cn) > 400:
        check(WARN, f"geolocation: Country database built {cn['built']} is over a year old")
    else:
        old_city = ct["available"] and age(ct) is not None and age(ct) > 730
        check(OK, f"geolocation: country from the database built {cn['built']}"
                  + (f"; city and coordinates from one built {ct['built']}, used only when it agrees on the country"
                     if old_city else ("" if ct["available"] else "; no City database, so no city or coordinates")))


def check_disk() -> None:
    total, used, free = shutil.disk_usage(CHECK_PATH)
    pct = 100 * used / total
    if pct >= CRITICAL_THRESHOLD:
        check(FAIL, f"{CHECK_PATH}: {pct:.1f}% used ({free / 1e9:.1f}GB free) -- "
                    f"above the {CRITICAL_THRESHOLD:.0f}% critical threshold")
    elif pct >= MEDIUM_THRESHOLD:
        check(WARN, f"{CHECK_PATH}: {pct:.1f}% used ({free / 1e9:.1f}GB free) -- "
                    f"above the {MEDIUM_THRESHOLD:.0f}% warning threshold")
    else:
        check(OK, f"{CHECK_PATH}: {pct:.1f}% used ({free / 1e9:.1f}GB free)")


def check_last_scan() -> None:
    port_state = DATA_DIR / "port_state.json"
    if not port_state.exists():
        check(WARN, "port_state.json missing -- the scheduled scan has never completed successfully")
        return
    try:
        data = json.loads(port_state.read_text())
        dt = datetime.fromisoformat(data.get("generated", ""))
        age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    except Exception as e:
        check(WARN, f"port_state.json: couldn't read its timestamp ({e})")
        return
    if age_hours < 6:
        check(OK, f"last scheduled scan completed {age_hours:.1f}h ago")
    elif age_hours < 24:
        check(WARN, f"last scheduled scan completed {age_hours:.1f}h ago -- "
                    f"expected roughly every 4h, this is later than usual")
    else:
        check(FAIL, f"last scheduled scan completed {age_hours:.1f}h ago -- "
                    f"the scheduled job looks stalled")


def check_suppressions() -> None:
    import suppressions
    rules, errors = suppressions.load_rules()
    if not suppressions.CONFIG_FILE.exists():
        check(OK, "no suppression file -- every alert is shown")
        return
    for err in errors:
        check(FAIL if "cannot read rules" in err else WARN, f"suppressions: {err}")
    expired = [r["id"] for r in rules if suppressions.is_expired(r)]
    for rid in expired:
        check(WARN, f"suppressions: rule {rid} has expired and no longer applies -- renew or remove it")
    active = [r for r in rules if not suppressions.is_expired(r)]
    if not errors and not expired:
        check(OK, f"suppressions: {len(active)} active rule(s), file valid")
    log = DATA_DIR / "alerts_suppressed.jsonl"
    if active and log.exists():
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        hits: dict = {}
        for line in log.read_text().splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("timestamp", "") >= cutoff:
                hits[rec.get("suppressed_by")] = hits.get(rec.get("suppressed_by"), 0) + 1
        for r in active:
            check(OK, f"suppressions: {r['id']} hid {hits.get(r['id'], 0)} alert(s) in the last 24h")


def check_platform() -> None:
    import correlate, threat_intel
    rules, _ignore, errors = correlate.load_rules()
    for err in errors:
        check(FAIL if "cannot read rules" in err else WARN, f"correlation: {err}")
    if not errors:
        active = sum(1 for r in rules if r["enabled"])
        check(OK, f"correlation: {active} active rule(s), file valid")
    incs = correlate.list_incidents()
    open_incs = [i for i in incs if i["status"] != "closed"]
    check(OK, f"incidents: {len(open_incs)} open, {len(incs) - len(open_incs)} closed")

    import playbooks
    pbs, pb_errors = playbooks.load_playbooks()
    for err in pb_errors:
        check(FAIL if "cannot read playbooks" in err else WARN, f"playbooks: {err}")
    ov = playbooks.overview()
    enabled = [p for p in ov["playbooks"] if p["enabled"]]
    check(OK, f"playbooks: {len(enabled)} enabled ({sum(1 for p in enabled if p['dry_run'])} in dry-run), "
              f"{len(ov['playbooks']) - len(enabled)} disabled")
    for p in enabled:
        if p["errors_24h"]:
            check(WARN, f"playbooks: {p['id']} had {p['errors_24h']} failed action(s) in the last 24h "
                        "(python3 scripts/playbooks.py --runs)")

    import alert_aging
    _rules, aging_errors = alert_aging.load_rules()
    for err in aging_errors:
        check(WARN, f"alert aging: {err}")
    if not aging_errors:
        check(OK, f"alert aging: {len(_rules)} rule(s), file valid")
    try:
        bk = json.loads((DATA_DIR / "backup_status.json").read_text())
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(bk["last_ok"])).total_seconds() / 3600
        check(OK if age_h <= 26 and bk.get("last_result") == "ok" else WARN,
              f"backup: last success {age_h:.0f}h ago, remote copy: {bk.get('remote', 'none')}"
              + ("" if bk.get("remote") == "ok" else " (only a local copy: set SOC_BACKUP_REMOTE)")
              + ("" if bk.get("last_result") == "ok" else f" -- last run FAILED: {bk.get('message')}"))
    except (OSError, ValueError, KeyError):
        check(WARN, "backup: no successful backup recorded -- run kali/backup_data.sh")
    try:
        st = json.loads((DATA_DIR / "selftest_last.json").read_text())
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(st["at"])).total_seconds() / 3600
        if st["failed"]:
            check(WARN, f"self-test: {st['failed']} check(s) failed in the last run: "
                        + "; ".join(f["name"] for f in st["failures"][:3]))
        elif age_h > 48:
            check(WARN, f"self-test: last run {age_h:.0f}h ago (it is scheduled daily at 06:30)")
        else:
            check(OK, f"self-test: {st['passed']} checks passed, last run {age_h:.0f}h ago")
    except (OSError, ValueError, KeyError):
        check(WARN, "self-test: never run -- python3 scripts/soc_selftest.py --live")

    meta = threat_intel._load_meta()
    for feed in ("kev", "feodo"):
        m = meta.get(feed)
        if not m:
            check(WARN, f"threat intel: {feed} never downloaded -- run: python3 scripts/threat_intel.py --refresh")
            continue
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(m["fetched"])).total_seconds() / 3600
        check(OK if age_h <= 72 else WARN,
              f"threat intel: {feed} {m['count']} entries, refreshed {age_h:.0f}h ago"
              + ("" if age_h <= 72 else " (older than 3 days -- is soc-tor-refresh.timer running?)"))

    state_file = DATA_DIR / "source_health.json"
    try:
        state = json.loads(state_file.read_text())
        age_min = (datetime.now(timezone.utc) - datetime.fromisoformat(state["checked"])).total_seconds() / 60
    except (OSError, ValueError, KeyError):
        check(WARN, "data sources: no health state yet (written by soc-watchdog every 2 minutes)")
        return
    if age_min > 15:
        check(WARN, f"data sources: health last checked {age_min:.0f} min ago -- is soc-watchdog.timer running?")
    for src in state["sources"]:
        if src["status"] == "stale":
            if src.get("reason"):
                check(WARN, f"data sources: {src['name']} is not working: {src['reason']}")
            elif src.get("age_minutes") is None:
                check(WARN, f"data sources: {src['name']} is unhealthy")
            else:
                check(WARN, f"data sources: {src['name']} has been silent for {src['age_minutes']:.0f} min "
                            f"(limit {src['max_age_minutes']})")
    bad = sum(1 for s in state["sources"] if s["status"] == "stale")
    ok_n = sum(1 for s in state["sources"] if s["status"] == "healthy")
    if not bad:
        check(OK, f"data sources: {ok_n} healthy, {len(state['sources']) - ok_n} not measurable from here")


def main() -> int:
    print("=" * 72)
    print(" SENTINEL SOC -- pipeline health check")
    print(f" {datetime.now(timezone.utc).isoformat()}")
    print("=" * 72)
    for title, fn in [
        ("shared state file permissions", check_permissions),
        ("scan marker", check_scan_marker),
        ("services", check_services),
        ("service code freshness", check_code_freshness),
        ("timers", check_timers),
        ("geolocation", check_geoip),
        ("disk space", check_disk),
        ("last scheduled scan", check_last_scan),
        ("suppression rules", check_suppressions),
        ("detection platform", check_platform),
    ]:
        print(f"\n-- {title} --")
        fn()

    fails = sum(1 for lvl, _ in results if lvl == FAIL)
    warns = sum(1 for lvl, _ in results if lvl == WARN)
    print("\n" + "=" * 72)
    if fails:
        print(f" {fails} FAILURE(S), {warns} warning(s) -- see above")
    elif warns:
        print(f" {warns} warning(s), no failures")
    else:
        print(" All checks passed.")
    print("=" * 72)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
