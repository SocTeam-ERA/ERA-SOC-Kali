#!/usr/bin/env python3
"""
aide_to_alerts.py
-------------------
Runs `aide --check` (file integrity monitoring -- see /etc/aide/aide.conf.d/
90_sentinel_soc for what's watched and why) and turns every added, removed,
or changed file into a SOC alert. Meant to run as root via
soc-aide-check.timer, since AIDE needs to read across every owner on the
box.

Kali/Debian's own default AIDE config watches the ENTIRE filesystem with
full content checksums by default (99_aide_root: "/ 0 Full"), with
specific exceptions for known-volatile paths -- this project's
90_sentinel_soc adds exceptions for our own tools' operational data
(Suricata/Zeek/osquery logs, this project's own results/data dirs,
routine system bookkeeping like DHCP leases and systemd timer stamps) on
top of the distro's ~180 built-in ones. Confirmed empirically: without
those additions, a clean, unmodified system still reported over 100
"changed" entries per check, purely from normal tool operation -- not a
real finding. Only genuine, unexpected filesystem changes should reach
this script now.

Every finding here is inherently high-confidence: unlike a port scan or a
signature match, a file's cryptographic hash changing when nothing was
supposed to touch it is about as close to ground truth as detection gets.

Usage:
    sudo python3 aide_to_alerts.py
"""
from __future__ import annotations
import os, re, subprocess, sys
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert  # noqa: E402

AIDE_CONFIG = os.environ.get("AIDE_CONFIG", "/etc/aide/aide.conf")

# Paths where an unexpected change is a classic persistence / privilege-
# escalation / defense-evasion indicator -- always critical. Everything
# else the catch-all in 99_aide_root still watches is medium: still a
# real, high-confidence finding, just not automatically in the
# highest-value category.
CRITICAL_PREFIXES = (
    "/opt/sentinel-soc",  # this project's own detection code/config
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/systemd/system", "/etc/cron",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/boot",
)

SECTION_ADDED = "added"
SECTION_REMOVED = "removed"
SECTION_CHANGED = "changed"

# "f++++++++++++++++++: /path"  (added)
# "f------------------: /path"  (removed)
# "f =.... mc..H.. .  : /path"  (changed -- the flag block has spaces
# mixed into it, so anchoring on the start of the line doesn't work;
# every format ends the same way, ": " immediately followed by the path)
ENTRY_RE = re.compile(r": (/\S.*)$")


def severity_for(path: str) -> str:
    return "critical" if path.startswith(CRITICAL_PREFIXES) else "medium"


def parse_report(text: str) -> list[tuple[str, str]]:
    """Return [(change_kind, path), ...] from an `aide --check` report."""
    section = None
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Added entries:"):
            section = SECTION_ADDED
            continue
        if stripped.startswith("Removed entries:"):
            section = SECTION_REMOVED
            continue
        if stripped.startswith("Changed entries:"):
            section = SECTION_CHANGED
            continue
        if stripped.startswith("---") or stripped.startswith("Detailed information"):
            if stripped.startswith("Detailed information"):
                section = None  # done with the summary lists
            continue
        if section is None or not stripped:
            continue
        m = ENTRY_RE.search(stripped)
        if m:
            out.append((section, m.group(1).strip()))
    return out


def refresh_baseline() -> None:
    """Accept the current filesystem state as the new baseline, so tomorrow's
    --check only reports changes since TODAY, not since the database was
    last (re)built. Without this, aide --check compares against the same
    fixed snapshot forever and every legitimate change (an apt upgrade, a
    Suricata ruleset auto-update, ...) gets re-reported on every single
    future run -- confirmed empirically: the database was never refreshed
    since this project's initial setup, and alerts piled up into the tens
    of thousands as a result, almost all re-reports of already-seen,
    already-alerted changes rather than new findings."""
    proc = subprocess.run(
        ["aide", f"--config={AIDE_CONFIG}", "--update"],
        capture_output=True, text=True,
    )
    new_db = Path("/var/lib/aide/aide.db.new")
    db = Path("/var/lib/aide/aide.db")
    if new_db.exists():
        os.replace(new_db, db)
    elif proc.returncode not in (0, 1):
        # 0 = no diffs, 1 = diffs found (both produce aide.db.new); anything
        # else is a real failure -- surface it instead of silently leaving
        # the stale baseline in place.
        print(f"[!] aide --update failed (rc={proc.returncode}), baseline NOT refreshed:\n{proc.stderr}",
              file=sys.stderr)


def run() -> int:
    proc = subprocess.run(
        ["aide", f"--config={AIDE_CONFIG}", "--check"],
        capture_output=True, text=True,
    )
    # aide's exit code is a bitmask (0 = no differences, nonzero = found
    # differences and/or errors) -- always parse stdout regardless, it
    # tells us which case we're in.
    entries = parse_report(proc.stdout)

    n = 0
    for kind, path in entries:
        sev = severity_for(path)
        verb = {"added": "appeared", "removed": "was removed", "changed": "changed"}[kind]
        emit_alert(Alert(
            type="intrusion", severity=sev,
            title=f"File integrity: {path} {verb}",
            detector="aide",
            description=(f"AIDE file integrity check: {path} {verb} unexpectedly. "
                         f"See /etc/aide/aide.conf.d/90_sentinel_soc for what's watched."),
            details={"path": path, "change": kind},
        ))
        n += 1

    print(f"[*] aide_to_alerts: {n} finding(s) "
          f"({sum(1 for k, _ in entries if k == 'added')} added, "
          f"{sum(1 for k, _ in entries if k == 'removed')} removed, "
          f"{sum(1 for k, _ in entries if k == 'changed')} changed).")
    if proc.stderr.strip():
        print(f"[!] aide stderr (not fatal, informational):\n{proc.stderr}", file=sys.stderr)
    refresh_baseline()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
