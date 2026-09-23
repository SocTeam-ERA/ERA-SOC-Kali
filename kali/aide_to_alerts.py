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
# else the catch-all in 99_aide_root still watches is normal (a file
# changed on the SOC host is routine unless there is a concrete reason),
# except system configuration and local programs, which are medium.
CRITICAL_PREFIXES = (
    "/opt/sentinel-soc",  # this project's own detection code/config
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/sudoers",
    "/etc/ssh/sshd_config", "/etc/systemd/system", "/etc/cron",
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/boot", "/var/spool/cron",
)
MEDIUM_PREFIXES = ("/etc/", "/root/", "/usr/local/", "/usr/lib/systemd", "/lib/systemd")

# More than this many entries of one kind and severity under the same top-level folder in one
# check become ONE alert with the list inside (a package upgrade or a deploy touches dozens).
AIDE_BULK_THRESHOLD = int(os.environ.get("SOC_AIDE_BULK_THRESHOLD", "5"))
MAX_BULK_LISTED = 100
VERB = {"added": "appeared", "removed": "was removed", "changed": "changed"}
PLURAL = {"added": "appeared", "removed": "were removed", "changed": "changed"}

SECTION_ADDED = "added"
SECTION_REMOVED = "removed"
SECTION_CHANGED = "changed"

# "f++++++++++++++++++: /path"  (added)
# "f------------------: /path"  (removed)
# "f =.... mc..H.. .  : /path"  (changed -- the flag block has spaces
# mixed into it, so anchoring on the start of the line doesn't work;
# every format ends the same way, ": " immediately followed by the path)
ENTRY_RE = re.compile(r": (/\S.*)$")


REPO = Path(os.environ.get("SOC_REPO", "/opt/sentinel-soc"))


def severity_for(path: str) -> str:
    if path.startswith(CRITICAL_PREFIXES):
        return "critical"
    if path.startswith(MEDIUM_PREFIXES) or "/.ssh/" in path:
        return "medium"
    return "normal"


def group_folder(path: str) -> str:
    """The folder a path is grouped under: its parent directory, at most 3 levels deep.

    This used to be "/".join(path.split("/")[:4]), which for a path only three components
    long (/usr/bin/ac, /etc/cron.daily/debsums) is the FILE ITSELF -- every such file was its
    own group and never reached the threshold. Confirmed 2026-09-23: a routine package install
    put 16 new files in /usr/bin and 7 in /usr/sbin, all critical, and they raised 34 separate
    alerts instead of a handful. The last component is never part of the folder."""
    dirs = path.split("/")[1:-1]
    return "/" + "/".join(dirs[:3]) if dirs else "/"


def _record(kind: str, path: str, sev: str) -> dict:
    return {"title": f"File integrity: {path} {VERB[kind]}", "severity": sev, "detector": "aide",
            "details": {"path": path, "change": kind}}


def _emit_group(kind: str, sev: str, folder: str, members: list) -> None:
    from mitre_tags import tag
    mitre: dict = {}
    for _, path, _, _ in members:
        for t in tag(_record(kind, path, sev)):
            mitre.setdefault(t["technique"], t)
    details = {"change": f"bulk_{kind}", "dir": folder, "count": len(members),
               "files": [m[1] for m in members[:MAX_BULK_LISTED]],
               "truncated": len(members) > MAX_BULK_LISTED}
    if mitre:
        details["mitre"] = list(mitre.values())
    emit_alert(Alert(
        type="intrusion", severity=sev,
        title=f"File integrity: {len(members)} files {PLURAL[kind]} under {folder}",
        detector="aide",
        description=(f"AIDE file integrity check: {len(members)} files {PLURAL[kind]} under {folder}. "
                     f"Grouped into one alert; the full list is in details.files."),
        details=details))


def committed_version(path: str) -> str | None:
    """If `path` is a tracked file in this project's git repo whose content is exactly its last
    commit, return "<short sha> by <author>", else None. A change like that is a committed,
    reviewable edit, not an unexplained modification. Any git problem means None (stays critical)."""
    try:
        rel = str(Path(path).resolve().relative_to(REPO))
    except (ValueError, OSError):
        return None
    git = ["git", "-c", f"safe.directory={REPO}", "-C", str(REPO)]
    try:
        if subprocess.run(git + ["ls-files", "--error-unmatch", "--", rel], capture_output=True, timeout=10).returncode:
            return None
        if subprocess.run(git + ["diff", "--quiet", "HEAD", "--", rel], capture_output=True, timeout=10).returncode:
            return None
        out = subprocess.run(git + ["log", "-1", "--format=%h by %an", "--", rel], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        return out or None
    except (OSError, subprocess.SubprocessError):
        return None


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

    items = []                     # (kind, path, severity, git commit)
    for kind, path in entries:
        sev = severity_for(path)
        commit = committed_version(path) if kind != "removed" and sev == "critical" else None
        items.append((kind, path, "normal" if commit else sev, commit))

    # An entry a suppression rule would hide is always emitted on its own so the rule keeps
    # working (a grouped title would not match it).
    from suppressions import find_match
    groups: dict = {}
    singles = []
    for it in items:
        kind, path, sev, _ = it
        if find_match(_record(kind, path, sev)):
            singles.append(it)
        else:
            groups.setdefault((kind, sev, group_folder(path)), []).append(it)

    n = 0
    for (kind, sev, folder), members in groups.items():
        if len(members) > AIDE_BULK_THRESHOLD:
            _emit_group(kind, sev, folder, members)
            n += 1
        else:
            singles += members

    for kind, path, sev, commit in singles:
        details = {"path": path, "change": kind}
        note = ""
        if commit:
            details["git_commit"] = commit
            note = (f" The file matches its last commit ({commit}), so this is a committed edit; "
                    "review that commit if you did not make it.")
        emit_alert(Alert(
            type="intrusion", severity=sev,
            title=f"File integrity: {path} {VERB[kind]}",
            detector="aide",
            description=(f"AIDE file integrity check: {path} {VERB[kind]} unexpectedly. "
                         f"See /etc/aide/aide.conf.d/90_sentinel_soc for what's watched.{note}"),
            details=details,
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
