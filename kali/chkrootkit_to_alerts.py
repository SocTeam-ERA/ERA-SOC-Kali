#!/usr/bin/env python3
"""
chkrootkit_to_alerts.py
------------------------
Parses chkrootkit's daily log (/var/log/chkrootkit/chkrootkit-daily.log,
one full run per day, overwritten each time -- not append-only, so this
runs once per day after chkrootkit itself, not as a --follow tail) and
turns genuinely unexplained findings into SOC alerts.

chkrootkit's own docs are explicit that several of its checks are broad
heuristics that need per-box context to interpret. Confirmed on THIS box
2026-09-17: every single daily run currently produces the same 3
WARNINGs, all expected/benign for what this appliance actually is:

  1. "suspicious files and dirs" -- dotfiles (.gitignore, .github, ...)
     shipped inside Ruby gems bundled with Kali's own `dradis` package.
     Standard packaging convention, not hidden malware. chkrootkit already
     annotates any such file with "[From Debian package: X]" when it can
     attribute it via dpkg -- suppressed only when EVERY flagged path
     carries that annotation; anything unattributed still alerts.
  2. "Linux.Xor.DDoS" -- flags any non-Debian-packaged executable under
     /tmp. Claude Code (and whoever works on this project through it)
     leaves ad-hoc scripts in /tmp/claude-*/.../ constantly -- expected
     housekeeping, not a backdoor. Suppressed only when EVERY flagged path
     is under that prefix; anything outside it still alerts.
  3. "ifpromisc" -- promiscuous-mode NICs, normally a packet-sniffing/
     credential-theft indicator, are the deliberate, correct state for
     this box's own IDS stack (Zeek, Suricata, tcpdump, arp-scan).
     Suppressed only when EVERY process attached to a promiscuous
     interface is on the KNOWN_SNIFFERS allowlist below (or chkrootkit's
     own "<Standard network manager>" placeholder) -- an unrecognized
     process sniffing traffic on any interface still alerts.

Blindly forwarding chkrootkit's raw WARNING lines without this filtering
would alert on all three of the above on every single run, forever -- the
same false-positive class already found and fixed for Suricata's Tor
checks, traffic_to_alerts.py's loopback traffic, and nmap_to_alerts.py's
closed-port noise elsewhere in this project.

State (data/chkrootkit_seen.json) remembers which specific unexplained
findings already alerted, so a persistent one alerts once, not on every
future daily run -- same diff-state convention as nmap_to_alerts.py /
arp_to_alerts.py.

Usage:
    python3 chkrootkit_to_alerts.py --log /var/log/chkrootkit/chkrootkit-daily.log
"""
from __future__ import annotations
import argparse, json, os, re, sys, tempfile
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, diff_state_lock  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DEFAULT_LOG = Path("/var/log/chkrootkit/chkrootkit-daily.log")
STATE_FILE = DATA_DIR / "chkrootkit_seen.json"


def _load_state(path: Path) -> dict:
    """{check_name: [already-alerted finding, ...]}."""
    try:
        return json.loads(path.read_text()).get("checks", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(path: Path, checks: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"checks": checks}, f)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

# Claude Code's scratch space: /tmp/claude-<uid>/ on older versions, /tmp/user/<uid>/claude-<uid>/ on current
# ones (sessions clone repositories and write scripts there, and chkrootkit's Xor.DDoS check flags things such as
# a clone's .git/hooks/*.sample files; 14 false critical alerts on 2026-09-25).
SAFE_TMP_RE = re.compile(r"^/tmp/(claude-|user/\d+/claude-\d+/)")
# nmap is this appliance's own scanner: its raw socket shows up as a "packet sniffer" for as
# long as a scan runs. Debian's chkrootkit cron.daily job runs at ~00:11, in the middle of the
# nightly scan cycle (00:04-00:50), so this fires by coincidence of schedules -- confirmed
# 2026-09-23, eth2: /usr/lib/nmap/nmap. Someone running an unexpected nmap here is not this
# check's job to catch (process-level detection is osquery's and Suricata's).
KNOWN_SNIFFERS = {"zeek", "suricata", "tcpdump", "arp-scan", "nmap"}
# chkrootkit's own text for "this looks like NetworkManager/a bridge, not a
# rogue sniffer" -- not a real process name, don't require it on the allowlist.
NETWORK_MANAGER_PLACEHOLDER = "<standard network manager>"

# check names can contain dots themselves (e.g. "Linux.Xor.DDoS"), so the
# capture can't stop at the first one -- rely on the anchored "...  WARNING"
# at end-of-line to find where the check name actually ends instead.
WARNING_HEADER_RE = re.compile(r"^(?:Checking|Searching for) `?(?P<check>.+?)'?\.\.\.\s+WARNING\s*$")


def _proc_basename(entry: str) -> str:
    """'/opt/zeek/bin/zeek[1299139]' -> 'zeek'; '<Standard network manager>[PID]' -> the placeholder."""
    name = entry.rsplit("[", 1)[0].strip()
    if name.lower() == NETWORK_MANAGER_PLACEHOLDER:
        return NETWORK_MANAGER_PLACEHOLDER
    return Path(name).name


def parse_warnings(text: str) -> list[tuple[str, list[str]]]:
    """Return [(check_name, [detail_lines...]), ...] for each WARNING block."""
    lines = text.splitlines()
    out = []
    i = 0
    while i < len(lines):
        m = WARNING_HEADER_RE.match(lines[i])
        if not m:
            i += 1
            continue
        check = m.group("check")
        details = []
        i += 1
        while i < len(lines) and not re.match(r"^(Checking|Searching for)\b", lines[i]):
            if lines[i].strip():
                details.append(lines[i].strip())
            i += 1
        out.append((check, details))
    return out


def unexplained_suspicious_files(details: list[str]) -> list[str]:
    """'suspicious files and dirs' -- each real finding is its own line;
    keep only the ones chkrootkit couldn't attribute to a Debian package."""
    paths = [d for d in details if d.startswith("/")]
    return [p for p in paths if "[from debian package:" not in p.lower()]


def unexplained_xor_ddos(details: list[str]) -> list[str]:
    paths = [d for d in details if d.startswith("/")]
    return [p for p in paths if not SAFE_TMP_RE.match(p)]


def unexplained_ifpromisc(details: list[str]) -> list[str]:
    """One finding per interface that has a process NOT on the allowlist."""
    bad_ifaces = []
    for line in details:
        m = re.match(r"^(?P<iface>\S+):\s*PACKET SNIFFER\((?P<procs>.*)\)\s*$", line)
        if not m:
            continue
        procs = [_proc_basename(p) for p in m.group("procs").split(",")]
        unknown = [p for p in procs if p and p not in KNOWN_SNIFFERS and p != NETWORK_MANAGER_PLACEHOLDER]
        if unknown:
            bad_ifaces.append(f"{m.group('iface')}: unrecognized sniffer(s) {', '.join(unknown)}")
    return bad_ifaces


CHECK_HANDLERS = {
    "suspicious files and dirs": (unexplained_suspicious_files,
                                   "Unexplained suspicious file"),
    "Linux.Xor.DDoS": (unexplained_xor_ddos,
                        "Possible Linux.Xor.DDoS"),
    "sniffer": (unexplained_ifpromisc,
                "Unrecognized packet sniffer"),
}


def run(log_path: Path) -> int:
    text = log_path.read_text(errors="ignore")
    warnings = parse_warnings(text)

    n = 0
    with diff_state_lock(STATE_FILE):
        seen = _load_state(STATE_FILE)  # {check: [finding, ...]} already alerted
        new_seen = {}
        for check, details in warnings:
            handler = CHECK_HANDLERS.get(check)
            if handler is None:
                # An unrecognized chkrootkit WARNING type we've never triaged --
                # always alert, don't silently drop it the way an unmatched
                # regex elsewhere in this project would.
                findings = [" / ".join(details) or check]
                title_prefix = f"chkrootkit: {check}"
            else:
                extractor, title_prefix = handler
                findings = extractor(details)
            prev = set(seen.get(check, []))
            new_seen[check] = findings
            for finding in findings:
                if finding in prev:
                    continue  # already alerted, still present -- stay quiet
                emit_alert(Alert(
                    type="intrusion", severity="critical",
                    title=f"{title_prefix}: {finding}",
                    detector="chkrootkit",
                    description=(f"chkrootkit's '{check}' check found something not explained by "
                                 f"this box's known-benign patterns (dradis packaging, Claude Code "
                                 f"scratchpad scripts, this appliance's own IDS sniffers). Investigate: "
                                 f"{finding}"),
                    details={"check": check, "finding": finding},
                ))
                n += 1
        _save_state(STATE_FILE, new_seen)
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="chkrootkit daily log -> SOC alerts")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="Path to chkrootkit's daily log")
    args = ap.parse_args()

    path = Path(args.log)
    if not path.exists():
        print(f"[x] {path} not found -- has chkrootkit run yet?", file=sys.stderr)
        return 1

    n = run(path)
    print(f"[*] chkrootkit_to_alerts: {n} new alert(s) from {path}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
