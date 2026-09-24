#!/usr/bin/env python3
"""
deploy_drift.py
---------------
Does deploy/ still describe what is installed on this machine?

deploy/ is the source of truth for everything the SOC needs outside this
directory: the systemd units and timers, their drop-ins, the user crontab and
the sudoers rule. deploy/install_all.sh copies it into place on a fresh Kali.
That only works if every change reaches deploy/ first. On 2026-09-23 only 8 of
the 48 installed units were in the repository: the rest had been written
straight into /etc/systemd/system and existed nowhere else, so losing the VM
would have lost them.

Problems reported (each one names the file):
  missing        a soc-* unit or drop-in is installed but has no copy in deploy/
  changed        the installed file differs from its copy in deploy/
  not installed  deploy/ has a unit or drop-in that is not installed
  crontab        the user crontab differs from deploy/crontab.txt
  secret         a file in deploy/ carries a value for NTFY_TOPIC

Secrets never live in deploy/: the ntfy topic goes in a private drop-in
(<unit>.service.d/ntfy.conf, mode 600), so ntfy.conf drop-ins are skipped and
an Environment=NTFY_TOPIC= line in an installed unit is ignored when comparing.
Comments, blank lines and surrounding whitespace are ignored too.

soc_selftest.py runs this every day (live part), so a unit added in /etc and
forgotten here raises an alert the next morning.

    python3 deploy_drift.py          list the problems; exit 1 if there are any
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

SUITE = Path(__file__).resolve().parent.parent
REPO = SUITE / "deploy"
LIVE = Path("/etc/systemd/system")
SECRET_DROPINS = {"ntfy.conf"}
_SECRET_LINE = re.compile(r"^\s*(Environment=)?\"?NTFY_TOPIC=\S")


def normalize(text: str) -> list[str]:
    """The lines that matter: no comments, blanks, whitespace or ntfy topic."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")) or _SECRET_LINE.match(line):
            continue
        out.append(line)
    return out


def _units(root: Path) -> dict[str, Path]:
    """soc-* units and their drop-ins under root, keyed by path relative to root."""
    found = {}
    for p in root.glob("soc-*"):
        if p.is_file() and p.suffix in (".service", ".timer"):
            found[p.name] = p
        elif p.is_dir() and p.name.endswith(".d"):
            for conf in p.glob("*.conf"):
                if conf.name not in SECRET_DROPINS:
                    found[f"{p.name}/{conf.name}"] = conf
    return found


def _read(p: Path) -> str | None:
    try:
        return p.read_text()
    except OSError:
        return None


def _crontab() -> str | None:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else ""


def drift(repo: Path = REPO, live: Path = LIVE, crontab: str | None = None,
          check_crontab: bool = True) -> list[tuple[str, str]]:
    """[(kind, name)] of every way deploy/ and this machine disagree; [] when they match."""
    problems = []
    have, want = _units(live), _units(repo)
    for name in sorted(have.keys() | want.keys()):
        if name not in want:
            problems.append(("missing", name))
        elif name not in have:
            problems.append(("not installed", name))
        else:
            live_text = _read(have[name])
            if live_text is not None and normalize(live_text) != normalize(_read(want[name]) or ""):
                problems.append(("changed", name))
    if check_crontab and (repo / "crontab.txt").exists():
        current = _crontab() if crontab is None else crontab
        if current is not None and normalize(current) != normalize(_read(repo / "crontab.txt") or ""):
            problems.append(("crontab", "crontab.txt"))
    for p in sorted(repo.rglob("*")):
        if p.is_file() and any(_SECRET_LINE.match(l) for l in (_read(p) or "").splitlines()):
            problems.append(("secret", str(p.relative_to(repo))))
    return problems


EXPLAIN = {
    "missing": "installed but not in deploy/: copy it there (without the ntfy topic) and commit",
    "changed": "edited on this machine: bring the change into deploy/ and commit, or reinstall from deploy/",
    "not installed": "in deploy/ but not installed: run sudo deploy/install_all.sh",
    "crontab": "the crontab differs from deploy/crontab.txt: crontab -l > deploy/crontab.txt, or install that file",
    "secret": "carries the ntfy topic: remove the value, it belongs in a private ntfy.conf drop-in",
}


def main() -> int:
    problems = drift()
    for kind, name in problems:
        print(f"{kind:14} {name}   -- {EXPLAIN[kind]}")
    if not problems:
        print("deploy/ matches this machine")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
