#!/usr/bin/env python3
"""
deploy_drift.py
---------------
Does deploy/ still describe what is installed on this machine?

deploy/ is the source of truth for everything the SOC needs outside this
directory: the systemd units and timers, their drop-ins, the user crontab and
the sudoers rule, and the sensors' configuration (deploy/sensors/<absolute path>: Zeek, Suricata,
osquery). deploy/install_all.sh copies it into place on a fresh Kali.
That only works if every change reaches deploy/ first. On 2026-09-23 only 8 of
the 48 installed units were in the repository: the rest had been written
straight into /etc/systemd/system and existed nowhere else, so losing the VM
would have lost them.

A sensor file is the typical victim of a package update: on 2026-09-17 the zeek package replaced
site/local.zeek, Zeek silently switched its logs to TSV at the next restart, and its notices stopped
producing alerts for about two days. Such a file shows up here as "changed" (a version never committed).

Problems reported (each one names the file):
  missing        a soc-* unit or drop-in is installed but has no copy in deploy/
  changed        the installed file differs from its copy in deploy/, and from every version of it
                 ever committed: it was edited on this machine
  outdated       the installed file is an earlier committed version of its copy in deploy/: deploy/
                 moved on (a pull, a commit) and install_all.sh has not been run since. Safe to install
  not installed  deploy/ has a unit or drop-in that is not installed
  crontab        the user crontab differs from deploy/crontab.txt
  secret         a file in deploy/ carries a value for NTFY_TOPIC
  unsafe         a helper sudo runs as root (deploy/bin/ -> /usr/local/sbin) is not root-owned or is writable
                 by others
  package missing / package unlisted
                 deploy/packages.txt (what install_packages.sh puts on a fresh Kali) vs what is installed
  firewall       the live ufw rules differ from deploy/firewall/ufw-status.txt (read through a read-only
                 sudo rule; rules are never applied automatically)

Secrets never live in deploy/: the ntfy topic goes in a private drop-in
(<unit>.service.d/ntfy.conf, mode 600), so ntfy.conf drop-ins are skipped and
an Environment=NTFY_TOPIC= line in an installed unit is ignored when comparing.
Comments, blank lines and surrounding whitespace are ignored too.

soc_selftest.py runs this every day (live part), so a unit added in /etc and
forgotten here raises an alert the next morning.

    python3 deploy_drift.py                    list the problems; exit 1 if there are any
    python3 deploy_drift.py --save-firewall    record the live firewall in deploy/firewall/ufw-status.txt
    python3 deploy_drift.py --save-packages    record the stock Kali packages in deploy/packages-baseline.txt
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
    except (OSError, UnicodeDecodeError):     # unreadable, or not a text file (e.g. a stray .pyc)
        return None


def _crontab() -> str | None:
    try:
        r = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 else ""


def _committed_versions(repo: Path, name: str) -> list[list[str]]:
    """Every version of repo/name ever committed to git, normalized; [] when repo is not in a git
    repository or git fails (the caller then treats a difference as a local edit, the safe side).
    install_all.sh runs this as root on a checkout owned by the SOC user, hence safe.directory."""
    rel = f"{repo.name}/{name}"
    git = ["git", "-c", f"safe.directory={repo.parent}", "-C", str(repo.parent)]
    try:
        log = subprocess.run(git + ["log", "--format=%H", "--", rel], capture_output=True, text=True, timeout=20)
        if log.returncode != 0:
            return []
        out = []
        for commit in log.stdout.split():
            show = subprocess.run(git + ["show", f"{commit}:{rel}"], capture_output=True, text=True, timeout=20)
            if show.returncode == 0:
                out.append(normalize(show.stdout))
        return out
    except (OSError, subprocess.TimeoutExpired):
        return []


FIREWALL_FILE = REPO / "firewall" / "ufw-status.txt"
FIREWALL_HEADER = """# The Kali's firewall as it should be: the output of 'sudo ufw status verbose'.
# scripts/deploy_drift.py (run daily by the self-test) compares it with the live firewall and reports any
# difference. Rules are NOT applied automatically (a wrong rule could lock everyone out): change the
# firewall with ufw by hand, then record the new state with
#     python3 /opt/sentinel-soc/scripts/deploy_drift.py --save-firewall
# and commit. Lines starting with # are ignored when comparing.
#
"""


def live_firewall() -> str | None:
    """'ufw status verbose' through the read-only sudo rule (deploy/sudoers/soc-ufw-status); None when
    that rule is not installed or ufw is missing."""
    try:
        r = subprocess.run(["sudo", "-n", "/usr/sbin/ufw", "status", "verbose"], capture_output=True, text=True,
                           timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout if r.returncode == 0 and r.stdout.startswith("Status:") else None


def firewall_drift(repo: Path = REPO, live: str | None = None) -> list[tuple[str, str]]:
    """[("firewall", "firewall/ufw-status.txt")] when the live firewall differs from deploy/firewall/, or
    [("firewall outdated", ...)] when it equals an earlier committed version (deploy/ has rules not applied
    yet). [] when they match or the firewall cannot be read."""
    want = repo / "firewall" / "ufw-status.txt"
    if not want.exists():
        return []
    live = live_firewall() if live is None else live
    if live is None or normalize(live) == normalize(_read(want) or ""):
        return []
    name = "firewall/ufw-status.txt"
    return [("firewall outdated" if normalize(live) in _committed_versions(repo, name) else "firewall", name)]


def bin_drift(repo: Path = REPO, sbin: Path = Path("/usr/local/sbin")) -> list[tuple[str, str]]:
    """[(kind, "bin/<name>")] for each helper of repo/bin/ that differs from sbin/<name>, or whose installed
    copy is not root-owned and closed to others' writes: a sudoers rule runs it as root, so anyone who
    can change the file owns the machine."""
    problems = []
    base = repo / "bin"
    if not base.is_dir():
        return problems
    for f in sorted(p for p in base.iterdir() if p.is_file()):
        live, name = sbin / f.name, f"bin/{f.name}"
        if not live.exists():
            problems.append(("not installed", name))
            continue
        st = live.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            problems.append(("unsafe", name))
        if _read(live) != _read(f):
            committed = _committed_versions(repo, name)
            problems.append(("outdated" if normalize(_read(live) or "") in committed else "changed", name))
    return problems


PACKAGES_HEADER = """# The stock set of manually-installed packages on this Kali (apt-mark showmanual) that the SOC does not
# depend on: the Kali install itself. deploy_drift.py ignores these; anything installed later that is
# neither here nor in packages.txt is reported. Refresh with: python3 scripts/deploy_drift.py --save-packages
"""


def _pkg_list(path: Path) -> list[str]:
    return [l.split("#")[0].strip() for l in (_read(path) or "").splitlines() if l.split("#")[0].strip()]


def _manual_packages() -> set[str] | None:
    try:
        r = subprocess.run(["apt-mark", "showmanual"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return set(r.stdout.split()) if r.returncode == 0 else None


def _installed_packages() -> set[str] | None:
    try:
        r = subprocess.run(["dpkg-query", "-W", "-f", "${Package} ${db:Status-Status}\\n"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return {p for p, _, st in (l.partition(" ") for l in r.stdout.splitlines()) if st.strip() == "installed"}


def package_drift(repo: Path = REPO, manual: set | None = None, installed: set | None = None) -> list[tuple[str, str]]:
    """("package missing", p) for each package of deploy/packages.txt that is not installed, and
    ("package unlisted", p) for each package installed by hand that is neither in packages.txt nor in the
    stock baseline (packages-baseline.txt): the rebuild recipe would not have it."""
    want = _pkg_list(repo / "packages.txt")
    if not want:
        return []
    manual = _manual_packages() if manual is None else manual
    installed = _installed_packages() if installed is None else installed
    out: list[tuple[str, str]] = []
    if installed is not None:
        out += [("package missing", p) for p in want if p not in installed]
    if manual is not None:
        known = set(want) | set(_pkg_list(repo / "packages-baseline.txt"))
        out += [("package unlisted", p) for p in sorted(manual - known)]
    return out


def sensor_drift(repo: Path = REPO, root: Path = Path("/")) -> list[tuple[str, str]]:
    """[(kind, "sensors/<path>")] for each file of repo/sensors/ that differs from root/<path>. A file this
    user cannot read is skipped rather than reported (the daily self-test runs unprivileged)."""
    problems = []
    base = repo / "sensors"
    if not base.is_dir():
        return problems
    for f in sorted(p for p in base.rglob("*") if p.is_file()):
        rel = f.relative_to(base)
        name = f"sensors/{rel}"
        live = root / rel
        if not live.exists():
            problems.append(("not installed", name))
            continue
        text = _read(live)
        if text is None or normalize(text) == normalize(_read(f) or ""):
            continue
        problems.append(("outdated" if normalize(text) in _committed_versions(repo, name) else "changed", name))
    return problems


def drift(repo: Path = REPO, live: Path = LIVE, crontab: str | None = None,
          check_crontab: bool = True, sensors_root: Path | None = Path("/"),
          check_firewall: bool = True) -> list[tuple[str, str]]:
    """[(kind, name)] of every way deploy/ and this machine disagree; [] when they match."""
    problems = []
    if check_firewall:
        problems += firewall_drift(repo)
    if sensors_root is not None:
        problems += bin_drift(repo)
        problems += package_drift(repo)
    if sensors_root is not None:
        problems += sensor_drift(repo, sensors_root)
    have, want = _units(live), _units(repo)
    for name in sorted(have.keys() | want.keys()):
        if name not in want:
            problems.append(("missing", name))
        elif name not in have:
            problems.append(("not installed", name))
        else:
            live_text = _read(have[name])
            if live_text is not None and normalize(live_text) != normalize(_read(want[name]) or ""):
                committed = _committed_versions(repo, name)
                problems.append(("outdated" if normalize(live_text) in committed else "changed", name))
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
    "changed": ("edited on this machine, or replaced by a package update (sensors/): bring the change into "
                "deploy/ and commit, or reinstall from deploy/ (install_all.sh --force)"),
    "outdated": "an earlier version from deploy/ is installed: run sudo deploy/install_all.sh",
    "not installed": "in deploy/ but not installed: run sudo deploy/install_all.sh",
    "crontab": "the crontab differs from deploy/crontab.txt: crontab -l > deploy/crontab.txt, or install that file",
    "package missing": "listed in deploy/packages.txt but not installed: run sudo deploy/install_packages.sh",
    "package unlisted": ("installed by hand but not in deploy/packages.txt: add it there if the SOC needs it (a "
                         "rebuilt Kali would lack it), or remove it; for stock Kali packages, --save-packages"),
    "unsafe": "a root helper in /usr/local/sbin is writable by someone other than root: reinstall it (install_all.sh)",
    "firewall": ("the live firewall (ufw) differs from deploy/firewall/ufw-status.txt: someone changed a rule. If it "
                 "was intended, record it (deploy_drift.py --save-firewall) and commit; if not, undo it"),
    "firewall outdated": ("deploy/firewall/ has rules that are not applied yet: apply them with ufw by hand "
                          "(not automatic, to avoid locking anyone out)"),
    "secret": "carries the ntfy topic: remove the value, it belongs in a private ntfy.conf drop-in",
}


def main() -> int:
    if "--save-firewall" in sys.argv:
        live = live_firewall()
        if live is None:
            print("cannot read the firewall: is deploy/sudoers/soc-ufw-status installed?")
            return 1
        FIREWALL_FILE.parent.mkdir(parents=True, exist_ok=True)
        FIREWALL_FILE.write_text(FIREWALL_HEADER + live)
        print(f"saved {FIREWALL_FILE}; review with git diff, then commit")
        return 0
    if "--save-packages" in sys.argv:
        manual = _manual_packages()
        if manual is None:
            print("cannot list the installed packages (apt-mark)")
            return 1
        base = sorted(manual - set(_pkg_list(REPO / "packages.txt")))
        (REPO / "packages-baseline.txt").write_text(PACKAGES_HEADER + "\n".join(base) + "\n")
        print(f"saved {len(base)} stock packages to {REPO / 'packages-baseline.txt'}; review with git diff, then commit")
        return 0
    problems = drift()
    for kind, name in problems:
        print(f"{kind:14} {name}   -- {EXPLAIN[kind]}")
    if not problems:
        print("deploy/ matches this machine")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
