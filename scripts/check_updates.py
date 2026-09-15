#!/usr/bin/env python3
"""
check_updates.py
-----------------
Notify-only update checker for this Kali appliance.

Kali is a rolling release with no separate "security-only" channel the way
Debian stable has, so unattended-upgrades here would mean auto-applying
EVERY pending package, not just security patches -- risky on a box that
runs the detection pipeline itself (a tool update could silently change
behavior mid-scan). Instead, this just runs `apt-get update` and raises a
SOC alert listing what's pending, so a human reviews and applies it
(`sudo apt-get upgrade`) on their own schedule.

Usage:
    sudo python3 check_updates.py
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import Alert, emit_alert  # noqa: E402


def run() -> int:
    subprocess.run(["apt-get", "update", "-qq"], check=False)
    out = subprocess.run(
        ["apt", "list", "--upgradable"], capture_output=True, text=True, check=False
    ).stdout
    pkgs = [ln.split("/")[0] for ln in out.splitlines() if ln and not ln.startswith("Listing...")]

    if not pkgs:
        print("[*] check_updates: system is up to date.")
        return 0

    preview = ", ".join(pkgs[:15]) + ("..." if len(pkgs) > 15 else "")
    emit_alert(Alert(
        type="vuln", severity="medium",
        title=f"{len(pkgs)} package update(s) pending on this Kali appliance",
        detector="system_updates",
        description=("Notify-only check (Kali's rolling release has no security-only "
                     "channel, so updates aren't auto-applied here). Review and apply "
                     f"with 'sudo apt-get upgrade' when convenient: {preview}"),
        details={"pending_count": len(pkgs), "packages": pkgs[:100]},
    ))
    print(f"[*] check_updates: {len(pkgs)} package(s) pending, alert raised.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
