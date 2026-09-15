#!/usr/bin/env python3
"""
nikto_to_alerts.py
-------------------
Parses nikto's --Format json output and turns real findings into SOC
alerts. Unlike ftp-anon/http-default-accounts, nikto is NOT silent when
nothing is wrong -- confirmed empirically on a healthy internal web
service: it still reported 7 items, 5 of which were just "suggested
security header missing" advisories (nikto ID 013587). Those five alone
would flood the dashboard with one alert per missing header per host on
every scan, so they're treated as routine noise and skipped by default
(SKIP_SUBSTRINGS below). Everything else becomes one alert per host:port,
summarizing all remaining findings, with severity bumped to "medium" only
when at least one finding looks like a real, actionable issue (outdated
software, exposed backups/admin paths, injection, disclosure, etc. --
see INTERESTING_SUBSTRINGS).

Usage:
    python3 nikto_to_alerts.py results/nikto_XXXX.json
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, resolve_hostname  # noqa: E402

# Routine advisory nikto reports on almost every host regardless of actual
# risk -- confirmed on a healthy internal service (5 of 7 findings were
# exactly this). Not a real vulnerability by itself, just noise at scan
# frequency.
SKIP_SUBSTRINGS = (
    "suggested security header missing",
)

# Keywords marking a finding as worth a second look rather than routine
# housekeeping -- bumps the alert to "medium".
INTERESTING_SUBSTRINGS = (
    "vulnerable", "outdated", "backup", "default file", "default credential",
    "directory indexing", "index listing", "disclos", "exposed", "injection",
    "traversal", "shellshock", "x-powered-by", "server leaks", "osvdb",
    "allows arbitrary", "authentication bypass", "sql", "cross site", "xss",
    "shell", "command execution", "remote code",
)


def is_noise(msg: str) -> bool:
    low = msg.lower()
    return any(s in low for s in SKIP_SUBSTRINGS)


def is_interesting(msg: str) -> bool:
    low = msg.lower()
    return any(s in low for s in INTERESTING_SUBSTRINGS)


def run(json_path: Path) -> int:
    try:
        hosts = json.loads(json_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"[x] cannot read {json_path}: {e}", file=sys.stderr)
        return 1

    n = 0
    for entry in hosts:
        ip = entry.get("ip") or entry.get("host")
        host_label = entry.get("host") or ip
        port = entry.get("port")
        vulns = entry.get("vulnerabilities") or []

        findings = [v for v in vulns if v.get("msg") and not is_noise(v["msg"])]
        if not findings:
            continue

        interesting = any(is_interesting(v["msg"]) for v in findings)
        severity = "medium" if interesting else "normal"

        shown = findings[:15]
        lines = [f"[{v.get('id', '?')}] {v['url']}: {v['msg']}" for v in shown]
        if len(findings) > len(shown):
            lines.append(f"(+{len(findings) - len(shown)} more finding(s) not shown)")

        target = f"{host_label}:{port}" if port else host_label
        emit_alert(Alert(
            type="vuln", severity=severity,
            title=f"nikto: {len(findings)} finding(s) on {target}"
                  + (" -- includes actionable issue(s)" if interesting else ""),
            source_ip=ip, hostname=resolve_hostname(ip) if ip else None,
            detector="nikto",
            description="\n".join(lines),
            details={"target": target, "finding_count": len(findings),
                     "interesting": interesting,
                     "ids": sorted({v.get("id") for v in findings if v.get("id")})},
        ))
        n += 1

    print(f"[*] nikto_to_alerts: {n} alert(s) from {len(hosts)} host(s) scanned.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("json_file", help="nikto -Format json output file")
    args = ap.parse_args()
    return run(Path(args.json_file))


if __name__ == "__main__":
    raise SystemExit(main())
