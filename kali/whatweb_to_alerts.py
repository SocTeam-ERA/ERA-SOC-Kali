#!/usr/bin/env python3
"""
whatweb_to_alerts.py
---------------------
Parses whatweb's --log-json output and turns detected web technology
fingerprints into SOC alerts -- so shadow IT, EOL software versions, and
exposed admin panels on the network's internal web services show up on the
dashboard as more than just "port 80 is open".

Two severities:
    normal  -- routine tech-stack fingerprint (informational, asset inventory)
    medium  -- the fingerprint includes something worth a second look (an
               exposed admin panel / CMS commonly targeted by opportunistic
               attacks -- see INTERESTING_PLUGINS; NOT a real vulnerability
               check, just "this is the kind of thing scanners go for")

Usage:
    python3 whatweb_to_alerts.py results/whatweb_XXXX.json
"""
from __future__ import annotations
import argparse, json, os, sys
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert  # noqa: E402

INTERESTING_PLUGINS = {
    "WordPress", "Drupal", "Joomla", "Magento", "phpMyAdmin", "Jenkins",
    "Apache-Tomcat", "Tomcat", "Webmin", "GLPI", "Grafana", "Kibana",
    "Jira", "Confluence", "vBulletin", "MediaWiki",
}

# Environment/metadata plugins -- noise for a human-readable summary, not
# actual technology.
SKIP_PLUGINS = {"Country", "IP", "Title", "RedirectLocation", "UncommonHeaders"}


def summarize(plugins: dict) -> tuple[str, list[str], bool]:
    """Return (human-readable summary, all plugin names, any interesting hit)."""
    names = sorted(plugins.keys())
    bits = []
    for name in names:
        if name in SKIP_PLUGINS:
            continue
        info = plugins.get(name) or {}
        vals = info.get("string") or info.get("version") or []
        bits.append(f"{name}[{', '.join(str(v) for v in vals[:2])}]" if vals else name)
    interesting = bool(INTERESTING_PLUGINS & set(names))
    return (", ".join(bits) if bits else "(no distinguishing plugins matched)", names, interesting)


def run(json_path: Path) -> int:
    try:
        entries = json.loads(json_path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"[x] cannot read {json_path}: {e}", file=sys.stderr)
        return 1

    n = 0
    for entry in entries:
        target = entry.get("target", "")
        plugins = entry.get("plugins", {})
        if not target or not plugins:
            continue
        summary, names, interesting = summarize(plugins)
        server = (plugins.get("HTTPServer", {}).get("string") or [""])[0]
        ip = (plugins.get("IP", {}).get("string") or [None])[0]

        severity = "medium" if interesting else "normal"
        title = f"Web fingerprint: {target}"
        if interesting:
            hit = sorted(INTERESTING_PLUGINS & set(names))
            title += f" -- {', '.join(hit)} detected"

        emit_alert(Alert(
            type="vuln", severity=severity,
            title=title,
            source_ip=ip, detector="whatweb",
            description=f"{target}: {summary}",
            details={"target": target, "server": server, "plugins": names,
                     "interesting": interesting},
        ))
        n += 1

    print(f"[*] whatweb_to_alerts: {n} alert(s) from {len(entries)} target(s).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("json_file", help="whatweb --log-json output file")
    args = ap.parse_args()
    return run(Path(args.json_file))


if __name__ == "__main__":
    raise SystemExit(main())
