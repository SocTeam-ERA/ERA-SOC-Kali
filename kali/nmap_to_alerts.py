#!/usr/bin/env python3
"""
nmap_to_alerts.py
-----------------
Parses nmap XML output (from the service scan or the vuln scan) and turns it
into SOC alerts in the common schema, so Kali scan results show up on the
dashboard alongside the live detectors.

Two modes:
  * default      — emit one alert per open port (full inventory each run).
  * change-only  — with --diff-state <file>, compare against the previous scan
                   and emit alerts ONLY for ports that just OPENED or CLOSED.
                   Unchanged ports stay quiet (kills the repetitive noise).
                   Vulnerabilities (NSE) get the same treatment via a sibling
                   state file: a finding always alerts the first time it's
                   seen, then stays quiet while still present, and gets one
                   low-severity "resolved" alert if it stops being detected.
                   Without --diff-state, every vulnerability is always
                   reported on every run (legacy/manual-run behavior).

Usage:
    python3 nmap_to_alerts.py results/services_XXXX.xml --baseline 22,443
    python3 nmap_to_alerts.py results/services_XXXX.xml --baseline 22,443 \
            --diff-state ../data/port_state.json

It imports soc_core from ../scripts, so run it from the project or set
SOC_SCRIPTS to the scripts directory.
"""
from __future__ import annotations
import argparse, json, os, re, sys, tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

# make soc_core importable
SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, diff_state_lock  # noqa: E402

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017, 9200}

# These scripts stay completely silent unless they actually found something
# (anonymous FTP that works, default credentials that log in, or a working
# SNMP community string) -- so their mere presence in the XML is itself the
# finding, with no "VULNERABLE" or "CVE-" keyword to match on. Confirmed
# empirically for snmp-brute/snmp-info: no <script> output at all against a
# host with no real SNMP responding, same as the other two.
ALWAYS_REPORT_SCRIPTS = {"vulners", "ftp-anon", "http-default-accounts", "snmp-brute", "snmp-info"}
# A confirmed working anonymous login, default credential, or default SNMP
# community string is exploitable immediately, no CVE research needed --
# treat it as critical, same as a confirmed VULNERABLE finding, not the
# generic "medium" fallback.
CRITICAL_FINDING_SCRIPTS = {"ftp-anon", "http-default-accounts", "snmp-brute", "snmp-info"}

# ssl-enum-ciphers / ssl-cert produce output for EVERY TLS service, including
# perfectly healthy ones -- unlike ftp-anon/http-default-accounts they can't
# go in ALWAYS_REPORT_SCRIPTS (that would alert on every single HTTPS port).
# Only flag them when the output actually shows a real problem.
WEAK_TLS_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1")
WEAK_CIPHER_MARKERS = ("EXPORT", "RC4", "3DES", "_DES_", "_MD5", "NULL", "anon")


def tls_finding(sid: str, output: str) -> str | None:
    """Return a human-readable reason if an ssl-enum-ciphers/ssl-cert output
    shows a real problem, else None (healthy TLS -- nothing to alert on)."""
    if sid == "ssl-enum-ciphers":
        bad_protocols = sorted({p for p in WEAK_TLS_PROTOCOLS if p in output})
        bad_ciphers = sorted({m for m in WEAK_CIPHER_MARKERS if m in output})
        if not bad_protocols and not bad_ciphers:
            return None
        bits = []
        if bad_protocols:
            bits.append("deprecated protocol(s): " + ", ".join(bad_protocols))
        if bad_ciphers:
            bits.append("weak cipher indicator(s): " + ", ".join(bad_ciphers))
        return "; ".join(bits)

    if sid == "ssl-cert":
        m = re.search(r"[Nn]ot valid after:\s*(\S+)", output)
        if m:
            try:
                expiry = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
                if expiry.tzinfo is None:
                    expiry = expiry.replace(tzinfo=timezone.utc)
                if expiry < datetime.now(timezone.utc):
                    return f"certificate EXPIRED on {expiry.date()}"
            except ValueError:
                pass  # unparseable date -- fall through to the self-signed check
        if re.search(r"(?i)self[- ]signed", output):
            return "self-signed certificate"
        return None

    return None


def sev_for_port(port: int, in_baseline: bool) -> str:
    if not in_baseline and port in HIGH_RISK_PORTS:
        return "critical"
    if port in HIGH_RISK_PORTS:
        return "medium"
    return "normal" if in_baseline else "medium"


def sev_for_new_port(port: int, in_baseline: bool) -> str:
    """A newly-opened port is always worth a look — never 'normal'."""
    s = sev_for_port(port, in_baseline)
    return "medium" if s == "normal" else s


_SEV_ORDER = ["normal", "medium", "critical"]


def _escalate(sev: str) -> str:
    """Bump a severity one level up (critical stays critical)."""
    i = _SEV_ORDER.index(sev)
    return _SEV_ORDER[min(i + 1, len(_SEV_ORDER) - 1)]


def _load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text()).get("hosts", {})
    except Exception:
        return {}


def _save_state(path: Path, hosts: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated": datetime.now(timezone.utc).isoformat(), "hosts": hosts}
    # atomic write so a crash never leaves a half-written state file
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    # mkstemp() defaults to mode 0600 (owner-only), and os.replace() swaps
    # that in wholesale -- left as-is, whichever user runs this next (the
    # scheduled job as root vs. a manual run as a team member) locks
    # everyone else out of reading/updating the state file afterward.
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def parse_xml(path: Path):
    """Return (current_hosts, hostnames, vulns).
    current_hosts: { ip: { "tcp/3389": {"port":3389,"proto":"tcp","service":"ms-wbt-server","banner":".."} } }
    hostnames:     { ip: "name" or None }
    vulns:         list of Alert kwargs (always emitted)
    """
    tree = ET.parse(path)
    root = tree.getroot()
    current: dict = {}
    hostnames: dict = {}
    vulns: list = []

    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr") if addr_el is not None else None
        if not ip:
            continue
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else None
        hostnames[ip] = hostname
        current.setdefault(ip, {})

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            pnum = int(port.get("portid"))
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            sname = (svc.get("name") if svc is not None else "unknown") or "unknown"
            product = (svc.get("product") if svc is not None else "") or ""
            version = (svc.get("version") if svc is not None else "") or ""
            # nmap's own confidence in the service guess: method="table" means it
            # never got a protocol-level response and just looked up the port
            # number in its services database — the name may be wrong.
            method = (svc.get("method") if svc is not None else "") or ""
            conf = svc.get("conf") if svc is not None else None
            banner = f"{product} {version}".strip()
            key = f"{proto}/{pnum}"
            current[ip][key] = {"port": pnum, "proto": proto, "service": sname, "banner": banner,
                                 "method": method, "conf": conf}

            # vulnerabilities reported by NSE scripts on this port (always reported)
            for script in port.findall("script"):
                sid = script.get("id", "")
                output = (script.get("output", "") or "").strip()
                tls_reason = tls_finding(sid, output) if sid in ("ssl-enum-ciphers", "ssl-cert") else None
                if tls_reason:
                    vulns.append(dict(
                        type="vuln", severity="medium",
                        title=f"Weak TLS on {ip}:{pnum} ({sid}): {tls_reason}",
                        source_ip=ip, hostname=hostname, detector="kali_scan",
                        description=f"{tls_reason}. " + output[:350],
                        details={"port": pnum, "script": sid, "output": output[:2000]},
                        _key=f"{ip}:{pnum}:{sid}",
                    ))
                elif "VULNERABLE" in output.upper() or sid in ALWAYS_REPORT_SCRIPTS or "CVE-" in output:
                    crit = ("critical" if "VULNERABLE" in output.upper() or sid in CRITICAL_FINDING_SCRIPTS
                             else "medium")
                    vulns.append(dict(
                        type="vuln", severity=crit,
                        title=f"Vulnerability on {ip}:{pnum} ({sid})",
                        source_ip=ip, hostname=hostname, detector="kali_scan",
                        description=output[:400],
                        details={"port": pnum, "script": sid, "output": output[:2000]},
                        _key=f"{ip}:{pnum}:{sid}",
                    ))

        # host-level scripts (e.g. smb-vuln-*)
        for script in host.findall("hostscript/script"):
            output = (script.get("output", "") or "").strip()
            if "VULNERABLE" in output.upper():
                vulns.append(dict(
                    type="vuln", severity="critical",
                    title=f"Host vulnerability on {ip} ({script.get('id')})",
                    source_ip=ip, hostname=hostname, detector="kali_scan",
                    description=output[:400],
                    details={"script": script.get("id"), "output": output[:2000]},
                    _key=f"{ip}:-:{script.get('id')}",
                ))

    return current, hostnames, vulns


def emit_port(info: dict, ip: str, hostname, baseline: set, *, change: str | None):
    pnum, proto = info["port"], info["proto"]
    sname, banner = info["service"], info["banner"]
    in_base = pnum in baseline
    # method="table" means nmap never got the port to respond in a way it could
    # actually fingerprint, and just guessed the name from the port number —
    # i.e. something is listening, but it doesn't behave like whatever its
    # port suggests. This exact signal (an "irc?" match that nmap's own
    # irc-info script couldn't even talk to) is what led straight to a
    # suspected IoT botnet listener on 2026-09-11 — worth surfacing loudly.
    unconfirmed = change != "closed" and info.get("method") == "table"
    if change == "new":
        sev = sev_for_new_port(pnum, in_base)
        if unconfirmed:
            sev = _escalate(sev)
        title = f"NEW open port {pnum}/{proto} ({sname}) on {ip}"
        desc = f"A port that was NOT open in the previous scan is now open: {pnum}/{proto} {sname} on {ip}"
    elif change == "closed":
        sev = "normal"
        title = f"Port {pnum}/{proto} ({sname}) CLOSED on {ip}"
        desc = f"A port that was open in the previous scan is now closed: {pnum}/{proto} {sname} on {ip}"
    else:
        sev = sev_for_port(pnum, in_base)
        if unconfirmed:
            sev = _escalate(sev)
        title = f"Open port {pnum}/{proto} ({sname}) on {ip}" + ("" if in_base else " (not in baseline)")
        desc = f"nmap found {pnum}/{proto} {sname} open on {ip}"
    if unconfirmed:
        title += " — unconfirmed service fingerprint"
    if banner and change != "closed":
        desc += f" running {banner}"
    if unconfirmed:
        desc += (". Nmap could not confirm this service via protocol probing and fell back to "
                 "a port-number guess — the service name may be wrong; investigate directly")
    emit_alert(Alert(
        type="port_scan", severity=sev, title=title,
        source_ip=ip, hostname=hostname, detector="kali_scan",
        description=desc + ".",
        details={"port": pnum, "proto": proto, "service": sname, "banner": banner,
                 "in_baseline": in_base, "change": change or "present",
                 "service_method": info.get("method") or "unknown",
                 "service_conf": info.get("conf"), "unconfirmed_fingerprint": unconfirmed},
    ))


def _vuln_state_path(diff_state: Path) -> Path:
    return diff_state.with_name(diff_state.stem + "_vulns" + diff_state.suffix)


def _run_vulns(vulns: list, diff_state: Path | None) -> int:
    """Emit vulnerability findings (weak TLS, ftp-anon, CVE hits, etc).

    Without --diff-state, this always reported every vulnerability on every
    run (documented as "always reported" for years) -- confirmed 2026-09-15
    this meant the scheduled scan (every ~4h) re-alerted the exact same
    still-unfixed finding forever: one host's anonymous-FTP finding alone
    fired 24 times over 4 days, and 85% of every vuln alert in the whole
    feed turned out to be pure repetition of the same ~44 real findings.

    With --diff-state, vulnerabilities now get their own persisted state
    (a sibling file next to the port diff-state, e.g. port_state_vulns.json)
    so a still-present finding only alerts once. Unlike the port baseline,
    a vulnerability's FIRST-ever detection is never seeded silently -- a
    real finding is worth knowing about immediately, there's no such thing
    as an acceptable "baseline" vulnerability the way an already-open port
    can be normal. A finding that stops being detected gets one low-severity
    "resolved" alert, so remediation is visible without having to keep
    re-alerting the original problem to prove it's gone.
    """
    n = 0
    if diff_state is None:
        for v in vulns:
            v.pop("_key", None)
            emit_alert(Alert(**v))
            n += 1
        return n

    vuln_state = _vuln_state_path(diff_state)
    with diff_state_lock(vuln_state):
        previous = _load_state(vuln_state)
        current_by_key = {}
        for v in vulns:
            key = v.pop("_key")
            current_by_key[key] = v
            if key not in previous:
                emit_alert(Alert(**v))
                n += 1
            # else: identical finding still present and already alerted once -- stay quiet

        for key, old in previous.items():
            if key not in current_by_key:
                emit_alert(Alert(
                    type="vuln", severity="normal",
                    title=f"RESOLVED (no longer detected): {old.get('title', key)}",
                    source_ip=old.get("source_ip"), hostname=old.get("hostname"),
                    detector="kali_scan",
                    description=("This finding was present in a previous scan and is no longer "
                                  "detected -- either it was fixed, or the host wasn't reachable "
                                  "in this scan. Confirm before treating it as resolved."),
                    details={"previous_title": old.get("title", key)},
                ))
                n += 1

        new_state = {k: {"title": v.get("title"), "source_ip": v.get("source_ip"),
                          "hostname": v.get("hostname"), "severity": v.get("severity")}
                     for k, v in current_by_key.items()}
        _save_state(vuln_state, new_state)
    return n


def run(xml_path: Path, baseline: set, diff_state: Path | None) -> int:
    current, hostnames, vulns = parse_xml(xml_path)
    n = vuln_n = _run_vulns(vulns, diff_state)

    if diff_state is None:
        # legacy behavior: emit every open port
        for ip, ports in current.items():
            for info in ports.values():
                emit_port(info, ip, hostnames.get(ip), baseline, change=None)
                n += 1
        print(f"[*] Imported {n} alert(s) from {xml_path} into the SOC feed.")
        return 0

    # ---- change-detection mode ----
    # Locked so a manual run can't race the scheduled job (or another manual
    # run) on the same state file -- see diff_state_lock()'s docstring.
    with diff_state_lock(diff_state):
        previous = _load_state(diff_state)
        # save the new state (as ip -> {portkey: service}) regardless of what we emit
        new_state = {ip: {k: v["service"] for k, v in ports.items()} for ip, ports in current.items()}

        if not previous:
            # first run: seed the baseline quietly, one summary alert (no flood)
            host_count = len(current)
            port_count = sum(len(p) for p in current.values())
            emit_alert(Alert(
                type="port_scan", severity="normal",
                title=f"Port baseline established: {port_count} open ports across {host_count} hosts",
                detector="kali_scan",
                description=("First change-detection run: recorded the current open-port baseline. "
                             "From now on, alerts fire only when a port opens or closes."),
                details={"hosts": host_count, "open_ports": port_count, "change": "baseline"},
            ))
            _save_state(diff_state, new_state)
            print(f"[*] Baseline seeded: {port_count} ports / {host_count} hosts. "
                  f"Emitted 1 summary + {n} vuln alert(s).")
            return 0

        new_c = closed_c = 0
        for ip in set(current) | set(previous):
            cur_ports = current.get(ip, {})
            prev_ports = previous.get(ip, {})
            for key in set(cur_ports) - set(prev_ports):          # newly opened
                emit_port(cur_ports[key], ip, hostnames.get(ip), baseline, change="new")
                new_c += 1
            for key in set(prev_ports) - set(cur_ports):          # newly closed
                proto, _, pnum = key.partition("/")
                info = {"port": int(pnum), "proto": proto, "service": prev_ports[key], "banner": ""}
                emit_port(info, ip, hostnames.get(ip), baseline, change="closed")
                closed_c += 1

        _save_state(diff_state, new_state)
    n += new_c + closed_c
    print(f"[*] Change detection: {new_c} new, {closed_c} closed port alert(s) "
          f"+ {vuln_n} vuln alert(s). ({n} total into the SOC feed.)")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("xml", help="nmap XML output file (-oX / -oA)")
    ap.add_argument("--baseline", default="", help="Comma list of allowed ports, e.g. 22,443")
    ap.add_argument("--diff-state", default="",
                    help="Path to a JSON state file. If set, only alert on ports that "
                         "opened/closed since the previous scan.")
    args = ap.parse_args()
    baseline = {int(p) for p in args.baseline.split(",") if p.strip().isdigit()}
    diff_state = Path(args.diff_state).expanduser().resolve() if args.diff_state.strip() else None
    return run(Path(args.xml), baseline, diff_state)


if __name__ == "__main__":
    raise SystemExit(main())
