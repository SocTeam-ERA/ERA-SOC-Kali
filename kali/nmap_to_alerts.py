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
                   and emit alerts ONLY for ports that just OPENED. A port
                   closing is logged to stdout but not alerted -- it's
                   almost always a device going offline, not a security
                   event, and alerting on it drowns out real detectors.
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
from soc_core import Alert, emit_alert, diff_state_lock, load_assets, build_ip_to_mac_map  # noqa: E402

HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017, 9200}

# A single scan run finding more "new" ports than this is far more likely to
# be a one-time settling event (a detection-logic change like switching to
# MAC-based device keys, or a genuine network-wide change) than 30+
# independent findings someone should triage one row at a time. Confirmed
# 2026-09-18: switching device_key() from IP to MAC alone produced 600 "new"
# alerts across 201 hosts in a single run, since every host's tracking key
# changed at once -- correct detection, but flooding the feed with 600 rows
# for what is really one event defeats the point of fixing alert noise
# elsewhere in this project. Above this threshold, emit one summary alert
# with the full list in `details` instead of one alert per port; at or below
# it, each finding is still worth its own row (existing behavior, unchanged).
PORT_BULK_ALERT_THRESHOLD = int(os.environ.get("SOC_PORT_BULK_THRESHOLD", "30"))

# lockdownd (62078) is Apple's iOS device-sync/AFC service -- it's the
# single most reliable fingerprint that a "new" tcpwrapped port is a
# personal phone/tablet joining Wi-Fi, not a finding. 49152 alone is too
# generic (it's the base of the OS ephemeral port range, used by lots of
# unrelated things), so it's only treated the same way when it shows up
# newly-opened on the SAME host in the SAME scan as 62078 -- confirmed
# empirically these two always appear together for an iOS device.
APPLE_SYNC_PORT = 62078
APPLE_SYNC_COMPANION_PORT = 49152

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
# (ftp-anon is not in this set any more: anonymous FTP is a real exposure but medium, and it
# was the only critical alert for something every printer does by default.)
CRITICAL_FINDING_SCRIPTS = {"http-default-accounts", "snmp-brute", "snmp-info"}

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
    """Severity of a port seen by a manual scan with no change history: normal, medium
    for a high-risk port that is not in the baseline."""
    return "medium" if (not in_baseline and port in HIGH_RISK_PORTS) else "normal"


def port_severity(port: int, notable: bool) -> str:
    """Severity of a NEWLY opened port. A port our own scan finds is information, not an
    alarm: it is normal unless there is a concrete reason. The reason is a remote-access,
    file-sharing or database port (HIGH_RISK_PORTS) opening on a device that was already
    known and had never shown that port (`notable`). On a device that just appeared, the
    new-device alert already covers the event, and a port the device showed before is a
    flapping scan result. Critical is only reached by the unconfirmed-fingerprint rule."""
    return "medium" if notable and port in HIGH_RISK_PORTS else "normal"


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
                    # an expired or self-signed certificate is hygiene (normal); weak protocols or
                    # ciphers are a real exposure (medium)
                    tls_sev = "normal" if ("EXPIRED" in tls_reason or tls_reason == "self-signed certificate") else "medium"
                    vulns.append(dict(
                        type="vuln", severity=tls_sev,
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


def build_port_alert(info: dict, ip: str, hostname, baseline: set, *, change: str | None,
                     apple_sync: bool = False, escalate_unconfirmed: bool = True):
    """The Alert for one port finding, or None (a closed port is only logged)."""
    pnum, proto = info["port"], info["proto"]
    sname, banner = info["service"], info["banner"]
    in_base = pnum in baseline
    # method="table" means nmap never got the port to respond in a way it could
    # actually fingerprint, and just guessed the name from the port number —
    # i.e. something is listening, but it doesn't behave like whatever its
    # port suggests. This exact signal (an "irc?" match that nmap's own
    # irc-info script couldn't even talk to) is what led straight to a
    # suspected IoT botnet listener on 2026-09-11 — worth surfacing loudly.
    # apple_sync already gives a more specific, confident explanation than
    # "unconfirmed" would -- tcpwrapped normally trips this flag, and we
    # don't want "likely a phone joining the network" immediately followed
    # by "unconfirmed service fingerprint, investigate directly".
    #
    # Raising the severity for every such port was too loud (2026-09-21: a Dell iDRAC's
    # VNC-over-TLS, a NETGEAR's 4242, an IP phone's SIP-TLS all became critical). The
    # signal that matters is an ESTABLISHED device suddenly opening a listener it never
    # had, so run() only asks for the escalation in that case (escalate_unconfirmed).
    # A brand-new device already has its own new-device alert, and a port the device has
    # shown before is a flapping scan result, not a new listener.
    unconfirmed = change != "closed" and info.get("method") == "table" and not apple_sync
    if change == "new":
        if apple_sync:
            # Confirmed 2026-09-18: this pair alone was 474 of kali_scan's
            # historical alerts -- every phone joining a VLAN re-triggers it,
            # not a security event.
            sev = "normal"
        else:
            sev = port_severity(pnum, escalate_unconfirmed)
            if unconfirmed and escalate_unconfirmed:
                sev = _escalate(sev)
        title = f"NEW open port {pnum}/{proto} ({sname}) on {ip}"
        if apple_sync:
            title += " — likely a phone/tablet joining the network"
        desc = f"A port that was NOT open in the previous scan is now open: {pnum}/{proto} {sname} on {ip}"
        if apple_sync:
            desc += (". Port 62078 is Apple's iOS device-sync service (lockdownd) -- this pattern "
                     "is almost always a personal phone/tablet joining Wi-Fi, not a finding")
    elif change == "closed":
        # A port closing isn't a security event -- it's usually just a
        # device going offline or a service restarting. Alerting on it
        # anyway (490 of 548 alerts in the first week were exactly this)
        # buries the handful of alerts from real detectors like Suricata,
        # Zeek and login_monitor under router noise. Log it for
        # troubleshooting; don't push it into the SOC feed.
        print(f"    (closed, not alerted) {pnum}/{proto} {sname} on {ip}")
        return
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
                 "a port-number guess — the service name may be wrong")
        desc += ("; investigate directly" if escalate_unconfirmed else
                 " (severity not raised: this device is newly seen, or has shown this port before)")
    return Alert(
        type="port_scan", severity=sev, title=title,
        source_ip=ip, hostname=hostname, detector="kali_scan",
        description=desc + ".",
        details={"port": pnum, "proto": proto, "service": sname, "banner": banner,
                 "in_baseline": in_base, "change": change or "present",
                 "service_method": info.get("method") or "unknown",
                 "service_conf": info.get("conf"), "unconfirmed_fingerprint": unconfirmed,
                 "unconfirmed_escalated": bool(unconfirmed and escalate_unconfirmed)},
    )


def emit_port(info: dict, ip: str, hostname, baseline: set, *, change: str | None,
              apple_sync: bool = False, escalate_unconfirmed: bool = True):
    alert = build_port_alert(info, ip, hostname, baseline, change=change, apple_sync=apple_sync,
                             escalate_unconfirmed=escalate_unconfirmed)
    if alert is not None:
        emit_alert(alert)


# More than this many newly opened ports on the SAME host in one scan are raised as one
# alert with the list inside (a device that just joined typically opens 5-10 at once).
HOST_BULK_THRESHOLD = int(os.environ.get("SOC_HOST_BULK_THRESHOLD", "4"))
_SEV_RANK = {"normal": 0, "medium": 1, "critical": 2}


def emit_host_group(ip: str, events: list, hostname, baseline: set) -> None:
    """One alert for all the new ports of one host; severity is the highest member's."""
    members = []
    for info, _ip, _hn, is_apple, esc in events:
        a = build_port_alert(info, ip, hostname, baseline, change="new", apple_sync=is_apple,
                             escalate_unconfirmed=esc)
        if a is not None:
            members.append((info, a))
    if not members:
        return
    sev = max((a.severity for _, a in members), key=_SEV_RANK.get)
    shown = ", ".join(f"{i['port']}/{i['proto']} {i['service']}" for i, _ in members[:6])
    more = f" (+{len(members) - 6} more)" if len(members) > 6 else ""
    mitre: dict = {}
    try:
        from mitre_tags import tag as _tag
        for _, a in members:
            for t in _tag({"title": a.title, "detector": "kali_scan", "details": a.details}):
                mitre.setdefault(t["technique"], t)
    except Exception:
        pass
    details = {"change": "host_new_ports", "count": len(members),
               "ports": [{"port": i["port"], "proto": i["proto"], "service": i["service"], "banner": i["banner"],
                          "severity": a.severity, "unconfirmed_fingerprint": a.details.get("unconfirmed_fingerprint")}
                         for i, a in members]}
    if mitre:
        details["mitre"] = list(mitre.values())
    emit_alert(Alert(
        type="port_scan", severity=sev,
        title=f"NEW open ports on {ip}: {shown}{more}",
        source_ip=ip, hostname=hostname, detector="kali_scan",
        description=(f"{len(members)} ports that were NOT open in the previous scan are now open on {ip}: {shown}{more}. "
                     "Grouped into one alert instead of one row per port; the full list is in details.ports."),
        details=details))


def device_key(ip: str, ip_to_mac: dict[str, str]) -> str:
    """The identity a host's port history is tracked under: its MAC when the
    asset inventory has one for its current IP, otherwise a fallback that
    behaves exactly like the old IP-only tracking (safe default when a MAC
    can't be resolved -- never silently assumes continuity it can't verify)."""
    mac = ip_to_mac.get(ip)
    return mac if mac else f"ip:{ip}"


# A vulnerability finding must be missing this long before "No longer detected" is
# raised; a shorter gap is treated as the scan simply not seeing it that time.
VULN_GONE_HOURS = float(os.environ.get("SOC_VULN_GONE_HOURS", "72"))


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
    "no longer detected" alert, so remediation is visible without having to
    keep re-alerting the original problem to prove it's gone. The title
    deliberately avoids the word "resolved" on its own -- the host being
    unreachable in one scan looks identical to the finding actually being
    fixed, and a title that just says RESOLVED reads as confirmed good news
    even though the description right below it says the opposite.
    """
    n = 0
    if diff_state is None:
        for v in vulns:
            v.pop("_key", None)
            emit_alert(Alert(**v))
            n += 1
        return n

    vuln_state = _vuln_state_path(diff_state)
    now = datetime.now(timezone.utc)
    with diff_state_lock(vuln_state):
        previous = _load_state(vuln_state)
        current_by_key = {}
        for v in vulns:
            key = v.pop("_key")
            current_by_key[key] = v
            if key not in previous:
                emit_alert(Alert(**v))
                n += 1
            # else: the finding is already known (present now, or missing only briefly)

        new_state = {}
        for key, v in current_by_key.items():
            new_state[key] = {"title": v.get("title"), "source_ip": v.get("source_ip"),
                              "hostname": v.get("hostname"), "severity": v.get("severity"),
                              "last_seen": now.isoformat()}
        for key, old in previous.items():
            if key in current_by_key:
                continue
            # Missing this scan. One missed scan is usually the host being asleep or a
            # script timing out, and dropping the finding here made it re-alert as
            # brand new the next time it showed up (23 real findings had produced 130
            # alerts by 2026-09-21). Keep it silently until it has been gone for
            # VULN_GONE_HOURS; only then say it is no longer detected.
            last = old.get("last_seen")
            try:
                gone_h = (now - datetime.fromisoformat(last)).total_seconds() / 3600 if last else 0.0
            except ValueError:
                gone_h = 0.0
            if gone_h < VULN_GONE_HOURS:
                new_state[key] = {**old, "last_seen": last or now.isoformat()}
                continue
            emit_alert(Alert(
                type="vuln", severity="normal",
                title=f"No longer detected (unconfirmed): {old.get('title', key)}",
                source_ip=old.get("source_ip"), hostname=old.get("hostname"),
                detector="kali_scan",
                description=(f"This finding was present in an earlier scan and has not been detected for "
                             f"{VULN_GONE_HOURS:g}+ hours -- either it was fixed, or the host has been "
                             "unreachable. Confirm before treating it as resolved."),
                details={"previous_title": old.get("title", key)},
            ))
            n += 1
        _save_state(vuln_state, new_state)
    return n


# A port that disappears and comes back is usually a flaky scan result (UDP
# especially: a service that misses one probe looks closed, then "opens" again),
# not a change. Each device keeps when every port was last seen; a port that is
# "new" but was seen within this many hours is logged, not alerted. A port that
# was never seen, or has been gone longer, still alerts.
PORT_QUIET_HOURS = float(os.environ.get("SOC_PORT_QUIET_HOURS", "24"))
SEEN_RETENTION_DAYS = 14

# A host absent from the current scan keeps its whole entry untouched (see the
# "merge into the previous state" comment below) -- deliberately, so a laptop
# asleep for a few scans doesn't lose its port history. But nothing ever removes
# a host that is gone for GOOD (decommissioned, replaced, moved off this network),
# so the state file only ever grows. This is a separate, much longer window than
# SEEN_RETENTION_DAYS: it drops the entry entirely, so if that device ever comes
# back every one of its ports looks "new" again -- worth avoiding for a routine
# short absence, acceptable once a host has been gone this long.
HOST_RETENTION_DAYS = float(os.environ.get("SOC_HOST_RETENTION_DAYS", "90"))


def _prune_stale_hosts(state: dict, touched: set, now: datetime) -> int:
    removed = 0
    for key in [k for k in state if k not in touched]:
        seen = state[key].get("seen") or {}
        last = None
        for t in seen.values():
            try:
                ts = datetime.fromisoformat(t)
            except ValueError:
                continue
            if last is None or ts > last:
                last = ts
        if last is None or (now - last).days >= HOST_RETENTION_DAYS:
            del state[key]
            removed += 1
    return removed


def _seen_recently(iso: str | None, now: datetime) -> bool:
    if not iso:
        return False
    try:
        return (now - datetime.fromisoformat(iso)).total_seconds() < PORT_QUIET_HOURS * 3600
    except ValueError:
        return False


def _update_seen(prev_seen: dict, ports: dict, now: datetime) -> dict:
    """Last-seen times: keep recent history (also for ports gone this scan), stamp what is open now."""
    keep = {}
    for k, t in prev_seen.items():
        try:
            if (now - datetime.fromisoformat(t)).days < SEEN_RETENTION_DAYS:
                keep[k] = t
        except ValueError:
            continue
    keep.update({k: now.isoformat() for k in ports})
    return keep


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
    ip_to_mac = build_ip_to_mac_map()
    resolved = sum(1 for ip in current if ip in ip_to_mac)
    print(f"[*] Device identity: {resolved}/{len(current)} host(s) resolved to a MAC "
          f"via the asset inventory; the rest fall back to IP-only tracking.")

    with diff_state_lock(diff_state):
        previous = _load_state(diff_state)

        if not previous:
            # first run: seed the baseline quietly, one summary alert (no flood)
            now_seed = datetime.now(timezone.utc)
            new_state = {device_key(ip, ip_to_mac): {"ip": ip, "ports": {k: v["service"] for k, v in ports.items()},
                                                     "seen": _update_seen({}, ports, now_seed)}
                         for ip, ports in current.items()}
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

        # Merge into the previous state rather than replacing it wholesale --
        # confirmed 2026-09-17: a host that simply didn't respond to THIS
        # scan pass (asleep laptop, printer powered off, a brief network
        # hiccup -- routine on a network of hundreds of real hosts) was
        # falling out of `current` entirely, which wiped its whole tracked
        # port history. The next time that same host showed up with the
        # exact same ports it always has, every one of them looked "new"
        # again -- one host alone (10.201.4.37) got re-flagged "new" 13
        # times over a week this way. Only hosts nmap actually saw this
        # run get their entry touched; anything absent from `current`
        # keeps whatever state it already had, so a transient miss no
        # longer costs that host its history.
        #
        # Keyed by device_key() (MAC when resolvable), not IP -- confirmed
        # 2026-09-18: on a DHCP network, keying this by IP meant a laptop
        # renewing its lease looked like a brand-new host (every normal
        # port flagged "new") and an IP handed to a different device looked
        # like the SAME host's ports changed. A device with no resolvable
        # MAC falls back to "ip:<addr>" -- identical behavior to before this
        # change, never assumes continuity it can't verify.
        new_state = dict(previous)
        now = datetime.now(timezone.utc)
        new_c = closed_c = reappeared_c = 0
        new_events = []  # (info, ip, hostname, is_apple, escalate) -- decide bulk vs. per-row after the loop
        for ip, ports in current.items():
            key = device_key(ip, ip_to_mac)
            prev_entry = previous.get(key, {})
            prev_ports = prev_entry.get("ports", {})
            prev_seen = prev_entry.get("seen", {})
            new_keys = set(ports) - set(prev_ports)
            back = {k for k in new_keys if _seen_recently(prev_seen.get(k), now)}
            for k in back:
                print(f"[*] {ip} {k} is back after a gap under {PORT_QUIET_HOURS:g}h -- flaky result, not alerted")
            new_keys -= back
            reappeared_c += len(back)
            # co-occurrence check across THIS host's newly-opened ports only --
            # see APPLE_SYNC_PORT's comment above.
            new_port_nums = {ports[k]["port"] for k in new_keys}
            has_sync_port = APPLE_SYNC_PORT in new_port_nums
            established = bool(prev_entry)                          # host was in the previous state
            for pkey in new_keys:                                  # newly opened
                is_apple = ports[pkey]["port"] == APPLE_SYNC_PORT or (
                    ports[pkey]["port"] == APPLE_SYNC_COMPANION_PORT and has_sync_port)
                escalate = established and pkey not in prev_seen
                new_events.append((ports[pkey], ip, hostnames.get(ip), is_apple, escalate))
                new_c += 1
            for pkey in set(prev_ports) - set(ports):               # newly closed
                proto, _, pnum = pkey.partition("/")
                info = {"port": int(pnum), "proto": proto, "service": prev_ports[pkey], "banner": ""}
                emit_port(info, ip, hostnames.get(ip), baseline, change="closed")
                closed_c += 1
            new_state[key] = {"ip": ip, "ports": {k: v["service"] for k, v in ports.items()},
                              "seen": _update_seen(prev_seen, ports, now)}

        touched = {device_key(ip, ip_to_mac) for ip in current}
        pruned_hosts = _prune_stale_hosts(new_state, touched, now)
        if pruned_hosts:
            print(f"[*] Pruned {pruned_hosts} host(s) not seen in over {HOST_RETENTION_DAYS:g} days "
                  f"from {diff_state.name}")

        _save_state(diff_state, new_state)

        if new_c > PORT_BULK_ALERT_THRESHOLD:
            hosts_affected = len({ip for _, ip, _, _, _ in new_events})
            emit_alert(Alert(
                type="port_scan", severity="medium",
                title=f"Bulk port change: {new_c} new open port(s) across {hosts_affected} host(s) in one scan",
                detector="kali_scan",
                description=(f"{new_c} newly-open ports were detected across {hosts_affected} hosts in a "
                             f"single scan pass -- collapsed into this one alert instead of {new_c} separate "
                             "rows. Usually a one-time settling event (e.g. a detection-logic change like "
                             "switching how devices are tracked) or a genuine broad network change, not "
                             f"{new_c} independent findings. Full per-port list in details."),
                details={"count": new_c, "hosts": hosts_affected, "change": "bulk_new",
                         "findings": [{"ip": ip, "hostname": hn, "port": info["port"], "proto": info["proto"],
                                       "service": info["service"], "apple_sync": is_apple}
                                      for info, ip, hn, is_apple, _esc in new_events]},
            ))
        else:
            by_host: dict = {}
            for ev in new_events:
                by_host.setdefault(ev[1], []).append(ev)
            for host_ip, evs in by_host.items():
                if len(evs) > HOST_BULK_THRESHOLD:
                    emit_host_group(host_ip, evs, evs[0][2], baseline)
                else:
                    for info, ip, hn, is_apple, esc in evs:
                        emit_port(info, ip, hn, baseline, change="new", apple_sync=is_apple, escalate_unconfirmed=esc)

    n += new_c
    print(f"[*] Change detection: {new_c} new port alert(s) "
          f"({'1 bulk summary' if new_c > PORT_BULK_ALERT_THRESHOLD else f'{new_c} individual'}), "
          f"{closed_c} port(s) closed and {reappeared_c} re-appeared within {PORT_QUIET_HOURS:g}h "
          f"(both logged, not alerted) + {vuln_n} vuln alert(s). ({n} total into the SOC feed.)")
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
