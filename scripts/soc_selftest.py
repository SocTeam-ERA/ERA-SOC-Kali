#!/usr/bin/env python3
"""
soc_selftest.py -- does the whole detection pipeline still work? Answer in about a minute.

Three parts:

  1. DETECTORS (isolated). Each detector is fed a small synthetic input it should react to
     (a Suricata scan alert, a Zeek password-guessing notice, five failed SSH logins, an
     osquery new-user row, a wave of ARP new devices, an nmap XML with a new port, an EICAR
     test file, a phishing email, tshark rows with a port scan...) and the resulting alert is
     checked. It all runs in a throwaway data directory with notifications and the backend
     forwarder switched off, so nothing reaches the dashboard or anyone's phone.
     Then the platform layers on top: MITRE tags, entities, batches, threat intel,
     correlation into an incident, and suppression; and the analyst-facing layers: alert
     aging, search, incident lifecycle, suppressions created from the dashboard, playbooks,
     the backup script, and an isolated API server exercised with read and write keys.

  2. LIVE (read-only). Services and timers active, the API answering with a real key, the
     data sources healthy, the backup and threat-intel feeds fresh, the config files valid,
     and soc_doctor passing. Nothing is written.

  3. CANARY (only with --canary). Sends one harmless "normal" alert through the real pipeline,
     checks that it shows up in the live feed and through the API, then resolves it.

    python3 soc_selftest.py            parts 1 and 2
    python3 soc_selftest.py --canary   parts 1, 2 and 3
    python3 soc_selftest.py --isolated | --live      only one part
    python3 soc_selftest.py --live --alert-on-fail   (what the daily cron runs) raise ONE alert
                                                     when checks fail; a repeat of the same failures
                                                     is not re-alerted, and a recovery is recorded

Exit code 0 = everything passed. The summary is saved to data/selftest_last.json:
{at, passed, total, failed, failures: [{name, detail}]}, which soc_doctor reads.
It only uses harmless test inputs (the EICAR string is the industry-standard antivirus
test file) and never touches the network beyond this machine's own API.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent
SUITE = SCRIPTS.parent
KALI = SUITE / "kali"
DATA = Path(os.environ.get("SOC_DATA_DIR", SUITE / "data"))
API = os.environ.get("SOC_API_URL", "http://127.0.0.1:8080")

results: list[tuple[str, bool, str]] = []
current_group = ""


def check(name: str, ok: bool, detail: str = "") -> None:
    results.append((f"{current_group}: {name}" if current_group else name, bool(ok), detail))


def group(name: str) -> None:
    global current_group
    current_group = name


# --------------------------------------------------------------------------- #
#  Part 1 -- detectors and platform layers, in a throwaway data dir
# --------------------------------------------------------------------------- #

def inner() -> int:
    """Runs with SOC_DATA_DIR pointing at a temp dir (set by run_isolated)."""
    sys.path[:0] = [str(KALI), str(SCRIPTS)]
    import soc_core
    tmp = Path(os.environ["SOC_DATA_DIR"])

    def feed() -> list:
        try:
            return json.loads(soc_core.ALERTS_SNAPSHOT.read_text())
        except (OSError, ValueError):
            return []

    def new_alerts(before: int) -> list:
        return feed()[: max(len(feed()) - before, 0)]

    def find(alerts: list, text: str, **kw):
        for a in alerts:
            if text in a["title"] and all(a.get(k) == v for k, v in kw.items()):
                return a
        return None

    def tags(a) -> set:
        return {t["technique"] for t in (a or {}).get("details", {}).get("mitre", [])}

    # ---- Suricata ------------------------------------------------------------
    group("suricata")
    import suricata_to_alerts as S
    n = len(feed())
    ok = S.handle_event({"event_type": "alert", "src_ip": "203.0.113.9", "dest_ip": "10.201.5.5", "dest_port": 80,
                         "proto": "TCP", "alert": {"severity": 1, "signature": "ET SCAN Possible Nmap User-Agent Observed",
                                                   "category": "Web Application Attack", "signature_id": 2024364, "gid": 1}})
    a = find(new_alerts(n), "ET SCAN")
    check("a scan signature becomes an alert", ok and a is not None, str(ok))
    check("tagged MITRE T1046 and has entities", "T1046" in tags(a) and bool((a or {}).get("details", {}).get("entities")))
    check("non-alert events (flows) are ignored", S.handle_event({"event_type": "flow", "src_ip": "10.0.0.1"}) is False)

    # ---- Zeek ----------------------------------------------------------------
    group("zeek")
    import zeek_to_alerts as Z
    n = len(feed())
    ok = Z.handle_event({"note": "SSH::Password_Guessing", "msg": "203.0.113.9 appears to be guessing SSH passwords",
                         "src": "203.0.113.9", "dst": "10.201.5.5"})
    a = find(new_alerts(n), "SSH::Password_Guessing")
    check("a password-guessing notice becomes an alert", ok and a is not None)
    check("tagged MITRE T1110.001", "T1110.001" in tags(a))
    check("known-noise notices are dropped (CaptureLoss)", Z.handle_event({"note": "CaptureLoss::Too_Much_Loss", "msg": "x"}) is False)

    # ---- osquery -------------------------------------------------------------
    group("osquery")
    import osquery_to_alerts as O
    seen: dict = {}
    n = len(feed())
    base = {"name": "local_users", "action": "added", "counter": 1, "columns": {"username": "alice", "uid": "1000"}}
    check("the first batch only records a baseline (no alert)", O.handle_row(base, seen) is False)
    ok = O.handle_row({"name": "local_users", "action": "added", "counter": 2,
                       "columns": {"username": "backdoor", "uid": "0"}}, seen)
    a = find(new_alerts(n), "backdoor")
    check("a NEW local user after the baseline is a critical alert", ok and a is not None and a["severity"] == "critical")

    # ---- login monitor -------------------------------------------------------
    group("login_monitor")
    import ipaddress
    import login_monitor as L
    trk = L.BruteForceTracker(5, 60)
    known = [ipaddress.ip_network("10.0.0.0/8")]
    parsed = L.parse_line("Sep 21 10:00:01 kali2 sshd[123]: Failed password for root from 203.0.113.50 port 5555 ssh2")
    check("an sshd failure line is parsed", parsed is not None and parsed[2] == "203.0.113.50", str(parsed))
    n = len(feed())
    for _ in range(5):
        L.handle_event("failed", "root", "203.0.113.50", None, trk, known)
    a = find(new_alerts(n), "Brute-force")
    check("5 failures from one IP raise a brute-force alert", a is not None)
    n = len(feed())
    L.handle_event("accepted", "root", "203.0.113.50", None, trk, known)
    check("a login right after the failures is flagged as possible compromise",
          find(new_alerts(n), "Successful login after") is not None)
    n = len(feed())
    L.handle_event("accepted", "carol", "198.51.100.7", None, trk, known)
    check("a login from an IP outside the trusted list is flagged", find(new_alerts(n), "Login from NEW IP") is not None)
    n = len(feed())
    L.handle_event("accepted", "carol", "198.51.100.7", None, trk, known)
    check("...and only once per IP and user (cooldown)", find(new_alerts(n), "Login from NEW IP") is None)

    # ---- AIDE ----------------------------------------------------------------
    group("aide")
    import aide_to_alerts as A
    report = ("Added entries:\n---------------------------------------------------\n\n"
              "f++++++++++++++++++: /etc/cron.d/evil\n\n"
              "Removed entries:\n---------------------------------------------------\n\n"
              "f------------------: /usr/local/bin/old\n\n"
              "Changed entries:\n---------------------------------------------------\n\n"
              "f =.... mc..H.. .  : /etc/passwd\n")
    entries = dict((p, k) for k, p in A.parse_report(report))
    check("added, removed and changed entries are parsed",
          entries.get("/etc/cron.d/evil") == "added" and entries.get("/usr/local/bin/old") == "removed"
          and entries.get("/etc/passwd") == "changed", str(entries))
    check("changes to /etc/passwd are critical", A.severity_for("/etc/passwd") == "critical")
    from soc_core import Alert, emit_alert
    n = len(feed())
    emit_alert(Alert(type="intrusion", severity="critical", title="File integrity: /etc/cron.d/evil appeared",
                     detector="aide", details={"path": "/etc/cron.d/evil", "change": "added"}), echo=False)
    check("a new cron file is tagged MITRE T1053.003", "T1053.003" in tags(feed()[0]))

    # ---- traffic monitor -----------------------------------------------------
    group("traffic")
    import traffic_to_alerts as T
    own = sorted(T._own_ips())
    rows = []
    for p in range(1000, 1040):                                   # 40 distinct ports from one external host
        rows.append(f"1\t203.0.113.77\t10.201.5.5\t{p}\t\ttcp\t\t\t1\t0")
    for _ in range(3):                                            # cleartext Telnet, real session (not bare SYN)
        rows.append("2\t10.201.5.20\t10.201.0.13\t23\t\ttcp\t\t\t0\t1")
    rows.append("3\t10.201.5.30\t185.220.101.4\t443\t\ttcp\t\t\t0\t1")   # known-bad IP
    rows.append("4\t10.201.5.31\t8.8.4.4\t\t53\tudp\ttotally-legit-updates.xyz\t\t\t")   # bad domain
    if own:
        rows += [f"5\t{own[0]}\t10.201.5.5\t{p}\t\ttcp\t\t\t1\t0" for p in range(2000, 2020)]   # 20 ports from THIS box
    n = len(feed())
    T.parse(iter([r + "\n" for r in rows]), {"185.220.101.4"}, {"totally-legit-updates.xyz"}, None, set())
    new = new_alerts(n)
    check("a 40-port sweep from another host is a port scan", find(new, "Port scan on the wire: 203.0.113.77") is not None)
    check("Telnet in use is flagged as a cleartext protocol", find(new, "Cleartext protocol Telnet") is not None)
    check("contact with a known-bad IP is flagged", find(new, "known-bad IP 185.220.101.4") is not None)
    check("a query for a bad domain is flagged", find(new, "totally-legit-updates.xyz") is not None)
    if own:
        check("this appliance's own 20-port traffic is NOT a scan (own-IP threshold)",
              find(new, f"Port scan on the wire: {own[0]}") is None)

    # ---- ARP discovery -------------------------------------------------------
    group("arp")
    import arp_to_alerts as R
    def tsv(rows_):
        p = tmp / "arp.tsv"; p.write_text("\n".join("\t".join(r) for r in rows_) + "\n"); return p
    base_rows = [("10.69.0.0/16", "eth0", f"10.69.9.{i}", f"3c:bb:cc:00:00:{i:02x}", "Dell Inc.") for i in range(1, 4)]
    R.run(tsv(base_rows), tmp / "mac_state.json")
    n = len(feed())
    R.run(tsv(base_rows + [("10.69.0.0/16", "eth0", "10.69.8.1", "3c:bb:cc:00:01:01", "Intel Corporate")]), tmp / "mac_state.json")
    a = find(new_alerts(n), "New device on VLAN")
    check("one new device raises a new-device alert", a is not None and a["severity"] == "medium")
    check("tagged MITRE T1200 and carries its MAC as an entity", "T1200" in tags(a)
          and any(e["type"] == "mac" for e in (a or {}).get("details", {}).get("entities", [])))
    n = len(feed())
    wave = base_rows + [("10.69.0.0/16", "eth0", f"10.69.7.{i}", f"3c:bb:cc:00:02:{i:02x}", "HP") for i in range(1, 9)]
    R.run(tsv(wave), tmp / "mac_state.json")
    wave_alerts = new_alerts(n)
    bulk = find(wave_alerts, "new device(s) on VLAN")
    check("a wave of 8 new devices becomes ONE grouped alert", bulk is not None and len(wave_alerts) == 1 and bulk["details"]["count"] == 8)

    # ---- nmap ----------------------------------------------------------------
    group("nmap")
    import nmap_to_alerts as N
    def xml(ports):
        body = "".join(f'<port protocol="tcp" portid="{p}"><state state="open"/><service name="{s}" method="probed" conf="10"/></port>'
                       for p, s in ports)
        return ('<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.1.1.5" addrtype="ipv4"/>'
                f'<hostnames/><ports>{body}</ports></host></nmaprun>')
    st = tmp / "port_state.json"
    (tmp / "scan1.xml").write_text(xml([(22, "ssh")])); N.run(tmp / "scan1.xml", {22}, st)
    n = len(feed())
    (tmp / "scan2.xml").write_text(xml([(22, "ssh"), (8080, "http")])); N.run(tmp / "scan2.xml", {22}, st)
    a = find(new_alerts(n), "NEW open port 8080/tcp")
    check("a port that opened between two scans raises an alert (normal: a new ordinary port is information)", a is not None and a["severity"] == "normal")
    n = len(feed()); N.run(tmp / "scan2.xml", {22}, st)
    check("the same scan again raises nothing (change detection)", len(new_alerts(n)) == 0)
    n = len(feed())
    (tmp / "scan3.xml").write_text(xml([(22, "ssh"), (8080, "http"), (3389, "ms-wbt-server")])); N.run(tmp / "scan3.xml", {22}, st)
    a = find(new_alerts(n), "NEW open port 3389/tcp")
    check("a new RDP port on a known device is medium and tagged T1021.001", a is not None and a["severity"] == "medium" and "T1021.001" in tags(a))

    # ---- malware / phishing --------------------------------------------------
    group("malware")
    import malware_detector as M
    eicar = tmp / "eicar.txt"
    eicar.write_text(r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    ioc = tmp / "iocs.txt"; ioc.write_text("44d88612fea8a8f36de82e1278abb02f\n")
    n = len(feed()); M.scan_file(eicar, M.load_iocs(ioc))
    a = find(new_alerts(n), "Suspicious file")
    check("the EICAR test file is caught by its hash and is critical", a is not None and a["severity"] == "critical")
    group("phishing")
    import phishing_detector as P
    eml = tmp / "sample.eml"; eml.write_text(P.DEMO_EML)
    n = len(feed()); P.analyse_file(eml)
    check("the bundled phishing sample raises a phishing alert", find(new_alerts(n), "Phishing indicators") is not None)

    # ---- platform layers -----------------------------------------------------
    group("platform")
    import correlate
    n = len(feed())
    emit_alert(Alert(type="port_scan", severity="medium", title="Port scan on the wire: 192.0.2.44 probed 120 ports",
                     detector="traffic_capture", source_ip="192.0.2.44"), echo=False)
    emit_alert(Alert(type="vuln", severity="critical", title="ET EXPLOIT D-Link command injection (192.0.2.44 -> 10.201.5.5)",
                     detector="suricata", source_ip="192.0.2.44"), echo=False)
    incs = [i for i in correlate.list_incidents() if i["rule_id"] == "scan-then-exploit"]
    check("a scan followed by an exploit from the same host opens a critical incident",
          len(incs) == 1 and incs[0]["severity"] == "critical")
    check("the incident raised its own alert (detector correlation)", find(new_alerts(n), "Incident #") is not None)
    a = emit_alert(Alert(type="malware", severity="medium", title="Contact", detector="traffic_capture",
                         source_ip="185.220.101.4"), echo=False)
    check("a source in the local IOC list is enriched with threat intel", bool(a["details"].get("threat_intel")))
    a1 = emit_alert(Alert(type="intrusion", severity="normal", title="batch probe", detector="selftest"), echo=False)
    a2 = emit_alert(Alert(type="intrusion", severity="normal", title="batch probe", detector="selftest"), echo=False)
    check("alerts of one kind close together share a batch id", a1["details"]["batch_id"] == a2["details"]["batch_id"])
    supp = tmp / "sup.json"
    supp.write_text(json.dumps({"rules": [{"id": "selftest-rule", "reason": "self-test rule",
                                            "match": {"detector": "selftest_suppressed", "title_contains": "hide me"}}]}))
    import suppressions
    suppressions.CONFIG_FILE = supp
    r1 = emit_alert(Alert(type="intrusion", severity="medium", title="please hide me", detector="selftest_suppressed"), echo=False)
    r2 = emit_alert(Alert(type="intrusion", severity="medium", title="but not this", detector="selftest_suppressed"), echo=False)
    check("a matching suppression rule hides an alert, others pass", r1.get("suppressed_by") == "selftest-rule" and "suppressed_by" not in r2)

    # ---- (added) alert aging --------------------------------------------------
    group("aging")
    import alert_aging
    from datetime import timedelta

    def _ago(days):
        return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    old_port = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 80/tcp (http) on 10.0.0.1",
                                detector="kali_scan", timestamp=_ago(6)), echo=False)
    old_crit = emit_alert(Alert(type="port_scan", severity="critical", title="NEW open port 3389/tcp on 10.0.0.2",
                                detector="kali_scan", timestamp=_ago(9)), echo=False)
    old_vuln = emit_alert(Alert(type="vuln", severity="medium", title="Weak TLS on 10.0.0.5:443 (ssl-cert): certificate EXPIRED",
                                detector="kali_scan", timestamp=_ago(6)), echo=False)
    new_port = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 81/tcp on 10.0.0.3",
                                detector="kali_scan", timestamp=_ago(1)), echo=False)
    alert_aging.run()
    st = {a["id"]: a["status"] for a in feed()}
    check("a 6-day-old informational port alert is closed automatically", st.get(old_port["id"]) == "resolved")
    check("an old CRITICAL alert is left open", st.get(old_crit["id"]) == "open")
    check("an old vulnerability finding is left open", st.get(old_vuln["id"]) == "open")
    check("a recent port alert is left open", st.get(new_port["id"]) == "open")

    # ---- (added) search -------------------------------------------------------
    group("search")
    import log_search
    res = log_search.search("alerts", "batch probe", "1h", 10, 5)
    check("a text search finds alerts in the history", res["count"] >= 1, str(res["count"]))
    res = log_search.search("alerts", "detector:kali_scan ip:10.0.0.0/8", "1h", 50, 5)
    check("a field + network query finds the port alerts", res["count"] >= 1, str(res["count"]))

    def _refused(fn):
        try:
            fn()
        except ValueError:
            return True
        return False
    check("a path-traversal source is refused", _refused(lambda: log_search.search("zeek:../../etc/passwd", "x")))
    check("an empty query is refused", _refused(lambda: log_search.search("alerts", "")))

    # ---- (added) incidents ----------------------------------------------------
    group("incidents")
    incs = correlate.list_incidents()
    inc_id = incs[0]["id"] if incs else None
    check("an incident exists to work with", inc_id is not None)
    if inc_id:
        check("closing an incident without a classification is refused",
              _refused(lambda: correlate.update_incident(inc_id, "selftest", status="closed")))
        upd = correlate.update_incident(inc_id, "selftest", status="closed", classification="benign", comment="self-test")
        check("it closes with a classification and keeps the comment", upd["status"] == "closed" and len(upd["comments"]) == 1)
        check("the change is attributed to who made it", upd["comments"][0]["by"] == "selftest")

    # ---- (added) suppressions created from the dashboard ------------------------
    group("dashboard suppressions")
    import suppression_admin
    tgt = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 62078/tcp (tcpwrapped) on 10.1.1.10",
                           detector="kali_scan", source_ip="10.1.1.10", details={"port": 62078, "proto": "tcp"}), echo=False)
    other = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 3389/tcp (ms-wbt-server) on 10.1.1.10",
                             detector="kali_scan", source_ip="10.1.1.10", details={"port": 3389, "proto": "tcp"}), echo=False)
    crit = emit_alert(Alert(type="intrusion", severity="critical", title="Something critical", detector="suricata",
                            source_ip="9.9.9.9"), echo=False)
    rule = suppression_admin.create_rule("selftest", "known benign Apple sync port", alert_id=tgt["id"], scope="similar")["rule"]
    check("a rule can be created from an alert (it always expires)", bool(rule["expires"]) and rule["added_by"] == "selftest")
    again = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 62078/tcp (tcpwrapped) on 10.9.9.9",
                             detector="kali_scan", source_ip="10.9.9.9", details={"port": 62078, "proto": "tcp"}), echo=False)
    check("the same port on another host is now suppressed", again.get("suppressed_by") == rule["id"])
    other2 = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 3389/tcp (ms-wbt-server) on 10.9.9.9",
                              detector="kali_scan", source_ip="10.9.9.9", details={"port": 3389, "proto": "tcp"}), echo=False)
    check("a different port (RDP) is NOT suppressed", not other2.get("suppressed_by"))
    check("critical alerts cannot be suppressed from the dashboard",
          _refused(lambda: suppression_admin.create_rule("selftest", "should be refused", alert_id=crit["id"])))
    check("a client-supplied regular expression is refused",
          _refused(lambda: suppression_admin.create_rule("selftest", "should be refused",
                                                          match={"detector": "aide", "title_regex": ".*"})))
    suppression_admin.delete_rule(rule["id"], "selftest")
    back = emit_alert(Alert(type="port_scan", severity="medium", title="NEW open port 62078/tcp (tcpwrapped) on 10.8.8.8",
                            detector="kali_scan", source_ip="10.8.8.8", details={"port": 62078, "proto": "tcp"}), echo=False)
    check("after deleting the rule the alert is shown again", not back.get("suppressed_by"))

    # ---- (added) playbooks ----------------------------------------------------
    group("playbooks")
    import playbooks
    ov = playbooks.overview()
    check("the playbook file is valid", not ov["errors"] and len(ov["playbooks"]) >= 1)
    check("the shipped playbooks are all disabled", not any(p["enabled"] for p in ov["playbooks"]))
    check("an incident alert triggers no action while disabled",
          playbooks.run_for_alert({"detector": "correlation", "severity": "critical", "title": "Incident #1",
                                   "details": {"incident_id": "x"}}) == [])

    # ---- (added) backup -------------------------------------------------------
    group("backup")
    bk = tmp / "bk"
    bp = subprocess.run(["bash", str(KALI / "backup_data.sh")], capture_output=True, text=True, timeout=120,
                        env=dict(os.environ, SOC_BACKUP_DIR=str(bk), SOC_DATA_DIR=str(tmp)))
    arch = sorted(bk.glob("soc-backup-*.tar.gz"))
    check("the backup script runs and writes an archive", bp.returncode == 0 and bool(arch), bp.stderr[-120:])
    if arch:
        names = subprocess.run(["tar", "-tzf", str(arch[-1])], capture_output=True, text=True).stdout
        check("the archive has the alerts and config but NOT the API keys",
              "data/alerts.json" in names and "config/" in names and "api_keys" not in names)

    # ---- (added) API server with read and write keys ------------------------------
    group("api")
    import socket
    import urllib.error
    (tmp / "api_keys.json").write_text(json.dumps({"keys": [{"token": "t-read", "user": "reader", "role": "read"},
                                                             {"token": "t-write", "user": "writer", "role": "write"}]}))
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        port = sk.getsockname()[1]
    proc = subprocess.Popen([sys.executable, str(SCRIPTS / "soc_api.py")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=dict(os.environ, SOC_API_HOST="127.0.0.1", SOC_API_PORT=str(port)))

    def _call(path, token="t-read", method="GET", body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"} if token else {})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, None
    try:
        for _ in range(40):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1)
                break
            except OSError:
                time.sleep(0.25)
        check("the API answers health without a key", _call("/api/health", None)[0] == 200)
        check("the API refuses a request without a key", _call("/api/alerts", None)[0] == 401)
        code, d = _call("/api/alerts?limit=5")
        check("the alerts endpoint serves the feed", code == 200 and d["count"] >= 1)
        check("incidents, entities, metrics, sources, detections and playbooks answer",
              all(_call(p)[0] == 200 for p in ("/api/incidents", "/api/entities", "/api/metrics", "/api/sources",
                                               "/api/detections", "/api/playbooks", "/api/suppressions")))
        check("a search through the API works", _call("/api/search?source=alerts&q=batch&since=1h")[0] == 200)
        check("a path-traversal search source is rejected", _call("/api/search?source=zeek:../../etc/passwd&q=x")[0] == 400)
        check("a read-only key cannot change an incident", _call(f"/api/incidents/{inc_id}", "t-read", "POST", {"comment": "x"})[0] == 403)
        code, d = _call(f"/api/incidents/{inc_id}", "t-write", "POST", {"comment": "through the API"})
        check("a write key can comment, attributed to its user", code == 200 and d["comments"][-1]["by"] == "writer")
        check("a read-only key cannot create a suppression", _call("/api/suppressions", "t-read", "POST", {"reason": "x"})[0] == 403)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    print(json.dumps([{"name": n_, "ok": ok_, "detail": d} for n_, ok_, d in results]))
    return 0


def run_isolated() -> None:
    tmp = tempfile.mkdtemp(prefix="soc_selftest_")
    env = {k: v for k, v in os.environ.items() if k not in ("SOC_INGEST_URL", "NTFY_TOPIC", "SOC_SUPPRESSIONS_FILE")}
    env.update(SOC_DATA_DIR=tmp, SOC_PLAYBOOKS_DRY_RUN="1")
    shutil_assets = DATA / "assets.json"
    if shutil_assets.exists():
        Path(tmp, "assets.json").write_bytes(shutil_assets.read_bytes())
    try:
        proc = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--inner"], env=env,
                              capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        check("isolated tests finished", False, "timed out after 180 s")
        return
    out = proc.stdout.strip().splitlines()
    try:
        for r in json.loads(out[-1]):
            results.append((r["name"], r["ok"], r["detail"]))
    except (ValueError, IndexError):
        check("isolated tests ran", False, (proc.stderr or proc.stdout)[-400:])
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------------------- #
#  Part 2 -- live, read-only
# --------------------------------------------------------------------------- #

def api_get(path: str, token: str, timeout: int = 20):
    req = urllib.request.Request(API + path, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)


def read_token() -> str | None:
    try:
        keys = json.loads((DATA / "api_keys.json").read_text())["keys"]
        return next((k["token"] for k in keys if k["role"] == "read"), keys[0]["token"])
    except (OSError, ValueError, KeyError, IndexError):
        return None


def run_live() -> None:
    sys.path[:0] = [str(SCRIPTS)]
    group("live")
    from service_watchdog import SERVICES
    for svc in SERVICES:
        state = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True).stdout.strip()
        check(f"service {svc} is active", state == "active", state)
    from soc_doctor import TIMERS
    bad = [t for t in TIMERS if subprocess.run(["systemctl", "is-enabled", t], capture_output=True, text=True).stdout.strip() != "enabled"]
    check("all scheduled timers are enabled", not bad, ", ".join(bad))

    token = read_token()
    if token is None:
        check("API checks", False, "cannot read data/api_keys.json (run with the soc group: sg soc -c ...)")
    else:
        try:
            health = json.load(urllib.request.urlopen(API + "/api/health", timeout=10))
            check("the API answers /api/health", health.get("status") == "ok")
            for path, key in (("/api/alerts?limit=1", "alerts"), ("/api/incidents", "incidents"), ("/api/entities?limit=1", "entities"),
                              ("/api/metrics", "alerts"), ("/api/sources", "sources"), ("/api/detections", "detectors"),
                              ("/api/suppressions", "rules"), ("/api/playbooks", "playbooks"),
                              ("/api/search?source=alerts&q=selftest&limit=1", "results")):
                try:
                    check(f"API {path.split('?')[0]} responds", key in api_get(path, token))
                except Exception as e:
                    check(f"API {path.split('?')[0]} responds", False, f"{type(e).__name__}: {e}")
        except Exception as e:
            check("the API answers /api/health", False, f"{type(e).__name__}: {e}")

    import source_health
    for s in source_health.check():
        if s["status"] == "stale":
            check(f"data source {s['name']} is fresh", False, f"silent for {s['age_minutes']} min")
    check("no data source is silent", not any(s["status"] == "stale" for s in source_health.check()))

    import correlate, playbooks, suppressions, alert_aging
    for label, errs in (("correlation rules", correlate.load_rules()[2]), ("suppression rules", suppressions.load_rules()[1]),
                        ("playbooks", playbooks.load_playbooks()[1]), ("alert aging rules", alert_aging.load_rules()[1])):
        check(f"{label} file is valid", not errs, "; ".join(errs)[:200])
    try:
        st = json.loads((DATA / "backup_status.json").read_text())
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(st["last_ok"])).total_seconds() / 3600
        check("the last backup succeeded within 26 hours", age_h <= 26, f"{age_h:.1f} h ago")
    except (OSError, ValueError, KeyError):
        check("the last backup succeeded within 26 hours", False, "no backup status yet (run kali/backup_data.sh)")
    try:
        meta = json.loads((DATA / "threat_intel" / "meta.json").read_text())
        age_h = (datetime.now(timezone.utc) - datetime.fromisoformat(meta["kev"]["fetched"])).total_seconds() / 3600
        check("the threat-intel feeds were refreshed within 72 hours", age_h <= 72, f"{age_h:.0f} h ago")
    except (OSError, ValueError, KeyError):
        check("the threat-intel feeds were refreshed within 72 hours", False, "never downloaded")
    doc = subprocess.run([sys.executable, str(SCRIPTS / "soc_doctor.py")], capture_output=True, text=True, timeout=120)
    check("soc_doctor reports no failures", doc.returncode == 0, (doc.stdout.strip().splitlines() or [""])[-2][:120])


# --------------------------------------------------------------------------- #
#  Part 3 -- canary through the real pipeline
# --------------------------------------------------------------------------- #

def run_canary() -> None:
    sys.path[:0] = [str(SCRIPTS)]
    group("canary")
    import soc_core
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rec = soc_core.emit_alert(soc_core.Alert(
        type="intrusion", severity="normal", detector="selftest", title=f"SELFTEST canary {stamp}",
        description="Harmless round-trip test by soc_selftest.py; resolved automatically."), echo=False)
    time.sleep(1)
    in_feed = any(a["id"] == rec["id"] for a in soc_core._load_snapshot())
    check("the alert reached the live feed", in_feed)
    token = read_token()
    if token:
        try:
            got = api_get("/api/alerts?limit=20", token)["alerts"]
            check("the alert is served by the API", any(a["id"] == rec["id"] for a in got))
        except Exception as e:
            check("the alert is served by the API", False, str(e))
    try:
        soc_core.set_alert_status(rec["id"], "resolved", note="Self-test canary; resolved automatically.", actor="selftest")
        check("the canary was resolved (dashboard stays clean)", True)
    except ValueError as e:
        check("the canary was resolved (dashboard stays clean)", False, str(e))


def alert_on_change(summary: dict, previous: dict) -> None:
    """One alert when the set of failing checks changes to something non-empty, one 'recovered'
    alert when a failing run is followed by a clean one. The same failures on consecutive
    daily runs stay quiet."""
    sys.path[:0] = [str(SCRIPTS)]
    from soc_core import Alert, emit_alert
    now_failed = sorted(f["name"] for f in summary["failures"])
    was_failed = sorted(f["name"] for f in previous.get("failures", []))
    if now_failed and now_failed != was_failed:
        emit_alert(Alert(
            type="intrusion", severity="medium", detector="selftest",
            title=f"Self-test failed: {len(now_failed)} check(s)",
            description=("The daily self-test found problems in the detection pipeline: "
                         + "; ".join(now_failed[:5]) + (" ..." if len(now_failed) > 5 else "")
                         + ". Run: sg soc -c 'python3 /opt/sentinel-soc/scripts/soc_selftest.py'"),
            details={"failures": summary["failures"][:20], "passed": summary["passed"], "total": summary["total"]}), echo=False)
    elif not now_failed and was_failed:
        emit_alert(Alert(
            type="intrusion", severity="normal", detector="selftest",
            title="Self-test recovered",
            description=f"All {summary['total']} self-test checks pass again.",
            details={"passed": summary["passed"], "total": summary["total"]}), echo=False)


def main() -> int:
    args = sys.argv[1:]
    if "--inner" in args:
        return inner()
    started = time.time()
    if "--live" not in args:
        run_isolated()
    if "--isolated" not in args:
        run_live()
    if "--canary" in args:
        run_canary()
    failed = [r for r in results if not r[1]]
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed in {time.time() - started:.0f}s"
          + ("" if not failed else f" -- {len(failed)} FAILED"))
    summary = {"at": datetime.now(timezone.utc).isoformat(), "passed": len(results) - len(failed), "total": len(results),
               "failed": len(failed), "failures": [{"name": n, "detail": d} for n, _, d in failed]}
    try:
        previous = json.loads((DATA / "selftest_last.json").read_text())
    except (OSError, ValueError):
        previous = {}
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "selftest_last.json").write_text(json.dumps(summary, indent=2))
    except OSError:
        pass
    if "--alert-on-fail" in args:
        alert_on_change(summary, previous)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
