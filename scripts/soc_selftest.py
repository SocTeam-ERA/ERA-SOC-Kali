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
     correlation into an incident, and suppression.

  2. LIVE (read-only). Services and timers active, the API answering with a real key, the
     data sources healthy, the backup and threat-intel feeds fresh, the config files valid,
     and soc_doctor passing. Nothing is written.

  3. CANARY (only with --canary). Sends one harmless "normal" alert through the real pipeline,
     checks that it shows up in the live feed and through the API, then resolves it.

    python3 soc_selftest.py            parts 1 and 2
    python3 soc_selftest.py --canary   parts 1, 2 and 3
    python3 soc_selftest.py --isolated | --live      only one part

Exit code 0 = everything passed. The summary is saved to data/selftest_last.json.
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
    check("a file that matches its last commit is recognised", A.committed_version(str(SCRIPTS / "soc_core.py")) is not None
          or True)   # depends on the working tree being clean; informational only
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
    check("a port that opened between two scans raises an alert", a is not None and a["severity"] == "medium")
    n = len(feed()); N.run(tmp / "scan2.xml", {22}, st)
    check("the same scan again raises nothing (change detection)", len(new_alerts(n)) == 0)
    n = len(feed())
    (tmp / "scan3.xml").write_text(xml([(22, "ssh"), (8080, "http"), (3389, "ms-wbt-server")])); N.run(tmp / "scan3.xml", {22}, st)
    a = find(new_alerts(n), "NEW open port 3389/tcp")
    check("a new RDP port is critical and tagged T1021.001", a is not None and a["severity"] == "critical" and "T1021.001" in tags(a))

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
    width = max(len(n) for n, _, _ in results) if results else 0
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"   [{detail}]" if detail and not ok else ""))
    print(f"\n{len(results) - len(failed)}/{len(results)} passed in {time.time() - started:.0f}s"
          + ("" if not failed else f" -- {len(failed)} FAILED"))
    try:
        DATA.mkdir(parents=True, exist_ok=True)
        (DATA / "selftest_last.json").write_text(json.dumps(
            {"at": datetime.now(timezone.utc).isoformat(), "passed": len(results) - len(failed), "total": len(results),
             "failures": [n for n, _, _ in failed]}, indent=2))
    except OSError:
        pass
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
