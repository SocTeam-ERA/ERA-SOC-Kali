#!/usr/bin/env python3
"""
soc_core.py
-----------
Shared library for the SOC monitoring project.

Every detection script (port scanner, login/intrusion monitor, phishing
detector, malware detector) imports this module and calls `emit_alert(...)`.
That keeps ALL alerts in one common JSON schema so the dashboard, the
database, or a real SIEM (Wazuh / Elastic) can ingest them the same way.

Storage model (prototype):
    data/alerts.jsonl   -> append-only log, one JSON object per line (audit trail)
    data/alerts.json    -> rolling snapshot of the most recent N alerts (dashboard feed)

In production you would replace the two file writers below with a call to
your database / message queue / SIEM forwarder. The rest of the scripts do
not need to change.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import socket
import ssl
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# --------------------------------------------------------------------------- #
#  Configuration
# --------------------------------------------------------------------------- #

# Project data directory (data/ sits next to scripts/)
DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

ALERTS_LOG = DATA_DIR / "alerts.jsonl"     # append-only history
ALERTS_SNAPSHOT = DATA_DIR / "alerts.json"  # rolling feed for the dashboard
ALERTS_LOCK = DATA_DIR / ".alerts_snapshot.lock"  # serializes concurrent snapshot updates
FAILED_OUTBOX = DATA_DIR / "ingest_outbox.jsonl"  # alerts that failed to reach the backend
MAX_SNAPSHOT = int(os.environ.get("SOC_MAX_SNAPSHOT", "500"))

# --------------------------------------------------------------------------- #
#  Backend forwarder (send alerts to the Sentinel SOC backend / SIEM)
# --------------------------------------------------------------------------- #
#  Turn this ON by setting SOC_INGEST_URL (and usually SOC_INGEST_TOKEN). When
#  it is empty, the scripts just write the local files as before — nothing
#  changes. Sixto & Tomas give you the endpoint URL and token; you set them as
#  environment variables (e.g. in the systemd service or /etc/environment):
#
#      export SOC_INGEST_URL="https://soc.era.ca/api/ingest/alerts"
#      export SOC_INGEST_TOKEN="the-token-they-give-you"
#
#  Every alert is POSTed as JSON (the common schema, incl. its unique "id" so
#  the backend can dedupe). If the POST fails, the alert is queued in
#  ingest_outbox.jsonl and can be replayed later — no alert is ever lost.
INGEST_URL = os.environ.get("SOC_INGEST_URL", "").strip()
INGEST_TOKEN = os.environ.get("SOC_INGEST_TOKEN", "").strip()
INGEST_AUTH_HEADER = os.environ.get("SOC_INGEST_AUTH_HEADER", "Authorization")
INGEST_AUTH_PREFIX = os.environ.get("SOC_INGEST_AUTH_PREFIX", "Bearer ")
INGEST_TIMEOUT = float(os.environ.get("SOC_INGEST_TIMEOUT", "5"))
INGEST_RETRIES = int(os.environ.get("SOC_INGEST_RETRIES", "2"))
# Set SOC_INGEST_VERIFY_TLS=0 only for an internal CA / self-signed cert.
INGEST_VERIFY_TLS = os.environ.get("SOC_INGEST_VERIFY_TLS", "1") != "0"

# --------------------------------------------------------------------------- #
#  Real-time critical notification (ntfy.sh) -- fires straight from Kali, so
#  it reaches a human even if nobody has the dashboard open and even if the
#  dashboard backend is unreachable (unlike everything above, which depends
#  on that connection). Turn on with:
#
#      export NTFY_TOPIC="your-private-topic-name"
#
#  Subscribe to the same topic in the ntfy app (Android/iOS) or at
#  https://ntfy.sh/<topic> to receive the push. Treat the topic name as a
#  secret -- anyone who knows it can read (or spoof) your alerts.
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
NTFY_URL = os.environ.get("NTFY_URL", "https://ntfy.sh").rstrip("/")

# Burst window for critical push notifications: the FIRST critical alert in
# a quiet period still pushes immediately, but any more that land within
# this many seconds get queued instead of each firing their own push --
# they go out as one grouped summary once the window closes. Without this,
# a real incident that trips several critical-severity detectors at once
# (Suricata + Zeek + osquery all firing within a few seconds of each other,
# say) means the operator's phone gets a rapid burst of individual pushes --
# the same alert-fatigue problem as the false-positive flood earlier in
# this project's life, except triggered by a REAL incident, which is worse:
# that's exactly when missing/dismissing a notification matters most.
NTFY_BATCH_WINDOW = float(os.environ.get("NTFY_BATCH_WINDOW", "10"))
NTFY_BATCH_FILE = DATA_DIR / "ntfy_batch.json"
NTFY_BATCH_LOCK = DATA_DIR / ".ntfy_batch.lock"

# --------------------------------------------------------------------------- #
#  Severity + alert type vocabulary (keep in sync with the dashboard)
# --------------------------------------------------------------------------- #

SEVERITIES = ("normal", "medium", "critical")

ALERT_TYPES = (
    "port_scan",   # open port / port sweep detected
    "intrusion",   # login / auth event inside the company domain
    "phishing",    # suspicious / malicious email
    "malware",     # malicious file / hash / IOC match
    "vuln",        # vulnerability found by the Kali network scan
)


@dataclass
class Alert:
    """One security event in the common schema."""
    type: str                       # one of ALERT_TYPES
    severity: str                   # one of SEVERITIES
    title: str                      # short human-readable headline
    source_ip: Optional[str] = None
    hostname: Optional[str] = None  # resolved host name if known
    user: Optional[str] = None      # username / account if known
    description: str = ""
    detector: str = ""              # which script raised this
    details: Dict[str, Any] = field(default_factory=dict)
    status: str = "open"            # open | acknowledged | resolved
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def validate(self) -> None:
        if self.type not in ALERT_TYPES:
            raise ValueError(f"Unknown alert type: {self.type!r} (expected one of {ALERT_TYPES})")
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unknown severity: {self.severity!r} (expected one of {SEVERITIES})")


# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def resolve_hostname(ip: Optional[str]) -> Optional[str]:
    """Best-effort reverse DNS. Returns None if it cannot be resolved."""
    if not ip:
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def tail_follow(path, poll_interval: float = 0.5, from_start: bool = False):
    """Generator: yields lines from `path` as they're written, tailing it
    forever -- and transparently surviving log rotation.

    Every --follow detector in this project (login_monitor.py's auth.log,
    suricata_to_alerts.py's eve.json, zeek_to_alerts.py's notice.log,
    osquery_to_alerts.py's results.log) used to open the file once and
    just keep calling readline() on that same handle. That silently breaks
    the moment logrotate rotates the file (rename old + create new, or
    truncate-in-place): the held file descriptor keeps pointing at the old,
    no-longer-growing inode, so the process looks alive and never crashes,
    it just stops seeing anything new -- forever, until someone manually
    restarts it. Confirmed as a live, active bug: login_monitor.py (which
    runs as root, watching SSH/auth activity) went completely blind for
    over 24 hours after /var/log/auth.log's weekly logrotate rotation,
    with zero alerts and zero errors the whole time. Suricata's eve.json
    is on the same weekly logrotate schedule and would have hit the exact
    same wall the first time it rotated.

    Detects rotation by checking, whenever a read comes back empty, whether
    the path's inode changed (rename+create) or its size shrank below our
    current read position (copytruncate) -- either way, close and reopen,
    picking up the new file from its beginning since none of it has been
    seen yet.
    """
    fh = None
    inode = None
    seek_to_end = not from_start
    while True:
        if fh is None:
            try:
                fh = open(path, "r", errors="ignore")
            except (FileNotFoundError, PermissionError):
                time.sleep(poll_interval)
                continue
            inode = os.fstat(fh.fileno()).st_ino
            if seek_to_end:
                fh.seek(0, 2)
            seek_to_end = False  # only skip existing content on the very first open
        line = fh.readline()
        if line:
            yield line
            continue
        try:
            st = os.stat(path)
        except OSError:
            fh.close()
            fh = None
            time.sleep(poll_interval)
            continue
        if st.st_ino != inode or st.st_size < fh.tell():
            fh.close()
            fh = None
            continue  # reopen immediately, no sleep -- there may be data waiting
        time.sleep(poll_interval)


# ---- "an authorized scan is running right now" marker ----------------------
# Written by mark_scan_start/mark_scan_end in kali/lib.sh. suricata_to_alerts.py
# and zeek_to_alerts.py both check this before forwarding an IDS alert, so
# this box's own nmap/whatweb/nikto traffic doesn't get flagged as an attack
# on itself -- previously duplicated in each script; centralized here after
# fixing the bug below in both places identically.
SCAN_MARKER_FILE = DATA_DIR / "scan_in_progress"
SCAN_LAST_ENDED_FILE = DATA_DIR / "scan_last_ended"
# Confirmed 2026-09-15: a 331-host vuln scan crashed (nmap's own NSE/nsock
# engine bug, unrelated to this project) mid-run. The crash killed the nmap
# process and its EXIT trap cleared the marker immediately, but nmap's
# already-sent HTTP NSE requests (http-default-accounts) were still in
# flight -- their responses kept landing on the wire for tens of seconds
# afterward, triggering a 41-second burst of 20 "ET SCAN Possible Nmap
# User-Agent" Suricata alerts against our own scan traffic, all timestamped
# AFTER the marker had already gone empty. A short grace window past
# marker-clear absorbs this trailing traffic without masking anything real
# (a genuine external scan starting in the exact seconds after ours ends is
# not a meaningfully more likely event than at any other moment).
SCAN_GRACE_SECONDS = 30


def scan_active() -> bool:
    try:
        if SCAN_MARKER_FILE.stat().st_size > 0:
            return True
    except OSError:
        pass
    try:
        ended = datetime.fromisoformat(SCAN_LAST_ENDED_FILE.read_text().strip())
        return (datetime.now(timezone.utc) - ended).total_seconds() < SCAN_GRACE_SECONDS
    except (OSError, ValueError):
        return False


def _load_snapshot() -> list:
    if ALERTS_SNAPSHOT.exists():
        try:
            return json.loads(ALERTS_SNAPSHOT.read_text())
        except (json.JSONDecodeError, OSError):
            return []
    return []


@contextmanager
def diff_state_lock(state_path):
    """File lock for scripts that keep their own diff-state JSON (e.g.
    kali/nmap_to_alerts.py's port_state.json, kali/arp_to_alerts.py's
    mac_state.json). Several people can run these scripts by hand while the
    scheduled job is also running; without a lock, two processes can both
    load the same "previous" state, each compute their own diff against it,
    and then the second one's save silently clobbers whatever the first one
    just wrote -- the same class of bug fixed in emit_alert() below, just
    for scripts that manage their own state file instead of the shared
    alerts snapshot. Wrap the whole load -> diff -> save cycle in this.
    """
    state_path = Path(state_path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = state_path.with_name(state_path.name + ".lock")
    # Whichever user hits this first creates the lock file, and file-creation
    # modes default to no-group-write regardless of umask tricks -- lock
    # everyone else out of the very lock meant to let them cooperate. Force
    # it permissive every time; if we don't own an already-existing lock
    # file (e.g. root created it first) we can't chmod it ourselves, so
    # best-effort and move on -- root or a later self-heal will fix it.
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o666)
    os.close(fd)
    try:
        os.chmod(lock_path, 0o664)
    except PermissionError:
        pass
    with lock_path.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


# --------------------------------------------------------------------------- #
#  Backend forwarding
# --------------------------------------------------------------------------- #

def _ssl_context():
    if INGEST_VERIFY_TLS:
        return None  # default verified context
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _post_once(record: Dict[str, Any]) -> tuple[bool, str]:
    """Single POST attempt. Returns (ok, message)."""
    data = json.dumps(record).encode("utf-8")
    req = urllib.request.Request(INGEST_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if INGEST_TOKEN:
        req.add_header(INGEST_AUTH_HEADER, f"{INGEST_AUTH_PREFIX}{INGEST_TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=INGEST_TIMEOUT, context=_ssl_context()) as resp:
            code = resp.getcode()
            if 200 <= code < 300:
                return True, f"HTTP {code}"
            return False, f"HTTP {code}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code} {e.reason}"
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        return False, f"connection error: {e}"


def _ntfy_push(title: str, message: str) -> None:
    """Raw ntfy.sh publish. Uses ntfy's JSON publish endpoint (everything in
    the body) rather than custom HTTP headers for the title/tags -- Python's
    http.client requires header VALUES to be latin-1 encodable, and alert
    titles routinely contain characters outside that range (an em dash, for
    one, appears in a real title this project already emits: "...
    -- unconfirmed service fingerprint"), which would raise
    UnicodeEncodeError and silently drop the notification. The JSON body has
    no such restriction. Never raises -- a notification failure must not
    break the pipeline that is trying to tell someone about a real critical
    finding."""
    try:
        payload = json.dumps({
            "topic": NTFY_TOPIC,
            "title": f"Sentinel SOC: {title}"[:250],
            "message": message[:2000],
            "priority": 5,
            "tags": ["rotating_light"],
        }).encode("utf-8")
        req = urllib.request.Request(NTFY_URL, data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass


def _alert_body(record: Dict[str, Any]) -> str:
    title = str(record.get("title") or "Critical alert")
    body = str(record.get("description") or title)
    extra = []
    if record.get("source_ip"):
        extra.append(f"source: {record['source_ip']}")
    if record.get("hostname"):
        extra.append(f"host: {record['hostname']}")
    if record.get("detector"):
        extra.append(f"detector: {record['detector']}")
    if extra:
        body = f"{body}\n\n" + " | ".join(extra)
    return body


def _load_ntfy_batch() -> Optional[Dict[str, Any]]:
    try:
        return json.loads(NTFY_BATCH_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def _save_ntfy_batch(state: Optional[Dict[str, Any]]) -> None:
    if state is None:
        NTFY_BATCH_FILE.unlink(missing_ok=True)
        return
    fd, tmp = tempfile.mkstemp(dir=str(NTFY_BATCH_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f)
        os.replace(tmp, NTFY_BATCH_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _flush_ntfy_batch_locked(state: Optional[Dict[str, Any]]) -> None:
    """Send the queued-up summary for a batch window that has closed.
    Caller must already hold the batch lock."""
    if not state or not state.get("pending"):
        return
    titles = state["pending"]
    n = len(titles)
    preview = "\n".join(f"- {t}" for t in titles[:10])
    if n > 10:
        preview += f"\n(+{n - 10} more)"
    _ntfy_push(
        f"{n} more critical alert(s)",
        f"{n} additional critical alert(s) landed within the last "
        f"{NTFY_BATCH_WINDOW:.0f}s (grouped to avoid a notification burst):\n\n{preview}",
    )


def flush_ntfy_batch() -> None:
    """Send any pending grouped-critical summary whose window has closed.
    Called both from notify_critical() itself (so a new critical alert
    naturally flushes a stale window before starting a fresh one) and by
    soc-ntfy-flush.timer (so a summary still goes out even if nothing else
    critical happens after a burst ends -- otherwise the last few alerts of
    a burst that don't get followed by anything would queue up and just sit
    there, silently, forever)."""
    if not NTFY_TOPIC:
        return
    with NTFY_BATCH_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            state = _load_ntfy_batch()
            if state and (time.time() - state.get("window_start", 0)) > NTFY_BATCH_WINDOW:
                _flush_ntfy_batch_locked(state)
                _save_ntfy_batch(None)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


def notify_critical(record: Dict[str, Any]) -> None:
    """Push a real-time notification for a critical alert via ntfy.sh -- the
    first critical alert in a quiet period pushes immediately; any more
    within NTFY_BATCH_WINDOW seconds are queued and sent as one grouped
    summary instead of each firing their own push (see NTFY_BATCH_WINDOW's
    comment above for why). Locked across processes: every detector runs as
    its own process, and a real incident can trip several of them (Suricata,
    Zeek, osquery, nmap) within the same few seconds, so the batch state has
    to be shared and race-free, not just in-memory in whichever process
    happens to be emitting.
    """
    if not NTFY_TOPIC:
        return
    title = str(record.get("title") or "Critical alert")[:250]
    with NTFY_BATCH_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            state = _load_ntfy_batch()
            now = time.time()
            if state and (now - state.get("window_start", 0)) > NTFY_BATCH_WINDOW:
                _flush_ntfy_batch_locked(state)
                state = None
            if state is None:
                _ntfy_push(title, _alert_body(record))
                _save_ntfy_batch({"window_start": now, "pending": []})
            else:
                state["pending"].append(title)
                _save_ntfy_batch(state)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


def forward_alert(record: Dict[str, Any]) -> Optional[bool]:
    """
    POST one alert to the backend if SOC_INGEST_URL is configured.
    Returns True on success, False on failure (queued to the outbox),
    or None if forwarding is disabled. Never raises — a detector must not
    crash because the backend is momentarily down.
    """
    if not INGEST_URL:
        return None  # forwarding disabled -> local files only
    last = ""
    for attempt in range(1, INGEST_RETRIES + 1):
        ok, msg = _post_once(record)
        if ok:
            return True
        last = msg
        if attempt < INGEST_RETRIES:
            time.sleep(0.5 * attempt)
    # all attempts failed -> queue for later replay, don't lose the alert
    try:
        with FAILED_OUTBOX.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass
    print(f"[!] ingest failed ({last}); alert queued in {FAILED_OUTBOX.name}")
    return False


def replay_outbox() -> Dict[str, int]:
    """Try to resend every alert queued in the outbox. Keeps the ones that
    still fail. Run this from cron so a backend outage self-heals."""
    if not INGEST_URL:
        print("[!] SOC_INGEST_URL not set — nothing to replay to.")
        return {"sent": 0, "kept": 0}
    if not FAILED_OUTBOX.exists():
        return {"sent": 0, "kept": 0}
    lines = [l for l in FAILED_OUTBOX.read_text().splitlines() if l.strip()]
    still_failed, sent = [], 0
    for line in lines:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        ok, _ = _post_once(record)
        if ok:
            sent += 1
        else:
            still_failed.append(line)
    if still_failed:
        FAILED_OUTBOX.write_text("\n".join(still_failed) + "\n")
    else:
        FAILED_OUTBOX.unlink(missing_ok=True)
    print(f"[*] replay: sent {sent}, still queued {len(still_failed)}")
    return {"sent": sent, "kept": len(still_failed)}


def confirm_demo_on_live_instance() -> None:
    """Guard for any script's --demo/self-test mode: demo alerts go through
    the exact same emit_alert() as real ones (same schema, same files), so
    they are indistinguishable from a real detection once written -- see
    2026-09-17's incident, where a synthetic "root login from a Tor exit
    node" produced by a --demo run sat in the live dashboard feed looking
    exactly like an active compromise. Call this at the top of any --demo
    path, before emitting a single alert.

    NTFY_TOPIC and INGEST_URL are the two ways an alert leaves this local
    snapshot and reaches an actual human or another system: a real phone
    push, or a forward into the real backend/dashboard. Neither being
    configured means synthetic data is still harmless. Either one being
    configured means this looks like a live, wired instance -- ask first.
    """
    live_bits = []
    if NTFY_TOPIC:
        live_bits.append("NTFY_TOPIC is set -- fake critical alerts will push real phone notifications")
    if INGEST_URL:
        live_bits.append("SOC_INGEST_URL is set -- fake alerts will forward to the real backend/dashboard")
    if not live_bits:
        return
    print("[!] This looks like a LIVE, wired instance, not a throwaway demo one:")
    for b in live_bits:
        print(f"      - {b}")
    print("[!] Demo/synthetic alerts are about to be mixed into real production data.")
    ans = input("Type 'yes' to confirm you really want this: ")
    if ans != "yes":
        print("[x] Not confirmed. Aborting.")
        raise SystemExit(2)


def emit_alert(alert: Alert, echo: bool = True) -> Dict[str, Any]:
    """
    Persist an alert to the append-only log and the rolling snapshot.
    Returns the alert as a dict. This is the single entry point every
    detection script uses.
    """
    alert.validate()
    record = asdict(alert)

    # 0) enrich with IP geolocation for PUBLIC source IPs
    #    (no-op unless the GeoLite2 DB + geoip2 library are installed)
    try:
        from geoip_enrich import geolocate
        geo = geolocate(record.get("source_ip"))
        if geo:
            record.setdefault("details", {})["geo"] = geo
    except Exception:
        pass

    # 0b) flag Tor / VPN / proxy / datacenter (offline, cheap; no-op without data)
    try:
        from proxy_check import check as _anon_check
        anon = _anon_check(record.get("source_ip"))
        if anon:
            record.setdefault("details", {})["anonymizer"] = anon
    except Exception:
        pass

    # 0c) optional Shodan OSINT enrichment — OFF by default (rate-limited).
    #     Turn on with: export SOC_SHODAN_ENRICH=1  (needs SHODAN_API_KEY)
    if os.environ.get("SOC_SHODAN_ENRICH") == "1":
        try:
            from shodan_enrich import lookup as _shodan_lookup
            sho = _shodan_lookup(record.get("source_ip"))
            if sho:
                record.setdefault("details", {})["shodan"] = sho
        except Exception:
            pass

    # 1) append-only audit log
    with ALERTS_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

    # 2) rolling snapshot (newest first, capped). Locked + atomic: several
    #    detectors (soc-login runs continuously, a scan import can emit
    #    hundreds of alerts in seconds) can call emit_alert() concurrently,
    #    and an unlocked read-modify-write here would let one process's
    #    write silently clobber another's -- the alert would still be safe
    #    in the append-only log, but vanish from what the dashboard reads.
    with ALERTS_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            snapshot = _load_snapshot()
            snapshot.insert(0, record)
            snapshot = snapshot[:MAX_SNAPSHOT]
            fd, tmp = tempfile.mkstemp(dir=str(ALERTS_SNAPSHOT.parent), suffix=".tmp")
            # mkstemp() defaults to mode 0600 (owner-only). Different
            # detectors run as different users (soc-login as root,
            # soc-api/manual runs as the operator), and os.replace() swaps
            # in this file's permissions wholesale -- left at 0600, whichever
            # user's process happens to write next locks every other user
            # out of reading the snapshot the API and dashboard depend on.
            os.chmod(tmp, 0o664)
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(snapshot, f, indent=2)
                os.replace(tmp, ALERTS_SNAPSHOT)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)

    # 3) forward to the backend (no-op unless SOC_INGEST_URL is set)
    forward_alert(record)

    # 4) real-time push for critical findings (no-op unless NTFY_TOPIC is
    #    set) -- independent of the backend connection above, so it still
    #    reaches someone even when that link is down.
    if record.get("severity") == "critical":
        notify_critical(record)

    if echo:
        sev = record["severity"].upper()
        print(f"[{record['timestamp']}] {sev:<8} {record['type']:<9} "
              f"{record.get('source_ip') or '-':<15} {record['title']}")
    return record


VALID_STATUSES = ("open", "acknowledged", "resolved")
ALERT_STATUS_LOG = DATA_DIR / "alert_status_log.jsonl"


def set_alert_status(alert_id: str, status: str, note: str = "", actor: str = "") -> Dict[str, Any]:
    """Update one alert's triage status (open / acknowledged / resolved).

    The Alert dataclass has always had a `status` field, but until now
    nothing ever set it to anything but the default "open" -- there was no
    way to record "someone looked at this" or "this is handled" anywhere,
    so every alert looked equally urgent forever, no matter how old.

    This updates the alert in place in the live snapshot (alerts.json is
    already documented as "the rolling feed for the dashboard", i.e.
    mutable current state -- unlike alerts.jsonl, which stays exactly what
    it always was: an immutable record of what each detector actually
    found, at the moment it found it). The status change itself is
    recorded as its own line in alert_status_log.jsonl, an append-only
    trail of who changed what and when, kept separate from alerts.jsonl so
    that file never needs a schema for anything other than "a detector
    found something".

    Note the live snapshot only holds the most recent MAX_SNAPSHOT alerts
    (default 500) -- an alert that has rolled off the snapshot can't have
    its status changed here; its original record is still in alerts.jsonl,
    just no longer part of the mutable "current" view this manages.

    Raises ValueError if status is invalid or the alert isn't found in the
    current snapshot.
    """
    if status not in VALID_STATUSES:
        raise ValueError(f"invalid status {status!r} (expected one of {VALID_STATUSES})")

    with ALERTS_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            snapshot = _load_snapshot()
            target = None
            for a in snapshot:
                if a.get("id") == alert_id:
                    target = a
                    break
            if target is None:
                raise ValueError(f"alert not found in current snapshot: {alert_id}")

            old_status = target.get("status", "open")
            now = datetime.now(timezone.utc).isoformat()
            target["status"] = status
            target["status_updated"] = now
            if note:
                target["status_note"] = note

            fd, tmp = tempfile.mkstemp(dir=str(ALERTS_SNAPSHOT.parent), suffix=".tmp")
            os.chmod(tmp, 0o664)
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(snapshot, f, indent=2)
                os.replace(tmp, ALERTS_SNAPSHOT)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)

    with ALERT_STATUS_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "alert_id": alert_id, "old_status": old_status, "new_status": status,
            "note": note, "actor": actor, "timestamp": now,
        }) + "\n")

    return target


# --------------------------------------------------------------------------- #
#  API key registry (used by soc_api.py for per-user authentication)
# --------------------------------------------------------------------------- #

API_KEYS_FILE = Path(os.environ.get("SOC_API_KEYS_FILE", str(DATA_DIR / "api_keys.json")))
VALID_API_ROLES = ("read", "write")  # "write" implies read; not an additive grant


def load_api_keys() -> list:
    """Load the API key registry, seeding it on first run.

    Each entry is {"token": str, "user": str, "role": "read"|"write"}. This
    replaces the single shared SOC_API_TOKEN every caller used to present as
    themselves -- with one token per person, a compromised or ex-collaborator
    key can be revoked individually, and the "actor" recorded against an
    alert status change (see set_alert_status) is a real, authenticated
    identity instead of a free-text string the client could put anything in.

    On first run (file missing), this migrates SOC_API_TOKEN if it was set,
    so the shared token already in use (e.g. by Tomás's poller on
    10.69.0.80) keeps working with no coordinated rotation -- it just shows
    up as user "legacy" until someone issues it a real name via
    manage_api_keys.py. If SOC_API_TOKEN was never set either, one fresh key
    is generated for user "default", mirroring the old behavior of always
    guaranteeing *some* token existed.
    """
    if API_KEYS_FILE.exists():
        keys = json.loads(API_KEYS_FILE.read_text()).get("keys", [])
        for k in keys:
            if k.get("role") not in VALID_API_ROLES:
                raise ValueError(f"invalid role in {API_KEYS_FILE}: {k!r}")
        return keys

    legacy = os.environ.get("SOC_API_TOKEN", "").strip()
    if legacy:
        keys = [{"token": legacy, "user": "legacy", "role": "write"}]
        print(f"[*] Migrated existing SOC_API_TOKEN into {API_KEYS_FILE} as user 'legacy'.")
        print("[*] Issue named keys going forward: python3 manage_api_keys.py add <user> <read|write>")
    else:
        token = secrets.token_urlsafe(24)
        keys = [{"token": token, "user": "default", "role": "write"}]
        print("=" * 66)
        print(" No API keys configured -- generated one for user 'default':")
        print(f"   {token}")
        print("=" * 66)
    save_api_keys(keys)
    return keys


def save_api_keys(keys: list) -> None:
    API_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(API_KEYS_FILE.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"keys": keys}, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, API_KEYS_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# --------------------------------------------------------------------------- #
#  Asset inventory (devices with a stable, vendor-assigned MAC)
# --------------------------------------------------------------------------- #
#  Deliberately does NOT try to track devices with a locally-administered
#  (randomized) MAC -- see arp_to_alerts.py's _is_locally_administered. A
#  modern phone/laptop generates a brand new, unlinkable random MAC on every
#  Wi-Fi reconnect specifically so it can't be tracked; correlating those
#  sightings back into "the same device" would mean defeating that privacy
#  feature on purpose (e.g. by hostname/DHCP fingerprinting), which is out
#  of scope here. Those sightings stay exactly what they already were --
#  lowered-severity "new device" alerts -- and never get an entry below.

ASSETS_FILE = DATA_DIR / "assets.json"
ASSET_ANNOTATION_LOG = DATA_DIR / "asset_annotation_log.jsonl"


def load_assets() -> Dict[str, Dict[str, Any]]:
    """Load the persistent asset inventory, keyed by MAC address."""
    try:
        return json.loads(ASSETS_FILE.read_text()).get("assets", {})
    except (OSError, json.JSONDecodeError):
        return {}


def _save_assets(assets: Dict[str, Dict[str, Any]]) -> None:
    ASSETS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(ASSETS_FILE.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump({"generated": datetime.now(timezone.utc).isoformat(),
                       "assets": assets}, f, indent=2, sort_keys=True)
        os.replace(tmp, ASSETS_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def record_asset_sightings(sightings: list) -> int:
    """Batch-record sightings of vendor-MAC devices: create an entry the
    first time a MAC is seen, refresh ip/last_seen/seen_count every time
    after. One lock/load/save cycle for the whole batch (not one per MAC --
    a single arp_to_alerts.py run can see hundreds of devices at once),
    mirroring the pattern diff_state_lock() already uses for mac_state.json.

    Each sighting is {"mac", "ip", "vendor", "cidr", "iface"}. Caller is
    responsible for never passing a locally-administered MAC (see module
    docstring above).

    Manual annotations (owner/notes/authorized) are never touched here --
    only set_asset_annotation() below writes them, so a scheduled scan can
    never silently overwrite what a human typed in. Returns how many assets
    were newly created (vs. just refreshed).
    """
    now = datetime.now(timezone.utc).isoformat()
    created = 0
    with diff_state_lock(ASSETS_FILE):
        assets = load_assets()
        for s in sightings:
            mac = s["mac"]
            rec = assets.get(mac)
            if rec is None:
                rec = {"mac": mac, "vendor": s.get("vendor", ""),
                       "cidr": s["cidr"], "iface": s.get("iface", ""),
                       "ip": s.get("ip", ""), "first_seen": now, "last_seen": now,
                       "seen_count": 1, "owner": None, "notes": None, "authorized": None}
                created += 1
            else:
                rec["ip"] = s.get("ip") or rec.get("ip", "")
                rec["vendor"] = s.get("vendor") or rec.get("vendor", "")
                rec["cidr"] = s.get("cidr", rec.get("cidr", ""))
                rec["iface"] = s.get("iface") or rec.get("iface", "")
                rec["last_seen"] = now
                rec["seen_count"] = rec.get("seen_count", 0) + 1
            assets[mac] = rec
        _save_assets(assets)
    return created


def set_asset_annotation(mac: str, *, owner: Optional[str] = None,
                          notes: Optional[str] = None,
                          authorized: Optional[bool] = None,
                          actor: str = "") -> Dict[str, Any]:
    """Let a human label a known asset (owner, free-text notes, authorized
    yes/no) -- kept separate from record_asset_sightings() so a scan re-run
    can never clobber what a person typed in. Only fields explicitly passed
    (not None) are changed. Raises ValueError if the MAC has no asset record
    yet (it must have been seen by a scan first)."""
    now = datetime.now(timezone.utc).isoformat()
    with diff_state_lock(ASSETS_FILE):
        assets = load_assets()
        rec = assets.get(mac)
        if rec is None:
            raise ValueError(f"asset not found: {mac}")
        changed: Dict[str, Any] = {}
        if owner is not None:
            rec["owner"] = owner; changed["owner"] = owner
        if notes is not None:
            rec["notes"] = notes; changed["notes"] = notes
        if authorized is not None:
            rec["authorized"] = authorized; changed["authorized"] = authorized
        assets[mac] = rec
        _save_assets(assets)

    with ASSET_ANNOTATION_LOG.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"mac": mac, "changed": changed, "actor": actor,
                              "timestamp": now}) + "\n")
    return rec


def group_by_host(alerts: list) -> list:
    """Aggregate a list of alert records by source_ip -- one summary entry
    per host instead of one row per finding, so a host with 5 issues can be
    shown as a single card (1 critical, 2 medium, ...) instead of scrolling
    through 5 separate feed rows to notice they're all the same machine.

    Grouping is by IP, not a more durable identity like MAC. On a DHCP
    network the same physical device can hold different IPs over time (see
    the DHCP/LLMNR findings from earlier today), so this reflects "what's
    true on the network right now" per address, not a perfect long-term
    per-device history -- a real asset-identity system is a separate,
    bigger piece of work.

    Alerts with no source_ip (host-less events, like the port-baseline
    summary alert) are grouped under the empty-string key and sort last.
    Hosts are ordered worst-first: most critical findings, then most
    medium, then most total -- the same priority order a person triaging
    the feed would want to look at first.
    """
    hosts: Dict[str, Dict[str, Any]] = {}
    for a in alerts:
        ip = a.get("source_ip") or ""
        h = hosts.setdefault(ip, {
            "source_ip": ip, "hostname": None,
            "counts": {s: 0 for s in SEVERITIES},
            "status_counts": {s: 0 for s in VALID_STATUSES},
            "total": 0, "last_seen": None, "alert_ids": [],
        })
        if a.get("hostname") and not h["hostname"]:
            h["hostname"] = a["hostname"]
        sev = a.get("severity", "normal")
        h["counts"][sev] = h["counts"].get(sev, 0) + 1
        st = a.get("status", "open")
        h["status_counts"][st] = h["status_counts"].get(st, 0) + 1
        h["total"] += 1
        h["alert_ids"].append(a.get("id"))
        ts = a.get("timestamp")
        if ts and (h["last_seen"] is None or ts > h["last_seen"]):
            h["last_seen"] = ts

    return sorted(
        hosts.values(),
        key=lambda h: (-h["counts"].get("critical", 0), -h["counts"].get("medium", 0), -h["total"]),
    )


def summarize() -> Dict[str, Any]:
    """Quick counts for a status line / health check."""
    snap = _load_snapshot()
    counts = {s: 0 for s in SEVERITIES}
    by_type = {t: 0 for t in ALERT_TYPES}
    by_status = {s: 0 for s in VALID_STATUSES}
    for a in snap:
        counts[a.get("severity", "normal")] = counts.get(a.get("severity", "normal"), 0) + 1
        by_type[a.get("type", "")] = by_type.get(a.get("type", ""), 0) + 1
        st = a.get("status", "open")
        by_status[st] = by_status.get(st, 0) + 1
    return {"total": len(snap), "by_severity": counts, "by_type": by_type, "by_status": by_status}


def _cli() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="soc_core — alert bus + backend forwarder")
    ap.add_argument("--test-ingest", action="store_true",
                    help="Send ONE test alert to the configured backend and report the result")
    ap.add_argument("--replay", action="store_true",
                    help="Resend any alerts queued in the outbox (run from cron)")
    ap.add_argument("--status", action="store_true", help="Show config + counts")
    args = ap.parse_args()

    if args.status or not (args.test_ingest or args.replay):
        print("Backend forwarding:", "ENABLED" if INGEST_URL else "disabled (SOC_INGEST_URL not set)")
        if INGEST_URL:
            print(f"  URL          : {INGEST_URL}")
            print(f"  Auth header  : {INGEST_AUTH_HEADER}: {INGEST_AUTH_PREFIX}<token {'set' if INGEST_TOKEN else 'MISSING'}>")
            print(f"  Verify TLS   : {INGEST_VERIFY_TLS}   timeout {INGEST_TIMEOUT}s   retries {INGEST_RETRIES}")
            if FAILED_OUTBOX.exists():
                n = sum(1 for _ in FAILED_OUTBOX.open())
                print(f"  Outbox       : {n} alert(s) waiting to resend")
        print(json.dumps(summarize(), indent=2))

    if args.test_ingest:
        if not INGEST_URL:
            print("[!] SOC_INGEST_URL is not set. Export it (and SOC_INGEST_TOKEN) first, e.g.:")
            print('    export SOC_INGEST_URL="https://soc.era.ca/api/ingest/alerts"')
            print('    export SOC_INGEST_TOKEN="the-token"')
            return 1
        rec = asdict(Alert(type="port_scan", severity="normal",
                           title="Sentinel SOC connectivity test",
                           source_ip="127.0.0.1", detector="soc_core",
                           description="If you see this alert in the dashboard, Kali -> backend works."))
        ok, msg = _post_once(rec)
        print(f"[{'OK' if ok else 'FAIL'}] POST to {INGEST_URL} -> {msg}")
        return 0 if ok else 2

    if args.replay:
        replay_outbox()
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli())
