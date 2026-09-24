#!/usr/bin/env python3
"""
cert_expiry.py
--------------
Alerts before a certificate this appliance depends on expires, rather than after the platform
backend has already stopped receiving alerts.

Checked daily (soc-cert-expiry.timer):
  * the Kali API's certificate (/etc/sentinel-soc/tls/api.pem, issued by deploy/make_api_cert.sh,
    825 days). When it expires, the backend's HTTPS poll fails and the dashboard silently stops
    getting Kali alerts;
  * the private CA that signs it (ca.pem, 10 years): the backend trusts that file;
  * the certificate the running HTTPS API actually serves on 8443, which differs from api.pem when
    the certificate was renewed but soc-api-tls was not restarted.

Levels (one alert per level change, like disk_space_check.py; data/cert_expiry_state.json):
    <= 30 days left  -> medium    ("renew: sudo bash deploy/make_api_cert.sh --renew")
    <= 7 days left   -> critical
    expired          -> critical
and a normal alert when a certificate goes back above 30 days (renewed).
"""
from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from soc_core import DATA_DIR, Alert, emit_alert  # noqa: E402

STATE_FILE = DATA_DIR / "cert_expiry_state.json"
TLS_DIR = Path(os.environ.get("SOC_TLS_DIR", "/etc/sentinel-soc/tls"))
LIVE_ENDPOINT = os.environ.get("SOC_CERT_LIVE", "127.0.0.1:8443")   # empty = do not check the served one
WARN_DAYS, CRIT_DAYS = 30, 7

# (key, label) of the files to watch, relative to TLS_DIR
FILES = (("api", "Kali API certificate (api.pem)"), ("ca", "Kali API CA (ca.pem)"))


def _enddate(args: list, data: Optional[bytes] = None) -> Optional[datetime]:
    """notAfter via the openssl CLI (always present on the Kali; no Python dependency)."""
    try:
        r = subprocess.run(["openssl", "x509", "-noout", "-enddate", *args], input=data,
                           capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = r.stdout.decode(errors="replace").strip()
    if r.returncode != 0 or not out.startswith("notAfter="):
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(out[len("notAfter="):]), tz=timezone.utc)
    except ValueError:
        return None


def not_after_file(path: Path) -> Optional[datetime]:
    """Expiry of a PEM certificate file, None when it is missing or unreadable."""
    return _enddate(["-in", str(path)]) if path.is_file() else None


def not_after_live(endpoint: str, cafile: Path) -> Optional[datetime]:
    """Expiry of the certificate a TLS server presents, verified against cafile when it exists."""
    host, _, port = endpoint.rpartition(":")
    ctx = ssl.create_default_context(cafile=str(cafile)) if cafile.exists() else ssl._create_unverified_context()
    ctx.check_hostname = False     # the check is about dates; the name is the backend's concern
    try:
        with socket.create_connection((host, int(port)), timeout=5) as raw, ctx.wrap_socket(raw) as tls:
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return None
    return _enddate(["-inform", "DER"], der)


def level(days_left: float) -> Optional[str]:
    if days_left <= CRIT_DAYS:
        return "critical"
    if days_left <= WARN_DAYS:
        return "medium"
    return None


def evaluate(expiries: Dict[str, Tuple[str, Optional[datetime]]], state: Dict[str, Optional[str]],
             now: datetime) -> Tuple[List[Dict], Dict[str, Optional[str]]]:
    """(alert kwargs, new state). expiries: {key: (label, not_after or None)}. A certificate that could
    not be read keeps its previous state (no alert: the file may simply not exist on this box)."""
    alerts, new_state = [], dict(state)
    for key, (label, na) in expiries.items():
        if na is None:
            continue
        days = (na - now).total_seconds() / 86400
        lvl = level(days)
        if lvl == state.get(key):
            continue
        new_state[key] = lvl
        renew = ("Renew it: sudo bash /opt/sentinel-soc/deploy/make_api_cert.sh --renew, then "
                 "sudo systemctl restart soc-api-tls. The backend keeps trusting the same CA, so nothing changes there.")
        if key == "ca":
            renew = ("Renewing the CA means the platform backend must be given the new ca.pem "
                     "(KALI_API_CA_CERT): plan it with whoever runs the backend.")
        if key == "live":
            renew = ("api.pem on disk may already be renewed: restart the HTTPS API so it serves it "
                     "(sudo systemctl restart soc-api-tls). Otherwise renew it first (make_api_cert.sh --renew).")
        if lvl is None:
            alerts.append(dict(type="vuln", severity="normal", detector="cert_expiry",
                               title=f"Certificate renewed: {label} valid until {na.date()}",
                               description=f"{label} now expires on {na.date()} ({int(days)} days).",
                               details={"certificate": key, "not_after": na.isoformat(), "days_left": int(days)}))
            continue
        when = "has EXPIRED" if days < 0 else f"expires in {int(days)} day(s)"
        alerts.append(dict(type="vuln", severity=lvl, detector="cert_expiry",
                           title=f"{label} {when} ({na.date()})",
                           description=(f"{label} {when}, on {na.isoformat()}. When the API certificate expires the "
                                        f"platform backend can no longer poll the Kali over HTTPS and the dashboard "
                                        f"stops receiving alerts. {renew}"),
                           details={"certificate": key, "not_after": na.isoformat(), "days_left": int(days)}))
    return alerts, new_state


def run() -> int:
    expiries: Dict[str, Tuple[str, Optional[datetime]]] = {
        key: (label, not_after_file(TLS_DIR / f"{key}.pem")) for key, label in FILES}
    if LIVE_ENDPOINT:
        expiries["live"] = (f"certificate served by the HTTPS API ({LIVE_ENDPOINT})",
                            not_after_live(LIVE_ENDPOINT, TLS_DIR / "ca.pem"))
    try:
        state = json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        state = {}
    alerts, new_state = evaluate(expiries, state, datetime.now(timezone.utc))
    for kw in alerts:
        emit_alert(Alert(**kw))
    if new_state != state:
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(new_state))
        os.chmod(tmp, 0o664)
        os.replace(tmp, STATE_FILE)
    for key, (label, na) in expiries.items():
        print(f"[*] {label}: {'not found' if na is None else na.date()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
