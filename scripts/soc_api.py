#!/usr/bin/env python3
"""Sentinel SOC — REST API exposing scan results/alerts as JSON.

Mostly read-only: every GET endpoint just reads the current snapshot.
The one write endpoint (POST /api/alerts/<id>/status) is deliberately
narrow -- it can only change an alert's triage status (open /
acknowledged / resolved), nothing else about the alert. This is this
project's own local API, unrelated to the separate backend Sentinel SOC
optionally forwards alerts to (SOC_INGEST_URL in soc_core.py).
"""
from __future__ import annotations
import json, os, secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
import soc_core
 
HOST = os.environ.get("SOC_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("SOC_API_PORT", "8080"))
TOKEN = os.environ.get("SOC_API_TOKEN", "").strip()
CORS = os.environ.get("SOC_API_CORS", "").strip()
 
if not TOKEN:
    TOKEN = secrets.token_urlsafe(24)
    print("=" * 66)
    print(" SOC_API_TOKEN was not set — generated a temporary one for this run:")
    print(f"   {TOKEN}")
    print(f'   export SOC_API_TOKEN="{TOKEN}"   # set it permanently')
    print("=" * 66)
 
def _to_epoch(v):
    if v is None: return None
    s = str(v).strip()
    if s.isdigit():
        n = int(s); return n if n > 10_000_000_000 else n * 1000
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None: dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)
    except ValueError:
        return None
 
def _alert_epoch(a): return _to_epoch(a.get("timestamp")) or 0

def _filter_alerts(alerts, qs):
    """Shared query-param filtering for /api/alerts and /api/hosts, so the
    two endpoints always agree on what "matching the current filters" means."""
    sev = (qs.get("severity") or [None])[0]
    typ = (qs.get("type") or [None])[0]
    det = (qs.get("detector") or [None])[0]
    status = (qs.get("status") or [None])[0]
    since = _to_epoch((qs.get("since") or [None])[0])
    out = []
    for a in alerts:
        if sev and a.get("severity") != sev: continue
        if typ and a.get("type") != typ: continue
        if det and a.get("detector") != det: continue
        # alerts emitted before the status field existed have no
        # "status" key at all -- treat that the same as "open"
        if status and a.get("status", "open") != status: continue
        if since and _alert_epoch(a) < since: continue
        out.append(a)
    return out

class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelSOC-API/1.0"
    def _send(self, code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if CORS:
            self.send_header("Access-Control-Allow-Origin", CORS)
            self.send_header("Access-Control-Allow-Headers", "Authorization")
        self.end_headers(); self.wfile.write(body)
    def _authed(self):
        return secrets.compare_digest(self.headers.get("Authorization", ""), f"Bearer {TOKEN}")
    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")
    def do_OPTIONS(self):
        self.send_response(204)
        if CORS:
            self.send_header("Access-Control-Allow-Origin", CORS)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()
    def do_GET(self):
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)
        if path == "/api/health":
            snap = soc_core._load_snapshot()
            return self._send(200, {"status": "ok", "alerts": len(snap),
                                    "time": datetime.now(timezone.utc).isoformat()})
        if not self._authed():
            return self._send(401, {"error": "unauthorized",
                                    "hint": "send header: Authorization: Bearer <token>"})
        if path == "/api/summary":
            return self._send(200, soc_core.summarize())
        if path == "/api/alerts":
            filtered = _filter_alerts(soc_core._load_snapshot(), qs)
            try:
                limit = min(max(int((qs.get("limit") or ["100"])[0]), 1), 1000)
            except ValueError:
                limit = 100
            out = filtered[:limit]
            return self._send(200, {"count": len(out), "alerts": out})
        if path == "/api/hosts":
            filtered = _filter_alerts(soc_core._load_snapshot(), qs)
            hosts = soc_core.group_by_host(filtered)
            return self._send(200, {"count": len(hosts), "hosts": hosts})
        if path.startswith("/api/alerts/"):
            aid = path.rsplit("/", 1)[-1]
            for a in soc_core._load_snapshot():
                if a.get("id") == aid: return self._send(200, a)
            return self._send(404, {"error": "alert not found", "id": aid})
        return self._send(404, {"error": "not found", "path": path})
    def do_POST(self):
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"
        if not self._authed():
            return self._send(401, {"error": "unauthorized",
                                    "hint": "send header: Authorization: Bearer <token>"})
        # only route: /api/alerts/<id>/status
        parts = path.split("/")
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "alerts" and parts[4] == "status":
            aid = parts[3]
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON body"})
            status = str(body.get("status", "")).strip()
            note = str(body.get("note", "")).strip()
            actor = str(body.get("actor", "")).strip()
            try:
                updated = soc_core.set_alert_status(aid, status, note=note, actor=actor)
            except ValueError as e:
                code = 404 if "not found" in str(e) else 400
                return self._send(code, {"error": str(e)})
            return self._send(200, updated)
        return self._send(404, {"error": "not found", "path": path})

def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[*] Sentinel SOC API listening on http://{HOST}:{PORT}")
    print(f"[*] Serving alerts from: {soc_core.ALERTS_SNAPSHOT}")
    print(f"[*] Auth: Authorization: Bearer <token>   (CORS: {CORS or 'off'})")
    print("[*] Endpoints: /api/health  /api/summary  /api/alerts  /api/alerts/<id>  /api/hosts")
    print("[*] Write:     POST /api/alerts/<id>/status  {\"status\": \"open|acknowledged|resolved\", \"note\": \"...\"}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopping."); srv.shutdown()
 
if __name__ == "__main__":
    main()
