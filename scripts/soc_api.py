#!/usr/bin/env python3
"""Sentinel SOC — REST API exposing scan results/alerts as JSON.

Mostly read-only: every GET endpoint just reads the current snapshot.
The write endpoints are deliberately narrow:
  - POST /api/alerts/<id>/status can only change an alert's triage status
    (open / acknowledged / resolved), nothing else about the alert.
  - POST /api/incidents/<id> can only change an incident's status,
    classification, owner and comments (see correlate.update_incident).
  - POST /api/assets/<mac>/notes can only set owner/notes/authorized on an
    already-seen asset (see soc_core.set_asset_annotation) -- it can't
    create an asset or touch anything a scan itself writes (ip, vendor,
    last_seen, ...).
This is this project's own local API, unrelated to the separate backend
Sentinel SOC optionally forwards alerts to (SOC_INGEST_URL in soc_core.py).

Auth is per-user API keys (see soc_core.load_api_keys / manage_api_keys.py),
not a single shared token: every key has a "role" of "read" (GET only) or
"write" (GET + the status endpoint), and every write is attributed to the
key's user, not a client-supplied field.
"""
from __future__ import annotations
import json, os, secrets
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote
import soc_core
import correlate
import soc_views
 
HOST = os.environ.get("SOC_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("SOC_API_PORT", "8080"))
CORS = os.environ.get("SOC_API_CORS", "").strip()
# Both POST bodies are tiny ({"status": "...", "note": "..."} / {"owner":
# ..., "notes": ..., "authorized": ...}) -- this is generous headroom, not
# a real limit on legitimate use. Without it, Content-Length is trusted
# blindly and rfile.read(length) buffers however much a caller claims to
# send, unbounded -- a write-role caller (or anyone who obtains a write
# key) could exhaust memory with one oversized request.
MAX_BODY_SIZE = 65536

API_KEYS = {k["token"]: k for k in soc_core.load_api_keys()}

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
    def _read_json_body(self):
        """Parse a small JSON request body. Returns (body, None) or (None, (code, error payload))."""
        try:
            length = int(self.headers.get("Content-Length", "0") or "0")
        except ValueError:
            return None, (400, {"error": "invalid Content-Length"})
        if length > MAX_BODY_SIZE:
            return None, (413, {"error": f"body too large (max {MAX_BODY_SIZE} bytes)"})
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return None, (400, {"error": "invalid JSON body"})
        if not isinstance(body, dict):
            return None, (400, {"error": "JSON body must be an object"})
        return body, None
    def _authenticate(self):
        """Return the matched API key entry ({token, user, role}), or None."""
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        supplied = auth[len("Bearer "):]
        for key in API_KEYS.values():
            if secrets.compare_digest(supplied, key["token"]):
                return key
        return None
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
        key = self._authenticate()
        if not key:
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
        if path == "/api/assets":
            assets = list(soc_core.load_assets().values())
            vlan = (qs.get("vlan") or [None])[0]
            if vlan:
                assets = [a for a in assets if a.get("cidr") == vlan]
            assets.sort(key=lambda a: a.get("last_seen") or "", reverse=True)
            return self._send(200, {"count": len(assets), "assets": assets})
        if path == "/api/incidents":
            incs = correlate.list_incidents((qs.get("status") or [None])[0], (qs.get("severity") or [None])[0])
            try:
                limit = min(max(int((qs.get("limit") or ["100"])[0]), 1), 500)
            except ValueError:
                limit = 100
            rows = [{**{k: v for k, v in i.items() if k != "comments"}, "comment_count": len(i["comments"])}
                    for i in incs[:limit]]
            return self._send(200, {"count": len(rows), "incidents": rows})
        if path.startswith("/api/incidents/"):
            inc = correlate.get_incident(unquote(path[len("/api/incidents/"):]))
            if inc is None:
                return self._send(404, {"error": "incident not found"})
            wanted = set(inc["alert_ids"])
            alerts = [a for a in soc_core._load_snapshot() if a.get("id") in wanted]
            alerts.sort(key=lambda a: a.get("timestamp", ""))
            return self._send(200, {**inc, "alerts": alerts, "alerts_not_in_feed": len(wanted) - len(alerts)})
        if path == "/api/entities":
            try:
                limit = min(max(int((qs.get("limit") or ["50"])[0]), 1), 200)
            except ValueError:
                limit = 50
            rows = soc_views.entities((qs.get("type") or [None])[0], limit)
            return self._send(200, {"count": len(rows), "entities": rows})
        if path.startswith("/api/entities/"):
            detail = soc_views.entity_detail(unquote(path[len("/api/entities/"):]))
            if detail is None:
                return self._send(404, {"error": "entity not found (use type:value, e.g. mac:aa:bb:cc:dd:ee:ff or ip:10.0.0.5)"})
            return self._send(200, detail)
        if path == "/api/metrics":
            return self._send(200, soc_views.metrics())
        if path == "/api/sources":
            return self._send(200, soc_views.sources())
        if path == "/api/detections":
            return self._send(200, soc_views.detections())
        if path.startswith("/api/alerts/"):
            aid = path.rsplit("/", 1)[-1]
            for a in soc_core._load_snapshot():
                if a.get("id") == aid: return self._send(200, a)
            return self._send(404, {"error": "alert not found", "id": aid})
        return self._send(404, {"error": "not found", "path": path})
    def do_POST(self):
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"
        key = self._authenticate()
        if not key:
            return self._send(401, {"error": "unauthorized",
                                    "hint": "send header: Authorization: Bearer <token>"})
        if key["role"] != "write":
            return self._send(403, {"error": "forbidden",
                                    "hint": f"key for {key['user']!r} is read-only"})
        parts = path.split("/")
        # /api/incidents/<id or number>: status, classification, owner, comment
        if len(parts) == 4 and parts[1] == "api" and parts[2] == "incidents":
            body, err = self._read_json_body()
            if err:
                return self._send(*err)
            try:
                updated = correlate.update_incident(
                    unquote(parts[3]), key["user"], status=body.get("status"),
                    classification=body.get("classification"), owner=body.get("owner"),
                    comment=body.get("comment"))
            except ValueError as e:
                return self._send(404 if "not found" in str(e) else 400, {"error": str(e)})
            print(f"[*] {key['user']} updated incident {parts[3]}")
            return self._send(200, updated)
        # /api/alerts/<id>/status
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "alerts" and parts[4] == "status":
            aid = parts[3]
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                return self._send(400, {"error": "invalid Content-Length"})
            if length > MAX_BODY_SIZE:
                return self._send(413, {"error": f"body too large (max {MAX_BODY_SIZE} bytes)"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON body"})
            status = str(body.get("status", "")).strip()
            note = str(body.get("note", "")).strip()
            # actor is the authenticated key's user, never client-supplied --
            # a body field would let any caller claim to be anyone.
            try:
                updated = soc_core.set_alert_status(aid, status, note=note, actor=key["user"])
            except ValueError as e:
                code = 404 if "not found" in str(e) else 400
                return self._send(code, {"error": str(e)})
            print(f"[*] {key['user']} set alert {aid} -> {status}")
            return self._send(200, updated)
        # /api/assets/<mac>/notes
        if len(parts) == 5 and parts[1] == "api" and parts[2] == "assets" and parts[4] == "notes":
            mac = parts[3]
            try:
                length = int(self.headers.get("Content-Length", "0") or "0")
            except ValueError:
                return self._send(400, {"error": "invalid Content-Length"})
            if length > MAX_BODY_SIZE:
                return self._send(413, {"error": f"body too large (max {MAX_BODY_SIZE} bytes)"})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except json.JSONDecodeError:
                return self._send(400, {"error": "invalid JSON body"})
            owner = body.get("owner")
            notes = body.get("notes")
            authorized = body.get("authorized")
            try:
                updated = soc_core.set_asset_annotation(
                    mac, owner=owner, notes=notes, authorized=authorized, actor=key["user"])
            except ValueError as e:
                return self._send(404, {"error": str(e)})
            print(f"[*] {key['user']} annotated asset {mac}")
            return self._send(200, updated)
        return self._send(404, {"error": "not found", "path": path})

def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"[*] Sentinel SOC API listening on http://{HOST}:{PORT}")
    print(f"[*] Serving alerts from: {soc_core.ALERTS_SNAPSHOT}")
    n_write = sum(1 for k in API_KEYS.values() if k["role"] == "write")
    print(f"[*] Auth: Authorization: Bearer <token>   "
          f"({len(API_KEYS)} key(s): {n_write} write, {len(API_KEYS) - n_write} read-only)   "
          f"(CORS: {CORS or 'off'})")
    print("[*] Endpoints: /api/health  /api/summary  /api/alerts  /api/alerts/<id>  /api/hosts  /api/assets")
    print("[*] Also:      /api/incidents  /api/incidents/<id|number>  /api/entities  /api/entities/<type:value>  /api/metrics  /api/sources  /api/detections")
    print("[*] Write:     POST /api/incidents/<id|number>  {\"status\": \"new|active|closed\", \"classification\": \"true_positive|false_positive|benign|undetermined\", \"owner\": \"...\", \"comment\": \"...\"}")
    print("[*] Write:     POST /api/alerts/<id>/status  {\"status\": \"open|acknowledged|resolved\", \"note\": \"...\"}")
    print("[*] Write:     POST /api/assets/<mac>/notes  {\"owner\": \"...\", \"notes\": \"...\", \"authorized\": true|false}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopping."); srv.shutdown()
 
if __name__ == "__main__":
    main()
