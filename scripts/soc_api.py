#!/usr/bin/env python3
"""Sentinel SOC — REST API exposing scan results/alerts as JSON.

Mostly read-only: every GET endpoint just reads the current snapshot.
The write endpoints are deliberately narrow:
  - POST /api/alerts/<id>/status can only change an alert's triage status
    (open / acknowledged / resolved), nothing else about the alert. GET /api/alerts?status_since=<iso>
    lists the alerts whose status changed since then, oldest change first, with status_actor/status_note.
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
import json, os, secrets, socket, ssl, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
import soc_core
import correlate
import soc_views
import suppression_admin
import log_search
import playbooks
import watchlists
import soc_activity
import soc_graph
import mitre_matrix
import weekly_report
import ad_views
 
HOST = os.environ.get("SOC_API_HOST", "0.0.0.0")
PORT = int(os.environ.get("SOC_API_PORT", "8080"))
CORS = os.environ.get("SOC_API_CORS", "").strip()
# HTTPS: set both to serve TLS on this instance (soc-api-tls.service does, on 8443). Unset = plain HTTP.
TLS_CERT = os.environ.get("SOC_API_TLS_CERT", "").strip()
TLS_KEY = os.environ.get("SOC_API_TLS_KEY", "").strip()
# Both POST bodies are tiny ({"status": "...", "note": "..."} / {"owner":
# ..., "notes": ..., "authorized": ...}) -- this is generous headroom, not
# a real limit on legitimate use. Without it, Content-Length is trusted
# blindly and rfile.read(length) buffers however much a caller claims to
# send, unbounded -- a write-role caller (or anyone who obtains a write
# key) could exhaust memory with one oversized request.
MAX_BODY_SIZE = 65536

API_KEYS = {k["token"]: k for k in soc_core.load_api_keys()}

# Only a packet capture actually resolving under this exact directory is ever served --
# GET /api/alerts/<id>/pcap takes an alert id, never a path, specifically so a caller can't
# ask this endpoint to read an arbitrary file off the appliance.
PCAP_DIR = (Path(__file__).resolve().parent.parent / "kali" / "results" / "flagged_captures").resolve()

# Searches read big log files; each runs in its own limited child process and at
# most this many run at once, so nobody can saturate the disk by hammering /api/search.
_SEARCH_SLOTS = threading.BoundedSemaphore(int(os.environ.get("SOC_SEARCH_SLOTS", "2")))

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
    # status_since: only alerts whose triage status changed at or after this instant (status_updated),
    # for a consumer that mirrors statuses (the platform backend's poller)
    status_since = _to_epoch((qs.get("status_since") or [None])[0])
    out = []
    for a in alerts:
        if sev and a.get("severity") != sev: continue
        if typ and a.get("type") != typ: continue
        if det and a.get("detector") != det: continue
        # alerts emitted before the status field existed have no
        # "status" key at all -- treat that the same as "open"
        if status and a.get("status", "open") != status: continue
        if since and _alert_epoch(a) < since: continue
        if status_since and (_to_epoch(a.get("status_updated")) or 0) < status_since: continue
        out.append(a)
    if status_since:
        # oldest change first, so a consumer paging with `limit` can advance its watermark to the last
        # status_updated it received without skipping changes
        out.sort(key=lambda a: _to_epoch(a.get("status_updated")) or 0)
    return out

class Handler(BaseHTTPRequestHandler):
    server_version = "SentinelSOC-API/1.0"
    timeout = 60   # per socket operation: a client that connects and goes silent frees its thread
    def _send(self, code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if CORS:
            self.send_header("Access-Control-Allow-Origin", CORS)
            self.send_header("Access-Control-Allow-Headers", "Authorization")
        self.end_headers(); self.wfile.write(body)
    def _send_file(self, path, download_name):
        size = path.stat().st_size
        self.send_response(200)
        self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
        self.send_header("Content-Length", str(size))
        self.send_header("Content-Disposition", f'attachment; filename="{download_name}"')
        if CORS:
            self.send_header("Access-Control-Allow-Origin", CORS)
            self.send_header("Access-Control-Allow-Headers", "Authorization")
        self.end_headers()
        with path.open("rb") as fh:
            while True:
                chunk = fh.read(1 << 20)
                if not chunk:
                    break
                self.wfile.write(chunk)
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
            self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
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
        if path == "/api/self":
            # this appliance's own addresses: an alert whose source_ip is one of these was raised
            # by the Kali itself (its scans, its feed refreshes), not by another machine
            return self._send(200, {"hostname": socket.gethostname(),
                                    "addresses": [{"ip": ip, "interface": ifc} for ip, ifc in sorted(soc_core.own_ips().items())]})
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
        if path.startswith("/api/incidents/") and path.endswith("/graph"):
            ref = unquote(path[len("/api/incidents/"):-len("/graph")])
            graph = soc_graph.incident_graph(ref)
            if graph is None:
                return self._send(404, {"error": "incident not found"})
            return self._send(200, graph)
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
        if path.startswith("/api/entities/") and path.endswith("/graph"):
            ref = unquote(path[len("/api/entities/"):-len("/graph")])
            graph = soc_graph.entity_graph(ref)
            if graph is None:
                return self._send(404, {"error": "entity not found (use type:value, e.g. mac:aa:bb:cc:dd:ee:ff or ip:10.0.0.5)"})
            return self._send(200, graph)
        if path.startswith("/api/entities/"):
            detail = soc_views.entity_detail(unquote(path[len("/api/entities/"):]))
            if detail is None:
                return self._send(404, {"error": "entity not found (use type:value, e.g. mac:aa:bb:cc:dd:ee:ff or ip:10.0.0.5)"})
            return self._send(200, detail)
        if path.startswith("/api/ad/"):
            # Active Directory, from the daily inventory (ad_inventory.py); see ad_views.py
            sub = path[len("/api/ad/"):]
            q1 = lambda k: (qs.get(k) or [None])[0]  # noqa: E731
            status = q1("status")
            if status and status not in ad_views.STATUSES:
                return self._send(400, {"error": f"unknown status {status!r}", "hint": f"one of {list(ad_views.STATUSES)}"})
            if sub == "summary":
                data = ad_views.summary()
            elif sub == "computers":
                rows = ad_views.computers(status=status, ou=q1("ou"), q=q1("q"), support=q1("support"))
                data = None if rows is None else {"count": len(rows), "computers": rows}
            elif sub == "users":
                rows = ad_views.users(status=status, ou=q1("ou"), q=q1("q"),
                                      privileged=q1("privileged") in ("1", "true", "yes"))
                data = None if rows is None else {"count": len(rows), "users": rows}
            elif sub == "history":
                try:
                    days = min(max(int(q1("days") or 90), 1), 730)
                except ValueError:
                    return self._send(400, {"error": "days must be an integer"})
                rows = ad_views.history(days)
                return self._send(200, {"count": len(rows), "days": rows})
            else:
                return self._send(404, {"error": "not found", "path": path})
            if data is None:
                return self._send(404, {"error": "no Active Directory inventory yet",
                                        "hint": "ad_inventory.py writes it daily (soc-ad-inventory.timer)"})
            return self._send(200, data)
        if path == "/api/metrics":
            return self._send(200, soc_views.metrics())
        if path == "/api/sources":
            return self._send(200, soc_views.sources())
        if path == "/api/detections":
            return self._send(200, soc_views.detections())
        if path == "/api/mitre":
            return self._send(200, mitre_matrix.matrix())
        if path == "/api/reports":
            return self._send(200, {"reports": weekly_report.list_reports()})
        if path == "/api/reports/weekly":
            date = (qs.get("date") or [None])[0]
            if date:
                report = weekly_report.load_saved(date)
                if report is None:
                    return self._send(404, {"error": f"no saved weekly report for {date!r}",
                                            "hint": "GET /api/reports lists the saved ones; omit date for a live report"})
            else:
                report = weekly_report.build()
            if (qs.get("format") or [None])[0] == "markdown":
                return self._send(200, {"period": report["period"], "markdown": weekly_report.to_markdown(report)})
            return self._send(200, report)
        if path == "/api/suppressions":
            return self._send(200, suppression_admin.list_detail())
        if path == "/api/watchlists":
            return self._send(200, {"watchlists": watchlists.list_watchlists()})
        if path.startswith("/api/watchlists/"):
            try:
                return self._send(200, watchlists.get(unquote(path[len("/api/watchlists/"):])))
            except ValueError as e:
                return self._send(404, {"error": str(e)})
        if path == "/api/activity":
            try:
                limit = min(max(int((qs.get("limit") or ["100"])[0]), 1), 500)
            except ValueError:
                limit = 100
            category = (qs.get("category") or [None])[0]
            if category and category not in soc_activity.CATEGORIES:
                return self._send(400, {"error": f"unknown category {category!r}",
                                        "hint": f"one of {list(soc_activity.CATEGORIES)}"})
            try:
                rows = soc_activity.feed(category=category, actor=(qs.get("actor") or [None])[0],
                                         since=(qs.get("since") or [None])[0], limit=limit)
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            return self._send(200, {"count": len(rows), "categories": list(soc_activity.CATEGORIES), "activity": rows})
        if path == "/api/playbooks":
            return self._send(200, playbooks.overview())
        if path == "/api/playbooks/runs":
            try:
                limit = min(max(int((qs.get("limit") or ["50"])[0]), 1), 200)
            except ValueError:
                limit = 50
            runs = playbooks.recent_runs(limit)
            return self._send(200, {"count": len(runs), "runs": runs})
        if path == "/api/search/sources":
            return self._send(200, log_search.available_sources())
        if path == "/api/search":
            params = {k: (qs.get(k) or [None])[0] for k in ("source", "q", "since", "limit", "timeout")}
            params = {k: v for k, v in params.items() if v is not None}
            params.setdefault("source", "alerts")
            if not _SEARCH_SLOTS.acquire(blocking=False):
                return self._send(429, {"error": "too many searches running; try again in a few seconds"})
            try:
                result = log_search.run_isolated(params)
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            except RuntimeError as e:
                return self._send(504 if "too long" in str(e) else 500, {"error": str(e)})
            finally:
                _SEARCH_SLOTS.release()
            print(f"[*] {key['user']} searched {params.get('source')} q={params.get('q', '')[:60]!r}"
                  f" -> {result['count']} result(s), {result['elapsed_ms']} ms")
            return self._send(200, result)
        if path.startswith("/api/alerts/") and path.endswith("/pcap"):
            aid = path[len("/api/alerts/"):-len("/pcap")]
            alert = next((a for a in soc_core._load_snapshot() if a.get("id") == aid), None)
            if alert is None:
                return self._send(404, {"error": "alert not found", "id": aid})
            pcap = (alert.get("details") or {}).get("pcap")
            if not pcap:
                return self._send(404, {"error": "this alert has no packet capture"})
            try:
                resolved = Path(pcap).resolve()
                resolved.relative_to(PCAP_DIR)  # raises ValueError if pcap escapes the capture directory
                if not resolved.is_file():
                    raise FileNotFoundError
            except (OSError, ValueError):
                return self._send(404, {"error": "capture file not found on this appliance"})
            print(f"[*] {key['user']} downloaded the capture for alert {aid}")
            return self._send_file(resolved, resolved.name)
        if path.startswith("/api/alerts/"):
            aid = path.rsplit("/", 1)[-1]
            for a in soc_core._load_snapshot():
                if a.get("id") == aid: return self._send(200, a)
            return self._send(404, {"error": "alert not found", "id": aid})
        return self._send(404, {"error": "not found", "path": path})
    def do_DELETE(self):
        parsed = urlparse(self.path); path = parsed.path.rstrip("/") or "/"
        key = self._authenticate()
        if not key:
            return self._send(401, {"error": "unauthorized",
                                    "hint": "send header: Authorization: Bearer <token>"})
        if key["role"] != "write":
            return self._send(403, {"error": "forbidden",
                                    "hint": f"key for {key['user']!r} is read-only"})
        parts = path.split("/")
        if len(parts) == 4 and parts[1:3] == ["api", "suppressions"]:
            try:
                removed = suppression_admin.delete_rule(unquote(parts[3]), key["user"])
            except ValueError as e:
                return self._send(404 if "not found" in str(e) else 400, {"error": str(e)})
            print(f"[*] {key['user']} deleted suppression {parts[3]}")
            return self._send(200, {"deleted": removed})
        if len(parts) == 4 and parts[1:3] == ["api", "watchlists"]:
            entry = (parse_qs(parsed.query).get("entry") or [None])[0]
            if not entry:
                return self._send(400, {"error": "query param 'entry' is required"})
            try:
                updated = watchlists.remove(unquote(parts[3]), unquote(entry), key["user"])
            except ValueError as e:
                return self._send(404 if str(e).startswith("unknown watchlist") else 400, {"error": str(e)})
            print(f"[*] {key['user']} removed from watchlist {parts[3]}: {entry}")
            return self._send(200, {"updated": updated})
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
        # /api/watchlists/<name> (add one entry)
        if len(parts) == 4 and parts[1:3] == ["api", "watchlists"]:
            body, err = self._read_json_body()
            if err:
                return self._send(*err)
            entry = body.get("entry")
            if not isinstance(entry, str) or not entry.strip():
                return self._send(400, {"error": "'entry' is required"})
            try:
                updated = watchlists.add(unquote(parts[3]), entry, key["user"])
            except ValueError as e:
                return self._send(404 if str(e).startswith("unknown watchlist") else 400, {"error": str(e)})
            print(f"[*] {key['user']} added to watchlist {parts[3]}: {entry.strip()}")
            return self._send(201, updated)
        # /api/suppressions (create) and /api/suppressions/preview
        if parts[1:3] == ["api", "suppressions"] and (len(parts) == 3 or parts[3:] == ["preview"]):
            body, err = self._read_json_body()
            if err:
                return self._send(*err)
            try:
                if len(parts) == 4:
                    if (body.get("alert_id") is None) == (body.get("match") is None):
                        raise ValueError("send either 'alert_id' (with 'scope') or 'match'")
                    match = body.get("match")
                    if body.get("alert_id") is not None:
                        match = suppression_admin.match_from_alert(
                            suppression_admin._find_alert(str(body["alert_id"])), body.get("scope", "similar"))
                    days = body.get("days", 30)
                    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365:
                        raise ValueError("days must be an integer between 1 and 365")
                    return self._send(200, {"match": match, "preview": suppression_admin.preview(match, days)})
                created = suppression_admin.create_rule(
                    key["user"], body.get("reason"), match=body.get("match"), alert_id=body.get("alert_id"),
                    scope=body.get("scope", "similar"), expires_days=body.get("expires_days", suppression_admin.DEFAULT_DAYS),
                    resolve_existing=bool(body.get("resolve_existing", False)))
            except ValueError as e:
                return self._send(404 if "not found" in str(e) else 400, {"error": str(e)})
            print(f"[*] {key['user']} created suppression {created['rule']['id']}")
            return self._send(201, created)
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

def tls_context(cert: str, key: str) -> ssl.SSLContext:
    """Server-side TLS: TLS 1.2 minimum, the certificate chain and its key (see deploy/make_api_cert.sh)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def main():
    srv = ThreadingHTTPServer((HOST, PORT), Handler)
    scheme = "http"
    if TLS_CERT or TLS_KEY:
        if not (TLS_CERT and TLS_KEY):
            raise SystemExit("[!] set both SOC_API_TLS_CERT and SOC_API_TLS_KEY, or neither")
        # The handshake is deferred to the request's own thread (do_handshake_on_connect=False, it runs on the
        # first read): done in accept(), one client that connects and stalls would block every other client.
        srv.socket = tls_context(TLS_CERT, TLS_KEY).wrap_socket(srv.socket, server_side=True,
                                                                do_handshake_on_connect=False)
        scheme = "https"
    print(f"[*] Sentinel SOC API listening on {scheme}://{HOST}:{PORT}")
    print(f"[*] Serving alerts from: {soc_core.ALERTS_SNAPSHOT}")
    n_write = sum(1 for k in API_KEYS.values() if k["role"] == "write")
    print(f"[*] Auth: Authorization: Bearer <token>   "
          f"({len(API_KEYS)} key(s): {n_write} write, {len(API_KEYS) - n_write} read-only)   "
          f"(CORS: {CORS or 'off'})")
    print("[*] Endpoints: /api/health  /api/summary  /api/alerts  /api/alerts/<id>  /api/hosts  /api/assets")
    print("[*] Also:      /api/incidents  /api/incidents/<id|number>  /api/entities  /api/entities/<type:value>  /api/metrics  /api/sources  /api/detections  /api/mitre  /api/reports  /api/reports/weekly  /api/watchlists  /api/watchlists/<name>")
    print("[*] Automation: GET /api/playbooks  GET /api/playbooks/runs")
    print("[*] AD:        GET /api/ad/summary  /api/ad/computers  /api/ad/users  /api/ad/history")
    print("[*] Search:    GET /api/search?source=alerts|suricata|zeek:<log>&q=...&since=1h&limit=100   GET /api/search/sources")
    print("[*] Suppress:  /api/suppressions  POST /api/suppressions/preview  POST /api/suppressions  DELETE /api/suppressions/<id>")
    print("[*] Write:     POST /api/incidents/<id|number>  {\"status\": \"new|active|closed\", \"classification\": \"true_positive|false_positive|benign|undetermined\", \"owner\": \"...\", \"comment\": \"...\"}")
    print("[*] Write:     POST /api/alerts/<id>/status  {\"status\": \"open|acknowledged|resolved\", \"note\": \"...\"}")
    print("[*] Write:     POST /api/assets/<mac>/notes  {\"owner\": \"...\", \"notes\": \"...\", \"authorized\": true|false}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopping."); srv.shutdown()
 
if __name__ == "__main__":
    main()
