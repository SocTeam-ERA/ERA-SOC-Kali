#!/usr/bin/env python3
"""
alert_context.py -- the common fields every alert gets, whatever detector raised it.

emit_alert() (soc_core.py) calls add_context(record), which stores in
record["details"]:

  entities   [{"type": "ip"|"mac"|"host"|"user", "value": ..., "role":
             "source"|"destination"}]. IPs are mapped to MACs through the
             asset inventory, so an alert about a DHCP address and one about
             the same device's MAC share an entity. This is what correlation,
             the per-host pages and risk scoring join on.
  group_key  what kind of alert this is and where: detector | type | the title
             with IPs/MACs/numbers blanked | the subnet. Alerts of one kind in
             one place share a key.
  batch_id   stable id for a burst: alerts with the same group_key arriving
             less than SOC_BATCH_WINDOW seconds (default 300) apart share it.
             A burst of 17 new devices is one batch, so a UI can show it as
             one row.

All of it sits under details (not new top-level keys) so the schema the
backend validates does not change.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import soc_core

BATCH_WINDOW = int(os.environ.get("SOC_BATCH_WINDOW", "300"))
_BATCH_STATE = soc_core.DATA_DIR / "batch_state.json"
_BATCH_LOCK = soc_core.DATA_DIR / ".batch_state.lock"

_SRC_KEYS = ("src", "src_ip")
_DST_KEYS = ("dst", "dest_ip", "dst_ip")
_ARROW = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})\s*(?:->|→)\s*(\d{1,3}(?:\.\d{1,3}){3})")
_MAC = re.compile(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}")

_assets_cache: Dict[str, Any] = {"sig": None, "ip_to_mac": {}}


def _valid_ip(value: Any) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _ip_to_mac() -> Dict[str, str]:
    """IP -> MAC from data/assets.json, cached until the file changes."""
    path = soc_core.DATA_DIR / "assets.json"
    try:
        st = path.stat()
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        return {}
    if _assets_cache["sig"] != sig:
        out: Dict[str, str] = {}
        for rec in soc_core.load_assets().values():
            m = _MAC.match(str(rec.get("mac") or ""))
            if rec.get("ip") and m:
                out[rec["ip"]] = m.group(0).lower()
        _assets_cache.update(sig=sig, ip_to_mac=out)
    return _assets_cache["ip_to_mac"]


def entities(record: Dict[str, Any]) -> List[Dict[str, str]]:
    details = record.get("details") or {}
    found: List[tuple] = []          # (type, value, role)

    def add_ip(value: Any, role: str) -> None:
        ip = _valid_ip(value)
        if ip:
            found.append(("ip", ip, role))

    add_ip(record.get("source_ip"), "source")
    for k in _SRC_KEYS:
        add_ip(details.get(k), "source")
    for k in _DST_KEYS:
        add_ip(details.get(k), "destination")
    target = details.get("target")
    if isinstance(target, str) and target:
        add_ip(urlparse(target if "://" in target else "//" + target).hostname, "destination")
    m = _ARROW.search(record.get("title") or "")
    if m:
        add_ip(m.group(1), "source")
        add_ip(m.group(2), "destination")

    mac = details.get("mac")
    if isinstance(mac, str) and _MAC.fullmatch(mac.strip()):
        found.append(("mac", mac.strip().lower(), "source"))
    ip_map = _ip_to_mac()
    for kind, value, role in list(found):
        if kind == "ip" and value in ip_map:
            found.append(("mac", ip_map[value], role))

    if record.get("hostname"):
        found.append(("host", str(record["hostname"]).lower(), "source"))
    if record.get("user"):
        found.append(("user", str(record["user"]).lower(), "source"))

    out, seen = [], set()
    for kind, value, role in found:
        if (kind, value) not in seen:
            seen.add((kind, value))
            out.append({"type": kind, "value": value, "role": role})
    return out


def entity_keys(record: Dict[str, Any]) -> List[str]:
    """'type:value' strings for the alert's entities (uses details.entities if present)."""
    ents = (record.get("details") or {}).get("entities")
    if ents is None:
        ents = entities(record)
    return [f"{e['type']}:{e['value']}" for e in ents]


_SHAPE_SUBS = [
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<ip>"),
    (re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b"), "<mac>"),
    (re.compile(r"\d+"), "N"),
]


_AIDE_TITLE = re.compile(r"^File integrity: (\S+) (\w+)$")


def title_shape(title: str, detector: str = "") -> str:
    """The title with the parts that vary per alert blanked out."""
    title = title or ""
    # Two detectors put per-alert text in the title that would split one burst
    # into many groups: the vendor name after a new device's MAC, and the file
    # name in an integrity change (group those by top-level directory instead).
    if detector == "arp_discovery" and title.startswith("New device on VLAN"):
        return "New device on VLAN"
    if detector == "aide":
        m = _AIDE_TITLE.match(title)
        if m:
            return f"File integrity: {'/'.join(m.group(1).split('/')[:4])} {m.group(2)}"
    for rx, sub in _SHAPE_SUBS:
        title = rx.sub(sub, title)
    return title[:60]


def _scope(record: Dict[str, Any]) -> str:
    details = record.get("details") or {}
    if isinstance(details.get("cidr"), str):
        return details["cidr"]
    ip = _valid_ip(record.get("source_ip"))
    if ip:
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return "-"


def group_key(record: Dict[str, Any]) -> str:
    return "|".join([record.get("detector") or "-", record.get("type") or "-",
                     title_shape(record.get("title") or "", record.get("detector") or ""),
                     _scope(record)])


def assign_batch(key: str, when: float) -> str:
    """Return the batch id for an alert with this group_key at time `when`."""
    with _BATCH_LOCK.open("a") as lockfh:
        fcntl.flock(lockfh, fcntl.LOCK_EX)
        try:
            try:
                state = json.loads(_BATCH_STATE.read_text())
            except (OSError, ValueError):
                state = {}
            cur = state.get(key)
            if cur and 0 <= when - cur["last"] < BATCH_WINDOW:
                cur["last"] = when
                cur["count"] += 1
            else:
                stamp = datetime.fromtimestamp(when, tz=timezone.utc).strftime("%Y%m%d%H%M%S")
                cur = {"batch_id": f"b{stamp}-{uuid.uuid4().hex[:4]}", "last": when, "count": 1}
                state[key] = cur
            cutoff = when - 86400
            state = {k: v for k, v in state.items() if v["last"] >= cutoff}
            fd, tmp = tempfile.mkstemp(dir=str(_BATCH_STATE.parent), suffix=".tmp")
            os.chmod(tmp, 0o664)
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(state, f)
                os.replace(tmp, _BATCH_STATE)
            finally:
                if os.path.exists(tmp):
                    os.remove(tmp)
            return cur["batch_id"]
        finally:
            fcntl.flock(lockfh, fcntl.LOCK_UN)


def _epoch(record: Dict[str, Any]) -> float:
    try:
        dt = datetime.fromisoformat(record["timestamp"])
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp()
    except (KeyError, ValueError, TypeError):
        return time.time()


# What alert.source_ip means. "actor": the party that caused the activity (the scanner, the
# attacker, the login source). "asset": the host the alert is about (the scanned or
# monitored device, or an internal host whose traffic was flagged); the other side, if any,
# is in details (dst, ioc_ip, ...). A detector can set details.source_role itself; this is the
# default per detector.
_ROLE_BY_DETECTOR = {
    "login_monitor": "actor",
    "kali_scan": "asset", "arp_discovery": "asset", "port_scanner": "asset", "nikto": "asset",
    "whatweb": "asset", "osquery": "asset", "vlan_segmentation": "asset",
    "phishing_detector": "actor", "malware_detector": "asset",
}


def source_role(record: Dict[str, Any]) -> Optional[str]:
    if not record.get("source_ip"):
        return None
    detector = record.get("detector")
    if detector in ("suricata", "zeek"):
        # an internal host talking to the internet is the asset; anything else is the actor
        d = record.get("details") or {}
        dst = d.get("dst") or d.get("dest_ip")
        if dst is None and detector == "suricata":
            m = _ARROW.search(record.get("title") or "")
            dst = m.group(2) if m else None
        try:
            if ipaddress.ip_address(record["source_ip"]).is_private and dst and ipaddress.ip_address(dst).is_global:
                return "asset"
        except ValueError:
            pass
        return "actor"
    return _ROLE_BY_DETECTOR.get(detector)


def add_context(record: Dict[str, Any]) -> None:
    """Set details.entities / group_key / batch_id / source_role on the alert record in place."""
    details = record.setdefault("details", {})
    src = record.get("source_ip")
    if src and src in soc_core.own_ips():
        details["source_is_self"] = True     # the alert's source_ip is one of this appliance's own addresses
    if "source_role" not in details:
        role = source_role(record)
        if role:
            details["source_role"] = role
    if "entities" not in details:
        ents = entities(record)
        if ents:
            details["entities"] = ents
    if "group_key" not in details:
        details["group_key"] = group_key(record)
    if "batch_id" not in details:
        details["batch_id"] = assign_batch(details["group_key"], _epoch(record))
