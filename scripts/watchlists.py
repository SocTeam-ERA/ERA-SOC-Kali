#!/usr/bin/env python3
"""
watchlists.py -- named lists of trusted/known-bad values shared across
detectors (or curated by an analyst instead of editing a file by hand),
each backed by the same one-entry-per-line, '#'-comment text file its
consumer already reads directly (data/known_ips.txt, kali/ioc_ips.txt, ...).
Adding or removing an entry through here is the same edit a human would
make in a text editor -- just done safely (locked, atomic, audited) and
without disturbing the file's own comment header, which every one of
these files uses to record where the list came from and why.

This module only manages membership. The detectors themselves are
unchanged (they still just read their file); vlan_segmentation_to_alerts.py
is the one exception that now reads its two VLAN sets from here instead of
a hardcoded constant, since those never had a file of their own.
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import re
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

SUITE = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", SUITE / "data"))
# Same override convention every kali/*.py detector already uses (SOC_SCRIPTS for its sibling) --
# without it, a test running with SOC_DATA_DIR pointed at a throwaway directory would still
# read and WRITE the real kali/ioc_ips.txt and kali/bad_domains.txt (bad_ips/bad_domains below
# are the only two watchlists backed by a file under here, not under DATA_DIR).
KALI_DIR = Path(os.environ.get("SOC_KALI_DIR", SUITE / "kali"))
LOCK_FILE = DATA_DIR / ".watchlists.lock"
LOG_FILE = DATA_DIR / "watchlist_log.jsonl"

_DOMAIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
_HASH_RE = re.compile(r"^([0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


def _ip_or_cidr(v: str) -> str:
    ipaddress.ip_network(v, strict=False)  # raises ValueError if not one
    return v


def _domain(v: str) -> str:
    if not _DOMAIN_RE.match(v):
        raise ValueError(f"not a valid domain: {v!r}")
    return v.lower()


def _hash(v: str) -> str:
    if not _HASH_RE.match(v):
        raise ValueError(f"not an md5/sha1/sha256 hash: {v!r}")
    return v.lower()


def _account(v: str) -> str:
    """An AD sAMAccountName (lower-cased); a DOMAIN\\ prefix or @domain suffix is dropped."""
    v = v.split("\\")[-1].split("@")[0].strip().lower()
    if not re.fullmatch(r"[a-z0-9._$-]{1,64}", v):
        raise ValueError(f"not an AD account name (sAMAccountName): {v!r}")
    return v


def _vlan_name(v: str) -> str:
    if not v or "/" in v or v.startswith("#"):
        raise ValueError(f"not a valid VLAN name: {v!r}")
    return v


REGISTRY: Dict[str, Dict[str, Any]] = {
    "trusted_ips": {
        "path": DATA_DIR / "known_ips.txt",
        "description": "IPs/CIDRs that don't raise \"login from a new IP\" (login_monitor.py --known-ips).",
        "used_by": ["login_monitor"],
        "validate": _ip_or_cidr,
    },
    "bad_ips": {
        "path": KALI_DIR / "ioc_ips.txt",
        "description": "Manually curated known-bad IPs flagged on sight by the live traffic monitor "
                       "(separate from the auto-refreshed threat_intel feed in data/threat_intel/).",
        "used_by": ["traffic_capture"],
        "validate": _ip_or_cidr,
    },
    "bad_domains": {
        "path": KALI_DIR / "bad_domains.txt",
        "description": "Known-bad/suspicious domains the live traffic monitor matches DNS queries against "
                       "(substring match).",
        "used_by": ["traffic_capture"],
        "validate": _domain,
    },
    "bad_hashes": {
        "path": DATA_DIR / "ioc_hashes.txt",
        "description": "Known-bad file hashes (md5/sha1/sha256) malware_detector.py flags on sight.",
        "used_by": ["malware_detector"],
        "validate": _hash,
    },
    "dhcp_servers": {
        "path": DATA_DIR / "watchlists" / "dhcp_servers.txt",
        "description": "DHCP servers allowed to hand out addresses. l2_watch raises a critical alert when any other "
                       "address answers a client with an OFFER or ACK (a rogue DHCP server can redirect or block every "
                       "machine that trusts it); arp_to_alerts also treats these as critical addresses whose MAC must not change.",
        "used_by": ["l2_watch", "arp_discovery"],
        "validate": _ip_or_cidr,
    },
    "ra_sources": {
        "path": DATA_DIR / "watchlists" / "ra_sources.txt",
        "description": "IPv6 link-local addresses of the routers allowed to send Router Advertisements. l2_watch raises "
                       "an alert on any other source (a rogue RA can make hosts send their IPv6 traffic through the attacker).",
        "used_by": ["l2_watch"],
        "validate": _ip_or_cidr,
    },
    "sensitive_vlans": {
        "path": DATA_DIR / "watchlists" / "sensitive_vlans.txt",
        "description": "VLANs where reachability from an untrusted VLAN is critical on its own "
                       "(vlan_segmentation_to_alerts.py).",
        "used_by": ["vlan_segmentation"],
        "validate": _vlan_name,
        "seed_header": "# VLANs where any reachability from an untrusted VLAN is itself a critical finding.\n"
                       "# One VLAN name per line, must match the VLAN names in kali/5_vlan_segmentation_test.sh.\n",
        "seed": ["Management", "Wiping"],
    },
    "untrusted_vlans": {
        "path": DATA_DIR / "watchlists" / "untrusted_vlans.txt",
        "description": "VLANs that should never be able to reach a sensitive VLAN "
                       "(vlan_segmentation_to_alerts.py).",
        "used_by": ["vlan_segmentation"],
        "validate": _vlan_name,
        "seed_header": "# VLANs that should never be able to reach a sensitive VLAN.\n"
                       "# One VLAN name per line, must match the VLAN names in kali/5_vlan_segmentation_test.sh.\n",
        "seed": ["Guest-Employee-WiFi"],
    },
    "on_leave_accounts": {
        "path": DATA_DIR / "watchlists" / "on_leave_accounts.txt",
        "description": "AD accounts of people who are away (leave, long absence). Any new sign-in raises a critical "
                       "alert (ad_inventory.py): nobody should be using them.",
        "used_by": ["ad_inventory"],
        "validate": _account,
        "seed_header": "# AD accounts (sAMAccountName) of people on leave: any sign-in raises a critical alert.\n"
                       "# Add a comment line above each with who, why and until when; remove the entry when they return.\n",
        "seed": [],
    },
}


def _spec(name: str) -> Dict[str, Any]:
    spec = REGISTRY.get(name)
    if spec is None:
        raise ValueError(f"unknown watchlist {name!r} (known: {sorted(REGISTRY)})")
    return spec


def _seed_if_missing(spec: Dict[str, Any]) -> None:
    path = spec["path"]
    if "seed" in spec and not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(spec.get("seed_header", "") + "\n".join(spec["seed"]) + "\n")


def _read_raw(path: Path) -> List[str]:
    if not path.exists():
        return []
    return path.read_text().splitlines()


def _entries(lines: List[str]) -> List[str]:
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def _write_raw(path: Path, lines: List[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    text = "\n".join(lines) + ("\n" if lines else "")
    tmp.write_text(text)
    os.chmod(tmp, 0o664)
    os.replace(tmp, path)


@contextmanager
def _locked():
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _audit(actor: str, action: str, name: str, entry: str) -> None:
    with LOG_FILE.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": datetime.now(timezone.utc).isoformat(), "actor": actor,
                             "action": action, "watchlist": name, "entry": entry}) + "\n")


def list_watchlists() -> List[Dict[str, Any]]:
    out = []
    for name, spec in REGISTRY.items():
        _seed_if_missing(spec)
        entries = _entries(_read_raw(spec["path"]))
        out.append({"name": name, "description": spec["description"], "used_by": spec["used_by"],
                    "count": len(entries), "entries": entries})
    return out


def get(name: str) -> Dict[str, Any]:
    spec = _spec(name)
    _seed_if_missing(spec)
    entries = _entries(_read_raw(spec["path"]))
    return {"name": name, "description": spec["description"], "used_by": spec["used_by"],
            "count": len(entries), "entries": entries}


def add(name: str, entry: str, actor: str) -> Dict[str, Any]:
    spec = _spec(name)
    value = spec["validate"](entry.strip())
    _seed_if_missing(spec)
    with _locked():
        lines = _read_raw(spec["path"])
        if value in _entries(lines):
            raise ValueError(f"{value!r} is already in watchlist {name!r}")
        lines.append(value)
        _write_raw(spec["path"], lines)
        _audit(actor, "added", name, value)
    return get(name)


def remove(name: str, entry: str, actor: str) -> Dict[str, Any]:
    spec = _spec(name)
    try:
        value = spec["validate"](entry.strip())
    except ValueError:
        value = entry.strip()  # let an analyst remove a legacy entry even if it predates validation
    with _locked():
        lines = _read_raw(spec["path"])
        idx = next((i for i, ln in enumerate(lines) if ln.strip() == value), None)
        if idx is None:
            raise ValueError(f"{value!r} is not in watchlist {name!r}")
        del lines[idx]
        _write_raw(spec["path"], lines)
        _audit(actor, "removed", name, value)
    return get(name)
