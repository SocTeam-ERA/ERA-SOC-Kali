#!/usr/bin/env python3
"""
proxy_check.py
--------------
Tells you whether an attacker IP is hiding behind Tor, a VPN/proxy, or a
datacenter/hosting provider — so the dashboard can flag it and the analyst
knows the geolocation is probably NOT the attacker's real location.

Detection (offline-first, degrades gracefully):
    * Tor      -> membership in the official Tor exit-node list
                  (download once with --refresh-tor; then checked offline)
    * Hosting  -> the IP's ASN organization matches a known
      / VPN         datacenter / cloud / VPN provider (uses GeoLite2-ASN.mmdb)
    * Residential -> has an ASN org that is not a known hosting/VPN provider

Returns a dict you can drop into an alert's details:
    {"tor": true, "datacenter": false, "type": "tor",
     "org": "...", "anonymized": true}
"anonymized": true means the source is deliberately hiding (Tor/VPN/hosting)
and the shown country should NOT be trusted as the attacker's real location.

Setup:
    # download / refresh the Tor exit list (needs internet, run periodically):
    python3 proxy_check.py --refresh-tor
    # (optional) GeoLite2-ASN.mmdb in data/ for the VPN/hosting heuristic
    # test:
    python3 proxy_check.py 185.220.101.4
"""
from __future__ import annotations

import ipaddress
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

_DATA = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
TOR_FILE = _DATA / "tor_exits.txt"
TOR_LIST_URL = os.environ.get("TOR_LIST_URL", "https://check.torproject.org/torbulkexitlist")
_ASN_DB = os.environ.get("GEOIP_ASN_DB", str(_DATA / "GeoLite2-ASN.mmdb"))

# ASN org substrings that indicate datacenter / cloud / VPN (not residential)
HOSTING_HINTS = (
    "ovh", "digitalocean", "amazon", "aws", "google", "microsoft", "azure",
    "hetzner", "linode", "akamai", "vultr", "m247", "choopa", "leaseweb",
    "contabo", "scaleway", "oracle", "datacamp", "cloudflare", "fastly",
    "quadranet", "hostwinds", "colocrossing", "psychz", "gcore", "constant",
    "datacenter", "data center", "hosting", "server", "cloud", "vps", "dedicated",
    # common VPN provider ASNs / names:
    "nordvpn", "mullvad", "private internet", "expressvpn", "cyberghost",
    "surfshark", "protonvpn", "ipvanish", "windscribe", "tunnelbear", "vpn",
)

_tor_set = None
_asn_reader = None
try:
    import geoip2.database  # type: ignore
    if os.path.exists(_ASN_DB):
        _asn_reader = geoip2.database.Reader(_ASN_DB)
except Exception:
    _asn_reader = None


def refresh_tor() -> int:
    """Download the current Tor exit-node list to TOR_FILE. Returns count."""
    _DATA.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(TOR_LIST_URL, headers={"User-Agent": "sentinel-soc"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read().decode("utf-8", "ignore")
    ips = [ln.strip() for ln in data.splitlines() if ln.strip() and not ln.startswith("#")]
    # Atomic write: this runs daily via soc-tor-refresh.timer, unattended --
    # a kill/crash/network-drop mid-write must never leave TOR_FILE truncated,
    # since every alert in the system calls check() against it (via
    # soc_core.emit_alert's anonymizer enrichment).
    fd, tmp = tempfile.mkstemp(dir=str(_DATA), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(ips) + "\n")
        os.replace(tmp, TOR_FILE)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return len(ips)


def _load_tor():
    global _tor_set
    if _tor_set is None:
        if TOR_FILE.exists():
            _tor_set = {ln.strip() for ln in TOR_FILE.read_text().splitlines() if ln.strip()}
        else:
            _tor_set = set()
    return _tor_set


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def _asn_org(ip: str):
    if _asn_reader is None:
        return None
    try:
        return _asn_reader.asn(ip).autonomous_system_organization
    except Exception:
        return None


def check(ip):
    """Return an anonymizer dict for a public IP, or None."""
    if not ip or not is_public(ip):
        return None
    tor = ip in _load_tor()
    org = _asn_org(ip)
    dc = bool(org) and any(h in org.lower() for h in HOSTING_HINTS)
    if tor:
        typ = "tor"
    elif dc:
        typ = "hosting/vpn"
    elif org:
        typ = "residential"
    else:
        typ = "unknown"
    result = {"tor": tor, "datacenter": dc, "type": typ, "anonymized": tor or dc}
    if org:
        result["org"] = org
    return result


def main():
    if "--refresh-tor" in sys.argv:
        try:
            n = refresh_tor()
            print(f"[*] Tor exit list updated: {n} nodes -> {TOR_FILE}")
        except Exception as e:
            print(f"[!] could not download Tor list: {e}")
            return 1
        return 0
    import json
    tor_n = len(_load_tor())
    print(f"[i] Tor list: {tor_n} nodes | ASN DB: {'yes' if _asn_reader else 'no'}", file=sys.stderr)
    for ip in (sys.argv[1:] or ["185.220.101.4"]):
        print(ip, "->", json.dumps(check(ip)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
