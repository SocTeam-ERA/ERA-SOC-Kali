#!/usr/bin/env python3
"""
geoip_enrich.py
----------------
Looks up the country/city for a public source IP so alerts show roughly
where an attacker is connecting from. Same "optional, degrades gracefully"
shape as proxy_check.py: no-op if the geoip2 library or the GeoLite2-City
database isn't installed, so soc_core.emit_alert()'s enrichment step (which
imports this on every single alert) never breaks anything by calling it.

This was referenced from soc_core.py's emit_alert() from the start but the
module itself was never written -- every alert's geo enrichment has been a
silent no-op (caught by emit_alert()'s broad except) since day one. Building
it now actually turns that on.

Setup (optional):
    Put GeoLite2-City.mmdb in data/ (same free MaxMind database used by
    proxy_check.py's GeoLite2-ASN.mmdb, different edition -- register at
    https://www.maxmind.com/en/geolite2/signup and download the City one).
    pip install geoip2

Returns a dict you can drop into an alert's details, or None if the IP is
private/unresolvable/the database isn't installed:
    {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam",
     "lat": 52.37, "lon": 4.89}
"""
from __future__ import annotations

import ipaddress
import os
from pathlib import Path

_DATA = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
_CITY_DB = os.environ.get("GEOIP_CITY_DB", str(_DATA / "GeoLite2-City.mmdb"))

_city_reader = None
try:
    import geoip2.database  # type: ignore
    if os.path.exists(_CITY_DB):
        _city_reader = geoip2.database.Reader(_CITY_DB)
except Exception:
    _city_reader = None


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def geolocate(ip):
    """Return a geo dict for a public IP, or None."""
    if _city_reader is None or not ip or not is_public(ip):
        return None
    try:
        r = _city_reader.city(ip)
    except Exception:
        return None
    out = {}
    if r.country.name:
        out["country"] = r.country.name
    if r.country.iso_code:
        out["country_code"] = r.country.iso_code
    if r.city.name:
        out["city"] = r.city.name
    if r.location.latitude is not None:
        out["lat"] = r.location.latitude
    if r.location.longitude is not None:
        out["lon"] = r.location.longitude
    return out or None


def main():
    import json
    import sys
    print(f"[i] City DB: {'yes' if _city_reader else 'no (' + _CITY_DB + ' not found, or geoip2 not installed)'}",
          file=sys.stderr)
    for ip in (sys.argv[1:] or ["8.8.8.8"]):
        print(ip, "->", json.dumps(geolocate(ip)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
