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
import time
from pathlib import Path

_DATA = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
_CITY_DB = os.environ.get("GEOIP_CITY_DB", str(_DATA / "GeoLite2-City.mmdb"))
_COUNTRY_DB = os.environ.get("GEOIP_COUNTRY_DB", str(_DATA / "GeoLite2-Country.mmdb"))
RETRY_SECONDS = 60

# Two databases, because the only City database on this machine (the copy bundled with Gophish) was
# built in 2015 and misses or misplaces many modern address blocks, while the Country database that
# ships with Ettercap is from 2026-01. The country always comes from the newer one; the city and the
# coordinates are added only when the old database agrees on the country, so an old guess can never
# contradict a current one. With only one database present it is used on its own.
_readers: dict = {"city": None, "country": None}
_next_try: dict = {"city": 0.0, "country": 0.0}
_paths = lambda: {"city": _CITY_DB, "country": _COUNTRY_DB}


def _reader(kind: str):
    """A database reader, opened on first use and retried at most once a minute while its file is
    missing: geolocation was a silent no-op for the first two weeks (no database, no error), and a
    service that started before a database was installed should pick it up without a restart."""
    if _readers[kind] is not None:
        return _readers[kind]
    now = time.monotonic()
    if now < _next_try[kind]:
        return None
    _next_try[kind] = now + RETRY_SECONDS
    try:
        import geoip2.database  # type: ignore
        if os.path.exists(_paths()[kind]):
            _readers[kind] = geoip2.database.Reader(_paths()[kind])
    except Exception:
        _readers[kind] = None
    return _readers[kind]


def status() -> dict:
    """For the doctor: per database {"available", "path", "built"}, plus "available" overall."""
    out: dict = {}
    for kind in ("country", "city"):
        r, built = _reader(kind), None
        if r is not None:
            try:
                from datetime import datetime, timezone
                built = datetime.fromtimestamp(r.metadata().build_epoch, tz=timezone.utc).date().isoformat()
            except Exception:
                pass
        out[kind] = {"available": r is not None, "path": _paths()[kind], "built": built}
    out["available"] = out["country"]["available"] or out["city"]["available"]
    return out


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local
                or a.is_multicast or a.is_reserved or a.is_unspecified)


def geolocate(ip):
    """Return a geo dict for a public IP, or None. `precision` says how much of it to trust:
    "city" (a city name confirmed against the country) or "country" (coordinates, if any, are the country's centre)."""
    if not ip or not is_public(ip):
        return None
    out: dict = {}
    country_r, city_r = _reader("country"), _reader("city")
    if country_r is not None:
        try:
            c = country_r.country(ip).country
            if c.iso_code:
                out["country_code"] = c.iso_code
                if c.name:
                    out["country"] = c.name
        except Exception:
            pass
    if city_r is not None:
        try:
            r = city_r.city(ip)
        except Exception:
            r = None
        if r is not None and (not out or r.country.iso_code == out.get("country_code")):
            if not out:
                if r.country.iso_code:
                    out["country_code"] = r.country.iso_code
                if r.country.name:
                    out["country"] = r.country.name
            if r.city.name:
                out["city"] = r.city.name
            if r.location.latitude is not None:
                out["lat"] = r.location.latitude
            if r.location.longitude is not None:
                out["lon"] = r.location.longitude
    if out:
        out["precision"] = "city" if "city" in out else "country"    # coordinates alone are a country's centre
    return out or None


def main():
    import json
    import sys
    st = status()
    for kind in ("country", "city"):
        d = st[kind]
        print(f"[i] {kind} DB: {'yes, built ' + str(d['built']) if d['available'] else 'no (' + d['path'] + ' not found, or geoip2 not installed)'}",
              file=sys.stderr)
    for ip in (sys.argv[1:] or ["8.8.8.8"]):
        print(ip, "->", json.dumps(geolocate(ip)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
