#!/usr/bin/env python3
"""
software_to_assets.py
----------------------
Enriches the asset inventory (data/assets.json, built by arp_to_alerts.py)
with software Zeek fingerprinted on a device's own ports -- its software
framework passively parses HTTP Server/User-Agent headers, SSH version
banners, and a handful of other protocols, no active probing needed. This
is often the only way to tell an embedded device's actual make/model apart
from the generic chip-vendor MAC lookup: a MAC vendor lookup says "Intel
Corporate", Zeek's software.log says "GoAhead-Webs" (a web server firmware
almost exclusively bundled with printers, IP cameras and other embedded
IoT gear) or "Apache/2.2.17 (Win32) PHP/5.3.6" (an actual Windows server),
without ever running `nmap -O`.

Zeek's software.log is keyed by IP (the `host` field), not MAC, so each
sighting is resolved through the CURRENT asset inventory's ip-to-MAC
mapping (soc_core.build_ip_to_mac_map()) before being recorded -- same
reasoning as dhcp_to_assets.py's hostname enrichment: only ever attached to
an asset this project already independently confirmed is present, never
used to create one. A sighting for an IP not currently mapped to a known
asset (a device this box's ARP sweep hasn't seen, or a link-local/IPv6
address with no MAC mapping at all) is simply skipped.

No alerts are raised here, by design, same reasoning as the other asset
enrichment scripts: what software a device runs is inventory context, not
a security event on its own (a NEW, unexpected service appearing on an
already-known device is instead nmap_to_alerts.py's job -- it already
alerts on that from its own scans; this script only adds a label).

Usage:
    python3 software_to_assets.py --log /opt/zeek/logs/current/software.log
    python3 software_to_assets.py --follow                 # continuous (systemd)
"""
from __future__ import annotations
import argparse, os, sys, time
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import record_asset_software, build_ip_to_mac_map, tail_follow  # noqa: E402
from zeek_tsv import ZeekTSVReader, read_header_lines  # noqa: E402
from reader_health import Reporter  # noqa: E402

DEFAULT_LOG = Path("/opt/zeek/logs/current/software.log")
# How long a cached ip-to-MAC mapping is trusted before rebuilding it from the asset
# inventory again, in --follow mode. A sighting arrives one at a time over hours, so
# rebuilding it once per sighting (a full pass over every asset) is wasteful, but the
# mapping does drift as DHCP hands IPs to different devices -- same tradeoff, same
# window, as soc_core.own_ips()'s cache.
MAP_REFRESH_SECONDS = 60


def _extract(row: dict) -> dict | None:
    host = row.get("host")
    software_type = row.get("software_type")
    name = row.get("name")
    if not host or not software_type or not name:
        return None
    return {"host": host, "software_type": software_type, "name": name,
            "version": row.get("unparsed_version")}


class _MapCache:
    """The ip-to-MAC mapping, rebuilt at most once every MAP_REFRESH_SECONDS."""
    def __init__(self) -> None:
        self._map: dict[str, str] = {}
        self._at = 0.0

    def get(self) -> dict[str, str]:
        now = time.monotonic()
        if now - self._at > MAP_REFRESH_SECONDS:
            self._map = build_ip_to_mac_map()
            self._at = now
        return self._map


def process_file(path: Path, follow: bool) -> int:
    reader = ZeekTSVReader()
    if follow:
        # Prime the column layout from the log's CURRENT header before tailing from the
        # end (see zeek_tsv.read_header_lines) -- otherwise a service that starts
        # mid-hour stays blind to software.log until the next hourly rotation.
        # software.log is often missing entirely in a quiet hour; one that appears later must
        # be read from its beginning, or the header (and so every row) is lost until the next
        # hourly rotation.
        appears_later = not path.exists()
        for header in read_header_lines(path):
            reader.feed(header)
        cache = _MapCache()
        n = 0
        health = Reporter("software_to_assets", reader)
        for line in tail_follow(path, from_start=appears_later):
            row = reader.feed(line)
            health.tick()
            sighting = _extract(row) if row else None
            if not sighting:
                continue
            mac = cache.get().get(sighting.pop("host"))
            if mac and record_asset_software([{"mac": mac, **sighting}]):
                n += 1
        return n

    ip_to_mac = build_ip_to_mac_map()
    sightings = []
    with path.open(errors="ignore") as fh:
        for line in fh:
            row = reader.feed(line)
            sighting = _extract(row) if row else None
            if not sighting:
                continue
            mac = ip_to_mac.get(sighting.pop("host"))
            if mac:
                sightings.append({"mac": mac, **sighting})
    n = record_asset_software(sightings)
    print(f"[*] software_to_assets: {n} asset(s) enriched with a software fingerprint "
          f"out of {len(sightings)} sighting(s) resolved to a known asset.")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="Zeek software.log -> asset inventory enrichment (no alerts)")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="Path to Zeek's software.log")
    ap.add_argument("--follow", action="store_true", help="Tail continuously (for a systemd service)")
    args = ap.parse_args()
    process_file(Path(args.log), args.follow)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
