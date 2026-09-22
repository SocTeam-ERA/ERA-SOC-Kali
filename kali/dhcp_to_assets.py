#!/usr/bin/env python3
"""
dhcp_to_assets.py
------------------
Enriches the asset inventory (data/assets.json, built by arp_to_alerts.py)
with the hostname each device announced during its DHCP handshake --
Zeek's dhcp.log already captures this from ordinary DHCP DISCOVER/REQUEST
traffic, no active scanning needed. A hostname like "HP2055DN-3F" or
"IPHONE-JGARCIA" often says far more about a device than the MAC vendor
lookup alone (which only ever tells you who made the network chip).

Deliberately does NOT do this for randomized/locally-administered MACs
(see the note in soc_core.py just above ASSETS_FILE): correlating a DHCP
hostname back to a phone/laptop's rotating Wi-Fi MAC would defeat the
privacy feature those addresses exist for. This is a non-issue in
practice, not a filter this script has to apply itself -- it only ever
enriches assets that already exist in the inventory, and arp_to_alerts.py
already never creates an asset record for a randomized MAC in the first
place (see record_asset_sightings()). A DHCP sighting for a MAC this
project isn't already tracking as an asset is simply skipped.

No alerts are raised here, by design -- same reasoning as
record_asset_sightings() itself: a hostname is inventory context, not a
security event. If a hostname ever needs to be alert-worthy on its own
(e.g. a device renaming itself to impersonate another), that's a
separate, sharper detector to build later -- not this one.

Usage:
    python3 dhcp_to_assets.py --log /opt/zeek/logs/current/dhcp.log
    python3 dhcp_to_assets.py --follow                 # continuous (systemd)
"""
from __future__ import annotations
import argparse, os, sys
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import record_dhcp_hostnames, tail_follow  # noqa: E402
from zeek_tsv import ZeekTSVReader, read_current_header  # noqa: E402

DEFAULT_LOG = Path("/opt/zeek/logs/current/dhcp.log")


def _extract(row: dict) -> dict | None:
    mac = row.get("mac")
    hostname = row.get("host_name") or row.get("client_fqdn")
    if not mac or not hostname:
        return None
    return {"mac": mac.lower(), "hostname": hostname}


def process_file(path: Path, follow: bool) -> int:
    reader = ZeekTSVReader()
    if follow:
        # Prime the column layout from the log's CURRENT header before tailing from the
        # end (see zeek_tsv.read_current_header): without this, a service that starts
        # mid-hour stays blind to dhcp.log until the next hourly rotation hands it a
        # fresh #fields line on its own.
        header = read_current_header(path)
        if header:
            reader.feed(header)
        # tail_follow() survives zeekctl's own log rotation, same as the
        # other Zeek-log consumers (zeek_to_alerts.py) -- see its docstring.
        n = 0
        for line in tail_follow(path, from_start=False):
            row = reader.feed(line)
            sighting = _extract(row) if row else None
            if sighting and record_dhcp_hostnames([sighting]):
                n += 1
        return n

    sightings = []
    with path.open(errors="ignore") as fh:
        for line in fh:
            row = reader.feed(line)
            sighting = _extract(row) if row else None
            if sighting:
                sightings.append(sighting)
    n = record_dhcp_hostnames(sightings)
    print(f"[*] dhcp_to_assets: {n} asset(s) enriched with a DHCP hostname "
          f"out of {len(sightings)} sighting(s) read.")
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="Zeek dhcp.log -> asset inventory enrichment (no alerts)")
    ap.add_argument("--log", default=str(DEFAULT_LOG), help="Path to Zeek's dhcp.log")
    ap.add_argument("--follow", action="store_true", help="Tail continuously (for a systemd service)")
    args = ap.parse_args()
    process_file(Path(args.log), args.follow)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
