#!/usr/bin/env python3
"""
arp_to_alerts.py
-----------------
Turns the per-VLAN asset inventory from 1c_arp_discovery.sh into SOC alerts:
it remembers which MAC addresses have been seen on each authorized VLAN and
raises a "new/unknown device" alert the first time a MAC shows up there that
wasn't there before. A device that goes offline is NOT alerted on — that is
normal churn, not a security event.

Severity depends on which VLAN the new device appeared on (edit
VLAN_SEVERITY below if the network changes — keep it in sync with
targets.conf / the VLANS[] array in 1c_arp_discovery.sh):

    Management / Wiping VLANs   -> critical  (should never see a random NIC)
    Floor / Printers / Office   -> medium
    Guest / Employees WiFi      -> skipped entirely (unknown personal
                                    devices are the expected, normal case
                                    there — alerting would be pure noise and
                                    a privacy problem, same reasoning
                                    scheduled_scan.sh already applies when it
                                    excludes that VLAN from port-scanning).

Input (written by 1c_arp_discovery.sh): a TSV with one line per host seen,
    cidr<TAB>iface<TAB>ip<TAB>mac<TAB>vendor

Usage:
    python3 arp_to_alerts.py results/arp_assets_XXXX.tsv
    python3 arp_to_alerts.py results/arp_assets_XXXX.tsv --state /path/to/mac_state.json
"""
from __future__ import annotations
import argparse, json, os, sys, tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, diff_state_lock  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DEFAULT_STATE = DATA_DIR / "mac_state.json"

VLAN_SEVERITY = {
    "10.201.0.0/16":   "critical",  # Management
    "10.21.0.0/16":    "critical",  # Wiping
    "10.69.0.0/16":    "medium",    # Floor
    "192.168.61.0/24": "medium",    # Printers
    "192.168.7.0/24":  "medium",    # Office
}
SKIP_VLANS = {"192.168.8.0/24"}     # Guest / Employees WiFi — unknown devices expected


def _is_locally_administered(mac: str) -> bool:
    """True if the MAC's U/L bit (bit 1 of the first octet) is set --
    meaning the address was generated locally, not assigned by a hardware
    vendor's registered OUI.

    Confirmed 2026-09-15: 90 of 211 "New device" alerts on Floor VLAN had
    this bit set, EVERY one with a different prefix and none repeating --
    the textbook signature of MAC randomization, the privacy feature every
    modern phone/laptop OS (iOS 14+, Android 10+, Windows 10+, macOS) now
    turns on by default for Wi-Fi: the same physical device generates a
    brand new random MAC on every reconnect specifically so it can't be
    tracked by address. Treated as an ordinary new device, this means
    Floor's "new device" alerts grow without bound forever as the same
    handful of phones keep reconnecting -- and each one carries much
    weaker signal than a real vendor-registered NIC appearing for the
    first time, since it can't even identify a consistent device.
    """
    try:
        first_octet = int(mac.split(":", 1)[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first_octet & 0x02)


def _load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text()).get("vlans", {})
    except Exception:
        return {}


def _save_state(path: Path, vlans: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"generated": datetime.now(timezone.utc).isoformat(), "vlans": vlans}
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    # mkstemp() defaults to mode 0600 (owner-only), and os.replace() swaps
    # that in wholesale -- left as-is, whichever user runs this next (the
    # scheduled job as root vs. a manual run as a team member) locks
    # everyone else out of reading/updating the state file afterward.
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def parse_assets(path: Path) -> dict:
    """Returns { cidr: { mac: {"ip":.., "vendor":.., "iface":..} } }."""
    current: dict[str, dict] = {}
    for line in path.read_text().splitlines():
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        cidr, iface, ip, mac = parts[0], parts[1], parts[2], parts[3].lower()
        vendor = parts[4].strip() if len(parts) > 4 else ""
        current.setdefault(cidr, {})[mac] = {"ip": ip, "vendor": vendor, "iface": iface}
    return current


def run(assets_path: Path, state_path: Path) -> int:
    current = parse_assets(assets_path)
    n = 0

    # Locked so a manual run can't race the scheduled job (or another
    # manual run) on the same state file -- see diff_state_lock()'s
    # docstring in soc_core.py.
    with diff_state_lock(state_path):
        previous = _load_state(state_path)

        for cidr, macs in current.items():
            if cidr in SKIP_VLANS:
                continue
            if cidr not in VLAN_SEVERITY:
                print(f"[!] arp_to_alerts: VLAN {cidr} has no entry in VLAN_SEVERITY/SKIP_VLANS "
                      f"— defaulting to 'medium'. Update arp_to_alerts.py to match targets.conf.",
                      file=sys.stderr)
            severity = VLAN_SEVERITY.get(cidr, "medium")
            prev_macs = previous.get(cidr)

            if prev_macs is None:
                # first time we see this VLAN at all: seed quietly, no flood of alerts
                emit_alert(Alert(
                    type="intrusion", severity="normal",
                    title=f"Asset baseline established for VLAN {cidr}: {len(macs)} device(s)",
                    detector="arp_discovery",
                    description=("First run for this VLAN: recorded the current set of MAC "
                                 "addresses as the known baseline. From now on, alerts fire "
                                 "only when a NEW device appears."),
                    details={"cidr": cidr, "device_count": len(macs), "change": "baseline"},
                ))
                n += 1
                continue

            for mac, info in macs.items():
                if mac not in prev_macs:
                    randomized = _is_locally_administered(mac)
                    dev_severity = "normal" if randomized else severity
                    title = f"New device on VLAN {cidr}: {mac} ({info['vendor'] or 'unknown vendor'})"
                    desc = (f"A MAC address not seen before on VLAN {cidr} "
                            f"({info['iface']}) is now present at {info['ip']}: {mac}, "
                            f"vendor '{info['vendor'] or 'unknown'}'. Confirm this device "
                            f"is authorized.")
                    if randomized:
                        title += " — likely randomized Wi-Fi MAC"
                        desc += (" This MAC is locally-administered (its vendor lookup normally "
                                 "shows 'Unknown: locally administered'), which almost always means "
                                 "a phone or laptop's private/randomized Wi-Fi address rather than a "
                                 "genuinely new physical device -- most operating systems generate a "
                                 "fresh random MAC on every reconnect by default. Lower priority than "
                                 "a real vendor-registered NIC appearing for the first time.")
                    emit_alert(Alert(
                        type="intrusion", severity=dev_severity,
                        title=title,
                        source_ip=info["ip"], detector="arp_discovery",
                        description=desc,
                        details={"cidr": cidr, "iface": info["iface"], "mac": mac,
                                 "vendor": info["vendor"], "change": "new_device",
                                 "locally_administered": randomized},
                    ))
                    n += 1

        # merge into the persistent baseline: keep every MAC ever seen (per
        # VLAN), including ones absent from this run (offline, not "removed").
        merged = dict(previous)
        for cidr, macs in current.items():
            merged[cidr] = {**merged.get(cidr, {}), **macs}
        _save_state(state_path, merged)

    print(f"[*] arp_to_alerts: {n} alert(s) raised.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("assets", help="TSV from 1c_arp_discovery.sh: cidr<TAB>iface<TAB>ip<TAB>mac<TAB>vendor")
    ap.add_argument("--state", default=str(DEFAULT_STATE),
                    help=f"Path to the known-MAC-addresses state file (default: {DEFAULT_STATE})")
    args = ap.parse_args()
    return run(Path(args.assets), Path(args.state).expanduser().resolve())


if __name__ == "__main__":
    raise SystemExit(main())
