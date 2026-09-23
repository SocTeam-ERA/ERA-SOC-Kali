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

    Management VLAN             -> critical  (should never see a random NIC)
    Floor / Printers / Office   -> medium
    Wiping                      -> normal (racks are rebuilt constantly)
    Guest / Employees WiFi      -> skipped entirely (unknown personal
                                    devices are the expected, normal case
                                    there — alerting would be pure noise and
                                    a privacy problem, same reasoning
                                    scheduled_scan.sh already applies when it
                                    excludes that VLAN from port-scanning).

Wiping was "critical" originally, on the assumption it should only ever
have a small fixed set of known machines like Management. Confirmed
otherwise 2026-09-17: it's a still-being-built-out HDD/NVMe/SAS wiping
rack, devices are actively being added and removed as the team builds it
out, and nothing there is inventoried yet -- "critical" on every new MAC
was alerting on normal, expected churn. Revisit once that rack's device
set stabilizes and someone can actually maintain a known-good list for it.

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
from soc_core import Alert, emit_alert, diff_state_lock, record_asset_sightings  # noqa: E402
import l2_watch  # noqa: E402

DATA_DIR = Path(os.environ.get("SOC_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DEFAULT_STATE = DATA_DIR / "mac_state.json"

VLAN_SEVERITY = {
    "10.201.0.0/16":   "critical",  # Management
    "10.21.0.0/16":    "normal",    # Wiping -- racks come and go constantly; churn is the normal state
    "10.69.0.0/16":    "medium",    # Floor
    "192.168.61.0/24": "medium",    # Printers
    "192.168.7.0/24":  "medium",    # Office
}
SKIP_VLANS = {"192.168.8.0/24"}     # Guest / Employees WiFi — unknown devices expected

# More than this many new devices of one kind on one VLAN in a single scan are raised as ONE
# alert with the list inside, not one row each (a wave of 10-22 laptops joining at once is a
# single event; 2026-09-18 produced 39 rows in two waves). At or below it, each device still
# gets its own alert exactly as before.
ARP_BULK_THRESHOLD = int(os.environ.get("SOC_ARP_BULK_THRESHOLD", "5"))
MAX_BULK_LISTED = 100


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


def _emit_bulk(cidr: str, devices: list, randomized: bool, severity: str) -> int:
    """One alert for a wave of new devices on a VLAN. The list is kept in details, and the
    entities are set here so correlation still sees every device (see alert_context.py)."""
    n = len(devices)
    kind = "likely-randomized Wi-Fi MAC(s)" if randomized else "new device(s)"
    listed = devices[:MAX_BULK_LISTED]
    vendors = {}
    for _, info in devices:
        v = info["vendor"] or "unknown vendor"
        vendors[v] = vendors.get(v, 0) + 1
    top = ", ".join(f"{v} x{c}" for v, c in sorted(vendors.items(), key=lambda kv: -kv[1])[:4])
    entities = []
    for mac, info in listed:
        entities.append({"type": "mac", "value": mac, "role": "source"})
        entities.append({"type": "ip", "value": info["ip"], "role": "source"})
    emit_alert(Alert(
        type="intrusion", severity=severity,
        title=f"{n} {kind} on VLAN {cidr} in one scan" if not randomized
              else f"{n} likely-randomized Wi-Fi MACs on VLAN {cidr} in one scan",
        detector="arp_discovery",
        description=(f"{n} MAC address(es) not seen before on VLAN {cidr} appeared in a single scan "
                     f"({top}). Grouped into one alert instead of {n} rows; the full list is in "
                     "details.devices. Confirm these devices are authorized."
                     + (" These are locally-administered (private/randomized) MACs, almost always "
                        "phones or laptops reconnecting." if randomized else "")),
        details={"cidr": cidr, "change": "bulk_new_devices", "count": n, "locally_administered": randomized,
                 "truncated": n > len(listed), "entities": entities,
                 "devices": [{"mac": m, "ip": i["ip"], "vendor": i["vendor"], "iface": i["iface"]}
                             for m, i in listed]},
    ))
    return 1


def check_critical_addresses(current: dict, owners_path: Path) -> int:
    """ARP poisoning and rogue gateways, from what the scan just saw. For each critical address
    (gateway of every VLAN, DNS servers, trusted DHCP servers -- see l2_watch.critical_addresses):
      * two MACs answering for it in the same scan is an address conflict or an active spoof;
      * a different MAC than the last scan is the same thing happening between scans.
    Either is critical. Both also happen innocently (a router failover, a replaced NIC, a virtual
    machine restored on a new host), so the alert says to confirm with whoever runs that machine. The
    first time an address is seen its MAC is recorded silently."""
    critical = l2_watch.critical_addresses()
    seen: dict = {}
    for macs in current.values():
        for mac, info in macs.items():
            # arp-scan appends, in parentheses, the Ethernet source MAC when it differs from the MAC in the
            # ARP reply -- for a VRRP/CARP gateway that is the physical firewall that answered ("00:00:5e:00:01:45
            # (00:08:a2:12:b2:4a)"). Compare only the ARP MAC: the virtual one stays put when the two firewalls
            # swap the master role, so a normal failover must not look like a hijack.
            seen.setdefault(info["ip"], {})[mac.split()[0].lower()] = info
    state = l2_watch.State(owners_path.with_name("l2_watch_state.json"))
    n = 0
    with diff_state_lock(owners_path):
        try:
            owners = json.loads(owners_path.read_text())
        except (OSError, ValueError):
            owners = {}
        for ip, role in critical.items():
            answers = seen.get(ip)
            if not answers:
                continue                                  # not seen this scan: say nothing
            macs = sorted(answers)
            vendors = ", ".join(f"{m} ({answers[m]['vendor'] or 'unknown vendor'})" for m in macs)
            if len(macs) > 1:
                if state.should_alert(f"arp-dup:{ip}:{','.join(macs)}"):
                    emit_alert(Alert(
                        type="intrusion", severity="critical", detector="arp_discovery", source_ip=ip,
                        title=f"Two MAC addresses answer for critical address {ip} ({role}): {macs[0]}, {macs[1]}",
                        description=(f"{ip} is this network's {role}, and in the same scan two different machines answered ARP "
                                     f"for it: {vendors}. Either two machines share the address by mistake, or one is "
                                     "impersonating the other (ARP poisoning: everything sent to that address can be read or "
                                     "altered). A router pair with a virtual address can also do this legitimately -- confirm "
                                     "with whoever runs that device."),
                        details={"ip": ip, "role": role, "macs": macs, "change": "arp_conflict"}), echo=False)
                    n += 1
                continue
            mac = macs[0]
            previous = owners.get(ip)
            if previous is None:
                owners[ip] = mac                          # first sighting: record it silently
            elif previous != mac:
                if state.should_alert(f"arp-change:{ip}:{mac}"):
                    emit_alert(Alert(
                        type="intrusion", severity="critical", detector="arp_discovery", source_ip=ip,
                        title=f"Critical address {ip} ({role}) is now answered by a different MAC: {mac} (was {previous})",
                        description=(f"{ip} is this network's {role}. At the previous scan it belonged to {previous}; now it "
                                     f"answers from {vendors}. That is what ARP poisoning or a rogue gateway looks like, and "
                                     "also what a router failover, a replaced network card or a restored virtual machine look "
                                     "like -- confirm with whoever runs that device before treating it as an attack."),
                        details={"ip": ip, "role": role, "mac": mac, "previous_mac": previous, "change": "arp_owner_changed"}),
                        echo=False)
                    n += 1
                owners[ip] = mac
        tmp = owners_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(owners, indent=2))
        os.replace(tmp, owners_path)
    return n


def run(assets_path: Path, state_path: Path) -> int:
    current = parse_assets(assets_path)
    n = 0
    sightings = []  # vendor-MAC devices only -- see record_asset_sightings()

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

            # Asset inventory: every device with a real vendor MAC on this
            # VLAN, new or already known -- refreshes ip/last_seen either
            # way. Randomized MACs are never durable identity, so they're
            # excluded here (they still get their own "new device" alert
            # below, just no persistent asset record).
            for mac, info in macs.items():
                if not _is_locally_administered(mac):
                    sightings.append({"mac": mac, "ip": info["ip"], "vendor": info["vendor"],
                                       "cidr": cidr, "iface": info["iface"]})

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

            pending = {False: [], True: []}      # keyed by "randomized MAC"
            for mac, info in macs.items():
                if mac not in prev_macs:
                    pending[_is_locally_administered(mac)].append((mac, info))
            for randomized, devices in pending.items():
                if len(devices) > ARP_BULK_THRESHOLD:
                    n += _emit_bulk(cidr, devices, randomized, "normal" if randomized else severity)
                    devices = []
                for mac, info in devices:
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

    try:
        n += check_critical_addresses(current, state_path.with_name("critical_ip_owners.json"))
    except Exception as e:  # noqa: BLE001 -- must never stop the inventory update
        print(f"[!] arp_to_alerts: critical-address check skipped: {e}", file=sys.stderr)

    if sightings:
        created = record_asset_sightings(sightings)
        print(f"[*] arp_to_alerts: asset inventory updated ({len(sightings)} sighting(s), {created} new).")

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
