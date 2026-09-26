#!/usr/bin/env python3
"""
net_presence.py -- which known machines are answering on the network right now, and since when.

The ARP scan runs every 4 hours, far too slowly to say "this PC lost the network at 10:42". This checks
the machines we care about every ~2 minutes by asking the kernel to resolve their addresses:

  1. send one tiny UDP datagram (port 9, discard) to each tracked address, which makes Linux ask "who has
     that address?" on the layer-2 network the machine sits on (ARP), whatever a firewall on the machine
     would do with ICMP or with the datagram itself (a Windows PC that drops ping still answers ARP);
  2. wait for the kernel's neighbour states to settle (~14 s: DELAY 5 s, then 3 unicast + 3 multicast probes);
  3. read them: REACHABLE = the machine answered, FAILED = nobody did, anything else = not settled, which
     counts as "don't know" and never as a miss.

It needs no root and no extra package. It only tells whether a machine answers on ITS OWN network (the Kali
has a leg in every VLAN); it does not say the machine has internet access. Guest Wi-Fi is left out on
purpose, like the port scans (config/net_presence.json: exclude_cidrs).

Tracked machines: the Active Directory computers the SOC can put an address on (scan names, DHCP names and
the domain's DNS: see ad_identity.py / ip_names.py), plus whatever config/net_presence.json lists under
"always_on" (an address, a MAC or a computer name).

A machine is reported DOWN only after `down_after_misses` consecutive FAILED probes (3 x 2 min = ~6 min: a
phone or laptop in power-save can miss one round) and UP again on the first answer. Every change goes to
data/net_presence_events.jsonl. Alerts are raised ONLY for machines listed in "always_on" (a laptop that is
closed for the night is not an incident), and when `outage_min_hosts` or more machines of one network drop in
the same round it is ONE alert about the network, not one per machine. If most of the tracked machines seem
to vanish at once the round is discarded: that is the Kali's own network having trouble, not theirs.

    python3 net_presence.py            one round now, print the summary
    python3 net_presence.py --dry-run  probe and print, write nothing, raise nothing
Called every couple of minutes by service_watchdog.py (run_if_due).
"""
from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soc_core  # noqa: E402

SUITE = Path(__file__).resolve().parent.parent
CONFIG_FILE = Path(os.environ.get("SOC_NET_PRESENCE_CONFIG", SUITE / "config" / "net_presence.json"))
DEFAULTS: Dict[str, Any] = {
    "always_on": [],                     # addresses, MACs or computer names that must always answer
    "exclude_cidrs": ["192.168.8.0/24"],  # Guest / Employee Wi-Fi: not probed
    "down_after_misses": 3,
    "outage_min_hosts": 5,
    "interval_seconds": 110,
    "settle_seconds": 14,
    "max_tracked": 400,
}
VLAN_NAMES = {"10.69.": "Floor", "10.201.": "Management", "10.21.": "Wiping",
              "192.168.61.": "Printers", "192.168.7.": "Office", "192.168.8.": "Guest/Employee Wi-Fi"}


def _state_file() -> Path:
    return soc_core.DATA_DIR / "net_presence.json"


def _events_file() -> Path:
    return soc_core.DATA_DIR / "net_presence_events.jsonl"


def load_config() -> Dict[str, Any]:
    cfg = dict(DEFAULTS)
    try:
        raw = json.loads(CONFIG_FILE.read_text())
        cfg.update({k: v for k, v in raw.items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    return cfg


def vlan_of(ip: str) -> str:
    for prefix, name in VLAN_NAMES.items():
        if ip.startswith(prefix):
            return name
    return "Other"


def _usable(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_private and not (a.is_loopback or a.is_link_local or a.is_multicast)


def tracked_hosts(cfg: Optional[Dict[str, Any]] = None) -> Dict[str, Dict[str, Any]]:
    """{ip: {"name", "mac", "source", "always_on"}} for the machines to probe."""
    cfg = cfg or load_config()
    assets = soc_core.load_assets()
    by_ip = {r["ip"]: (m, r) for m, r in assets.items() if r.get("ip")}
    out: Dict[str, Dict[str, Any]] = {}

    # Active Directory computers with an address: the scan's own name for them, then DHCP/DNS matches
    try:
        import ad_identity
        idx = ad_identity._index()
    except Exception:
        idx = None
    if idx:
        for ip, name in idx["ip_name"].items():
            key = ad_identity.find_computer(idx, name)
            if not key:
                continue
            c = idx["computers"][key]
            if not c.get("enabled") or ip not in by_ip:
                continue
            out[ip] = {"name": c["name"], "mac": by_ip[ip][0], "source": "ad", "always_on": False}

    # what the administrator says must always answer
    names = {v["name"].upper(): ip for ip, v in out.items()}
    for item in cfg.get("always_on") or []:
        s = str(item).strip()
        ip = None
        if _usable(s):
            ip = s
        elif s.upper() in names:
            ip = names[s.upper()]
        else:
            for m, r in assets.items():
                if m.lower().startswith(s.lower()) and r.get("ip"):
                    ip = r["ip"]
                    break
                if str(r.get("dhcp_hostname") or "").split(".")[0].upper() == s.upper() and r.get("ip"):
                    ip = r["ip"]
                    break
        if ip:
            rec = out.setdefault(ip, {"name": (by_ip.get(ip, (None, {}))[1].get("dhcp_hostname") or ip),
                                      "mac": by_ip.get(ip, (None, {}))[0], "source": "config", "always_on": False})
            rec["always_on"] = True

    excluded = [ipaddress.ip_network(c, strict=False) for c in cfg.get("exclude_cidrs") or []]
    keep = {ip: v for ip, v in out.items()
            if _usable(ip) and not any(ipaddress.ip_address(ip) in n for n in excluded)}
    if len(keep) > int(cfg["max_tracked"]):
        keep = dict(sorted(keep.items())[: int(cfg["max_tracked"])])
    return keep


def probe(ips: List[str], settle: float = 10.0) -> Dict[str, str]:
    """{ip: "up" | "down" | "unknown"} by the kernel's neighbour states after poking every address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        for ip in ips:
            try:
                sock.sendto(b".", (ip, 9))
            except OSError:
                pass               # no route / interface down: the state below stays unresolved
        time.sleep(settle)
    finally:
        sock.close()
    try:
        raw = subprocess.run(["ip", "-j", "neigh", "show"], capture_output=True, text=True, timeout=10).stdout
        table = {n["dst"]: n for n in json.loads(raw)}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {ip: "unknown" for ip in ips}
    out = {}
    for ip in ips:
        n = table.get(ip)
        states = set(n.get("state") or []) if n else set()
        if "REACHABLE" in states or "PERMANENT" in states:
            out[ip] = "up"
        elif n and (states & {"FAILED", "INCOMPLETE"}) and not n.get("lladdr"):
            out[ip] = "down"
        else:
            out[ip] = "unknown"
    return out


def _now_iso(now: Optional[float] = None) -> str:
    return datetime.fromtimestamp(now or time.time(), tz=timezone.utc).isoformat()


def _minutes(a: str, b: str) -> int:
    try:
        return max(0, round((datetime.fromisoformat(b) - datetime.fromisoformat(a)).total_seconds() / 60))
    except (TypeError, ValueError):
        return 0


def load_state() -> Dict[str, Any]:
    try:
        return json.loads(_state_file().read_text())
    except (OSError, ValueError):
        return {}


def _write(path: Path, data: Any) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.chmod(tmp, 0o664)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _event(ev: Dict[str, Any]) -> None:
    with soc_core.open_shared_append(_events_file()) as fh:
        fh.write(json.dumps(ev) + "\n")


def run_once(probe_fn: Callable[[List[str], float], Dict[str, str]] = probe, now: Optional[float] = None,
             cfg: Optional[Dict[str, Any]] = None, emit: bool = True) -> Dict[str, Any]:
    cfg = cfg or load_config()
    now_iso = _now_iso(now)
    tracked = tracked_hosts(cfg)
    prev = load_state()
    prev_hosts: Dict[str, Any] = prev.get("hosts") or {}
    results = probe_fn(sorted(tracked), float(cfg["settle_seconds"])) if tracked else {}

    down_now = sum(1 for v in results.values() if v == "down")
    settled = sum(1 for v in results.values() if v in ("up", "down"))
    suspect = len(tracked) >= 10 and settled and down_now / max(settled, 1) > 0.6
    hosts: Dict[str, Any] = {}
    went_down: List[Dict[str, Any]] = []
    came_back: List[Dict[str, Any]] = []
    for ip, meta in tracked.items():
        old = prev_hosts.get(ip) or {}
        rec = {"name": meta["name"], "mac": meta["mac"], "source": meta["source"], "always_on": meta["always_on"],
               "vlan": vlan_of(ip), "state": old.get("state") or "unknown", "since": old.get("since") or now_iso,
               "last_up": old.get("last_up"), "misses": int(old.get("misses") or 0),
               "first_miss": old.get("first_miss"), "last_probe": now_iso}
        result = results.get(ip, "unknown")
        if suspect and result == "down":
            result = "unknown"           # the Kali's own network is the likelier culprit: do not count it
        if result == "up":
            rec["last_up"] = now_iso
            if rec["state"] == "down":
                came_back.append({"ip": ip, **rec, "down_minutes": _minutes(rec["since"], now_iso)})
            if rec["state"] != "up":
                rec["state"], rec["since"] = "up", now_iso
            rec["misses"], rec["first_miss"] = 0, None
        elif result == "down":
            rec["misses"] += 1
            rec["first_miss"] = rec["first_miss"] or now_iso
            if rec["misses"] >= int(cfg["down_after_misses"]) and rec["state"] != "down":
                if rec["state"] == "up":              # a machine we never saw answering did not "go down"
                    went_down.append({"ip": ip, **rec})
                rec["state"], rec["since"] = "down", rec["first_miss"]
        hosts[ip] = rec

    summary = {"tracked": len(hosts), "up": sum(1 for r in hosts.values() if r["state"] == "up"),
               "down": sum(1 for r in hosts.values() if r["state"] == "down"),
               "unknown": sum(1 for r in hosts.values() if r["state"] == "unknown"), "round_discarded": bool(suspect)}
    state = {"checked": now_iso, "summary": summary, "hosts": hosts}
    if not emit:
        return {**state, "went_down": went_down, "came_back": came_back}

    for h in went_down:
        _event({"at": now_iso, "ip": h["ip"], "name": h["name"], "mac": h["mac"], "vlan": h["vlan"], "event": "down",
                "since": h["since"]})
    for h in came_back:
        _event({"at": now_iso, "ip": h["ip"], "name": h["name"], "mac": h["mac"], "vlan": h["vlan"], "event": "up",
                "down_minutes": h["down_minutes"]})
    _write(_state_file(), state)
    _alerts(went_down, came_back, hosts, cfg)
    return {**state, "went_down": went_down, "came_back": came_back}


def _alerts(went_down: List[Dict[str, Any]], came_back: List[Dict[str, Any]], hosts: Dict[str, Any],
            cfg: Dict[str, Any]) -> None:
    """Alerts only for the always-on machines, and one alert for a whole network when many drop together."""
    by_vlan: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for h in went_down:
        by_vlan[h["vlan"]].append(h)
    outage_vlans = {v for v, hs in by_vlan.items() if len(hs) >= int(cfg["outage_min_hosts"])}
    for vlan in sorted(outage_vlans):
        hs = by_vlan[vlan]
        soc_core.emit_alert(soc_core.Alert(
            type="intrusion", severity="medium", detector="net_presence",
            title=f"Network outage suspected on {vlan}: {len(hs)} machines stopped answering",
            description=(f"{len(hs)} machines on the {vlan} network stopped answering within the same few minutes "
                         f"({', '.join(sorted(h['name'] for h in hs)[:8])}{'...' if len(hs) > 8 else ''}). Several going "
                         "quiet together points to a switch, an access point or a power problem rather than to the machines."),
            details={"vlan": vlan, "machines": sorted(h["name"] for h in hs), "change": "outage"}), echo=False)
    for h in went_down:
        if h["always_on"] and h["vlan"] not in outage_vlans:
            soc_core.emit_alert(soc_core.Alert(
                type="intrusion", severity="medium", detector="net_presence", source_ip=h["ip"],
                title=f"Machine lost the network: {h['name']} ({h['ip']})",
                description=(f"{h['name']} ({h['ip']}, {h['vlan']}) is on the always-on list and has not answered for "
                             f"{cfg['down_after_misses']} checks in a row (since {h['since']})."),
                details={"name": h["name"], "mac": h["mac"], "vlan": h["vlan"], "since": h["since"], "change": "down",
                         "source_role": "asset"}), echo=False)
    for h in came_back:
        if h["always_on"]:
            soc_core.emit_alert(soc_core.Alert(
                type="intrusion", severity="normal", detector="net_presence", source_ip=h["ip"],
                title=f"Machine is back on the network: {h['name']} ({h['ip']})",
                description=f"{h['name']} answers again after about {h['down_minutes']} minutes.",
                details={"name": h["name"], "vlan": h["vlan"], "down_minutes": h["down_minutes"], "change": "up",
                         "source_role": "asset"}), echo=False)


def run_if_due(**kw) -> Optional[Dict[str, Any]]:
    """One round if the last one is older than interval_seconds; a lock keeps two callers from probing at once."""
    cfg = load_config()
    try:
        if time.time() - _state_file().stat().st_mtime < float(cfg["interval_seconds"]):
            return None
    except OSError:
        pass
    lock = soc_core.DATA_DIR / ".net_presence.lock"
    with soc_core.open_shared_append(lock) as fh:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return None
        try:
            return run_once(cfg=cfg, **kw)
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def recent_events(limit: int = 50) -> List[Dict[str, Any]]:
    try:
        lines = _events_file().read_text().splitlines()[-max(1, min(limit, 500)):]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return list(reversed(out))


if __name__ == "__main__":
    dry = "--dry-run" in sys.argv
    res = run_once(emit=not dry)
    print(json.dumps(res["summary"], indent=2))
    for ip, h in sorted(res["hosts"].items()):
        if h["state"] != "up":
            print(f"  {h['state']:8} {h['name']:22} {ip:16} {h['vlan']}")
