#!/usr/bin/env python3
"""
l2_watch.py
-----------
Attacks on the local network segment that need no mirror port.

Kali sees only the broadcast and multicast traffic of each VLAN it sits on (measured
2026-09-23: 99% of the conversations between OTHER hosts in Zeek's conn.log were
broadcast/multicast, 2 TCP connections in the whole window). That is little, but it is
exactly the traffic these attacks live in, because they all start by answering something a
client broadcast:

  * a rogue DHCP server answers a client's DHCPDISCOVER before the real one and hands out its
    own gateway or DNS server, so the client's traffic goes through the attacker;
  * a rogue IPv6 router advertises itself (Router Advertisement) and hosts adopt it as their
    default IPv6 gateway -- the first half of the "mitm6" attack against Active Directory.

Both are visible in Zeek logs (dhcp.log, conn.log) with no unicast traffic needed, and in
this environment the normal state is tiny and stable: five pairs of DHCP servers (one per
VLAN) plus one, and exactly one IPv6 router. So the detection is a trusted list per kind
(watchlists dhcp_servers and ra_sources) learned from the history Zeek already has, and an
alert for anything else.

The third broadcast attack, LLMNR / NBT-NS poisoning (Responder), cannot be seen this way:
the poisoner's answers are unicast to the victim. poisoner_canary.py catches it actively.

Trusted lists are learned once, at first start, from the last days of Zeek logs, and a normal
alert lists them for someone to check (a rogue already present in the window would be learned
too, which is why the alert shows how often each was seen). After that they are only changed
by hand or through /api/watchlists.
"""
from __future__ import annotations

import glob
import gzip
import ipaddress
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Set

import soc_core
import watchlists
import zeek_tsv
from soc_core import Alert, emit_alert

ZEEK_DIR = Path(os.environ.get("SOC_ZEEK_DIR", "/opt/zeek/logs"))
STATE_FILE = soc_core.DATA_DIR / "l2_watch_state.json"
DHCP_LIST, RA_LIST = "dhcp_servers", "ra_sources"
REALERT_SECONDS = 24 * 3600     # the same unknown device alerts again after a day if it is still there
RARE_BASELINE_COUNT = 5         # a source seen fewer times than this while learning is flagged for a second look
RA_ICMP_TYPE = 134              # ICMPv6 Router Advertisement (133 is the Solicitation a client sends)
# A router's IPv6 link-local address can change (measured 2026-09-18 09:17: the only router here was
# re-addressed and the old address never advertised again), so the IPv6 list learns only from recent
# days; DHCP servers keep fixed IPs, so theirs learns from the whole history.
RA_LEARN_DAYS = 3


# --------------------------------------------------------------------------- #
#  Small persistent state: when each unknown device last alerted, what was learned
# --------------------------------------------------------------------------- #

class State:
    def __init__(self, path: Path = STATE_FILE) -> None:
        self.path = path

    def _load(self) -> Dict[str, Any]:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, data: Dict[str, Any]) -> None:
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
        os.chmod(tmp, 0o664)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)

    def should_alert(self, key: str, now: Optional[float] = None) -> bool:
        """True (and remembered) unless `key` already alerted within REALERT_SECONDS."""
        now = now or time.time()
        with soc_core.diff_state_lock(self.path):
            data = self._load()
            alerted = data.setdefault("alerted", {})
            if now - alerted.get(key, 0) < REALERT_SECONDS:
                return False
            alerted[key] = now
            self._save(data)
            return True

    def seeded(self, name: str) -> bool:
        return bool(self._load().get("seeded", {}).get(name))

    def mark_seeded(self, name: str) -> None:
        with soc_core.diff_state_lock(self.path):
            data = self._load()
            data.setdefault("seeded", {})[name] = time.time()
            self._save(data)


class TrustedSet:
    """A watchlist as a set of networks, re-read when its file changes (so an entry added
    through the API takes effect without restarting the service)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._nets: List[Any] = []
        self._loaded = 0.0

    def contains(self, ip: str, ttl: float = 15.0) -> bool:
        if time.monotonic() - self._loaded > ttl:
            nets = []
            for entry in watchlists.get(self.name)["entries"]:
                try:
                    nets.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    continue
            self._nets, self._loaded = nets, time.monotonic()
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self._nets if n.version == addr.version)


# --------------------------------------------------------------------------- #
#  Detectors: one Zeek row in, an alert out if it is something unknown
# --------------------------------------------------------------------------- #

class DhcpWatch:
    def __init__(self, trusted: Optional[TrustedSet] = None, state: Optional[State] = None) -> None:
        self.trusted = trusted or TrustedSet(DHCP_LIST)
        self.state = state or State()

    def feed(self, row: Dict[str, Any]) -> bool:
        msgs = row.get("msg_types") or []
        server = row.get("server_addr")
        if not server or not any(m in ("OFFER", "ACK") for m in msgs):
            return False           # a client's DISCOVER/REQUEST has no server; only an answer counts
        if server in soc_core.own_ips() or self.trusted.contains(server):
            return False
        if not self.state.should_alert(f"dhcp:{server}"):
            return False
        emit_alert(Alert(
            type="intrusion", severity="critical", detector="l2_watch", source_ip=server,
            title=f"Unknown DHCP server {server} is handing out addresses",
            description=(f"{server} answered a DHCP request ({'/'.join(msgs)}) from client {row.get('mac')} "
                         f"(address {row.get('assigned_addr') or row.get('client_addr') or 'n/a'}) but is not on the "
                         "trusted DHCP server list. A rogue DHCP server can give clients its own gateway or DNS server, "
                         "redirecting and intercepting their traffic, or hand out addresses that break the network. It may "
                         "also be a legitimate server nobody added to the list: if IT confirms it, add it to the "
                         "dhcp_servers watchlist (POST /api/watchlists/dhcp_servers)."),
            details={"server": server, "client_mac": row.get("mac"), "assigned_addr": row.get("assigned_addr"),
                     "msg_types": msgs, "watchlist": DHCP_LIST}), echo=False)
        return True


class RaWatch:
    def __init__(self, trusted: Optional[TrustedSet] = None, state: Optional[State] = None) -> None:
        self.trusted = trusted or TrustedSet(RA_LIST)
        self.state = state or State()

    def feed(self, row: Dict[str, Any]) -> bool:
        # a Router Advertisement is ICMPv6 type 134 sent BY the router (orig_p); the 134 that shows
        # up as resp_p is only the reply a client's Router Solicitation (orig_p 133) expects
        if row.get("proto") != "icmp" or row.get("id.orig_p") != RA_ICMP_TYPE:
            return False
        src = row.get("id.orig_h")
        if not src or src == "::" or self.trusted.contains(src):
            return False
        if not self.state.should_alert(f"ra:{src}"):
            return False
        emit_alert(Alert(
            type="intrusion", severity="medium", detector="l2_watch", source_ip=src,
            title=f"Unknown IPv6 router {src} is sending Router Advertisements",
            description=(f"{src} announced itself as an IPv6 router (to {row.get('id.resp_h')}) and is not on the trusted "
                         "list. Hosts that accept it send their IPv6 traffic through it; combined with a rogue DHCPv6 "
                         "server this is the 'mitm6' attack used to take over Active Directory accounts. Other causes are "
                         "a laptop sharing its connection (Windows hotspot / Internet Connection Sharing) or a new router. "
                         "If IT confirms it, add it to the ra_sources watchlist."),
            details={"router": src, "destination": row.get("id.resp_h"), "watchlist": RA_LIST}), echo=False)
        return True


# --------------------------------------------------------------------------- #
#  Learning the trusted lists from the Zeek history
# --------------------------------------------------------------------------- #

def _rows(name: str, needle: str, zeek_dir: Optional[Path] = None, days: Optional[float] = None) -> Iterator[Dict[str, Any]]:
    """Every row of Zeek log `name` (archives, oldest first, then the live file) whose raw line
    contains `needle` -- a cheap prefilter, since conn.log is ~10 MB an hour. With `days`, only
    the archive folders (one per date) that can hold that recent a row are opened."""
    zeek_dir = zeek_dir or ZEEK_DIR
    files = sorted(glob.glob(str(zeek_dir / "20??-??-??" / f"{name}.*.log.gz")))
    if days is not None:
        oldest = time.strftime("%Y-%m-%d", time.localtime(time.time() - (days + 1) * 86400))
        files = [f for f in files if Path(f).parent.name >= oldest]
    files.append(str(zeek_dir / "current" / f"{name}.log"))
    for path in files:
        reader = zeek_tsv.ZeekTSVReader()
        opener = gzip.open if path.endswith(".gz") else open
        try:
            with opener(path, "rt", errors="ignore") as fh:
                for line in fh:
                    if needle in line or line.startswith("#"):
                        row = reader.feed(line)
                        if row:
                            yield row
        except OSError:
            continue


def learn_dhcp_servers(zeek_dir: Optional[Path] = None) -> Dict[str, int]:
    found: Dict[str, int] = {}
    for row in _rows("dhcp", "", zeek_dir):
        if any(m in ("OFFER", "ACK") for m in (row.get("msg_types") or [])) and row.get("server_addr"):
            found[row["server_addr"]] = found.get(row["server_addr"], 0) + 1
    return found


def learn_ra_sources(zeek_dir: Optional[Path] = None, days: float = RA_LEARN_DAYS) -> Dict[str, int]:
    found: Dict[str, int] = {}
    cutoff = time.time() - days * 86400
    for row in _rows("conn", "icmp", zeek_dir, days=days):
        src = row.get("id.orig_h")
        if (row.get("proto") == "icmp" and row.get("id.orig_p") == RA_ICMP_TYPE and src and src != "::"
                and (row.get("ts") or 0) >= cutoff):
            found[src] = found.get(src, 0) + 1
    return found


def ensure_baselines(state: Optional[State] = None, zeek_dir: Optional[Path] = None) -> List[str]:
    """First start only: learn each trusted list from the history, and say so in one normal alert
    so someone can check it. Returns the names of the lists that were learned now."""
    state = state or State()
    learned = []
    for name, learn, label in ((DHCP_LIST, learn_dhcp_servers, "DHCP server"), (RA_LIST, learn_ra_sources, "IPv6 router")):
        if state.seeded(name):
            continue
        found = learn(zeek_dir)
        if not found:
            continue                      # no history yet: try again at the next start
        for ip in found:
            try:
                watchlists.add(name, ip, "l2-baseline")
            except ValueError:
                pass                      # already listed
        state.mark_seeded(name)
        learned.append(name)
        rare = sorted(ip for ip, n in found.items() if n < RARE_BASELINE_COUNT)
        listing = ", ".join(f"{ip} ({n}x)" for ip, n in sorted(found.items(), key=lambda kv: -kv[1]))
        emit_alert(Alert(
            type="intrusion", severity="normal", detector="l2_watch",
            title=f"Baseline established: {len(found)} trusted {label}(s) learned from the Zeek history",
            description=(f"Learned from the Zeek logs already on disk: {listing}. From now on any {label} outside this list "
                         "raises an alert. This list comes from observation, not from a document: check it against what IT "
                         "actually runs" + (f", especially the rarely seen ones ({', '.join(rare)})." if rare else ".")),
            details={"watchlist": name, "entries": found, "rarely_seen": rare}), echo=False)
    return learned


# --------------------------------------------------------------------------- #
#  Critical addresses: the ones whose owner (MAC) must never quietly change
# --------------------------------------------------------------------------- #

def critical_addresses(targets: Optional[Path] = None, resolv: Optional[Path] = None) -> Dict[str, str]:
    """{ip: role} for the addresses an attacker gains most by impersonating with ARP: the .1 gateway of
    every VLAN in targets.conf (the convention here), this box's DNS servers, and the trusted DHCP
    servers. Whoever answers ARP for one of these sees, and can alter, every machine's traffic to it."""
    suite = Path(__file__).resolve().parent.parent
    targets = targets or Path(os.environ.get("SOC_TARGETS_FILE", suite / "kali" / "targets.conf"))
    resolv = resolv or Path("/etc/resolv.conf")
    out: Dict[str, str] = {}
    try:
        for line in targets.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            if net.version == 4 and net.num_addresses >= 4:
                out[str(net.network_address + 1)] = "gateway"
    except OSError:
        pass
    try:
        for line in resolv.read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "nameserver":
                try:
                    if ipaddress.ip_address(parts[1]).version == 4:
                        out.setdefault(parts[1], "DNS server")
                except ValueError:
                    continue
    except OSError:
        pass
    try:
        for entry in watchlists.get(DHCP_LIST)["entries"]:
            try:
                if ipaddress.ip_network(entry, strict=False).num_addresses == 1 and ":" not in entry:
                    out.setdefault(entry, "DHCP server")
            except ValueError:
                continue
    except (OSError, ValueError):
        pass
    return out
