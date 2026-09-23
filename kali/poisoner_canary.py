#!/usr/bin/env python3
"""
poisoner_canary.py
------------------
Catch LLMNR / NBT-NS poisoning (the "Responder" attack) with a question only a poisoner answers.

When a Windows machine cannot resolve a name through DNS (a typo in a share path, an old
printer name, "wpad"), it asks the whole network by multicast/broadcast: LLMNR
(224.0.0.252:5355) and NetBIOS name service (UDP 137). A legitimate machine answers only if the
name is its own. An attacker's tool such as Responder answers EVERY such question with its own
address, so the victim connects to it and hands over an NTLM authentication -- the hash can be
cracked offline or relayed to a machine that does not require SMB signing (see the "SMB signing
not required" findings). It is the most common way into a Windows domain from inside.

The poisoner's answers go straight to the victim, unicast, which a machine that is not on a mirror
port never sees (measured 2026-09-23: none in the Zeek logs). So instead of listening, this asks:
once every ten minutes, on every network Kali sits on, it queries a random, nonexistent name by
LLMNR and by NBT-NS and waits two seconds. Nobody can legitimately own a name that was just
invented, so any positive answer is a poisoner, and it is addressed to us, so we do see it.

The probe is one small multicast/broadcast name query per protocol per network, no ports scanned,
nothing exploited: what any Windows machine sends when a name does not resolve. Set
SOC_CANARY_IFACES=eth0,eth1 to limit it to some interfaces.

Usage:
    python3 poisoner_canary.py              run once (soc-poisoner-canary.timer does this every 10 min)
    python3 poisoner_canary.py --dry-run    ask, print what answered, raise no alert
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import string
import struct
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
import soc_core  # noqa: E402
from soc_core import Alert, emit_alert  # noqa: E402
import l2_watch  # noqa: E402

LLMNR_GROUP = ("224.0.0.252", 5355)
NBNS_PORT = 137
WAIT_SECONDS = 2.0
STATE_FILE = soc_core.DATA_DIR / "poisoner_canary_state.json"


# --------------------------------------------------------------------------- #
#  Packets
# --------------------------------------------------------------------------- #

def random_name(length: int = 12) -> str:
    """A name nobody owns: a letter, then random letters and digits."""
    return random.choice(string.ascii_lowercase) + "".join(random.choices(string.ascii_lowercase + string.digits, k=length - 1))


def build_llmnr_query(name: str, txid: int) -> bytes:
    label = name.encode()
    question = bytes([len(label)]) + label + b"\x00" + struct.pack(">HH", 1, 1)   # type A, class IN
    return struct.pack(">HHHHHH", txid, 0, 1, 0, 0, 0) + question


def build_nbns_query(name: str, txid: int) -> bytes:
    netbios = name.upper().ljust(15)[:15].encode() + b"\x20"        # 16 bytes; suffix 0x20 = file server
    encoded = b"".join(bytes([0x41 + (b >> 4), 0x41 + (b & 0x0F)]) for b in netbios)   # first-level encoding
    # flags 0x0110 = name query + broadcast + recursion desired
    return struct.pack(">HHHHHH", txid, 0x0110, 1, 0, 0, 0) + b"\x20" + encoded + b"\x00" + struct.pack(">HH", 0x20, 1)


def _positive_answer(data: bytes, txid: int, protocol: str) -> Optional[Dict[str, Any]]:
    """A response to OUR query that actually resolves the name. LLMNR and NBNS share the header
    layout: id, flags (bit 15 = response, low 4 bits = result code), then the section counts."""
    if len(data) < 12:
        return None
    tid, flags, _qd, answers = struct.unpack(">HHHH", data[:8])
    if tid != txid or not flags & 0x8000 or flags & 0x000F or answers < 1:
        return None                      # not ours, not a response, an error (a WINS "not found"), or empty
    return {"protocol": protocol, "answers": answers}


def parse_llmnr_response(data: bytes, txid: int) -> Optional[Dict[str, Any]]:
    return _positive_answer(data, txid, "LLMNR")


def parse_nbns_response(data: bytes, txid: int) -> Optional[Dict[str, Any]]:
    return _positive_answer(data, txid, "NBT-NS")


# --------------------------------------------------------------------------- #
#  Asking
# --------------------------------------------------------------------------- #

def probe(bind_ip: str, dest: tuple, packet: bytes, txid: int, parser: Callable, own_ips: Set[str],
          wait: float = WAIT_SECONDS, broadcast: bool = False, multicast: bool = False) -> List[Dict[str, Any]]:
    """Send `packet` from `bind_ip` and return every positive answer that comes back."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.25)
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if multicast:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        sock.bind((bind_ip, 0))
        sock.sendto(packet, dest)
        hits: List[Dict[str, Any]] = []
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                data, (ip, _port) = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if ip in own_ips:
                continue
            parsed = parser(data, txid)
            if parsed:
                hits.append({"responder": ip, **parsed})
        return hits
    finally:
        sock.close()


def interfaces() -> List[Dict[str, str]]:
    out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
    found = []
    for m in re.finditer(r"^\d+:\s+(\S+)\s+inet (\d+\.\d+\.\d+\.\d+)/(\d+)(?: brd (\d+\.\d+\.\d+\.\d+))?", out, re.M):
        if m.group(1) != "lo" and m.group(4):
            found.append({"iface": m.group(1), "ip": m.group(2), "prefix": m.group(3), "brd": m.group(4)})
    return found


def run(only: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Ask on every interface (or `only`); returns one dict per positive answer."""
    all_ifaces = interfaces()
    own = {i["ip"] for i in all_ifaces}
    wanted = only if only is not None else [x for x in os.environ.get("SOC_CANARY_IFACES", "").split(",") if x]
    results: List[Dict[str, Any]] = []
    asked = []
    for i in all_ifaces:
        if wanted and i["iface"] not in wanted:
            continue
        asked.append(i["iface"])
        for protocol, build, parser, dest, kw in (
                ("LLMNR", build_llmnr_query, parse_llmnr_response, LLMNR_GROUP, {"multicast": True}),
                ("NBT-NS", build_nbns_query, parse_nbns_response, (i["brd"], NBNS_PORT), {"broadcast": True})):
            name, txid = random_name(), random.randrange(1 << 16)
            try:
                hits = probe(i["ip"], dest, build(name, txid), txid, parser, own, **kw)
            except OSError as e:
                print(f"[!] canary {protocol} on {i['iface']}: {e}", file=sys.stderr)
                continue
            for h in hits:
                results.append({**h, "iface": i["iface"], "name": name, "network": f"{i['ip']}/{i['prefix']}"})
    _write_state(asked, len(results))
    return results


def _write_state(asked: List[str], answers: int) -> None:
    """When the canary last ran, for source_health (a canary that stopped is a blind spot)."""
    try:
        fd, tmp = tempfile.mkstemp(dir=str(STATE_FILE.parent), suffix=".tmp")
        os.chmod(tmp, 0o664)
        with os.fdopen(fd, "w") as f:
            json.dump({"last_run": datetime.now(timezone.utc).isoformat(), "interfaces": asked, "answers": answers}, f)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


def report(hit: Dict[str, Any], state: Optional[l2_watch.State] = None) -> bool:
    """Raise the alert for one positive answer (once a day per responder). True if raised."""
    state = state or l2_watch.State()
    if not state.should_alert(f"poisoner:{hit['responder']}"):
        return False
    mac = soc_core.build_ip_to_mac_map().get(hit["responder"])
    emit_alert(Alert(
        type="intrusion", severity="critical", detector="l2_watch", source_ip=hit["responder"],
        title=f"LLMNR/NBT-NS poisoner answering on {hit['iface']}: {hit['responder']} ({hit['protocol']})",
        description=(f"Kali asked the network {hit['network']} to resolve '{hit['name']}', a name invented a moment ago, "
                     f"by {hit['protocol']}, and {hit['responder']}{f' (MAC {mac})' if mac else ''} answered it. No legitimate "
                     "machine can own that name. A tool such as Responder answers every such question with its own address so "
                     "that Windows machines send it their NTLM credentials, which can be cracked offline or relayed to any "
                     "machine that does not require SMB signing. Find the device, take it off the network, and consider what "
                     "the users on this network typed or opened recently. Turning off LLMNR and NBT-NS by group policy "
                     "removes the weakness for good."),
        details={"responder": hit["responder"], "responder_mac": mac, "protocol": hit["protocol"], "queried_name": hit["name"],
                 "interface": hit["iface"], "network": hit["network"]}), echo=False)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="LLMNR / NBT-NS poisoner canary")
    ap.add_argument("--dry-run", action="store_true", help="ask and print, raise no alert")
    ap.add_argument("--iface", action="append", help="only this interface (repeatable)")
    args = ap.parse_args()
    results = run(args.iface)
    if not results:
        print("[*] poisoner_canary: nobody answered a made-up name on any network. Clean.")
        return 0
    for r in results:
        print(f"[!] {r['protocol']} answer on {r['iface']} from {r['responder']} for '{r['name']}'")
        if not args.dry_run:
            report(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
