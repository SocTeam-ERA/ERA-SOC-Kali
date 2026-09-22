#!/usr/bin/env python3
"""
traffic_to_alerts.py
--------------------
Reads tshark field output (TSV) from a live capture or a .pcap and turns
suspicious traffic into SOC alerts in the common schema. This is the
analysis half of the tshark module; 4_traffic_capture.sh feeds it.

It is passive network monitoring (read-only observation of traffic on an
interface you are authorized to monitor) — it never sends packets.

Expected TSV columns (produced by 4_traffic_capture.sh), tab-separated:
    1 frame.time_epoch
    2 ip.src
    3 ip.dst
    4 tcp.dstport
    5 udp.dstport
    6 _ws.col.Protocol
    7 dns.qry.name
    8 http.host
    9 tcp.flags.syn
   10 tcp.flags.ack

Usage:
    tshark -r cap.pcap -T fields -E separator=/t \\
        -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport \\
        -e _ws.col.Protocol -e dns.qry.name -e http.host \\
        -e tcp.flags.syn -e tcp.flags.ack | python3 traffic_to_alerts.py -

    python3 traffic_to_alerts.py capture_fields.tsv --ioc-ips ioc_ips.txt

Heuristics:
    * Horizontal port scan  : one src touches many distinct dst ports  -> port_scan
    * Cleartext protocol     : Telnet/FTP/POP3/IMAP/SNMP in use          -> intrusion (medium)
    * Talk to known-bad IP   : src/dst in the IOC IP list                -> malware  (critical)
    * Suspicious DNS         : query to high-risk TLD or bad-domain list -> phishing (medium)
"""
from __future__ import annotations
import argparse, ipaddress, os, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, resolve_hostname  # noqa: E402

CLEARTEXT = {23: "Telnet", 21: "FTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 512: "rexec", 513: "rlogin"}
SUSPICIOUS_TLDS = (".ru", ".su", ".top", ".xyz", ".tk", ".gq", ".cf", ".ml", ".zip", ".mov")
PORT_SCAN_THRESHOLD = 15          # distinct dst ports from one src => scan

# Linux's default ephemeral/dynamic port range (net.ipv4.ip_local_port_range). A port in here
# is one OUR OWN kernel assigned to one of our own outbound connections, so if some host shows
# up as the source of packets landing on many of them, that is response traffic answering
# queries we made -- most often DNS, since this box does one every minute (dns_probe.py) on top
# of routine hostname resolution -- not that host scanning us. A real scan targets registered
# service ports (21, 22, 80, 3389, ...); there is nothing to discover by touching our ephemeral
# ports. Confirmed 2026-09-22: our own DNS resolver (10.69.0.14) was flagged as running an
# hourly critical "scan" touching 40-70 ports, every one of them in this exact range.
EPHEMERAL_PORTS = range(32768, 61000)


def _own_ips() -> set:
    """This appliance's own IPv4 addresses. Its normal background traffic (updates, feed
    refreshes, the SOC's own services) touches a few dozen ports and kept being flagged
    as a scan; a wide sweep from here still is one, see the doubled threshold below."""
    try:
        out = subprocess.run(["ip", "-o", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        return set(re.findall(r"inet (\d+\.\d+\.\d+\.\d+)/", out))
    except (OSError, subprocess.SubprocessError):
        return set()
SYN_ONLY_THRESHOLD = 20           # SYN-without-ACK count from one src => scan

TARGETS_FILE = Path(os.environ.get("SOC_TARGETS_FILE", Path(__file__).resolve().parent / "targets.conf"))


def known_gateway_ips(path: Path = TARGETS_FILE) -> set:
    """The .1 address of every VLAN in targets.conf -- by convention the
    router/firewall for that segment (confirmed: 10.201.0.1 is the pfSense
    gateway for the Management VLAN). A gateway NATs/relays traffic for
    every host behind it, so it will legitimately touch dozens of distinct
    ports just from ordinary multi-user traffic (confirmed empirically:
    10.201.0.1 alone sent UDP to 38 distinct ports on one internal host in
    about a minute, almost certainly QUIC/HTTP3 or similar ephemeral-port
    churn relayed through it -- not a scan). Excluding known gateways from
    the port-scan-on-wire heuristic avoids that whole false-positive class;
    they're still covered by the cleartext/IOC/DNS checks below, just not
    this one, since "touches many ports" is meaningless for a router by
    design.
    """
    gateways = set()
    if not path.exists():
        return gateways
    for ln in path.read_text().splitlines():
        ln = ln.split("#", 1)[0].strip()
        if not ln:
            continue
        try:
            net = ipaddress.ip_network(ln, strict=False)
        except ValueError:
            continue
        hosts = net.num_addresses
        if hosts >= 4:  # skip /31, /32 -- no distinct "first host" to speak of
            gateways.add(str(net.network_address + 1))
    return gateways


def load_list(path: str | None) -> set:
    s = set()
    if path and Path(path).exists():
        for ln in Path(path).read_text().splitlines():
            ln = ln.strip().lower()
            if ln and not ln.startswith("#"):
                s.add(ln)
    return s


def _emit(alert: Alert, pcap_path: str | None) -> None:
    """emit_alert(), plus a pointer to the full packet capture for this
    window when one was kept (see 4b_traffic_monitor.sh -- it only retains
    the .pcap for windows that actually raised an alert, everything else
    gets discarded to control disk use). Lets an analyst open the exact
    traffic behind an alert in Wireshark instead of only seeing the
    extracted summary fields."""
    if pcap_path:
        alert.details = {**alert.details, "pcap": pcap_path}
    emit_alert(alert)


def parse(stream, ioc_ips: set, bad_domains: set, pcap_path: str | None = None,
          gateway_ips: set | None = None) -> int:
    gateway_ips = gateway_ips or set()
    dst_ports = defaultdict(set)     # src -> {dst ports}
    syn_only = defaultdict(int)      # src -> count of SYN w/o ACK
    cleartext_hits = defaultdict(int)   # (src,dst,port) -> packet count
    cleartext_info = {}                 # (src,dst,port) -> (service, l4proto)
    ioc_hits = set()
    dns_hits = {}                    # (src, name)

    for line in stream:
        parts = line.rstrip("\n").split("\t")
        parts += [""] * (10 - len(parts))
        ts, src, dst, tdport, udport, proto, dns_q, http_host, syn, ack = parts[:10]
        if not src:
            continue
        port = None
        l4proto = None
        for field, l4 in ((tdport, "tcp"), (udport, "udp")):
            # tshark can emit a comma-separated list when a field occurs more
            # than once in one packet (e.g. an ICMP unreachable wrapping the
            # original TCP header) — take the first value in that case.
            first = field.strip().split(",")[0]
            if first.isdigit():
                port = int(first)
                l4proto = l4
                break

        # port-scan tracking (not on an ephemeral destination port -- see EPHEMERAL_PORTS)
        if port:
            if port not in EPHEMERAL_PORTS:
                dst_ports[src].add(port)
            if syn == "1" and ack in ("0", ""):
                syn_only[src] += 1
            if port in CLEARTEXT:
                # A lone TCP SYN with no ACK is a scan probe touching the
                # port, not a real session -- this project runs a full port
                # sweep every 4h plus a UDP sweep that includes 161/SNMP, and
                # without this check every one of those probes got counted
                # as "cleartext protocol in use" (confirmed: this box's own
                # scan traffic was showing up as its own "intrusion" alerts).
                # A scan probe is a single packet that never repeats to the
                # same (src,dst,port); real traffic (TCP or UDP) always
                # exchanges more than one, so require a second sighting
                # before calling it real.
                is_bare_syn = l4proto == "tcp" and syn == "1" and ack in ("0", "")
                if not is_bare_syn:
                    key = (src, dst, port)
                    cleartext_hits[key] += 1
                    cleartext_info[key] = (CLEARTEXT[port], l4proto)

        # IOC IP match
        for ip in (src, dst):
            if ip and ip.lower() in ioc_ips:
                ioc_hits.add((src, dst, ip))

        # suspicious DNS
        if dns_q:
            name = dns_q.lower().split(",")[0]
            if name.endswith(SUSPICIOUS_TLDS) or name in bad_domains or \
               any(bd in name for bd in bad_domains):
                dns_hits[(src, name)] = http_host or name

    n = 0
    own_ips = _own_ips()
    # 1) port scans
    for src, ports in dst_ports.items():
        if src in gateway_ips:
            continue  # a router legitimately touches many ports relaying traffic -- see known_gateway_ips()
        try:
            if ipaddress.ip_address(src).is_loopback:
                continue  # 127.0.0.0/8 / ::1 traffic never leaves this host, so it can't be
                          # "on the wire" -- confirmed: this box's own desktop session and local
                          # tooling routinely touch dozens of distinct localhost ports (e.g. adb
                          # on 5037 plus a spread of ephemeral ports), which isn't scan behavior.
        except ValueError:
            pass
        own = src in own_ips
        threshold = PORT_SCAN_THRESHOLD * 2 if own else PORT_SCAN_THRESHOLD
        syn_threshold = SYN_ONLY_THRESHOLD * 2 if own else SYN_ONLY_THRESHOLD
        if len(ports) >= threshold or syn_only.get(src, 0) >= syn_threshold:
            sev = "critical" if len(ports) >= PORT_SCAN_THRESHOLD * 2 else "medium"
            _emit(Alert(
                type="port_scan", severity=sev,
                title=f"Port scan on the wire: {src} probed {len(ports)} ports",
                source_ip=src, hostname=resolve_hostname(src), detector="traffic_capture",
                description=f"Host {src} contacted {len(ports)} distinct destination ports "
                            f"({syn_only.get(src,0)} SYN-only) — horizontal scan pattern.",
                details={"distinct_ports": sorted(ports)[:40], "syn_only": syn_only.get(src, 0),
                         "source_role": "actor"},
            ), pcap_path)
            n += 1
    # 2) cleartext protocols -- only once a (src,dst,port) triple was seen
    # more than once (see the comment where cleartext_hits is built).
    for key, (svc, l4proto) in cleartext_info.items():
        if cleartext_hits[key] < 2:
            continue
        src, dst, port = key
        try:
            if ipaddress.ip_address(src).is_loopback or ipaddress.ip_address(dst).is_loopback:
                continue  # same reasoning as the port-scan loopback skip above: 127.0.0.0/8
                          # traffic never leaves this host, so it isn't "on the wire" cleartext
                          # exposure -- confirmed: this box's own local tooling talking to a
                          # service on 127.0.0.1 was showing up as a fake cleartext-protocol alert.
        except ValueError:
            pass
        _emit(Alert(
            type="intrusion", severity="medium",
            title=f"Cleartext protocol {svc} ({port}/{l4proto}): {src} → {dst}",
            source_ip=src, hostname=resolve_hostname(src), detector="traffic_capture",
            description=f"{svc} traffic seen from {src} to {dst}. Cleartext protocols expose "
                        f"credentials on the wire; migrate to an encrypted equivalent.",
            details={"service": svc, "port": port, "proto": l4proto, "dst": dst,
                     "dst_hostname": resolve_hostname(dst), "source_role": "asset"},
        ), pcap_path)
        n += 1
    # 3) IOC IP contact
    for (src, dst, ip) in ioc_hits:
        _emit(Alert(
            type="malware", severity="critical",
            title=f"Traffic to/from known-bad IP {ip}",
            source_ip=src, hostname=resolve_hostname(src), detector="traffic_capture",
            description=f"Observed communication involving IOC IP {ip} ({src} ↔ {dst}).",
            # the known-bad IP itself may be the source (it contacted us): then it is the actor
            details={"ioc_ip": ip, "src": src, "dst": dst,
                     "source_role": "actor" if src == ip else "asset"},
        ), pcap_path)
        n += 1
    # 4) suspicious DNS
    for (src, name), host in dns_hits.items():
        _emit(Alert(
            type="phishing", severity="medium",
            title=f"Suspicious DNS query: {name}",
            source_ip=src, hostname=resolve_hostname(src), detector="traffic_capture",
            description=f"{src} resolved {name}, a high-risk / flagged domain.",
            details={"query": name, "source_role": "asset"},
        ), pcap_path)
        n += 1
    return n


def main() -> int:
    ap = argparse.ArgumentParser(description="tshark traffic → SOC alerts")
    ap.add_argument("input", help="TSV file of tshark fields, or '-' for stdin")
    ap.add_argument("--ioc-ips", help="File of known-bad IPs (one per line)")
    ap.add_argument("--bad-domains", help="File of known-bad domains (one per line)")
    ap.add_argument("--pcap", help="Path to the full packet capture this TSV was extracted "
                    "from -- recorded in every alert's details so an analyst can open the "
                    "exact traffic in Wireshark. Omit if no .pcap was kept for this run.")
    args = ap.parse_args()

    ioc_ips = load_list(args.ioc_ips or str(Path(__file__).parent / "ioc_ips.txt"))
    bad_domains = load_list(args.bad_domains or str(Path(__file__).parent / "bad_domains.txt"))

    stream = sys.stdin if args.input == "-" else open(args.input, encoding="utf-8", errors="ignore")
    total = parse(stream, ioc_ips, bad_domains, pcap_path=args.pcap, gateway_ips=known_gateway_ips())
    if stream is not sys.stdin:
        stream.close()
    print(f"[*] traffic_to_alerts: raised {total} alert(s) from captured traffic.", file=sys.stderr)
    # Plain count on stdout (separate from the human-readable line above,
    # which goes to stderr) -- 4b_traffic_monitor.sh reads this to decide
    # whether to keep this window's .pcap. It used to diff alerts.jsonl's
    # line count before/after instead, but that file is shared by every
    # detector in the system (login/osquery/zeek/suricata/scans all write
    # to it concurrently) -- an unrelated alert landing in that same
    # instant made it look like this traffic window raised something when
    # it didn't. This total is specific to this one invocation, race-free.
    print(total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
