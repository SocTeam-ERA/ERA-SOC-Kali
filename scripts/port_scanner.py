#!/usr/bin/env python3
"""
port_scanner.py
---------------
Scans one or more hosts / subnets for open TCP ports and raises an alert for
each open port found. Severity is decided by whether the port is a common,
sensitive, or high-risk service.

This is a DEFENSIVE / inventory tool: run it against IP ranges your company
owns and has authorized you to scan. Its job is to notice unexpected open
ports (a sign of misconfiguration or a foothold) and feed them to the SOC
dashboard.

Usage:
    python3 port_scanner.py 10.10.0.0/24
    python3 port_scanner.py 10.10.0.5 10.10.0.6 --ports 1-1024
    python3 port_scanner.py --targets-file targets.txt --top-ports

Notes:
    * Pure Python standard library, so it runs on the Ubuntu server with no
      extra packages. For large ranges, use the Kali nmap scripts instead —
      they are much faster — and forward their results here (see kali/).
    * --workers controls concurrency.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import ipaddress
import socket
import sys
from datetime import datetime, timezone

from soc_core import Alert, emit_alert, resolve_hostname

# Ports we consider high-risk if exposed (management / lateral-movement / legacy)
HIGH_RISK = {
    23: "Telnet (cleartext)",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
    21: "FTP (cleartext)",
    135: "MSRPC",
    139: "NetBIOS",
    1433: "MSSQL",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis (often unauthenticated)",
    27017: "MongoDB",
    9200: "Elasticsearch",
}

# Sensitive-but-normal services -> medium if open on unexpected hosts
SENSITIVE = {
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    110: "POP3",
    143: "IMAP",
    389: "LDAP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

# Ordinary services -> normal
COMMON = {80: "HTTP", 443: "HTTPS"}

# A compact default port set (fast). Override with --ports or --top-ports.
DEFAULT_PORTS = sorted(set(list(HIGH_RISK) + list(SENSITIVE) + list(COMMON)))

TOP_1000_SAMPLE = DEFAULT_PORTS + [
    111, 199, 587, 631, 873, 990, 1080, 1521, 2049, 2181, 2375, 3000,
    4444, 5000, 5601, 5985, 5986, 7001, 8000, 8888, 9000, 9090, 9300, 11211,
]


def classify(port: int) -> tuple[str, str]:
    """Return (severity, service_name) for a port."""
    if port in HIGH_RISK:
        return "critical", HIGH_RISK[port]
    if port in SENSITIVE:
        return "medium", SENSITIVE[port]
    if port in COMMON:
        return "normal", COMMON[port]
    return "medium", "unknown"


def parse_ports(spec: str) -> list[int]:
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def expand_targets(items: list[str]) -> list[str]:
    """Expand CIDR blocks and single IPs/hostnames into a flat host list."""
    hosts: list[str] = []
    for item in items:
        item = item.strip()
        if not item:
            continue
        try:
            net = ipaddress.ip_network(item, strict=False)
            if net.num_addresses > 1:
                hosts.extend(str(h) for h in net.hosts())
            else:
                hosts.append(str(net.network_address))
        except ValueError:
            hosts.append(item)  # hostname
    return hosts


def check_port(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except (socket.gaierror, OSError):
        return False


def scan_host(host: str, ports: list[int], timeout: float, workers: int) -> list[int]:
    open_ports: list[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(check_port, host, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futs):
            if fut.result():
                open_ports.append(futs[fut])
    return sorted(open_ports)


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP port scanner -> SOC alerts")
    ap.add_argument("targets", nargs="*", help="IPs, hostnames, or CIDR blocks")
    ap.add_argument("--targets-file", dest="targets_file",
                    help="File with one target per line")
    ap.add_argument("--ports", default=None, help="e.g. 1-1024 or 22,80,443")
    ap.add_argument("--top-ports", action="store_true", help="Scan a wider common-port set")
    ap.add_argument("--timeout", type=float, default=0.5, help="Per-port timeout seconds")
    ap.add_argument("--workers", type=int, default=100, help="Concurrent socket checks")
    ap.add_argument("--baseline", default=None,
                    help="Comma list of ports expected/allowed on these hosts "
                         "(open ports NOT in the baseline are escalated one level)")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.targets_file:
        try:
            with open(args.targets_file) as fh:
                targets += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
        except OSError as e:
            print(f"[x] cannot read --targets-file {args.targets_file!r}: {e}", file=sys.stderr)
            return 1
    if not targets:
        ap.error("no targets given (pass IPs/CIDRs or --targets file)")

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.top_ports:
        ports = sorted(set(TOP_1000_SAMPLE))
    else:
        ports = DEFAULT_PORTS

    baseline = set(parse_ports(args.baseline)) if args.baseline else None

    hosts = expand_targets(targets)
    print(f"[*] Scanning {len(hosts)} host(s) x {len(ports)} port(s) "
          f"at {datetime.now(timezone.utc).isoformat()}", file=sys.stderr)

    total_open = 0
    for host in hosts:
        open_ports = scan_host(host, ports, args.timeout, args.workers)
        if not open_ports:
            continue
        hostname = resolve_hostname(host)
        for port in open_ports:
            severity, service = classify(port)
            unexpected = baseline is not None and port not in baseline
            if unexpected and severity == "normal":
                severity = "medium"
            elif unexpected and severity == "medium":
                severity = "critical"
            note = " (NOT in baseline)" if unexpected else ""
            emit_alert(Alert(
                type="port_scan",
                severity=severity,
                title=f"Open port {port}/tcp ({service}) on {host}{note}",
                source_ip=host,
                hostname=hostname,
                detector="port_scanner",
                description=f"Discovered open TCP port {port} ({service}) on {host}."
                            f"{' This port is not in the approved baseline.' if unexpected else ''}",
                details={"port": port, "service": service, "unexpected": unexpected},
            ))
            total_open += 1

    print(f"[*] Done. {total_open} open port alert(s) raised.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
