#!/usr/bin/env python3
"""
vlan_segmentation_to_alerts.py
--------------------------------
Turns 5_vlan_segmentation_test.sh's results TSV into SOC alerts: one per
cross-VLAN pair that turned out REACHABLE, i.e. a gap in network
segmentation. A properly segmented network should show ZERO of these --
every reachable pair here is a real finding worth putting in the network
analysis report (this is usually one of the headline findings IT cares
about most: which VLANs can talk to which, versus which ones are supposed
to be isolated).

Severity: Guest/Employee WiFi (the least-trusted network) reaching ANYTHING
else is critical -- that's personal devices on an open-ish network landing
on internal infrastructure. Anything reaching Management or Wiping (the
most sensitive VLANs) is also critical. Every other reachable pair is
medium -- still a real finding, just not the worst-case one.

Usage:
    python3 vlan_segmentation_to_alerts.py results/vlan_segmentation_XXXX.tsv
"""
from __future__ import annotations
import argparse, os, sys
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert  # noqa: E402

SENSITIVE_VLANS = {"Management", "Wiping"}
UNTRUSTED_VLANS = {"Guest-Employee-WiFi"}


def severity_for(src: str, dst: str) -> str:
    if src in UNTRUSTED_VLANS or dst in SENSITIVE_VLANS or src in SENSITIVE_VLANS:
        return "critical"
    return "medium"


def run(path: Path) -> int:
    lines = path.read_text().splitlines()
    if not lines:
        print("[x] empty results file", file=sys.stderr)
        return 1

    n = 0
    for line in lines[1:]:  # skip header
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        src, dst, src_gw, dst_gw, result = parts
        if result != "REACHABLE":
            continue
        sev = severity_for(src, dst)
        emit_alert(Alert(
            type="vuln", severity=sev,
            title=f"VLAN segmentation gap: {src} can reach {dst}",
            source_ip=src_gw, detector="vlan_segmentation",
            description=(f"A host on the {src} VLAN was able to reach {dst}'s gateway "
                         f"({dst_gw}) through {dst}'s own gateway path -- these two VLANs "
                         "are not isolated from each other. If this is unexpected, check "
                         "the firewall/router ACLs between them."),
            details={"source_vlan": src, "dest_vlan": dst,
                     "source_gateway": src_gw, "dest_gateway": dst_gw},
        ))
        n += 1

    print(f"[*] vlan_segmentation_to_alerts: {n} segmentation gap(s) found "
          f"out of {len(lines) - 1} pair(s) tested.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_tsv", help="TSV from 5_vlan_segmentation_test.sh")
    args = ap.parse_args()
    return run(Path(args.results_tsv))


if __name__ == "__main__":
    raise SystemExit(main())
