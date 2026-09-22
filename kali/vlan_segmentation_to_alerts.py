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

With --diff-state, a still-unfixed gap only alerts once instead of every
single night -- confirmed 2026-09-18: this test runs nightly
(soc-vlan-segmentation.timer) and found the SAME 30 of 30 pairs reachable
every run since the finding was escalated to IT, piling up 91 identical
alerts in 3 nights for a problem already known and already reported. Same
pattern nmap_to_alerts.py already uses for vulnerability findings: alert
once when a gap first appears, stay quiet while it's still present, and
emit one low-severity "no longer detected" alert if a pair stops being
reachable (network segmentation actually improved, or that path is
temporarily down -- either way, worth a look, without re-alerting the
original finding to prove it's gone). Without --diff-state, every
reachable pair is always reported on every run (legacy/manual-run
behavior, unchanged).

Usage:
    python3 vlan_segmentation_to_alerts.py results/vlan_segmentation_XXXX.tsv
    python3 vlan_segmentation_to_alerts.py results/vlan_segmentation_XXXX.tsv \
            --diff-state ../data/vlan_segmentation_state.json
"""
from __future__ import annotations
import argparse, json, os, sys, tempfile
from pathlib import Path

SCRIPTS = Path(os.environ.get("SOC_SCRIPTS", Path(__file__).resolve().parent.parent / "scripts"))
sys.path.insert(0, str(SCRIPTS))
from soc_core import Alert, emit_alert, diff_state_lock  # noqa: E402
import watchlists  # noqa: E402

SENSITIVE_VLANS = set(watchlists.get("sensitive_vlans")["entries"])
UNTRUSTED_VLANS = set(watchlists.get("untrusted_vlans")["entries"])


def severity_for(src: str, dst: str) -> str:
    if src in UNTRUSTED_VLANS or dst in SENSITIVE_VLANS or src in SENSITIVE_VLANS:
        return "critical"
    return "medium"


def _load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    os.chmod(tmp, 0o664)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def _gap_alert(src: str, dst: str, src_gw: str, dst_gw: str, sev: str) -> Alert:
    return Alert(
        type="vuln", severity=sev,
        title=f"VLAN segmentation gap: {src} can reach {dst}",
        source_ip=src_gw, detector="vlan_segmentation",
        description=(f"A host on the {src} VLAN was able to reach {dst}'s gateway "
                     f"({dst_gw}) through {dst}'s own gateway path -- these two VLANs "
                     "are not isolated from each other. If this is unexpected, check "
                     "the firewall/router ACLs between them."),
        details={"source_vlan": src, "dest_vlan": dst,
                 "source_gateway": src_gw, "dest_gateway": dst_gw},
    )


def run(path: Path, diff_state: Path | None) -> int:
    lines = path.read_text().splitlines()
    if not lines:
        print("[x] empty results file", file=sys.stderr)
        return 1

    gaps = {}  # (src, dst) -> (src_gw, dst_gw, sev)
    for line in lines[1:]:  # skip header
        parts = line.split("\t")
        if len(parts) != 5:
            continue
        src, dst, src_gw, dst_gw, result = parts
        if result != "REACHABLE":
            continue
        gaps[(src, dst)] = (src_gw, dst_gw, severity_for(src, dst))

    if diff_state is None:
        for (src, dst), (src_gw, dst_gw, sev) in gaps.items():
            emit_alert(_gap_alert(src, dst, src_gw, dst_gw, sev))
        print(f"[*] vlan_segmentation_to_alerts: {len(gaps)} segmentation gap(s) found "
              f"out of {len(lines) - 1} pair(s) tested.")
        return 0

    n = resolved_n = 0
    with diff_state_lock(diff_state):
        previous = _load_state(diff_state)
        new_state = {}
        for (src, dst), (src_gw, dst_gw, sev) in gaps.items():
            key = f"{src}->{dst}"
            new_state[key] = {"source_gateway": src_gw, "dest_gateway": dst_gw}
            if key not in previous:
                emit_alert(_gap_alert(src, dst, src_gw, dst_gw, sev))
                n += 1
            # else: same gap still present and already alerted once -- stay quiet

        for key, old in previous.items():
            if key not in new_state:
                src, _, dst = key.partition("->")
                emit_alert(Alert(
                    type="vuln", severity="normal",
                    title=f"No longer detected (unconfirmed): VLAN segmentation gap {src} -> {dst}",
                    source_ip=old.get("source_gateway"), detector="vlan_segmentation",
                    description=(f"{src} could no longer reach {dst}'s gateway "
                                 f"({old.get('dest_gateway')}) in this run -- either the "
                                 "segmentation gap was fixed, or that path was temporarily "
                                 "unreachable. Not re-alerted as a gap unless it reappears."),
                    details={"source_vlan": src, "dest_vlan": dst, "change": "resolved"},
                ))
                resolved_n += 1

        _save_state(diff_state, new_state)

    print(f"[*] vlan_segmentation_to_alerts: {n} new gap(s), {resolved_n} no-longer-detected, "
          f"{len(gaps)} total reachable pair(s) out of {len(lines) - 1} tested.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results_tsv", help="TSV from 5_vlan_segmentation_test.sh")
    ap.add_argument("--diff-state", help="Path to a JSON state file. If set, only alert on "
                                          "gaps that are new or newly-resolved since the previous run.")
    args = ap.parse_args()
    diff_state = Path(args.diff_state).expanduser().resolve() if args.diff_state else None
    return run(Path(args.results_tsv), diff_state)


if __name__ == "__main__":
    raise SystemExit(main())
