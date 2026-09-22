#!/usr/bin/env python3
"""
soc_graph.py
------------
Builds the node/edge graph Sentinel calls the "investigation graph": start
from an incident or an entity (IP/MAC/host/user) and see everything it
touches -- its alerts, the incidents those alerts belong to, and every
other entity that shows up in the same alerts, which is the actual
investigative payoff (this IP's other alert also shares a host with a
critical finding from yesterday, say).

Read-only, and deliberately thin: it reuses soc_views' entity index and
correlate's incident store rather than re-deriving either, so this graph
and the plain entity/incident pages can never disagree about what an
entity's alerts are.

Shape returned by both functions: {"nodes": [...], "edges": [...]}.
  node: {"id", "kind", "label", ...kind-specific fields}
    kind is one of: incident, alert, ip, mac, host, user
  edge: {"from": node id, "to": node id, "label": short relationship name}
Every node id is stable and globally unique across a single graph (an
entity's id is its canonical "type:value" key, an alert's is "alert:<id>",
an incident's is "incident:<id>"), so the same entity or alert appearing
through two different paths collapses into one node -- that convergence is
the whole point of a graph view over a flat list.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import correlate
import soc_core
import soc_views

ENTITY_KINDS = ("ip", "mac", "host", "user")
# Caps keep one graph request bounded and the resulting graph actually readable --
# a heavily-alerted entity (a busy gateway, a shared printer) could otherwise pull
# in hundreds of loosely-related alerts and swamp both the response and the UI.
MAX_RELATED_ALERTS = 30
MAX_ENTITY_ALERTS = 30


def _alert_node(a: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": f"alert:{a['id']}", "kind": "alert", "label": a.get("title"),
            "severity": a.get("severity"), "detector": a.get("detector"),
            "status": a.get("status", "open"), "timestamp": a.get("timestamp")}


def _incident_node(inc: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": f"incident:{inc['id']}", "kind": "incident",
            "label": f"Incident #{inc['number']}: {inc['title']}",
            "severity": inc["severity"], "status": inc["status"]}


def _entity_node(key: str) -> Dict[str, Any]:
    kind, _, value = key.partition(":")
    return {"id": key, "kind": kind, "label": value}


def _add_entity_edges(a: Dict[str, Any], alert_node_id: str, nodes: Dict[str, Any],
                      edges: List[Dict[str, Any]], skip: Optional[str] = None) -> None:
    """Every entity `a` mentions becomes an edge from its alert node (or is skipped if it
    IS the entity this whole graph is centered on -- that edge would be redundant)."""
    for e in soc_views._entities_of(a):
        if e["type"] not in ENTITY_KINDS:
            continue
        key = soc_views.canonical(f"{e['type']}:{e['value']}")
        if key == skip:
            continue
        nodes.setdefault(key, _entity_node(key))
        edges.append({"from": alert_node_id, "to": key, "label": e.get("role") or "related"})


def incident_graph(ref: str) -> Optional[Dict[str, Any]]:
    """Centered on one incident: the incident, every alert it contains, every entity
    those alerts mention, and -- the useful part -- every OTHER alert (outside this
    incident) that shares one of those entities."""
    inc = correlate.get_incident(ref)
    if inc is None:
        return None
    by_id = {a["id"]: a for a in soc_core._load_snapshot()}
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []

    inc_id = f"incident:{inc['id']}"
    nodes[inc_id] = _incident_node(inc)
    entity_keys: set = set()
    for aid in inc["alert_ids"]:
        a = by_id.get(aid)
        alert_id = f"alert:{aid}"
        nodes[alert_id] = _alert_node(a) if a else {"id": alert_id, "kind": "alert",
                                                     "label": aid, "in_feed": False}
        edges.append({"from": inc_id, "to": alert_id, "label": "contains"})
        if a is None:
            continue  # aged out of the snapshot cap -- still listed, just no detail
        before = set(nodes)
        _add_entity_edges(a, alert_id, nodes, edges)
        entity_keys |= (set(nodes) - before)

    index = soc_views._entity_index()
    added = 0
    for key in entity_keys:
        if added >= MAX_RELATED_ALERTS:
            break
        for a in index.get(key, {}).get("alerts", []):
            if added >= MAX_RELATED_ALERTS or a.get("id") in inc["alert_ids"] or a.get("test"):
                continue
            alert_id = f"alert:{a['id']}"
            if alert_id not in nodes:
                nodes[alert_id] = _alert_node(a)
                added += 1
            edges.append({"from": key, "to": alert_id, "label": "also_in"})
    return {"nodes": list(nodes.values()), "edges": edges}


def entity_graph(ref: str) -> Optional[Dict[str, Any]]:
    """Centered on one entity: the entity, its most recent alerts, the incidents those
    alerts belong to, and every OTHER entity that shows up alongside it in those same
    alerts -- one hop out, the natural "what else is this connected to" pivot."""
    key = soc_views.canonical(ref)
    data = soc_views._entity_index().get(key)
    if data is None:
        return None
    nodes: Dict[str, Dict[str, Any]] = {key: _entity_node(key)}
    edges: List[Dict[str, Any]] = []
    alerts = sorted(data["alerts"], key=lambda a: a.get("timestamp", ""), reverse=True)[:MAX_ENTITY_ALERTS]
    seen_incidents: set = set()
    for a in alerts:
        alert_id = f"alert:{a['id']}"
        nodes[alert_id] = _alert_node(a)
        edges.append({"from": key, "to": alert_id, "label": "involves"})
        inc_ref = (a.get("details") or {}).get("incident_id")
        if inc_ref and inc_ref not in seen_incidents:
            seen_incidents.add(inc_ref)
            inc = correlate.get_incident(inc_ref)
            if inc:
                inc_id = f"incident:{inc['id']}"
                nodes[inc_id] = _incident_node(inc)
                edges.append({"from": alert_id, "to": inc_id, "label": "part_of"})
        _add_entity_edges(a, alert_id, nodes, edges, skip=key)
    return {"nodes": list(nodes.values()), "edges": edges}
