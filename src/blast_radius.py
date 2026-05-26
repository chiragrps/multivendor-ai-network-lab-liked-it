#!/usr/bin/env python3
"""Phase 5-C — Blast Radius Guard.

Given any proposed network action — shutdown an interface, drop a BGP peer,
modify an ACL, revoke a route — enumerate every downstream device, session,
and service that could be affected. Health Gate uses this as a mandatory
pre-check: if the predicted blast radius is HIGH or CRIT, the apply is
blocked until an operator explicitly approves.

This is the topology-graph layer that complements Phase 5-B (Predict Mode).
While Predict says "this change will drop 5 sessions and reject", Blast
Radius says "those 5 dropped sessions will cascade to 8 devices and 2
customer VRFs at depth-3".

Public entry point:

    from blast_radius import compute_blast_radius
    result = compute_blast_radius(
        action="shutdown_interface",
        target_device="de-fra-core-01",
        target_object="ge-0/0/1",
        topology=current_topology,
        depth=3,
    )
    # result.affected_devices, result.affected_sessions, result.risk_score, ...

Risk scoring:
    LOW   — < 3 devices affected, no customer VRF impact
    MEDIUM— 3-7 devices, no critical service
    HIGH  — 8+ devices OR customer-VRF impact
    CRIT  — loss of redundancy on uplinks OR site isolation
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# DATA TYPES
# ════════════════════════════════════════════════════════════════════════════


ACTIONS = (
    "shutdown_interface",
    "drop_bgp_peer",
    "remove_bgp_process",
    "modify_acl",
    "revoke_route",
)

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRIT")


@dataclass(frozen=True)
class BlastRadius:
    """Frozen blast-radius computation."""

    action:               str
    target_device:        str
    target_object:        str
    depth:                int
    affected_devices:     list[str]         # ordered by BFS layer
    devices_by_hop:       dict[int, list[str]]  # {1: [...], 2: [...], 3: [...]}
    affected_sessions:    list[list[str]]   # [[peer_a, peer_b], ...]
    affected_sites:       list[str]
    affected_services:    list[str]
    isolation_risk:       bool              # would this isolate a site?
    redundancy_lost:      bool              # would this kill last-resort path?
    risk_score:           str               # LOW | MEDIUM | HIGH | CRIT
    approval_required:    bool
    explanation:          str
    ms:                   int


# ════════════════════════════════════════════════════════════════════════════
# CORE: build adjacency from topology
# ════════════════════════════════════════════════════════════════════════════


def _build_adjacency(topology: dict) -> dict[str, set[str]]:
    """Build a hostname → set of neighbor hostnames adjacency from BGP sessions
    (and any LLDP/OSPF edges if present)."""
    adj: dict[str, set[str]] = {}
    for s in topology.get("bgp_sessions", []):
        a = s.get("peer_a") or s.get("a", "")
        b = s.get("peer_b") or s.get("b", "")
        if not a or not b:
            continue
        adj.setdefault(a, set()).add(b)
        adj.setdefault(b, set()).add(a)
    # LLDP edges (optional, may be empty)
    for e in topology.get("lldp_edges", []):
        a = e.get("a", "")
        b = e.get("b", "")
        if a and b:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
    # ensure every device exists in adj so isolated nodes don't crash BFS
    for d in topology.get("devices", []):
        h = d.get("hostname")
        if h:
            adj.setdefault(h, set())
    return adj


def _filter_edges_for_action(
    action: str,
    target_device: str,
    target_object: str,
    topology: dict,
    adj: dict[str, set[str]],
) -> dict[str, set[str]]:
    """For each action type, return a modified adjacency reflecting the
    proposed change. e.g. "shutdown_interface" removes ALL edges from target
    (conservative model), "drop_bgp_peer" removes only one edge.
    """
    # Make a copy we can mutate
    after = {k: set(v) for k, v in adj.items()}

    if action == "remove_bgp_process":
        # All edges from target disappear
        for n in list(after.get(target_device, [])):
            after.setdefault(n, set()).discard(target_device)
        after[target_device] = set()
    elif action == "shutdown_interface":
        # Conservative: assume the interface carries all sessions from target
        # (real impl would consult per-interface session mapping)
        for n in list(after.get(target_device, [])):
            after.setdefault(n, set()).discard(target_device)
        after[target_device] = set()
    elif action == "drop_bgp_peer":
        # Remove specific edge (target ↔ peer)
        peer = target_object
        # try exact hostname or IP match against the inventory devices
        if peer not in after:
            # Match by device that has this peer IP
            for d in topology.get("devices", []):
                # devices may carry an "ip" or "primary_ip" field
                ip = d.get("ip") or d.get("primary_ip") or ""
                if ip == peer:
                    peer = d.get("hostname", peer)
                    break
        after.setdefault(target_device, set()).discard(peer)
        after.setdefault(peer, set()).discard(target_device)
    elif action == "modify_acl":
        # ACL changes don't drop sessions in the topology model
        pass
    elif action == "revoke_route":
        # Hard to model without RIB data; treat as no topology impact
        pass
    return after


# ════════════════════════════════════════════════════════════════════════════
# BFS to find affected devices
# ════════════════════════════════════════════════════════════════════════════


def _bfs_affected(
    before_adj: dict[str, set[str]],
    after_adj: dict[str, set[str]],
    target_device: str,
    depth: int,
) -> tuple[list[str], dict[int, list[str]], list[list[str]]]:
    """Compute the set of devices reachable from target_device through edges
    that EXISTED in before_adj but no longer exist in after_adj. These are
    devices that previously had a path via the target but now do not.

    Returns: (ordered_devices, devices_by_hop, lost_edges)
    """
    # Lost edges = set difference
    lost_edges: list[tuple[str, str]] = []
    for n, peers in before_adj.items():
        new_peers = after_adj.get(n, set())
        for p in peers - new_peers:
            edge = tuple(sorted([n, p]))
            if edge not in [(a, b) for a, b in lost_edges]:
                lost_edges.append(edge)

    # BFS from target_device in the BEFORE adjacency, but only follow
    # lost-edge transitions to find devices that depended on this path.
    affected: list[str] = []
    devices_by_hop: dict[int, list[str]] = {}
    seen = {target_device}

    # Hop 1: direct neighbors that lost the edge to target
    hop1 = []
    for peer in before_adj.get(target_device, set()):
        if peer not in after_adj.get(target_device, set()):
            hop1.append(peer)
    devices_by_hop[1] = sorted(hop1)
    affected.extend(devices_by_hop[1])
    seen.update(hop1)

    # Hop 2..depth: explore beyond direct neighbors, using the AFTER adjacency
    # to find devices that can no longer reach target through any path.
    # Simplified: do BFS from target in BEFORE topology, and tag any node
    # whose ONLY path back went through a lost edge.
    current = list(hop1)
    for hop in range(2, depth + 1):
        next_layer: list[str] = []
        for node in current:
            for nb in before_adj.get(node, set()):
                if nb in seen or nb == target_device:
                    continue
                # Conservative: include all 2+-hop neighbors of hop-1 affected nodes
                next_layer.append(nb)
                seen.add(nb)
        if not next_layer:
            break
        next_layer = sorted(set(next_layer))
        devices_by_hop[hop] = next_layer
        affected.extend(next_layer)
        current = next_layer

    return affected, devices_by_hop, [list(e) for e in lost_edges]


# ════════════════════════════════════════════════════════════════════════════
# RISK SCORING
# ════════════════════════════════════════════════════════════════════════════


def _score_risk(
    affected_devices: list[str],
    affected_sites: list[str],
    affected_services: list[str],
    isolation_risk: bool,
    redundancy_lost: bool,
) -> str:
    """Score the blast radius per the PHASE5_PLAN.md rules.

    LOW    — < 3 devices affected, no customer service impact
    MEDIUM — 3-7 devices, 1-2 sites, no critical service
    HIGH   — 8+ devices OR 3+ sites OR customer-service impact
    CRIT   — isolation of a site or loss of last-resort path
    """
    n = len(affected_devices)
    n_sites = len(affected_sites)
    if isolation_risk or redundancy_lost:
        return "CRIT"
    if n >= 8 or n_sites >= 3 or affected_services:
        return "HIGH"
    if n >= 3:
        return "MEDIUM"
    return "LOW"


def _check_isolation(
    target_device: str,
    target_site: str,
    topology: dict,
    after_adj: dict[str, set[str]],
) -> bool:
    """Would removing target's edges isolate its entire site from the rest?

    Returns True if no device in target's site has an edge to a device
    in another site (after the change is applied).
    """
    if not target_site:
        return False
    by_site: dict[str, set[str]] = {}
    for d in topology.get("devices", []):
        s = d.get("site", "")
        h = d.get("hostname", "")
        if s and h:
            by_site.setdefault(s, set()).add(h)
    site_devices = by_site.get(target_site, set())
    if not site_devices:
        return False
    # For each device in the site, look for at least one off-site neighbor
    for dev in site_devices:
        for nb in after_adj.get(dev, set()):
            # Find what site this neighbor belongs to
            for d in topology.get("devices", []):
                if d.get("hostname") == nb:
                    if d.get("site") and d.get("site") != target_site:
                        return False  # off-site link exists
                    break
    return True  # no off-site links → isolated


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════


def compute_blast_radius(
    action: str,
    target_device: str,
    target_object: str,
    topology: dict,
    depth: int = 3,
) -> BlastRadius:
    """Compute blast radius for a proposed action.

    Args:
        action:         one of ACTIONS
        target_device:  device the action will be applied to
        target_object:  interface name, peer IP, ACL name, ...
        topology:       {"devices": [...], "bgp_sessions": [...], "lldp_edges": [...]}
        depth:          BFS depth (default 3)

    Returns:
        BlastRadius — frozen dataclass with affected devices/sessions/sites,
        risk score, and whether approval is required.
    """
    if action not in ACTIONS:
        raise ValueError(f"unknown action: {action!r} (must be one of {ACTIONS})")
    if not target_device:
        raise ValueError("target_device is required")
    depth = max(1, min(depth, 6))

    t0 = time.perf_counter()

    before_adj = _build_adjacency(topology)
    after_adj = _filter_edges_for_action(
        action, target_device, target_object, topology, before_adj
    )

    affected_devices, devices_by_hop, lost_edges = _bfs_affected(
        before_adj, after_adj, target_device, depth
    )

    # Affected sites
    site_of = {d.get("hostname"): d.get("site", "") for d in topology.get("devices", [])}
    affected_sites = sorted({site_of.get(d, "") for d in affected_devices if site_of.get(d)})
    target_site = site_of.get(target_device, "")

    # Affected services — look up service-to-device map (optional)
    services_by_device = topology.get("services_by_device", {})
    affected_services_set: set[str] = set()
    for d in affected_devices + [target_device]:
        for s in services_by_device.get(d, []):
            affected_services_set.add(s)
    affected_services = sorted(affected_services_set)

    # Isolation + redundancy checks
    isolation_risk = _check_isolation(target_device, target_site, topology, after_adj)
    # Redundancy: target_device had degree N before; if N==1 and we lose it, that's the only path
    redundancy_lost = (
        len(before_adj.get(target_device, set())) == 1
        and len(after_adj.get(target_device, set())) == 0
        and action in ("remove_bgp_process", "shutdown_interface")
    )

    risk = _score_risk(
        affected_devices, affected_sites, affected_services, isolation_risk, redundancy_lost
    )
    approval = risk in ("HIGH", "CRIT") or (risk == "MEDIUM" and len(affected_devices) >= 5)

    explanation = _build_explanation(
        action, target_device, target_object,
        affected_devices, affected_sites, affected_services,
        isolation_risk, redundancy_lost, risk,
    )

    ms = int((time.perf_counter() - t0) * 1000)
    return BlastRadius(
        action=action,
        target_device=target_device,
        target_object=target_object,
        depth=depth,
        affected_devices=affected_devices,
        devices_by_hop=devices_by_hop,
        affected_sessions=lost_edges,
        affected_sites=affected_sites,
        affected_services=affected_services,
        isolation_risk=isolation_risk,
        redundancy_lost=redundancy_lost,
        risk_score=risk,
        approval_required=approval,
        explanation=explanation,
        ms=ms,
    )


def _build_explanation(
    action: str, target_device: str, target_object: str,
    affected_devices: list[str], affected_sites: list[str], affected_services: list[str],
    isolation_risk: bool, redundancy_lost: bool, risk: str,
) -> str:
    """One-paragraph human-readable explanation of the blast radius."""
    parts = [f"{action} on {target_device}"]
    if target_object:
        parts[0] += f"/{target_object}"
    if affected_devices:
        parts.append(f"affects {len(affected_devices)} device(s)")
        if len(affected_devices) <= 4:
            parts[-1] += f" ({', '.join(affected_devices)})"
    if affected_sites and len(affected_sites) > 1:
        parts.append(f"spans {len(affected_sites)} sites ({', '.join(affected_sites)})")
    if affected_services:
        parts.append(f"impacts services: {', '.join(affected_services)}")
    if isolation_risk:
        parts.append("would ISOLATE the entire site")
    if redundancy_lost:
        parts.append("removes the only remaining path")
    parts.append(f"Risk: {risk}")
    return ". ".join(parts) + "."


__all__ = [
    "ACTIONS",
    "RISK_LEVELS",
    "BlastRadius",
    "compute_blast_radius",
]
