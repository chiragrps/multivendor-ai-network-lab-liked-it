#!/usr/bin/env python3
"""Phase 5-B — Predict Mode (digital-twin what-if).

Takes a proposed config change, simulates its impact on the multivendor
topology, returns a structured before/after diff plus a verdict
(APPROVE | WARN | REJECT) that Health Gate can use as a pre-flight check.

Pluggable backend:

    DCN_PREDICT_PROVIDER=rule-based      (default · stdlib · ~5ms)
    DCN_PREDICT_PROVIDER=batfish         (opt-in · containerized · ~5s)

The rule-based backend parses common config patterns (drop neighbor,
shutdown interface, remove ACL, change ASN) and simulates against the
in-memory BGP/interface topology. The Batfish adapter (lazy-imported)
will run the same query through Batfish for higher-fidelity verification
when the container is available.

Public entry point:

    from predict_engine import predict
    result = predict(target_device="de-fra-core-01",
                     proposed_change="router bgp 65001\\n no neighbor 10.200.0.13\\n!",
                     topology=current_topology)
    # result.verdict, result.reasons, result.diff, result.parsed_op, ...
"""
from __future__ import annotations

import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional, Protocol

log = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════
# DATA TYPES
# ════════════════════════════════════════════════════════════════════════════


CHANGE_KINDS = (
    "drop_bgp_peer",
    "add_bgp_peer",
    "shutdown_interface",
    "no_shutdown_interface",
    "remove_acl_rule",
    "add_acl_rule",
    "change_asn",
    "remove_bgp_process",
    "unknown",
)


@dataclass(frozen=True)
class ChangeOp:
    """Structured representation of a proposed change."""

    kind: str                # one of CHANGE_KINDS
    target_device: str
    target_object: str = ""  # neighbor IP, iface name, ACL name, ASN
    detail: str = ""         # human-readable summary


@dataclass(frozen=True)
class PredictResult:
    target_device: str
    proposed_change: str
    parsed_op: ChangeOp
    before_state: dict
    after_state: dict
    diff: dict
    verdict: str           # APPROVE | WARN | REJECT
    reasons: list[str]
    ms: int
    backend: str
    notes: list[str] = field(default_factory=list)


# ════════════════════════════════════════════════════════════════════════════
# PROVIDER PROTOCOL
# ════════════════════════════════════════════════════════════════════════════


class Predictor(Protocol):
    name: str

    def predict(self, target_device: str, proposed_change: str, topology: dict) -> dict:
        """Returns dict with keys: parsed_op, before, after, diff, verdict, reasons, notes."""
        ...


# ════════════════════════════════════════════════════════════════════════════
# CHANGE-PARSER (regex-based)
# ════════════════════════════════════════════════════════════════════════════


# Pattern set covering Juniper-set, Cisco-IOS, FRR, and Arista-EOS.
# Each tuple: (regex, kind, group-name-of-target-object)
_PARSER_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^\s*no\s+neighbor\s+(?P<obj>\S+)", re.I | re.M),               "drop_bgp_peer"),
    (re.compile(r"^\s*delete\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+(?P<obj>\S+)", re.I | re.M),
                                                                                  "drop_bgp_peer"),
    (re.compile(r"^\s*neighbor\s+(?P<obj>\S+)\s+remote-as", re.I | re.M),         "add_bgp_peer"),
    (re.compile(r"^\s*set\s+protocols\s+bgp\s+group\s+\S+\s+neighbor\s+(?P<obj>\S+)", re.I | re.M),
                                                                                  "add_bgp_peer"),
    (re.compile(r"^\s*interface\s+(?P<obj>\S+)\s*\n\s*shutdown\s*$", re.I | re.M), "shutdown_interface"),
    (re.compile(r"^\s*set\s+interfaces\s+(?P<obj>\S+)\s+disable", re.I | re.M),    "shutdown_interface"),
    (re.compile(r"^\s*interface\s+(?P<obj>\S+)\s*\n\s*no\s+shutdown\s*$", re.I | re.M),
                                                                                  "no_shutdown_interface"),
    (re.compile(r"^\s*no\s+router\s+bgp\s+(?P<obj>\d+)", re.I | re.M),             "remove_bgp_process"),
    (re.compile(r"^\s*delete\s+protocols\s+bgp\s*$", re.I | re.M),                 "remove_bgp_process"),
    (re.compile(r"^\s*router\s+bgp\s+(?P<obj>\d+)", re.I | re.M),                  "change_asn"),
    (re.compile(r"^\s*no\s+access-list\s+(?P<obj>\S+)", re.I | re.M),              "remove_acl_rule"),
    (re.compile(r"^\s*delete\s+firewall\s+filter\s+(?P<obj>\S+)", re.I | re.M),    "remove_acl_rule"),
    (re.compile(r"^\s*access-list\s+(?P<obj>\S+)\s+(permit|deny)", re.I | re.M),   "add_acl_rule"),
    (re.compile(r"^\s*set\s+firewall\s+filter\s+(?P<obj>\S+)", re.I | re.M),       "add_acl_rule"),
]


def parse_change(target_device: str, change_text: str) -> ChangeOp:
    """Parse a config change into a structured ChangeOp. Returns 'unknown' if
    no pattern matched.

    Order matters — first match wins. Most destructive patterns appear first.
    """
    text = change_text or ""
    for rx, kind in _PARSER_RULES:
        m = rx.search(text)
        if m:
            # Patterns like "delete protocols bgp" have no 'obj' group; default to "".
            obj = m.groupdict().get("obj", "") or ""
            return ChangeOp(
                kind=kind,
                target_device=target_device,
                target_object=obj,
                detail=f"{kind} → {obj}" if obj else kind,
            )
    return ChangeOp(
        kind="unknown",
        target_device=target_device,
        target_object="",
        detail="no pattern matched",
    )


# ════════════════════════════════════════════════════════════════════════════
# RULE-BASED PREDICTOR
# ════════════════════════════════════════════════════════════════════════════


class RuleBasedPredictor:
    """Stdlib predictor — simulates change impact against in-memory topology."""

    name = "rule-based-stdlib"

    def predict(self, target_device: str, proposed_change: str, topology: dict) -> dict:
        """Topology shape:
            {
              "devices":      [{"hostname":..., "ip":..., "site":..., "asn":..., ...}],
              "bgp_sessions": [{"peer_a": "...", "peer_b": "...", "asn_a":..., "asn_b":...}],
            }
        """
        op = parse_change(target_device, proposed_change)
        before = self._snapshot(topology, target_device)
        after  = self._apply(topology, op)
        diff   = self._diff(before, after)
        verdict, reasons, notes = self._verdict(op, diff)
        return {
            "parsed_op": op,
            "before":    before,
            "after":     after,
            "diff":      diff,
            "verdict":   verdict,
            "reasons":   reasons,
            "notes":     notes,
        }

    # ── Snapshot current state from topology ─────────────────────────────────

    @staticmethod
    def _snapshot(topology: dict, target_device: str) -> dict:
        devices = topology.get("devices", [])
        sessions = topology.get("bgp_sessions", [])
        # find target device record
        target_record = next((d for d in devices if d.get("hostname") == target_device), None)
        # sessions involving the target
        target_sessions = [
            s for s in sessions
            if s.get("peer_a") == target_device or s.get("peer_b") == target_device
        ]
        return {
            "target_device":          target_device,
            "target_exists":          target_record is not None,
            "target_record":          target_record,
            "device_count":           len(devices),
            "bgp_session_count":      len(sessions),
            "target_session_count":   len(target_sessions),
            "target_sessions":        target_sessions,
            "all_sessions":           sessions,
        }

    # ── Apply parsed op to a deep-ish copy of the topology ───────────────────

    def _apply(self, topology: dict, op: ChangeOp) -> dict:
        devices  = list(topology.get("devices", []))
        sessions = [dict(s) for s in topology.get("bgp_sessions", [])]
        target   = op.target_device
        kind     = op.kind
        obj      = op.target_object

        if kind == "drop_bgp_peer":
            # Drop any session that involves target_device + has the peer IP/hostname matching obj.
            # We check BOTH the IP field and the hostname field because:
            #   - in production traces, neighbor is an IP and peer_b_ip is meaningful
            #   - in lab inventory, peer_b_ip may be "" so we fall back to peer_b hostname
            sessions = [
                s for s in sessions
                if not (
                    (s.get("peer_a") == target and (
                        self._peer_matches(s.get("peer_b_ip", ""), obj)
                        or self._peer_matches(s.get("peer_b", ""), obj)
                    ))
                    or
                    (s.get("peer_b") == target and (
                        self._peer_matches(s.get("peer_a_ip", ""), obj)
                        or self._peer_matches(s.get("peer_a", ""), obj)
                    ))
                )
            ]
        elif kind == "remove_bgp_process":
            # Drop ALL sessions involving target
            sessions = [
                s for s in sessions
                if s.get("peer_a") != target and s.get("peer_b") != target
            ]
        elif kind == "shutdown_interface":
            # Approximate: a shutdown on a core interface may drop sessions over it.
            # Conservative model: assume it drops all sessions to/from the target
            # (because we don't have per-interface session mapping). The verdict
            # output flags this as ambiguous.
            sessions = [
                s for s in sessions
                if s.get("peer_a") != target and s.get("peer_b") != target
            ]
        elif kind == "no_shutdown_interface":
            # Bringing an interface up doesn't lose sessions
            pass
        elif kind == "add_bgp_peer":
            sessions.append({
                "peer_a": target,
                "peer_b": obj,
                "site":   "predicted",
                "synthetic": True,
            })
        elif kind == "change_asn":
            # All sessions would re-negotiate — treat as full drop + readd (ambiguous)
            for s in sessions:
                if s.get("peer_a") == target:
                    s["asn_a"] = obj
                if s.get("peer_b") == target:
                    s["asn_b"] = obj
        # remove_acl_rule / add_acl_rule / unknown → no topology impact in this model

        target_sessions = [
            s for s in sessions
            if s.get("peer_a") == target or s.get("peer_b") == target
        ]
        target_record = next((d for d in devices if d.get("hostname") == target), None)
        return {
            "target_device":          target,
            "target_exists":          target_record is not None,
            "target_record":          target_record,
            "device_count":           len(devices),
            "bgp_session_count":      len(sessions),
            "target_session_count":   len(target_sessions),
            "target_sessions":        target_sessions,
            "all_sessions":           sessions,
        }

    @staticmethod
    def _peer_matches(peer_field: str, parsed_obj: str) -> bool:
        """Match parsed object to a session's peer field.

        Handles IP equality, IP-in-hostname, hostname equality.
        """
        if not peer_field or not parsed_obj:
            return False
        p, o = str(peer_field).strip(), str(parsed_obj).strip()
        return p == o or p.endswith("." + o) or o in p

    # ── Diff before / after ──────────────────────────────────────────────────

    @staticmethod
    def _diff(before: dict, after: dict) -> dict:
        # session-level diff: lost (in before but not after), gained (vice versa)
        def _key(s):
            return tuple(sorted([s.get("peer_a", ""), s.get("peer_b", "")]))

        before_keys = {_key(s) for s in before["target_sessions"]}
        after_keys  = {_key(s) for s in after["target_sessions"]}
        lost = sorted(before_keys - after_keys)
        gained = sorted(after_keys - before_keys)

        # device reachability heuristic: any session lost = peer becomes
        # potentially unreachable through this target. Conservative.
        affected_peers: list[str] = []
        for k in lost:
            for h in k:
                if h and h != before["target_device"]:
                    affected_peers.append(h)
        affected_peers = sorted(set(affected_peers))

        return {
            "bgp_sessions": {
                "before_total":      before["bgp_session_count"],
                "after_total":       after["bgp_session_count"],
                "target_before":     before["target_session_count"],
                "target_after":      after["target_session_count"],
                "lost":               [list(k) for k in lost],
                "gained":             [list(k) for k in gained],
            },
            "reachability": {
                "potentially_affected_peers": affected_peers,
                "affected_count":             len(affected_peers),
            },
        }

    # ── Verdict ──────────────────────────────────────────────────────────────

    @staticmethod
    def _verdict(op: ChangeOp, diff: dict) -> tuple[str, list[str], list[str]]:
        """Returns (verdict, reasons, notes).

        Rules:
          REJECT when 2+ BGP sessions would drop OR an entire BGP process is torn down.
          WARN   when 1 BGP session drops, or change is ambiguous (shutdown), or unknown.
          APPROVE for additive changes or no impact on session count.
        """
        bgp = diff["bgp_sessions"]
        reach = diff["reachability"]
        lost = bgp["lost"]
        gained = bgp["gained"]
        reasons: list[str] = []
        notes: list[str] = []
        verdict = "APPROVE"

        if op.kind == "unknown":
            verdict = "WARN"
            reasons.append("Could not parse the proposed change — manual review required.")
            notes.append("Add a regex pattern for this change type in predict_engine._PARSER_RULES.")
            return verdict, reasons, notes

        if op.kind == "remove_bgp_process":
            verdict = "REJECT"
            reasons.append(f"Removes entire BGP process on {op.target_device} ({bgp['target_before']} sessions).")
            if reach["affected_count"]:
                reasons.append(f"Reachability lost to {reach['affected_count']} peer(s): {', '.join(reach['potentially_affected_peers'])}.")
            return verdict, reasons, notes

        if op.kind == "shutdown_interface":
            verdict = "WARN" if bgp["target_after"] >= bgp["target_before"] else "REJECT"
            if verdict == "REJECT":
                reasons.append(f"Shutdown on {op.target_object} would drop {len(lost)} BGP session(s).")
            else:
                reasons.append(f"Shutdown on {op.target_object} — exact session impact requires per-interface mapping.")
                notes.append("Per-interface session map is approximate. Wire NetBox SoT for precise impact.")
            return verdict, reasons, notes

        if len(lost) >= 2:
            verdict = "REJECT"
            reasons.append(f"{len(lost)} BGP session(s) would drop: {', '.join('↔'.join(p) for p in lost)}")
            if reach["affected_count"]:
                reasons.append(f"Affected peers: {', '.join(reach['potentially_affected_peers'])}")
        elif len(lost) == 1:
            verdict = "WARN"
            reasons.append(f"1 BGP session would drop: {' ↔ '.join(lost[0])}")
        elif gained:
            verdict = "APPROVE"
            reasons.append(f"Additive change — {len(gained)} session(s) gained, no losses.")
        else:
            verdict = "APPROVE"
            reasons.append("No topology impact detected for this change.")

        return verdict, reasons, notes


# ════════════════════════════════════════════════════════════════════════════
# BATFISH ADAPTER (optional, lazy-loaded)
# ════════════════════════════════════════════════════════════════════════════


class BatfishPredictor:
    """Lazy stub — wraps pybatfish + a running Batfish container.

    Falls back gracefully if pybatfish is not installed or the container
    is not reachable. Implementation hook for production-grade verification.
    """

    name = "batfish"

    def __init__(self):
        # Optional dependency: load lazily so missing pybatfish does NOT break
        # the rest of the module. IDE-friendly: importlib hides the "missing
        # module" diagnostic until DCN_PREDICT_PROVIDER=batfish is set.
        import importlib
        importlib.import_module("pybatfish")  # raises ImportError if absent
        # Real impl would init a session here:
        # self.bf = Session(host=os.environ.get("BATFISH_HOST", "localhost"))
        self._lock = threading.RLock()

    def predict(self, target_device: str, proposed_change: str, topology: dict) -> dict:
        # In a real impl: snapshot configs, patch target, run reachability,
        # ACL, and BGP queries via pybatfish, return structured diff.
        # For now: fall back to rule-based and tag the backend name.
        rb = RuleBasedPredictor().predict(target_device, proposed_change, topology)
        rb["notes"].append("batfish-stub: container integration pending; using rule-based result")
        return rb


# ════════════════════════════════════════════════════════════════════════════
# REGISTRY (singleton, env-controlled)
# ════════════════════════════════════════════════════════════════════════════


_PREDICTOR_LOCK = threading.RLock()
_PREDICTOR: Optional[Predictor] = None


def get_predictor() -> Predictor:
    global _PREDICTOR
    with _PREDICTOR_LOCK:
        if _PREDICTOR is not None:
            return _PREDICTOR
        provider = os.environ.get("DCN_PREDICT_PROVIDER", "rule-based").lower()
        if provider == "batfish":
            try:
                _PREDICTOR = BatfishPredictor()
                log.info("Predict backend: Batfish")
            except Exception as e:
                log.warning("Batfish unavailable (%s) — falling back to rule-based", e)
                _PREDICTOR = RuleBasedPredictor()
        else:
            _PREDICTOR = RuleBasedPredictor()
            log.info("Predict backend: %s", _PREDICTOR.name)
        return _PREDICTOR


def reset_predictor() -> None:
    global _PREDICTOR
    with _PREDICTOR_LOCK:
        _PREDICTOR = None


# ════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════════════════


def predict(target_device: str, proposed_change: str, topology: dict) -> PredictResult:
    """Run a what-if prediction and return a fully-populated PredictResult."""
    if not target_device:
        raise ValueError("target_device is required")
    p = get_predictor()
    t0 = time.perf_counter()
    out = p.predict(target_device, proposed_change or "", topology or {})
    ms = int((time.perf_counter() - t0) * 1000)
    return PredictResult(
        target_device=target_device,
        proposed_change=proposed_change or "",
        parsed_op=out["parsed_op"],
        before_state=out["before"],
        after_state=out["after"],
        diff=out["diff"],
        verdict=out["verdict"],
        reasons=out["reasons"],
        notes=out.get("notes", []),
        ms=ms,
        backend=p.name,
    )


__all__ = [
    "ChangeOp",
    "PredictResult",
    "Predictor",
    "RuleBasedPredictor",
    "BatfishPredictor",
    "parse_change",
    "predict",
    "get_predictor",
    "reset_predictor",
    "CHANGE_KINDS",
]
