"""
Closed-loop remediation — Day-5/6.

Composes Day-1 (Health Gate) and Day-3/4 (NetBox SoT) into one workflow:

    drift detected   →   AI proposes a runbook   →   human approves
                                                          │
                                                          ▼
                              runbook executes THROUGH Health Gate
                              (so the fix itself gets the confirmed-commit watch)
                                                          │
                                          ┌───────────────┴───────────────┐
                                          ▼                               ▼
                                    confirmed                       abandoned
                                  (drift cleared)              (auto-reverted by device)

Public surface
--------------
    propose(runbook_id, device, ...)      → Proposal
    propose_for_drift(drift_row)          → Proposal (auto-picks runbook)
    approve(proposal_id, actor)           → Proposal (kicks Health Gate)
    reject(proposal_id, actor)            → Proposal
    get(proposal_id)                      → Proposal | None
    list_recent(limit)                    → list[dict]

State machine
-------------
    pending  ──approve──▶ approved ──submit──▶ executing ──HG done──▶ done
        │                                                       │
        ├──reject──▶ rejected                                   └──HG error──▶ error
"""
from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable


# ──────────────────────────────────────────────────────────────────────────────
# Drift → runbook catalog
# ──────────────────────────────────────────────────────────────────────────────
#
# Maps the *kind* of drift to the runbook that most plausibly fixes it. This is
# intentionally a small static table for the demo — in a real deployment an LLM
# would propose with a confidence score. The mapping returns None when no auto-
# remediation is appropriate (e.g. extra-in-lab presence drift needs human
# investigation, not a runbook).
#
# Schema: (field, sot_value, observed_value) → runbook_id | None.
# Wildcards: use "*" for any.
#
_DRIFT_TO_RUNBOOK: list[tuple[str, str, str, str | None, str]] = [
    # (field,        sot_match, observed_match, runbook_id,           rationale)
    ("presence",     "missing", "present",      None,                 "Extra-in-lab device — needs human triage, not auto-remediation."),
    ("presence",     "present", "missing",      None,                 "Planned device not deployed — provisioning task, not a runbook."),
    ("ip",           "*",       "*",            "bgp_peer_down",      "IP drift on a router commonly breaks BGP sessions — diagnose with bgp_peer_down."),
    ("as",           "*",       "*",            "bgp_peer_down",      "ASN drift breaks BGP — diagnose with bgp_peer_down."),
    ("site",         "*",       "*",            None,                 "Site mismatch is a metadata error, not a runtime issue."),
    ("vendor",       "*",       "*",            None,                 "Vendor mismatch indicates a model/inventory bug, not a runtime issue."),
    ("role",         "*",       "*",            None,                 "Role mismatch is a metadata error."),
    ("model",        "*",       "*",            None,                 "Model mismatch is cosmetic — no remediation."),
    ("os",           "*",       "*",            None,                 "OS mismatch is cosmetic — no remediation."),
]


# ──────────────────────────────────────────────────────────────────────────────
# Datamodel
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Proposal:
    proposal_id: str
    runbook_id: str
    device: str
    state: str = "pending"  # pending | approved | rejected | executing | done | error
    rationale: str = ""
    drift_row: dict | None = None
    proposed_at: str = ""
    approved_at: str | None = None
    approved_by: str | None = None
    rejected_at: str | None = None
    rejected_by: str | None = None
    health_gate_job_id: str | None = None
    verdict: str | None = None  # confirmed | abandoned | error
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# In-memory registry (single-worker assumption matches the rest of app.py)
# ──────────────────────────────────────────────────────────────────────────────


_PROPOSALS: dict[str, Proposal] = {}
_LOCK = threading.RLock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _store(p: Proposal) -> None:
    with _LOCK:
        _PROPOSALS[p.proposal_id] = p


def get(proposal_id: str) -> Proposal | None:
    with _LOCK:
        return _PROPOSALS.get(proposal_id)


def list_recent(limit: int = 20) -> list[dict]:
    with _LOCK:
        items = sorted(_PROPOSALS.values(), key=lambda p: p.proposed_at, reverse=True)
    return [p.to_dict() for p in items[:limit]]


# ──────────────────────────────────────────────────────────────────────────────
# Drift → runbook lookup
# ──────────────────────────────────────────────────────────────────────────────


def lookup_runbook_for_drift(drift_row: dict) -> tuple[str | None, str]:
    """Return (runbook_id, rationale) for a drift row, or (None, reason)."""
    fld = drift_row.get("field") or ""
    sot = str(drift_row.get("sot") or "")
    obs = str(drift_row.get("observed") or "")
    for f, s_match, o_match, rid, rationale in _DRIFT_TO_RUNBOOK:
        if f != fld:
            continue
        if s_match != "*" and s_match != sot:
            continue
        if o_match != "*" and o_match != obs:
            continue
        return rid, rationale
    return None, f"No runbook mapping for drift field={fld!r}."


# ──────────────────────────────────────────────────────────────────────────────
# Public API — propose / approve / reject
# ──────────────────────────────────────────────────────────────────────────────


def propose(
    runbook_id: str,
    device: str,
    *,
    drift_row: dict | None = None,
    rationale: str = "",
) -> Proposal:
    """Create a pending proposal. Idempotent only by proposal_id (new each call)."""
    if not runbook_id:
        raise ValueError("runbook_id required")
    if not device:
        raise ValueError("device required")
    p = Proposal(
        proposal_id=f"prop-{uuid.uuid4().hex[:12]}",
        runbook_id=runbook_id,
        device=device,
        drift_row=drift_row,
        rationale=rationale or "",
        proposed_at=_now_iso(),
    )
    _store(p)
    _record_gait(p, "propose", "ok")
    return p


def propose_for_drift(drift_row: dict) -> Proposal:
    """AI-proposer: pick a runbook for a drift row and propose it.

    If no runbook fits, still create a proposal in `rejected` state with the
    rationale explaining *why* no auto-remediation is appropriate. This gives
    the audit trail a record that the system *considered* the drift.
    """
    if not drift_row:
        raise ValueError("drift_row required")
    device = drift_row.get("hostname") or ""
    if not device:
        raise ValueError("drift_row missing hostname")
    runbook_id, rationale = lookup_runbook_for_drift(drift_row)
    if runbook_id is None:
        # Auto-reject — record-only, no action
        p = Proposal(
            proposal_id=f"prop-{uuid.uuid4().hex[:12]}",
            runbook_id="",
            device=device,
            state="rejected",
            drift_row=drift_row,
            rationale=rationale,
            proposed_at=_now_iso(),
            rejected_at=_now_iso(),
            rejected_by="auto",
        )
        _store(p)
        _record_gait(p, "auto_reject", "blocked")
        return p
    return propose(runbook_id, device, drift_row=drift_row, rationale=rationale)


def approve(
    proposal_id: str,
    actor: str = "operator",
    *,
    health_gate_submit: Callable | None = None,
    timeout_s: int = 30,
) -> Proposal:
    """Approve a pending proposal and kick the Health Gate.

    The Health Gate runs in its own thread; this function returns immediately
    once the job is submitted. The proposal transitions through
    pending → approved → executing, then later → done|error.

    `health_gate_submit` lets tests inject a stub instead of the real module.
    """
    p = get(proposal_id)
    if not p:
        raise KeyError(f"proposal {proposal_id} not found")
    if p.state != "pending":
        raise ValueError(f"cannot approve from state={p.state}")
    p.state = "approved"
    p.approved_at = _now_iso()
    p.approved_by = actor or "operator"
    _record_gait(p, "approve", "ok")

    # Kick the Health Gate. Lazy import to keep this module test-friendly.
    if health_gate_submit is None:
        try:
            import health_gate as hg  # noqa: WPS433 (intentional local import)
            health_gate_submit = hg.submit
        except ImportError:
            p.state = "error"
            p.error = "health_gate module not importable"
            _record_gait(p, "submit", "error")
            return p

    try:
        job = health_gate_submit(
            hostname=p.device,
            edit_payload=f"<!-- runbook:{p.runbook_id} via remediation:{p.proposal_id} -->",
            timeout_s=timeout_s,
            block=False,
        )
        p.state = "executing"
        p.health_gate_job_id = getattr(job, "job_id", None)
        _record_gait(p, "submit", "ok")
        # Background watcher: poll the job until done, then mirror verdict.
        if p.health_gate_job_id:
            t = threading.Thread(
                target=_watch_job, args=(p.proposal_id,), daemon=True,
            )
            t.start()
    except Exception as exc:
        p.state = "error"
        p.error = str(exc)
        _record_gait(p, "submit", "error")
    return p


def reject(proposal_id: str, actor: str = "operator", reason: str = "") -> Proposal:
    p = get(proposal_id)
    if not p:
        raise KeyError(f"proposal {proposal_id} not found")
    if p.state != "pending":
        raise ValueError(f"cannot reject from state={p.state}")
    p.state = "rejected"
    p.rejected_at = _now_iso()
    p.rejected_by = actor or "operator"
    if reason:
        p.rationale = (p.rationale + "\n" if p.rationale else "") + f"REJECT: {reason}"
    _record_gait(p, "reject", "blocked")
    return p


# ──────────────────────────────────────────────────────────────────────────────
# Background watcher
# ──────────────────────────────────────────────────────────────────────────────


def _watch_job(proposal_id: str) -> None:
    """Poll the Health Gate job until done, then mirror its verdict."""
    import time
    try:
        import health_gate as hg  # noqa: WPS433
    except ImportError:
        return
    p = get(proposal_id)
    if not p or not p.health_gate_job_id:
        return
    # Cap the watcher so a stuck HG doesn't leak a thread forever.
    deadline = time.monotonic() + 600  # 10 min hard ceiling
    while time.monotonic() < deadline:
        job = hg.get_job(p.health_gate_job_id)
        if job and job.phase == "done":
            p.verdict = job.final_verdict
            p.state = "done" if job.final_verdict != "error" else "error"
            if job.error:
                p.error = job.error
            _record_gait(p, "verdict", "ok" if p.verdict == "confirmed" else "blocked")
            return
        time.sleep(1)


# ──────────────────────────────────────────────────────────────────────────────
# GAIT helper
# ──────────────────────────────────────────────────────────────────────────────


def _record_gait(p: Proposal, action: str, status: str) -> None:
    """Best-effort GAIT logging — never raises (audit must not break flow)."""
    try:
        import gait_audit as g  # noqa: WPS433
    except ImportError:
        return
    try:
        g.record(
            actor="remediation",
            action=f"{action}:{p.runbook_id or 'none'}",
            target=p.device,
            tools_called=[p.runbook_id] if p.runbook_id else [],
            status=status,
            extra={
                "proposal_id": p.proposal_id,
                "state": p.state,
                "health_gate_job_id": p.health_gate_job_id,
                "verdict": p.verdict,
            },
        )
    except Exception:
        pass


__all__ = [
    "Proposal",
    "propose",
    "propose_for_drift",
    "approve",
    "reject",
    "get",
    "list_recent",
    "lookup_runbook_for_drift",
]
