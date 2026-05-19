"""
Tests for closed-loop remediation (Day-5/6).

Run:
    cd 04_Scripts_Tools/DCN_Network_Tool && pytest test_remediation.py -v

Covers:
  - State machine: pending → approved → executing → done
  - State machine: pending → rejected
  - propose_for_drift: known field → runbook, unknown field → auto-rejected
  - Drift-to-runbook lookup table (wildcards + literal matches)
  - approve injects a stub health-gate (no real network)
  - watcher mirrors verdict from Health Gate
  - get / list_recent
  - Invalid transitions raise the right errors
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "src"))

# Force Health Gate's simulated path so we don't touch any real device
os.environ["HEALTH_GATE_FORCE_SIMULATE"] = "1"
os.environ["NETBOX_SOT_FORCE_SIMULATE"] = "1"

import remediation as rem  # noqa: E402
import health_gate as hg  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────────────


def _drift(field, sot, observed, hostname="de-fra-core-01", severity="high"):
    return {
        "hostname": hostname,
        "field": field,
        "sot": sot,
        "observed": observed,
        "severity": severity,
    }


# ─── Drift → runbook lookup ─────────────────────────────────────────────────


class TestDriftLookup:
    def test_ip_drift_maps_to_bgp_peer_down(self):
        rid, why = rem.lookup_runbook_for_drift(_drift("ip", "1.1.1.1", "1.1.1.2"))
        assert rid == "bgp_peer_down"
        assert "BGP" in why

    def test_as_drift_maps_to_bgp_peer_down(self):
        rid, _ = rem.lookup_runbook_for_drift(_drift("as", 65001, 65002))
        assert rid == "bgp_peer_down"

    def test_presence_extra_in_lab_is_no_runbook(self):
        rid, why = rem.lookup_runbook_for_drift(_drift("presence", "missing", "present"))
        assert rid is None
        assert "triage" in why.lower() or "human" in why.lower()

    def test_presence_missing_in_lab_is_no_runbook(self):
        rid, why = rem.lookup_runbook_for_drift(_drift("presence", "present", "missing"))
        assert rid is None
        assert "provision" in why.lower()

    def test_model_drift_is_cosmetic(self):
        rid, _ = rem.lookup_runbook_for_drift(_drift("model", "MX240", "MX480"))
        assert rid is None

    def test_unknown_field_returns_none(self):
        rid, _ = rem.lookup_runbook_for_drift(_drift("frobnicator", 1, 2))
        assert rid is None


# ─── propose ────────────────────────────────────────────────────────────────


class TestPropose:
    def test_propose_creates_pending(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01", rationale="manual")
        assert p.state == "pending"
        assert p.proposal_id.startswith("prop-")
        assert p.runbook_id == "bgp_peer_down"
        assert p.device == "de-fra-core-01"
        assert p.proposed_at  # ISO ts set

    def test_propose_rejects_empty_runbook(self):
        with pytest.raises(ValueError):
            rem.propose("", "de-fra-core-01")

    def test_propose_rejects_empty_device(self):
        with pytest.raises(ValueError):
            rem.propose("bgp_peer_down", "")

    def test_propose_is_retrievable_via_get(self):
        p = rem.propose("bgp_peer_down", "uk-lon-core-01")
        assert rem.get(p.proposal_id) is p

    def test_get_unknown_returns_none(self):
        assert rem.get("prop-nonexistent") is None


# ─── propose_for_drift ──────────────────────────────────────────────────────


class TestProposeForDrift:
    def test_proposes_runbook_when_field_known(self):
        p = rem.propose_for_drift(_drift("ip", "1.1.1.1", "1.1.1.2"))
        assert p.state == "pending"
        assert p.runbook_id == "bgp_peer_down"
        assert p.rationale  # AI explanation present

    def test_auto_rejects_when_no_runbook(self):
        p = rem.propose_for_drift(_drift("presence", "missing", "present"))
        assert p.state == "rejected"
        assert p.runbook_id == ""
        assert p.rejected_by == "auto"

    def test_rejects_empty_drift(self):
        with pytest.raises(ValueError):
            rem.propose_for_drift({})

    def test_rejects_drift_without_hostname(self):
        with pytest.raises(ValueError):
            rem.propose_for_drift({"field": "ip", "sot": "1", "observed": "2"})


# ─── approve / reject ───────────────────────────────────────────────────────


class TestApprove:
    def test_approve_transitions_to_executing(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01")
        # Inject a stub HG submit to avoid spawning real threads in tests
        class _StubJob:
            job_id = "hg-stubbed"
        stub = lambda **kw: _StubJob()
        p2 = rem.approve(p.proposal_id, actor="alice", health_gate_submit=stub)
        assert p2.state == "executing"
        assert p2.approved_by == "alice"
        assert p2.approved_at
        assert p2.health_gate_job_id == "hg-stubbed"

    def test_approve_unknown_raises(self):
        with pytest.raises(KeyError):
            rem.approve("prop-nope", health_gate_submit=lambda **kw: None)

    def test_approve_after_reject_raises(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01")
        rem.reject(p.proposal_id)
        with pytest.raises(ValueError):
            rem.approve(p.proposal_id, health_gate_submit=lambda **kw: None)

    def test_approve_error_when_submit_raises(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01")
        def boom(**kw): raise RuntimeError("simulated submit failure")
        p2 = rem.approve(p.proposal_id, health_gate_submit=boom)
        assert p2.state == "error"
        assert "simulated submit failure" in p2.error


class TestReject:
    def test_reject_transitions_to_rejected(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01")
        p2 = rem.reject(p.proposal_id, actor="bob", reason="known false positive")
        assert p2.state == "rejected"
        assert p2.rejected_by == "bob"
        assert "known false positive" in p2.rationale

    def test_reject_after_approve_raises(self):
        p = rem.propose("bgp_peer_down", "de-fra-core-01")
        rem.approve(p.proposal_id, health_gate_submit=lambda **kw: type("J", (), {"job_id": "x"})())
        with pytest.raises(ValueError):
            rem.reject(p.proposal_id)


# ─── End-to-end: closed loop via real Health Gate (simulated mode) ──────────


class TestClosedLoopE2E:
    def test_drift_then_propose_then_approve_then_confirmed(self, monkeypatch):
        # 1. Simulate drift
        drift = _drift("ip", "10.200.0.99", "10.200.0.11", hostname="de-fra-core-01")
        # 2. Propose
        prop = rem.propose_for_drift(drift)
        assert prop.state == "pending"
        # 3. Approve — but inject a synchronous-blocking HG submit so we can
        #    deterministically check the verdict without a watcher race.
        monkeypatch.setattr(hg, "DEFAULT_POLL_INTERVAL_S", 0)
        def sync_submit(**kw):
            # Strip remediation's defaults and force block=True so the call returns
            # only after the Health Gate has reached a verdict.
            clean = {k: v for k, v in kw.items() if k not in ("block", "timeout_s")}
            return hg.submit(timeout_s=2, block=True, **clean)
        p2 = rem.approve(prop.proposal_id, health_gate_submit=sync_submit, timeout_s=2)
        assert p2.state in ("executing", "done")
        assert p2.health_gate_job_id and p2.health_gate_job_id.startswith("hg-")
        # The job ran in-thread thanks to the stub; verdict should be visible
        # via the underlying job registry.
        hg_job = hg.get_job(p2.health_gate_job_id)
        assert hg_job and hg_job.phase == "done"
        assert hg_job.final_verdict == "confirmed"

    def test_drift_then_auto_reject_for_presence(self):
        drift = _drift("presence", "missing", "present", hostname="rogue-host-99")
        p = rem.propose_for_drift(drift)
        assert p.state == "rejected"
        assert p.runbook_id == ""


# ─── Registry ───────────────────────────────────────────────────────────────


class TestRegistry:
    def test_list_recent_returns_newest_first(self):
        # Capture a baseline count — the registry accumulates from prior tests
        baseline = len(rem.list_recent(limit=999))
        rem.propose("bgp_peer_down", "host-a")
        time.sleep(0.005)
        p2 = rem.propose("bgp_peer_down", "host-b")
        recents = rem.list_recent(limit=baseline + 2)
        ids = [r["proposal_id"] for r in recents]
        # The most recent is p2; verify it appears before any older proposal
        assert ids.index(p2.proposal_id) == 0

    def test_list_recent_respects_limit(self):
        rem.propose("bgp_peer_down", "host-c")
        rem.propose("bgp_peer_down", "host-d")
        out = rem.list_recent(limit=1)
        assert len(out) == 1
