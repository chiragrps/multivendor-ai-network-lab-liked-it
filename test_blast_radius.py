"""Phase 5-C — blast_radius unit tests.

Run with:  pytest test_blast_radius.py -v
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "src"))

from blast_radius import (  # noqa: E402
    ACTIONS,
    RISK_LEVELS,
    BlastRadius,
    compute_blast_radius,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def small_topo():
    """4-device hub-and-spoke around de-fra-core-01."""
    return {
        "devices": [
            {"hostname": "de-fra-core-01", "site": "DE-FRA"},
            {"hostname": "de-fra-core-02", "site": "DE-FRA"},
            {"hostname": "uk-lon-core-01", "site": "UK-LON"},
            {"hostname": "us-nyc-core-01", "site": "US-NYC"},
        ],
        "bgp_sessions": [
            {"peer_a": "de-fra-core-01", "peer_b": "de-fra-core-02"},
            {"peer_a": "de-fra-core-01", "peer_b": "uk-lon-core-01"},
            {"peer_a": "de-fra-core-01", "peer_b": "us-nyc-core-01"},
        ],
    }


@pytest.fixture
def wide_topo():
    """8-device, 4-site topology that should trigger HIGH on cross-site shutdown."""
    return {
        "devices": [
            {"hostname": "de-fra-core-01", "site": "DE-FRA"},
            {"hostname": "de-fra-core-02", "site": "DE-FRA"},
            {"hostname": "de-fra-edge-01", "site": "DE-FRA"},
            {"hostname": "uk-lon-core-01", "site": "UK-LON"},
            {"hostname": "uk-lon-edge-01", "site": "UK-LON"},
            {"hostname": "us-nyc-core-01", "site": "US-NYC"},
            {"hostname": "nl-ams-core-01", "site": "NL-AMS"},
            {"hostname": "nl-ams-edge-01", "site": "NL-AMS"},
        ],
        "bgp_sessions": [
            {"peer_a": "de-fra-core-01", "peer_b": "de-fra-core-02"},
            {"peer_a": "de-fra-core-01", "peer_b": "de-fra-edge-01"},
            {"peer_a": "de-fra-core-01", "peer_b": "uk-lon-core-01"},
            {"peer_a": "de-fra-core-01", "peer_b": "us-nyc-core-01"},
            {"peer_a": "de-fra-core-02", "peer_b": "nl-ams-core-01"},
            {"peer_a": "uk-lon-core-01", "peer_b": "uk-lon-edge-01"},
            {"peer_a": "nl-ams-core-01", "peer_b": "nl-ams-edge-01"},
        ],
    }


@pytest.fixture
def single_link_topo():
    """A device with only one peer — losing that peer leaves it stranded."""
    return {
        "devices": [
            {"hostname": "lone-edge-01", "site": "SMALL"},
            {"hostname": "core-01",       "site": "SMALL"},
        ],
        "bgp_sessions": [
            {"peer_a": "lone-edge-01", "peer_b": "core-01"},
        ],
    }


# ─── Action validation ───────────────────────────────────────────────────────


class TestActionValidation:
    def test_unknown_action_raises(self, small_topo):
        with pytest.raises(ValueError, match="unknown action"):
            compute_blast_radius("delete_universe", "de-fra-core-01", "", small_topo)

    def test_empty_target_raises(self, small_topo):
        with pytest.raises(ValueError, match="target_device"):
            compute_blast_radius("shutdown_interface", "", "eth0", small_topo)

    @pytest.mark.parametrize("action", list(ACTIONS))
    def test_each_action_returns_a_blastradius(self, small_topo, action):
        r = compute_blast_radius(action, "de-fra-core-01", "eth0", small_topo, depth=2)
        assert isinstance(r, BlastRadius)
        assert r.action == action
        assert r.risk_score in RISK_LEVELS


# ─── Risk scoring ────────────────────────────────────────────────────────────


class TestRiskScoring:
    def test_low_for_acl_change(self, small_topo):
        r = compute_blast_radius("modify_acl", "de-fra-core-01", "MGMT-IN", small_topo)
        assert r.risk_score == "LOW"
        assert r.affected_devices == []

    def test_low_for_dropping_one_peer(self, small_topo):
        r = compute_blast_radius("drop_bgp_peer", "de-fra-core-01", "de-fra-core-02", small_topo)
        assert r.risk_score == "LOW"
        assert "de-fra-core-02" in r.affected_devices
        assert len(r.affected_devices) == 1

    def test_high_for_cross_site_shutdown(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "ge-0/0/1", wide_topo, depth=3)
        assert r.risk_score == "HIGH"  # 5 affected, 4 sites → HIGH per the 3+-site rule
        assert len(r.affected_sites) >= 3
        assert r.approval_required is True

    def test_crit_for_isolation(self, single_link_topo):
        # lone-edge-01 has only one peer; shutting its interface isolates it
        r = compute_blast_radius("shutdown_interface", "lone-edge-01", "eth0", single_link_topo)
        assert r.risk_score == "CRIT"
        assert r.isolation_risk is True or r.redundancy_lost is True

    def test_approval_required_for_high(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "ge-0/0/1", wide_topo)
        assert r.approval_required is True

    def test_no_approval_for_low(self, small_topo):
        r = compute_blast_radius("drop_bgp_peer", "de-fra-core-01", "de-fra-core-02", small_topo)
        assert r.approval_required is False


# ─── BFS correctness ─────────────────────────────────────────────────────────


class TestBFS:
    def test_hop1_neighbors_correct(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=1)
        # de-fra-core-01 has 4 direct neighbors
        assert set(r.devices_by_hop.get(1, [])) == {
            "de-fra-core-02", "de-fra-edge-01", "uk-lon-core-01", "us-nyc-core-01"
        }

    def test_depth_limit_respected(self, wide_topo):
        r3 = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=3)
        r1 = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=1)
        # depth=1 should never include hop2/3 nodes
        assert max(r1.devices_by_hop.keys() or [0]) == 1
        # depth=3 should include the hop-2 spread
        assert max(r3.devices_by_hop.keys() or [0]) >= 2

    def test_target_not_in_affected_list(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo)
        assert "de-fra-core-01" not in r.affected_devices

    def test_lost_edges_listed(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo)
        assert len(r.affected_sessions) >= 1
        # Each is a 2-list
        for s in r.affected_sessions:
            assert len(s) == 2


# ─── Affected sites + services ───────────────────────────────────────────────


class TestAffectedSites:
    def test_sites_extracted_correctly(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=2)
        # Should at least include the sites of de-fra-core-01's direct neighbors
        assert "DE-FRA" in r.affected_sites
        assert "UK-LON" in r.affected_sites

    def test_no_sites_for_acl_change(self, wide_topo):
        r = compute_blast_radius("modify_acl", "de-fra-core-01", "MGMT-IN", wide_topo)
        # ACL changes don't touch topology
        assert r.affected_sites == []

    def test_services_picked_up_when_provided(self, small_topo):
        small_topo["services_by_device"] = {"de-fra-core-02": ["customer-vrf-01"]}
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", small_topo)
        assert "customer-vrf-01" in r.affected_services
        # Service impact forces HIGH or CRIT (CRIT wins when the change also
        # isolates the target's site — de-fra-core-01 is the sole DE-FRA node).
        assert r.risk_score in ("HIGH", "CRIT")
        assert r.approval_required is True


# ─── Explanation text ────────────────────────────────────────────────────────


class TestExplanation:
    def test_explanation_contains_target(self, small_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", small_topo)
        assert "de-fra-core-01" in r.explanation
        assert "eth0" in r.explanation

    def test_explanation_contains_risk(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo)
        assert "Risk:" in r.explanation
        assert r.risk_score in r.explanation


# ─── Performance ─────────────────────────────────────────────────────────────


class TestPerformance:
    def test_single_compute_under_50ms(self, wide_topo):
        t0 = time.perf_counter()
        compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo)
        ms = (time.perf_counter() - t0) * 1000
        assert ms < 50, f"compute took {ms:.1f}ms (target < 50ms)"

    def test_1000_computations_under_1s(self, wide_topo):
        t0 = time.perf_counter()
        for _ in range(1000):
            compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo)
        total = time.perf_counter() - t0
        assert total < 1.0, f"1000 computations took {total:.2f}s (target < 1s)"


# ─── Edge cases ──────────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_topology(self):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0",
                                 {"devices": [], "bgp_sessions": []})
        # No neighbors → no affected devices → LOW (or CRIT if redundancy logic flags it)
        assert r.risk_score in ("LOW", "CRIT")
        assert r.affected_devices == []

    def test_target_not_in_topology(self, small_topo):
        # Device not in inventory; isolated treats it as having 0 neighbors
        r = compute_blast_radius("shutdown_interface", "nonexistent-device", "eth0", small_topo)
        assert r.affected_devices == []
        assert r.risk_score in ("LOW", "CRIT")

    def test_depth_clamped(self, wide_topo):
        # depth > 6 should clamp to 6
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=999)
        assert r.depth == 6

    def test_depth_minimum_1(self, wide_topo):
        r = compute_blast_radius("shutdown_interface", "de-fra-core-01", "eth0", wide_topo, depth=0)
        assert r.depth == 1


# ─── Immutability ────────────────────────────────────────────────────────────


class TestImmutable:
    def test_frozen_dataclass(self, small_topo):
        r = compute_blast_radius("modify_acl", "de-fra-core-01", "X", small_topo)
        with pytest.raises(Exception):
            r.risk_score = "CHANGED"  # type: ignore[misc]
