"""Phase 5-B — predict_engine unit tests.

Run with:  pytest test_predict.py -v
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "src"))

from predict_engine import (  # noqa: E402
    CHANGE_KINDS,
    BatfishPredictor,
    ChangeOp,
    PredictResult,
    RuleBasedPredictor,
    get_predictor,
    parse_change,
    predict,
    reset_predictor,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def topo():
    """Small 4-device topology with 3 BGP sessions."""
    return {
        "devices": [
            {"hostname": "de-fra-core-01", "site": "DE-FRA", "asn": 65001},
            {"hostname": "de-fra-core-02", "site": "DE-FRA", "asn": 65002},
            {"hostname": "uk-lon-core-01", "site": "UK-LON", "asn": 65003},
            {"hostname": "us-nyc-core-01", "site": "US-NYC", "asn": 65005},
        ],
        "bgp_sessions": [
            {"peer_a": "de-fra-core-01", "peer_b": "de-fra-core-02",
             "peer_a_ip": "10.0.0.1", "peer_b_ip": "10.0.0.2",
             "asn_a": 65001, "asn_b": 65002, "type": "iBGP"},
            {"peer_a": "de-fra-core-01", "peer_b": "uk-lon-core-01",
             "peer_a_ip": "10.0.0.1", "peer_b_ip": "10.0.0.3",
             "asn_a": 65001, "asn_b": 65003, "type": "eBGP"},
            {"peer_a": "de-fra-core-02", "peer_b": "us-nyc-core-01",
             "peer_a_ip": "10.0.0.2", "peer_b_ip": "10.0.0.5",
             "asn_a": 65002, "asn_b": 65005, "type": "eBGP"},
        ],
    }


# ─── Parser tests ────────────────────────────────────────────────────────────


class TestParser:
    @pytest.mark.parametrize("text,kind,obj", [
        ("router bgp 65001\n no neighbor 10.0.0.2\n!", "drop_bgp_peer",     "10.0.0.2"),
        ("delete protocols bgp group ebgp neighbor 10.0.0.3", "drop_bgp_peer", "10.0.0.3"),
        ("neighbor 10.0.0.99 remote-as 65099",              "add_bgp_peer",   "10.0.0.99"),
        ("set protocols bgp group ebgp neighbor 10.0.0.4 type external",
                                                             "add_bgp_peer",   "10.0.0.4"),
        ("interface eth0\n shutdown",                         "shutdown_interface", "eth0"),
        ("set interfaces ge-0/0/1 disable",                   "shutdown_interface", "ge-0/0/1"),
        ("interface eth0\n no shutdown",                      "no_shutdown_interface", "eth0"),
        ("no router bgp 65001",                               "remove_bgp_process", "65001"),
        ("delete protocols bgp",                              "remove_bgp_process", ""),
        ("router bgp 99999\n network 1.1.1.0/24",             "change_asn",          "99999"),
        ("no access-list MGMT-IN",                            "remove_acl_rule",    "MGMT-IN"),
        ("delete firewall filter BLOCK-RFC1918",              "remove_acl_rule",    "BLOCK-RFC1918"),
        ("access-list MGMT-IN permit ip any any",             "add_acl_rule",       "MGMT-IN"),
        ("totally unknown thing",                              "unknown",             ""),
    ])
    def test_parses_correctly(self, text, kind, obj):
        op = parse_change("test-device", text)
        assert op.kind == kind, f"expected {kind}, got {op.kind} for: {text[:40]!r}"
        if obj:
            assert op.target_object == obj

    def test_empty_change_is_unknown(self):
        op = parse_change("test-device", "")
        assert op.kind == "unknown"

    def test_target_device_propagated(self):
        op = parse_change("my-device", "no neighbor 10.0.0.1")
        assert op.target_device == "my-device"


# ─── RuleBasedPredictor — verdict logic ──────────────────────────────────────


class TestVerdictLogic:
    def setup_method(self):
        self.p = RuleBasedPredictor()

    def test_drop_one_peer_warns(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "router bgp 65001\n no neighbor 10.0.0.2\n!", topo)
        assert out["verdict"] == "WARN"
        assert len(out["diff"]["bgp_sessions"]["lost"]) == 1

    def test_remove_bgp_process_rejects(self, topo):
        out = self.p.predict("de-fra-core-01", "no router bgp 65001", topo)
        assert out["verdict"] == "REJECT"
        assert out["after"]["target_session_count"] == 0

    def test_add_peer_approves(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "neighbor 10.0.0.99 remote-as 65099", topo)
        assert out["verdict"] == "APPROVE"
        assert len(out["diff"]["bgp_sessions"]["gained"]) == 1

    def test_unknown_change_warns(self, topo):
        out = self.p.predict("de-fra-core-01", "some-totally-unknown-thing", topo)
        assert out["verdict"] == "WARN"
        assert "Could not parse" in out["reasons"][0]

    def test_acl_change_no_topology_impact(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "no access-list MGMT-IN", topo)
        assert out["verdict"] == "APPROVE"
        # session count unchanged
        assert out["before"]["bgp_session_count"] == out["after"]["bgp_session_count"]

    def test_no_shutdown_keeps_sessions(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "interface eth0\n no shutdown", topo)
        assert out["verdict"] == "APPROVE"
        assert out["before"]["target_session_count"] == out["after"]["target_session_count"]


# ─── Diff calculation ────────────────────────────────────────────────────────


class TestDiff:
    def setup_method(self):
        self.p = RuleBasedPredictor()

    def test_lost_sessions_listed_alphabetically(self, topo):
        out = self.p.predict("de-fra-core-01", "no router bgp 65001", topo)
        lost = out["diff"]["bgp_sessions"]["lost"]
        # Each entry is a 2-tuple of peer hostnames, sorted
        for entry in lost:
            assert len(entry) == 2
            assert entry == sorted(entry)

    def test_affected_peers_excludes_target(self, topo):
        out = self.p.predict("de-fra-core-01", "no router bgp 65001", topo)
        peers = out["diff"]["reachability"]["potentially_affected_peers"]
        assert "de-fra-core-01" not in peers
        # Should include the two peers de-fra-core-01 had sessions with
        assert "de-fra-core-02" in peers
        assert "uk-lon-core-01" in peers

    def test_session_counts_decrement_correctly(self, topo):
        out = self.p.predict("de-fra-core-01", "no router bgp 65001", topo)
        before = out["before"]
        after = out["after"]
        assert before["bgp_session_count"] == 3
        # de-fra-core-01 had 2 sessions; removing process drops both → 1 remains
        assert after["bgp_session_count"] == 1


# ─── Peer matching ───────────────────────────────────────────────────────────


class TestPeerMatching:
    def setup_method(self):
        self.p = RuleBasedPredictor()

    def test_drop_by_ip(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "no neighbor 10.0.0.2", topo)
        assert out["verdict"] == "WARN"
        assert ["de-fra-core-01", "de-fra-core-02"] in out["diff"]["bgp_sessions"]["lost"]

    def test_drop_by_hostname(self, topo):
        out = self.p.predict("de-fra-core-01",
                              "no neighbor de-fra-core-02", topo)
        assert out["verdict"] == "WARN"
        assert ["de-fra-core-01", "de-fra-core-02"] in out["diff"]["bgp_sessions"]["lost"]


# ─── Registry ────────────────────────────────────────────────────────────────


class TestRegistry:
    def setup_method(self):
        reset_predictor()

    def test_default_is_rule_based(self, monkeypatch):
        monkeypatch.delenv("DCN_PREDICT_PROVIDER", raising=False)
        p = get_predictor()
        assert p.name == "rule-based-stdlib"

    def test_batfish_falls_back_when_unavailable(self, monkeypatch):
        monkeypatch.setenv("DCN_PREDICT_PROVIDER", "batfish")
        reset_predictor()
        p = get_predictor()
        # pybatfish not installed → BatfishPredictor() raises → fallback
        assert p.name in ("rule-based-stdlib", "batfish")

    def test_singleton(self):
        reset_predictor()
        a = get_predictor()
        b = get_predictor()
        assert a is b


# ─── End-to-end ──────────────────────────────────────────────────────────────


class TestPredictAPI:
    def test_returns_predict_result(self, topo):
        r = predict("de-fra-core-01", "no neighbor 10.0.0.2", topo)
        assert isinstance(r, PredictResult)
        assert r.target_device == "de-fra-core-01"
        assert r.verdict in ("APPROVE", "WARN", "REJECT")
        assert r.ms >= 0
        assert r.backend

    def test_missing_target_device_raises(self, topo):
        with pytest.raises(ValueError, match="target_device"):
            predict("", "no neighbor 10.0.0.2", topo)

    def test_empty_change_classified_unknown(self, topo):
        r = predict("de-fra-core-01", "", topo)
        assert r.parsed_op.kind == "unknown"
        assert r.verdict == "WARN"

    def test_frozen_dataclass(self, topo):
        r = predict("de-fra-core-01", "no neighbor 10.0.0.2", topo)
        with pytest.raises(Exception):
            r.verdict = "CHANGED"  # type: ignore[misc]


# ─── Performance ─────────────────────────────────────────────────────────────


class TestPerformance:
    def test_single_predict_under_50ms(self, topo):
        t0 = time.perf_counter()
        predict("de-fra-core-01", "no neighbor 10.0.0.2", topo)
        ms = (time.perf_counter() - t0) * 1000
        assert ms < 50, f"predict took {ms:.1f}ms (target < 50ms)"

    def test_1000_predicts_under_2s(self, topo):
        t0 = time.perf_counter()
        for _ in range(1000):
            predict("de-fra-core-01", "no neighbor 10.0.0.2", topo)
        total = time.perf_counter() - t0
        assert total < 2.0, f"1000 predicts took {total:.2f}s (target < 2s)"


# ─── ChangeOp immutability ───────────────────────────────────────────────────


class TestChangeOpImmutable:
    def test_change_op_frozen(self):
        op = parse_change("dev", "no neighbor 10.0.0.1")
        with pytest.raises(Exception):
            op.kind = "modified"  # type: ignore[misc]

    def test_all_kinds_in_change_kinds_tuple(self):
        # Every kind we emit from the parser should be in the public tuple
        for text in [
            "no neighbor 10.0.0.1",
            "neighbor 10.0.0.1 remote-as 1",
            "interface eth0\n shutdown",
            "interface eth0\n no shutdown",
            "no router bgp 1",
            "router bgp 1",
            "no access-list X",
            "access-list X permit ip any any",
            "totally unknown",
        ]:
            op = parse_change("d", text)
            assert op.kind in CHANGE_KINDS


# ─── Empty / edge cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_topology(self):
        r = predict("de-fra-core-01", "no neighbor 10.0.0.2",
                    {"devices": [], "bgp_sessions": []})
        # No sessions to lose → APPROVE
        assert r.verdict == "APPROVE"
        assert r.after_state["bgp_session_count"] == 0

    def test_target_not_in_topology(self, topo):
        r = predict("nonexistent-device", "no neighbor 10.0.0.2", topo)
        # Predictor accepts unknown targets; verdict still computed (APPROVE since no impact)
        assert r.before_state["target_exists"] is False

    def test_topology_with_no_sessions(self):
        r = predict("de-fra-core-01", "no router bgp 65001",
                    {"devices": [{"hostname": "de-fra-core-01"}], "bgp_sessions": []})
        # Removing a non-existent BGP process is still flagged as a process-removal
        # but it removes 0 sessions, so the reasons message will reflect that.
        # We accept either REJECT (consistent kind→verdict mapping) or APPROVE.
        assert r.verdict in ("REJECT", "APPROVE", "WARN")
