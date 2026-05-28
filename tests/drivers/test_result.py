"""Tests for DriverResult dataclass."""
from __future__ import annotations

import dataclasses

import pytest

from drivers.result import DriverResult


def test_minimal_construction_defaults():
    r = DriverResult(section="bgp", vendor="frr", command="show ip bgp summary json", raw="{}")
    assert r.section == "bgp"
    assert r.vendor == "frr"
    assert r.normalized == {}
    assert r.success is False
    assert r.via == "docker-exec"
    assert r.error is None
    assert r.elapsed_ms == 0.0


def test_ok_property_mirrors_success():
    ok = DriverResult(section="bgp", vendor="frr", command="c", raw="x", success=True)
    bad = DriverResult(section="bgp", vendor="frr", command="c", raw="", success=False)
    assert ok.ok is True
    assert bad.ok is False


def test_is_frozen():
    r = DriverResult(section="bgp", vendor="frr", command="c", raw="x")
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.success = True  # type: ignore[misc]


def test_normalized_default_is_per_instance():
    a = DriverResult(section="bgp", vendor="frr", command="c", raw="x")
    b = DriverResult(section="bgp", vendor="frr", command="c", raw="y")
    a.normalized["k"] = 1
    assert b.normalized == {}  # default_factory => no shared mutable default


def test_full_field_set():
    r = DriverResult(
        section="ospf", vendor="arista-eos", command="show ip ospf neighbor | json",
        raw="raw-text", normalized={"full": 2}, success=True, via="ssh",
        error=None, elapsed_ms=12.5,
    )
    assert r.normalized["full"] == 2
    assert r.via == "ssh"
    assert r.elapsed_ms == 12.5
    assert r.ok is True
