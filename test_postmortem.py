"""
Tests for Auto-Postmortem (Day-8).

Run:
    cd 04_Scripts_Tools/DCN_Network_Tool && pytest test_postmortem.py -v

Covers:
  - Event dataclass + Incident dataclass shapes
  - generate() over an empty window
  - generate() correlates events from multiple sources
  - Root-cause heuristics: chaos · HG-abandon · remediation · fleet · unknown
  - Severity tiering (P1 / P2 / P3)
  - Status detection (resolved / abandoned / active)
  - Affected devices list excludes "fleet"
  - render_markdown() produces a paste-ready report
  - detect_incidents() anchors on HG abandons + error clusters
  - save() round-trip + list_saved()
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE / "src"))

# All upstream modules in simulated mode — no real network / threads.
os.environ["HEALTH_GATE_FORCE_SIMULATE"] = "1"
os.environ["NETBOX_SOT_FORCE_SIMULATE"] = "1"

import postmortem as pm  # noqa: E402
import health_gate as hg  # noqa: E402
import remediation as rem  # noqa: E402
import gait_audit as g  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _evt(ts, source, severity, target, message, **extra):
    return pm.Event(ts=ts, source=source, severity=severity,
                    target=target, message=message, extra=extra)


# ─── Dataclasses ────────────────────────────────────────────────────────────


class TestDataclasses:
    def test_event_has_required_fields(self):
        e = _evt("2026-05-19T14:32:00+00:00", "gait", "info", "de-fra-core-01", "hello")
        assert e.ts and e.source == "gait" and e.target == "de-fra-core-01"
        assert e.extra == {}

    def test_incident_to_dict(self):
        inc = pm.Incident(
            incident_id="INC-test", started_at="t1", ended_at="t2",
            severity="P2", affected_devices=["a"], root_cause="x",
            status="resolved", auto_detected=False,
        )
        d = inc.to_dict()
        assert d["incident_id"] == "INC-test"
        assert d["affected_devices"] == ["a"]


# ─── Root-cause heuristics ──────────────────────────────────────────────────


class TestRootCause:
    def test_chaos_takes_priority(self):
        events = [
            _evt("t1", "gait", "info", "fleet", "chaos_monkey → break"),
            _evt("t2", "health_gate", "critical", "host-a", "Health Gate abandoned"),
        ]
        rc = pm.correlate_root_cause(events)
        assert "chaos" in rc.lower()

    def test_hg_abandon_with_regression(self):
        events = [
            _evt("t1", "health_gate", "critical", "host-a", "Health Gate abandoned",
                 regressions=["BGP peers regressed by 1"]),
        ]
        rc = pm.correlate_root_cause(events)
        assert "BGP peers regressed by 1" in rc

    def test_hg_abandon_without_regression(self):
        events = [
            _evt("t1", "health_gate", "critical", "host-a", "Health Gate abandoned"),
        ]
        rc = pm.correlate_root_cause(events)
        assert "Health Gate" in rc and "watch window" in rc

    def test_remediation_rejection(self):
        events = [
            _evt("t1", "remediation", "warn", "host-a", "Remediation proposal rejected",
                 proposal_id="prop-1"),
        ]
        rc = pm.correlate_root_cause(events)
        assert "Remediation" in rc and "prop-1" in rc

    def test_fleet_level_multi_device(self):
        events = [
            _evt("t1", "gait", "error", "host-a", "x"),
            _evt("t2", "gait", "error", "host-b", "y"),
            _evt("t3", "gait", "critical", "host-c", "z"),
        ]
        rc = pm.correlate_root_cause(events)
        assert "Fleet-level event" in rc and "3 devices" in rc

    def test_unknown_when_only_info(self):
        events = [
            _evt("t1", "gait", "info", "host-a", "routine check"),
        ]
        rc = pm.correlate_root_cause(events)
        assert "Unknown" in rc


# ─── Severity + status ──────────────────────────────────────────────────────


class TestSeverityStatus:
    def test_severity_p1_on_critical(self):
        events = [_evt("t1", "health_gate", "critical", "h", "abandoned")]
        assert pm._severity(events) == "P1"

    def test_severity_p2_on_error(self):
        events = [_evt("t1", "gait", "error", "h", "x")]
        assert pm._severity(events) == "P2"

    def test_severity_p3_otherwise(self):
        events = [_evt("t1", "gait", "info", "h", "x")]
        assert pm._severity(events) == "P3"

    def test_status_resolved_when_final_confirmed(self):
        events = [
            _evt("t1", "health_gate", "critical", "h", "abandoned"),
            _evt("t2", "remediation", "info", "h", "Fix confirmed"),
        ]
        assert pm._status(events) == "resolved"

    def test_status_abandoned_when_last_is_abandon(self):
        events = [
            _evt("t1", "health_gate", "critical", "h", "Health Gate abandoned"),
        ]
        assert pm._status(events) == "abandoned"


# ─── Affected devices ───────────────────────────────────────────────────────


class TestAffectedDevices:
    def test_fleet_excluded(self):
        events = [
            _evt("t1", "gait", "info", "fleet", "x"),
            _evt("t2", "gait", "info", "host-a", "y"),
        ]
        assert pm._affected(events) == ["host-a"]

    def test_dedupe_and_sort(self):
        events = [
            _evt("t1", "gait", "info", "z", "x"),
            _evt("t2", "gait", "info", "a", "y"),
            _evt("t3", "gait", "info", "a", "z"),
        ]
        assert pm._affected(events) == ["a", "z"]


# ─── generate() end-to-end ──────────────────────────────────────────────────


class TestGenerate:
    def test_empty_window_returns_p3(self):
        # Far-past window — GAIT only retains today + yesterday, so this is
        # guaranteed to be empty regardless of how busy the live audit gets.
        start = _now() - timedelta(days=365)
        end = _now() - timedelta(days=364)
        inc = pm.generate(start, end)
        assert inc.severity == "P3"
        assert inc.events == []
        assert inc.incident_id.startswith("INC-")

    def test_correlates_health_gate_job(self, monkeypatch):
        # Drive Health Gate to produce an abandon job, then generate covers it
        monkeypatch.setattr(hg, "DEFAULT_POLL_INTERVAL_S", 0)
        stable = lambda host: {"bgp_peers_up": 4, "interfaces_up": 12, "alerts_count": 0}
        hg.submit(
            hostname="de-fra-core-01", timeout_s=2, block=True,
            snapshot_fn=stable, induce_regression_after_s=0,
        )
        start = _now() - timedelta(minutes=5)
        end = _now() + timedelta(minutes=5)
        inc = pm.generate(start, end, devices=["de-fra-core-01"])
        hg_events = [e for e in inc.events if e["source"] == "health_gate"]
        assert any("abandoned" in e["message"].lower() for e in hg_events)
        # And the root cause should mention BGP regression
        assert "BGP" in inc.root_cause


# ─── Markdown rendering ─────────────────────────────────────────────────────


class TestRender:
    def test_markdown_has_required_sections(self):
        inc = pm.Incident(
            incident_id="INC-X", started_at="2026-05-19T14:32:00+00:00",
            ended_at="2026-05-19T14:35:00+00:00", severity="P1",
            affected_devices=["de-fra-core-01"], root_cause="Chaos test",
            status="resolved", auto_detected=True,
            events=[{
                "ts": "2026-05-19T14:32:00+00:00", "source": "gait",
                "severity": "info", "target": "de-fra-core-01",
                "message": "chaos break", "extra": {},
            }],
        )
        md = pm.render_markdown(inc)
        assert "# Incident INC-X" in md
        assert "## Root cause" in md
        assert "## Timeline" in md
        assert "## Audit trail" in md
        assert "Chaos test" in md
        assert "de-fra-core-01" in md

    def test_empty_timeline_shows_placeholder(self):
        inc = pm.Incident(
            incident_id="INC-empty", started_at="t1", ended_at="t2",
            severity="P3", affected_devices=[], root_cause="Unknown",
            status="active", auto_detected=False, events=[],
        )
        md = pm.render_markdown(inc)
        assert "No events in window" in md


# ─── detect_incidents + save round-trip ─────────────────────────────────────


class TestDetectAndSave:
    def test_detect_returns_anchors_around_hg_abandons(self, monkeypatch):
        # Produce an abandon job
        monkeypatch.setattr(hg, "DEFAULT_POLL_INTERVAL_S", 0)
        stable = lambda host: {"bgp_peers_up": 4, "interfaces_up": 12, "alerts_count": 0}
        hg.submit(
            hostname="uk-lon-core-01", timeout_s=2, block=True,
            snapshot_fn=stable, induce_regression_after_s=0,
        )
        incs = pm.detect_incidents(window_h=2)
        assert len(incs) >= 1
        assert any(i.severity == "P1" for i in incs)
        assert all(i.auto_detected for i in incs)

    def test_save_writes_markdown_and_json(self, tmp_path, monkeypatch):
        # Point SAVE_DIR to tmp so we don't pollute the repo
        monkeypatch.setattr(pm, "_SAVE_DIR", tmp_path)
        inc = pm.Incident(
            incident_id="INC-savetest", started_at="t1", ended_at="t2",
            severity="P3", affected_devices=["host-a"], root_cause="rc",
            status="resolved", auto_detected=False, events=[],
        )
        path = pm.save(inc)
        assert path.endswith("INC-savetest.md")
        assert (tmp_path / "INC-savetest.md").exists()
        assert (tmp_path / "INC-savetest.json").exists()

    def test_list_saved_returns_recent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(pm, "_SAVE_DIR", tmp_path)
        for i in range(3):
            inc = pm.Incident(
                incident_id=f"INC-list-{i}", started_at="t1", ended_at="t2",
                severity="P3", affected_devices=[f"h-{i}"], root_cause="x",
                status="resolved", auto_detected=False, events=[],
            )
            pm.save(inc)
            time.sleep(0.005)
        listed = pm.list_saved()
        ids = [r["incident_id"] for r in listed]
        for i in range(3):
            assert f"INC-list-{i}" in ids
