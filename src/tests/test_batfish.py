"""
test_batfish.py — Tests for POST /api/batfish/analyze

Tests the static config analysis (rule-based Batfish-style checks):
  - Plaintext BGP auth key detection (ERROR)
  - Missing export policy on external BGP peer (ERROR)
  - BGP hold-time > 30s (WARN)
  - BFD configured (PASS)
  - OSPF area 0 (PASS)
  - LLM enhancement summary (optional)

Endpoint spec:
  POST /api/batfish/analyze
  Body: {"config": str}
  Returns: {"errors": int, "warnings": int, "passes": int, "findings": list, "llm_summary": str|null}
"""

import pytest
from unittest.mock import MagicMock


# ── Config fixtures ────────────────────────────────────────────────────────────

GOOD_CONFIG = """
set protocols bgp group UPSTREAM type external
set protocols bgp group UPSTREAM authentication md5
set protocols bgp group UPSTREAM hold-time 20
set protocols bgp group UPSTREAM export EXPORT-POLICY
set protocols bgp group UPSTREAM bfd-liveness-detection minimum-interval 300
set protocols bgp group UPSTREAM log-updown
set protocols bgp group UPSTREAM local-address 10.0.0.1
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
"""

BAD_CONFIG_PLAINTEXT_AUTH = """
set protocols bgp group UPSTREAM type external
set protocols bgp group UPSTREAM authentication-key "mysecret"
set protocols bgp group UPSTREAM hold-time 90
"""

BAD_CONFIG_NO_EXPORT = """
set protocols bgp group UPSTREAM type external
set protocols bgp group UPSTREAM authentication md5
set protocols bgp group UPSTREAM hold-time 20
"""

WARN_CONFIG_HOLD_TIME = """
set protocols bgp group UPSTREAM type external
set protocols bgp group UPSTREAM export POLICY
set protocols bgp group UPSTREAM hold-time 45
"""

EMPTY_CONFIG = ""

MINIMAL_GOOD = """
set protocols ospf area 0.0.0.0 interface ge-0/0/0.0
set protocols bgp group INTERNAL authentication md5
set protocols bgp group INTERNAL log-updown
"""


# ── Happy path — full good config ─────────────────────────────────────────────

def test_batfish_good_config_no_errors(app_client, monkeypatch):
    """Well-formed config produces 0 errors, 0 warnings, several passes."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value="Config looks good."))
    monkeypatch.setattr(dcn_app, "LLM_ENABLED", True)

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["errors"] == 0
    assert data["warnings"] == 0
    assert data["passes"] > 0


def test_batfish_response_schema(app_client, monkeypatch):
    """Response always contains all required keys."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    assert resp.status_code == 200
    data = resp.get_json()

    for key in ("errors", "warnings", "passes", "findings", "llm_summary"):
        assert key in data, f"Missing key: {key}"

    assert isinstance(data["findings"], list)
    assert isinstance(data["errors"], int)
    assert isinstance(data["warnings"], int)
    assert isinstance(data["passes"], int)


# ── Error detection ───────────────────────────────────────────────────────────

def test_batfish_detects_plaintext_auth_key(app_client, monkeypatch):
    """Plaintext authentication-key must trigger an ERROR finding."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": BAD_CONFIG_PLAINTEXT_AUTH})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["errors"] >= 1
    error_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "error"]
    assert any("plaintext" in m or "auth" in m for m in error_msgs), \
        f"Expected plaintext auth error, got: {error_msgs}"


def test_batfish_detects_missing_export_policy(app_client, monkeypatch):
    """External BGP peer without export policy must trigger ERROR."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": BAD_CONFIG_NO_EXPORT})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["errors"] >= 1
    error_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "error"]
    assert any("export" in m for m in error_msgs), \
        f"Expected missing export error, got: {error_msgs}"


# ── Warning detection ─────────────────────────────────────────────────────────

def test_batfish_warns_on_high_hold_time(app_client, monkeypatch):
    """BGP hold-time > 30s should produce a WARN finding."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": WARN_CONFIG_HOLD_TIME})
    assert resp.status_code == 200
    data = resp.get_json()

    assert data["warnings"] >= 1
    warn_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "warn"]
    assert any("hold-time" in m or "hold" in m for m in warn_msgs), \
        f"Expected hold-time warning, got: {warn_msgs}"


# ── Pass detection ────────────────────────────────────────────────────────────

def test_batfish_detects_bfd(app_client, monkeypatch):
    """BFD configuration should produce a PASS finding."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    assert resp.status_code == 200
    data = resp.get_json()

    pass_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "pass"]
    assert any("bfd" in m for m in pass_msgs), \
        f"Expected BFD pass, got: {pass_msgs}"


def test_batfish_detects_md5_auth(app_client, monkeypatch):
    """MD5 authentication should produce a PASS finding."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    data = resp.get_json()

    pass_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "pass"]
    assert any("md5" in m or "authentication" in m for m in pass_msgs)


def test_batfish_detects_ospf_area(app_client, monkeypatch):
    """OSPF area 0.0.0.0 should produce a PASS finding."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    data = resp.get_json()

    pass_msgs = [f["message"].lower() for f in data["findings"] if f["severity"] == "pass"]
    assert any("ospf" in m or "area" in m for m in pass_msgs)


# ── LLM integration ───────────────────────────────────────────────────────────

def test_batfish_llm_summary_included_when_available(app_client, monkeypatch):
    """When LLM is available, llm_summary is populated."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "LLM_ENABLED", True)
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value="No critical issues found."))

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    data = resp.get_json()

    assert data["llm_summary"] == "No critical issues found."


def test_batfish_llm_summary_null_when_unavailable(app_client, monkeypatch):
    """When LLM returns None, llm_summary is null (not an error)."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "LLM_ENABLED", False)

    resp = app_client.post("/api/batfish/analyze", json={"config": GOOD_CONFIG})
    data = resp.get_json()

    assert data["llm_summary"] is None


# ── Validation ────────────────────────────────────────────────────────────────

def test_batfish_empty_config_returns_400(app_client):
    """Empty config string returns HTTP 400."""
    resp = app_client.post("/api/batfish/analyze", json={"config": ""})
    assert resp.status_code == 400
    assert "config" in resp.get_json().get("error", "").lower()


def test_batfish_missing_config_returns_400(app_client):
    """Missing config key returns HTTP 400."""
    resp = app_client.post("/api/batfish/analyze", json={})
    assert resp.status_code == 400


def test_batfish_whitespace_only_returns_400(app_client):
    """Whitespace-only config returns HTTP 400."""
    resp = app_client.post("/api/batfish/analyze", json={"config": "   \n\t  "})
    assert resp.status_code == 400


# ── Findings count consistency ────────────────────────────────────────────────

def test_batfish_finding_counts_match_list(app_client, monkeypatch):
    """errors/warnings/passes counts must match actual findings list."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post("/api/batfish/analyze", json={"config": BAD_CONFIG_PLAINTEXT_AUTH})
    data = resp.get_json()

    actual_errors   = sum(1 for f in data["findings"] if f["severity"] == "error")
    actual_warnings = sum(1 for f in data["findings"] if f["severity"] == "warn")
    actual_passes   = sum(1 for f in data["findings"] if f["severity"] == "pass")

    assert data["errors"]   == actual_errors
    assert data["warnings"] == actual_warnings
    assert data["passes"]   == actual_passes
