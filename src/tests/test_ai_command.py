"""
test_ai_command.py — Tests for POST /api/ai-command

Tests the full NL→CLI→SSH→explain pipeline:
  1. LLM translates plain-English query → CLI command (JSON)
  2. SSH executes CLI on target device
  3. LLM explains the output in plain English

Endpoint spec:
  POST /api/ai-command
  Body: {"query": str, "hostname": str}
  Returns: {"query", "hostname", "cli", "output", "explanation"}
"""

import json
import pytest
from unittest.mock import MagicMock, patch, call


# ── Happy path ────────────────────────────────────────────────────────────────

def test_ai_command_bgp_query(app_client, mock_llm, mock_ssh):
    """Full pipeline: NL query → CLI translation → SSH execution → explanation."""
    # First call: translate query → CLI  |  Second call: explain output
    mock_llm.side_effect = [
        '{"cli": "show bgp summary"}',
        "BGP has 2 established peers with 12 total prefixes. No issues detected.",
    ]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Show BGP neighbors on de-fra-core-01", "hostname": "de-fra-core-01"},
        content_type="application/json",
    )

    assert resp.status_code == 200
    data = resp.get_json()

    assert data["query"] == "Show BGP neighbors on de-fra-core-01"
    assert data["cli"] == "show bgp summary"
    assert data["output"] is not None
    assert data["explanation"] is not None
    # SSH should have been called once with the translated command
    mock_ssh.assert_called_once()
    call_args = mock_ssh.call_args
    assert "show bgp summary" in call_args.args or "show bgp summary" in str(call_args)


def test_ai_command_interface_query(app_client, mock_llm, mock_ssh):
    """Interface query translates to correct JunOS-style command."""
    mock_llm.side_effect = [
        '{"cli": "show interface brief"}',
        "All interfaces are up. No alarms.",
    ]
    mock_ssh.return_value = {
        "success": True,
        "output": "eth0: up\neth1: up",
        "command": "show interface brief",
    }

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Which interfaces are down on uk-lon-core-01", "hostname": "uk-lon-core-01"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cli"] == "show interface brief"
    assert data["hostname"] == "uk-lon-core-01"


def test_ai_command_device_not_in_inventory(app_client, mock_llm, mock_ssh):
    """Unknown device: translation still happens but no SSH execution."""
    mock_llm.side_effect = ['{"cli": "show version"}', None]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Show version", "hostname": "nonexistent-device"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cli"] == "show version"
    # SSH should NOT have been called for unknown device
    mock_ssh.assert_not_called()
    assert "not in inventory" in str(data.get("output", "")).lower()


def test_ai_command_llm_preamble_stripped(app_client, mock_llm, mock_ssh):
    """LLM preamble (Qwen3 reasoning leak) is stripped before JSON parse."""
    mock_llm.side_effect = [
        'Okay, the user wants to check OSPF.\n{"cli": "show ip ospf neighbor"}',
        "OSPF has 2 full adjacencies.",
    ]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Check OSPF adjacencies", "hostname": "de-fra-core-01"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    # Should have extracted JSON despite preamble
    assert data["cli"] == "show ip ospf neighbor"


def test_ai_command_ssh_error_returned(app_client, mock_llm, mock_ssh):
    """SSH failure is included in response — not a 500 error."""
    mock_llm.side_effect = [
        '{"cli": "show bgp summary"}',
        None,
    ]
    mock_ssh.return_value = {
        "success": False,
        "output": "Connection refused",
        "command": "show bgp summary",
    }

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "BGP status", "hostname": "de-fra-core-01"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cli"] == "show bgp summary"
    assert "Connection refused" in str(data.get("output", ""))


# ── Validation / error cases ──────────────────────────────────────────────────

def test_ai_command_empty_query_returns_400(app_client):
    """Empty query string should return HTTP 400."""
    resp = app_client.post("/api/ai-command", json={"query": "", "hostname": "de-fra-core-01"})
    assert resp.status_code == 400
    assert "query" in resp.get_json().get("error", "").lower()


def test_ai_command_missing_query_returns_400(app_client):
    """Missing query key should return HTTP 400."""
    resp = app_client.post("/api/ai-command", json={"hostname": "de-fra-core-01"})
    assert resp.status_code == 400


def test_ai_command_llm_unavailable_returns_503(app_client, monkeypatch):
    """When all LLM attempts fail (returns None), endpoint returns 503."""
    import app as dcn_app
    monkeypatch.setattr(dcn_app, "_llm_query", MagicMock(return_value=None))

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Show BGP", "hostname": "de-fra-core-01"},
    )
    assert resp.status_code == 503
    assert "LLM" in resp.get_json().get("error", "")


def test_ai_command_llm_returns_plain_text(app_client, mock_llm, mock_ssh):
    """LLM sometimes returns plain CLI without JSON wrapper — should still work."""
    mock_llm.side_effect = [
        "show chassis alarms",   # plain text, no JSON
        "No active alarms.",
    ]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "Any alarms on de-fra-edge-01", "hostname": "de-fra-edge-01"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert "show chassis alarms" in data["cli"]


def test_ai_command_no_hostname(app_client, mock_llm, mock_ssh):
    """Missing hostname: translation runs, device defaults gracefully."""
    mock_llm.side_effect = ['{"cli": "show version"}', None]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "show version"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["cli"] == "show version"


# ── Response schema ───────────────────────────────────────────────────────────

def test_ai_command_response_schema(app_client, mock_llm, mock_ssh):
    """Response always contains all expected keys."""
    mock_llm.side_effect = ['{"cli": "show route summary"}', "3 active routes."]

    resp = app_client.post(
        "/api/ai-command",
        json={"query": "routing table", "hostname": "de-fra-core-01"},
    )
    assert resp.status_code == 200
    data = resp.get_json()

    for key in ("query", "hostname", "cli", "output", "explanation"):
        assert key in data, f"Missing key: {key}"
