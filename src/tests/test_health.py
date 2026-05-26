"""Tests for the per-device health collector + /api/health/<hostname> endpoint.

Covers:
  - FRR JSON path (vtysh json output)
  - FRR text fallback path (legacy vtysh, no json)
  - Partial failure (one command fails, others succeed → soft errors, partial data)
  - Unknown device type → graceful error in meta.errors
  - Empty/null output → schema with default empty values
  - The Flask route returns the right shape and 404s on unknown hostnames.
"""
import json

import pytest

from health import (
    COMMAND_MAP,
    collect_health,
    _parse_bgp,
    _parse_interfaces,
    _parse_ospf,
    _parse_version,
)


# ---------------------------------------------------------------------------
# Fixtures — canned FRR JSON output that vtysh would produce
# ---------------------------------------------------------------------------

FRR_BGP_JSON = json.dumps({
    "ipv4Unicast": {
        "peers": {
            "10.200.0.12": {
                "remoteAs": 65002,
                "state": "Established",
                "peerUptime": "01:23:45",
                "pfxRcd": 5,
            },
            "10.200.0.13": {
                "remoteAs": 65003,
                "state": "Active",
                "peerUptime": "never",
                "pfxRcd": 0,
            },
        }
    }
})

FRR_OSPF_JSON = json.dumps({
    "neighbors": {
        "10.200.0.12": [{
            "ifaceName": "eth0",
            "nbrState": "Full/DR",
            "upTimeInMsec": 4567,
        }],
        "10.200.0.13": [{
            "ifaceName": "eth0",
            "nbrState": "Init",
            "upTimeInMsec": 100,
        }],
    }
})

FRR_INTERFACE_JSON = json.dumps({
    "eth0": {
        "administrativeStatus": "up",
        "operationalStatus": "up",
        "ipAddresses": [{"address": "10.200.0.11/24"}],
    },
    "eth1": {
        "administrativeStatus": "up",
        "operationalStatus": "down",
        "ipAddresses": [{"address": "192.168.1.1/30"}],
    },
})

FRR_VERSION_TEXT = "FRRouting 9.1.0 (de-fra-core-01) compiled on 2024-01-15."

FRR_BGP_TEXT = """\
IPv4 Unicast Summary (VRF default):
BGP router identifier 10.200.0.11, local AS number 65001 vrf-id 0

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd
10.200.0.12     4      65002       145       148        0    0    0 00:12:34            5
10.200.0.13     4      65003       139       142        0    0    0 00:12:30            3
"""

FRR_INTERFACE_TEXT = """\
Interface       Status     VRF             Addresses
eth0            up         default         10.200.0.11/24
eth1            down       default         192.168.1.1/30
lo              up         default         127.0.0.1/8
"""


def _make_runner(responses: dict[str, dict]):
    """Build a fake runner that returns canned output keyed by command substring.

    Falls back to a generic success-but-empty result for any unmatched command, so
    individual section tests don't need to enumerate every command.
    """
    def runner(ip, dtype, command, port=22):
        for hint, response in responses.items():
            if hint in command:
                return response
        return {"success": True, "output": "", "command": command}
    return runner


# ---------------------------------------------------------------------------
# Unit tests — individual parsers
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_parse_version_frr_extracts_version_string():
    result = _parse_version({"output": FRR_VERSION_TEXT}, "frr")
    assert result["version"] == "9.1.0"


@pytest.mark.unit
def test_parse_version_empty_output_returns_defaults():
    result = _parse_version({"output": ""}, "frr")
    assert result == {"raw": "", "version": None, "uptime": None}


@pytest.mark.unit
def test_parse_bgp_json_counts_established_and_down():
    result = _parse_bgp({"output": FRR_BGP_JSON}, "frr")
    assert result["established"] == 1
    assert result["down"] == 1
    assert len(result["peers"]) == 2
    established_peer = next(p for p in result["peers"] if p["state"] == "Established")
    assert established_peer["neighbor"] == "10.200.0.12"
    assert established_peer["prefixes"] == 5


@pytest.mark.unit
def test_parse_bgp_text_fallback_handles_legacy_vtysh():
    """When the device doesn't speak JSON, the text fallback must still extract peers."""
    result = _parse_bgp({"output": FRR_BGP_TEXT}, "frr")
    assert result["established"] == 2
    assert result["down"] == 0
    assert {p["neighbor"] for p in result["peers"]} == {"10.200.0.12", "10.200.0.13"}


@pytest.mark.unit
def test_parse_ospf_json_counts_full_adjacencies():
    result = _parse_ospf({"output": FRR_OSPF_JSON}, "frr")
    assert result["full"] == 1
    assert len(result["neighbors"]) == 2


@pytest.mark.unit
def test_parse_interfaces_json_counts_up_down():
    result = _parse_interfaces({"output": FRR_INTERFACE_JSON}, "frr")
    assert result["up"] == 1
    assert result["down"] == 1
    eth0 = next(i for i in result["list"] if i["name"] == "eth0")
    assert "10.200.0.11/24" in eth0["addresses"]


@pytest.mark.unit
def test_parse_interfaces_text_fallback():
    result = _parse_interfaces({"output": FRR_INTERFACE_TEXT}, "frr")
    assert result["up"] == 2  # eth0, lo
    assert result["down"] == 1  # eth1


@pytest.mark.unit
def test_parse_bgp_no_data_returns_empty():
    result = _parse_bgp({"output": ""}, "frr")
    assert result == {"peers": [], "established": 0, "down": 0}


# ---------------------------------------------------------------------------
# Integration — collect_health end-to-end with a fake runner
# ---------------------------------------------------------------------------

@pytest.mark.unit
def test_collect_health_frr_happy_path():
    """All commands return clean JSON; the snapshot has populated sections + zero errors."""
    runner = _make_runner({
        "show version":                 {"success": True, "output": FRR_VERSION_TEXT, "command": "show version"},
        "show ip bgp summary json":     {"success": True, "output": FRR_BGP_JSON, "command": "..."},
        "show ip ospf neighbor json":   {"success": True, "output": FRR_OSPF_JSON, "command": "..."},
        "show interface brief json":    {"success": True, "output": FRR_INTERFACE_JSON, "command": "..."},
    })
    snap = collect_health("de-fra-core-01", "127.0.0.1", "frr", port=2201, runner=runner)

    assert snap["meta"]["hostname"] == "de-fra-core-01"
    assert snap["meta"]["dtype"] == "frr"
    assert snap["meta"]["errors"] == []
    assert snap["meta"]["collect_time"] >= 0  # should be very small

    assert snap["version"]["version"] == "9.1.0"
    assert snap["bgp"]["established"] == 1
    assert snap["ospf"]["full"] == 1
    assert snap["interfaces"]["up"] == 1


@pytest.mark.unit
def test_collect_health_falls_back_to_text_when_json_fails():
    """If `show ip bgp summary json` returns an error, the text fallback must run + parse."""
    def runner(ip, dtype, command, port=22):
        if "json" in command:
            return {"success": False, "output": "", "error": "Command not recognized"}
        if "show ip bgp summary" in command:
            return {"success": True, "output": FRR_BGP_TEXT, "command": command}
        if "show version" in command:
            return {"success": True, "output": FRR_VERSION_TEXT, "command": command}
        return {"success": True, "output": "", "command": command}

    snap = collect_health("de-fra-core-01", "127.0.0.1", "frr", port=2201, runner=runner)
    assert snap["bgp"]["established"] == 2  # text parser handled it


@pytest.mark.unit
def test_collect_health_partial_failure_records_errors():
    """One section fails entirely — snapshot still returns + errors are logged."""
    def runner(ip, dtype, command, port=22):
        if "bgp" in command:
            return {"success": False, "output": "", "error": "vtysh exit 1"}
        return {"success": True, "output": FRR_VERSION_TEXT, "command": command}

    snap = collect_health("de-fra-core-01", "127.0.0.1", "frr", port=2201, runner=runner)
    assert snap["bgp"]["established"] == 0
    assert snap["bgp"]["peers"] == []
    assert any("bgp" in e.lower() for e in snap["meta"]["errors"])


@pytest.mark.unit
def test_collect_health_unknown_dtype_returns_empty_with_error():
    """Unsupported dtype must NOT crash — return defaults + flag the error."""
    snap = collect_health("router-x", "192.0.2.1", "exotic-os", runner=lambda *a, **kw: {})
    assert snap["bgp"]["peers"] == []
    assert any("unsupported" in e.lower() for e in snap["meta"]["errors"])


@pytest.mark.unit
def test_command_map_covers_expected_vendors():
    """Smoke test: the map is wired for the vendors we care about."""
    for vendor in ("frr", "eos", "arista-eos", "junos"):
        assert vendor in COMMAND_MAP
        # Every section must have at least one command
        for section, cmds in COMMAND_MAP[vendor].items():
            assert cmds, f"empty command list for {vendor}/{section}"


# ---------------------------------------------------------------------------
# Flask route integration
# ---------------------------------------------------------------------------

@pytest.mark.integration
def test_api_health_returns_snapshot_for_known_device(app_client, monkeypatch):
    """GET /api/health/de-fra-core-01 returns a populated snapshot."""
    import app as dcn_app

    # Replace the per-command runner with our fake — sidesteps real SSH
    monkeypatch.setattr(dcn_app, "run_command_on_device",
                        _make_runner({
                            "show version": {"success": True, "output": FRR_VERSION_TEXT, "command": "x"},
                            "show ip bgp summary json": {"success": True, "output": FRR_BGP_JSON, "command": "x"},
                            "show ip ospf neighbor json": {"success": True, "output": FRR_OSPF_JSON, "command": "x"},
                            "show interface brief json": {"success": True, "output": FRR_INTERFACE_JSON, "command": "x"},
                        }))

    response = app_client.get("/api/health/de-fra-core-01")
    assert response.status_code == 200
    body = response.get_json()
    assert body["meta"]["hostname"] == "de-fra-core-01"
    assert body["version"]["version"] == "9.1.0"
    assert body["bgp"]["established"] == 1


@pytest.mark.integration
def test_api_health_404s_on_unknown_hostname(app_client):
    response = app_client.get("/api/health/does-not-exist-99")
    assert response.status_code == 404
    body = response.get_json()
    assert body["success"] is False
    assert "Unknown hostname" in body["error"]
