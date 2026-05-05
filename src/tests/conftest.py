"""
conftest.py — shared pytest fixtures for DCN Network Tool tests.

Provides:
  - Flask test client with LLM/SSH mocked out
  - Sample device inventory (6 FRR lab containers)
  - Reusable mock helpers
"""

import json
import os
import sys

import pytest

# ── Make the package importable without installing ────────────────────────────
TOOL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TOOL_DIR)

# Set env vars before importing app so defaults are correct for testing
os.environ.setdefault("DCN_SSH_MODE",    "key")
os.environ.setdefault("DCN_SSH_USER",    "root")
os.environ.setdefault("DCN_SSH_KEY",     "/tmp/test_key")
os.environ.setdefault("LLM_ENABLED",     "true")
os.environ.setdefault("MODEL_RUNNER_URL","http://127.0.0.1:19999")  # non-existent → falls to haiku
os.environ.setdefault("ANTHROPIC_API_KEY","test-key-placeholder")
os.environ.setdefault("DCN_SECURECRT_CSV",
    os.path.join(os.path.dirname(TOOL_DIR), "../../network-lab/lab_securecrt.csv"))
os.environ.setdefault("DCN_NETBOX_CSV",  "/dev/null")


# ── Lab device inventory (mirrors lab_securecrt.csv — 10 devices, new naming) ─
LAB_DEVICES = [
    {"hostname": "de-fra-core-01", "ip": "localhost", "host": "localhost", "port": 2201, "type": "frr", "site": "DE-FRA"},
    {"hostname": "de-fra-core-02", "ip": "localhost", "host": "localhost", "port": 2202, "type": "frr", "site": "DE-FRA"},
    {"hostname": "uk-lon-core-01", "ip": "localhost", "host": "localhost", "port": 2203, "type": "frr", "site": "UK-LON"},
    {"hostname": "nl-ams-core-01", "ip": "localhost", "host": "localhost", "port": 2204, "type": "frr", "site": "NL-AMS"},
    {"hostname": "us-nyc-core-01", "ip": "localhost", "host": "localhost", "port": 2205, "type": "frr", "site": "US-NYC"},
    {"hostname": "de-fra-edge-01", "ip": "localhost", "host": "localhost", "port": 2206, "type": "frr", "site": "DE-FRA"},
    {"hostname": "uk-lon-edge-01", "ip": "localhost", "host": "localhost", "port": 2207, "type": "frr", "site": "UK-LON"},
    {"hostname": "nl-ams-edge-01", "ip": "localhost", "host": "localhost", "port": 2208, "type": "frr", "site": "NL-AMS"},
    {"hostname": "uk-lon-dist-01", "ip": "localhost", "host": "localhost", "port": 2209, "type": "frr", "site": "UK-LON"},
    {"hostname": "de-fra-dist-01", "ip": "localhost", "host": "localhost", "port": 2210, "type": "frr", "site": "DE-FRA"},
]

# ── Sample CLI outputs ─────────────────────────────────────────────────────────
BGP_SUMMARY_OUTPUT = """\
BGP table version is 0, local router ID is 10.200.0.11
Status codes: s suppressed, d damped, h history, * valid, > best, = multipath,
              i internal, r RIB-failure, S Stale, R Removed
Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.200.0.12     4      65002    1234    1230        0    0    0 01:23:45        8
10.200.0.13     4      65003     987     980        0    0    0 00:45:12        4
"""

BGP_SUMMARY_WITH_DOWN = """\
BGP router identifier 10.200.0.11, local AS number 65001 vrf-id 0
Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
10.200.0.12     4      65002    1234    1230        0    0    0 01:23:45        8
10.200.0.13     4      65003       0       0        0    0    0 never    Active
"""

INTERFACE_OUTPUT = """\
Interface       Status     VRF             Addresses
eth0            up         default         10.200.0.11/24
eth1            up         default         192.168.1.1/30
lo              up         default         127.0.0.1/8
"""

VERSION_OUTPUT = "FRRouting 9.1.0 (de-fra-core-01) compiled on 2024-01-15."

ALARM_OUTPUT = """\
Interface eth1: DOWN
OSPF neighbor 10.200.0.12: FULL
"""


# ── Flask test client ─────────────────────────────────────────────────────────
@pytest.fixture(scope="session")
def app_client(monkeypatch_session):
    """
    Flask test client with heavy dependencies mocked out.
    SSH connections and LLM calls are replaced with fast, deterministic fakes.
    scope=session → one Flask app instance shared across all tests (fast).
    """
    import app as dcn_app

    # Patch device inventory so tests don't need real CSVs
    monkeypatch_session.setattr(dcn_app, "DEVICES", LAB_DEVICES)

    dcn_app.app.config["TESTING"] = True
    with dcn_app.app.test_client() as client:
        yield client


@pytest.fixture(scope="session")
def monkeypatch_session(request):
    """Session-scoped monkeypatch (pytest doesn't provide this by default)."""
    from _pytest.monkeypatch import MonkeyPatch
    mp = MonkeyPatch()
    yield mp
    mp.undo()


@pytest.fixture()
def mock_llm(monkeypatch):
    """
    Replace _llm_query with a simple callable that returns a preset response.
    Returns the mock so tests can configure .return_value dynamically.
    """
    import app as dcn_app
    from unittest.mock import MagicMock

    mock = MagicMock(return_value='{"cli": "show bgp summary"}')
    monkeypatch.setattr(dcn_app, "_llm_query", mock)
    return mock


@pytest.fixture()
def mock_ssh(monkeypatch):
    """
    Replace run_command_on_device with a fast fake that returns BGP summary output.
    Returns the mock so tests can override the return value per-test.
    """
    import app as dcn_app
    from unittest.mock import MagicMock

    mock = MagicMock(return_value={
        "success": True,
        "output":  BGP_SUMMARY_OUTPUT,
        "command": "show bgp summary",
    })
    monkeypatch.setattr(dcn_app, "run_command_on_device", mock)
    return mock
