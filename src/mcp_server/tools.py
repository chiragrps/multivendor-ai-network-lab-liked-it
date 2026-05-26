"""
MCP tool implementations.

Each function is a thin wrapper that calls the existing Flask API. Keeping
business logic out of this layer means the MCP server can't drift from the
HTTP API — they call the same endpoints.

Every mutating call writes a GAIT audit entry with actor="mcp" so the LLM's
actions are traceable in the audit trail.
"""
from __future__ import annotations

import os
from typing import Any

import requests

# Base URL for the Flask API the MCP tools delegate to. Override via env.
API_BASE = os.environ.get("DCN_API_URL", "http://localhost:5757")
HTTP_TIMEOUT = float(os.environ.get("DCN_MCP_TIMEOUT", "15"))


def _get(path: str, params: dict | None = None) -> Any:
    r = requests.get(API_BASE + path, params=params or {}, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


def _post(path: str, body: dict | None = None) -> Any:
    r = requests.post(API_BASE + path, json=body or {}, timeout=HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


# ── Tier 1: read-only inventory & state ─────────────────────────────────────


def list_devices(site: str | None = None, vendor: str | None = None,
                 role: str | None = None) -> dict:
    """Return all lab devices, optionally filtered by site / vendor / role."""
    data = _get("/api/devices")
    devices = data.get("devices") if isinstance(data, dict) else data
    devices = devices or []
    if site:
        devices = [d for d in devices if (d.get("site") or "").upper() == site.upper()]
    if vendor:
        v = vendor.lower()
        devices = [d for d in devices if (d.get("vendor") or "").lower() == v
                   or (d.get("os") or "").lower() == v]
    if role:
        devices = [d for d in devices if (d.get("role") or "").lower() == role.lower()]
    return {"count": len(devices), "devices": devices}


def bgp_status(hostname: str) -> dict:
    """Return BGP summary for a single device by running `show bgp summary`."""
    return _post("/api/run", {"hostname": hostname, "raw": "show bgp summary"})


def run_command(hostname: str, command: str) -> dict:
    """Run an arbitrary CLI command on a device — Flask dispatches per vendor.

    The Flask `/api/run` endpoint already knows how to talk to each device
    family (FRR vtysh, Junos NETCONF / CLI, Arista EOS eAPI / SSH, Nokia SRL
    `sr_cli`). MCP clients send the command in the operator's native syntax
    for the target — list_devices() exposes the vendor field so the LLM can
    pick the right syntax.
    """
    return _post("/api/run", {"hostname": hostname, "raw": command})


# Per-vendor "show running-config" mapping. Falls back to FRR/IOS-style if a
# vendor isn't in the map — most network OSes accept `show running-config`.
_CONFIG_COMMAND_BY_VENDOR: dict[str, str] = {
    "frr":             "show running-config",
    "cisco_iosxr":     "show running-config",
    "cisco_ios":       "show running-config",
    "arista_eos":      "show running-config",
    "eos":             "show running-config",
    "juniper":         "show configuration | display set",
    "junos":           "show configuration | display set",
    "nokia_srl":       "info",
    "srl":             "info",
}


def get_config(hostname: str, section: str | None = None) -> dict:
    """Fetch a device's running config — multivendor-aware.

    Looks up the device's vendor via /api/devices, then dispatches the right
    `show config` flavor (Junos uses `show configuration | display set`, EOS
    and FRR use `show running-config`, Nokia SRL uses `info`). Optional
    `section` is appended to scope the output (e.g. `interface eth0` on FRR,
    `protocols bgp` on Junos).
    """
    devices = list_devices().get("devices", []) or []
    dev = next(
        (d for d in devices
         if (d.get("hostname") or d.get("name") or "").lower() == hostname.lower()),
        None,
    )
    if not dev:
        return {"error": f"unknown hostname: {hostname}",
                "hint": "call list_devices() to enumerate"}
    vendor = (dev.get("vendor") or dev.get("dtype") or dev.get("os") or "").lower()
    base = _CONFIG_COMMAND_BY_VENDOR.get(vendor, "show running-config")
    command = f"{base} {section}".strip() if section else base
    result = _post("/api/run", {"hostname": hostname, "raw": command})
    if isinstance(result, dict):
        result.setdefault("vendor", vendor)
        result.setdefault("command", command)
    return result


def topology_snapshot() -> dict:
    """Return current BGP topology graph (nodes + edges + colors)."""
    try:
        return _get("/api/mv/topology")
    except requests.HTTPError:
        return _get("/api/topology")


def compliance_scan(site: str | None = None) -> dict:
    """Run compliance checks across the fleet, optionally filtered by site."""
    body: dict = {}
    if site:
        body["site"] = site
    else:
        body["hostnames"] = [
            "de-fra-core-01", "de-fra-core-02", "uk-lon-core-01",
            "nl-ams-core-01", "us-nyc-core-01", "de-fra-edge-01",
            "uk-lon-edge-01", "nl-ams-edge-01", "uk-lon-dist-01",
            "de-fra-dist-01",
        ]
    return _post("/api/compliance/scan", body)


# ── Tier 2: closed-loop (mutating, guarded) ─────────────────────────────────


def health_gate_apply(hostname: str, edit_payload: str = "",
                      timeout_s: int = 30) -> dict:
    """Submit a Health Gate job — confirmed-commit with watch window."""
    body = {"hostname": hostname, "edit_payload": edit_payload, "timeout_s": timeout_s}
    return _post("/api/mv/health-gate/apply", body)


def health_gate_status(job_id: str) -> dict:
    """Poll a Health Gate job for its verdict."""
    return _get(f"/api/mv/health-gate/status/{job_id}")


def netbox_sot_drift() -> dict:
    """Compute current SoT-vs-observed drift."""
    return _get("/api/mv/netbox-sot/drift")


def remediation_propose_for_drift(drift_row: dict) -> dict:
    """AI-propose a runbook for a single drift row (or auto-reject if cosmetic)."""
    return _post("/api/mv/remediation/propose-for-drift", {"drift_row": drift_row})


def remediation_approve(proposal_id: str, actor: str = "mcp") -> dict:
    """Approve a pending proposal — kicks Health Gate execution."""
    return _post(f"/api/mv/remediation/approve/{proposal_id}",
                 {"actor": actor, "timeout_s": 30})


def gait_recent_actions(actor: str | None = None, limit: int = 20) -> dict:
    """Query the GAIT audit trail."""
    params: dict = {"limit": limit}
    if actor:
        params["actor"] = actor
    return _get("/api/mv/gait/recent", params)


def postmortem_generate(minutes_back: int = 30,
                        devices: list[str] | None = None) -> dict:
    """Generate an incident report for the given window."""
    body: dict = {"minutes_back": minutes_back}
    if devices:
        body["devices"] = devices
    return _post("/api/mv/postmortem/generate", body)


def postmortem_auto_detect(window_h: int = 2) -> dict:
    """Auto-detect recent incidents anchored on Health Gate abandons."""
    return _get("/api/mv/postmortem/incidents", {"window_h": window_h})


# ── Helpers exposed for tests ───────────────────────────────────────────────


__all__ = [
    "API_BASE",
    "list_devices",
    "bgp_status",
    "run_command",
    "get_config",
    "topology_snapshot",
    "compliance_scan",
    "health_gate_apply",
    "health_gate_status",
    "netbox_sot_drift",
    "remediation_propose_for_drift",
    "remediation_approve",
    "gait_recent_actions",
    "postmortem_generate",
    "postmortem_auto_detect",
]
