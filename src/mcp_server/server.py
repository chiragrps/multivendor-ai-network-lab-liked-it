"""
Multivendor AI Network — MCP server.

Exposes the closed-loop NetOps tool to MCP clients (Claude Code, Cursor,
Cline, opencode, Claude Desktop). Tools are thin wrappers over the existing
Flask API; resources expose read-only snapshots.

Run:
    multivendor-ai-mcp                       # stdio (default)
    multivendor-ai-mcp --transport sse       # streamable HTTP / SSE on :8080
    DCN_API_URL=http://host:5757 multivendor-ai-mcp

Setup snippets shipped in mcp_server/README.md.
"""
from __future__ import annotations

import argparse
import json
import sys

from mcp.server.fastmcp import FastMCP

from . import tools as T

mcp = FastMCP(
    name="multivendor-ai-network",
    instructions=(
        "Operate the multivendor-ai-network-lab from natural language. "
        "Use list_devices / bgp_status / topology_snapshot to investigate. "
        "Use health_gate_apply for ANY mutating change — it provides "
        "confirmed-commit with auto-revert. Use postmortem_generate to "
        "produce incident reports. All actions land in the GAIT audit trail."
    ),
)


# ── Tier 1: read-only ───────────────────────────────────────────────────────

@mcp.tool()
def list_devices(site: str | None = None, vendor: str | None = None,
                 role: str | None = None) -> dict:
    """List lab devices, optionally filtered by site / vendor / role.

    Args:
        site:   one of DE-FRA, UK-LON, NL-AMS, EU-CDG, US-NYC (case-insensitive)
        vendor: juniper | arista | frr (matches vendor or os field)
        role:   core | edge | dist | firewall | leaf | access
    """
    return T.list_devices(site=site, vendor=vendor, role=role)


@mcp.tool()
def bgp_status(hostname: str) -> dict:
    """Return BGP summary for a single device (runs 'show bgp summary')."""
    return T.bgp_status(hostname)


@mcp.tool()
def topology_snapshot() -> dict:
    """Return the current BGP topology graph — nodes, edges, session colors."""
    return T.topology_snapshot()


@mcp.tool()
def compliance_scan(site: str | None = None) -> dict:
    """Run compliance audit (BGP auth, prefix-limits, OSPF timers, router-IDs).

    Optionally filter by site code. Returns per-device per-policy results.
    """
    return T.compliance_scan(site=site)


# ── Tier 2: closed-loop (mutating, guarded) ─────────────────────────────────

@mcp.tool()
def health_gate_apply(hostname: str, edit_payload: str = "",
                      timeout_s: int = 30) -> dict:
    """Apply a config change through the Health Gate — RFC 6241 §8.4
    confirmed-commit. The device auto-reverts at NETCONF timeout if any
    regression is detected during the watch window.

    Args:
        hostname:     target device (e.g. de-fra-core-01)
        edit_payload: NETCONF <edit-config> body (or a runbook reference)
        timeout_s:    confirmed-commit timeout window (default 30)
    """
    return T.health_gate_apply(hostname, edit_payload, timeout_s)


@mcp.tool()
def health_gate_status(job_id: str) -> dict:
    """Poll a Health Gate job for verdict (confirmed | abandoned | error)."""
    return T.health_gate_status(job_id)


@mcp.tool()
def netbox_sot_drift() -> dict:
    """Return current source-of-truth drift between NetBox and the lab.

    Severity-tiered: critical (extra-in-lab) / high (presence + IP/AS/site) /
    medium (vendor/role) / low (model/os).
    """
    return T.netbox_sot_drift()


@mcp.tool()
def remediation_propose_for_drift(drift_row: dict) -> dict:
    """AI-propose a runbook to fix a single drift row.

    Cosmetic drift (model/site/vendor mismatch) auto-rejects with rationale.
    """
    return T.remediation_propose_for_drift(drift_row)


@mcp.tool()
def remediation_approve(proposal_id: str, actor: str = "mcp") -> dict:
    """Approve a pending proposal. Kicks Health Gate execution of the runbook.

    Use this only after a human has reviewed the proposal — even though
    MCP clients are LLMs, approval should be intentional, not a side effect
    of investigation.
    """
    return T.remediation_approve(proposal_id, actor=actor)


@mcp.tool()
def gait_recent_actions(actor: str | None = None, limit: int = 20) -> dict:
    """Query the GAIT audit trail (append-only JSONL of every action)."""
    return T.gait_recent_actions(actor=actor, limit=limit)


@mcp.tool()
def postmortem_auto_detect(window_h: int = 2) -> dict:
    """Auto-detect recent incidents — anchored on Health Gate abandons and
    clusters of error/critical events. Returns each incident with severity,
    root-cause guess, affected devices, and the correlated event list.
    """
    return T.postmortem_auto_detect(window_h=window_h)


@mcp.tool()
def postmortem_generate(minutes_back: int = 30,
                        devices: list[str] | None = None) -> dict:
    """Generate an incident report (with Markdown) for the given window.

    Args:
        minutes_back: lookback window from now (default 30)
        devices:      optional hostname filter
    """
    return T.postmortem_generate(minutes_back=minutes_back, devices=devices)


# ── Resources: read-only snapshots LLMs can subscribe to ────────────────────

@mcp.resource("inventory://devices")
def inventory_resource() -> str:
    """All lab devices in JSON form (hostname, ip, port, vendor, model, role, site)."""
    return json.dumps(T.list_devices(), indent=2)


@mcp.resource("topology://bgp")
def topology_resource() -> str:
    """Current BGP topology graph in JSON form."""
    return json.dumps(T.topology_snapshot(), indent=2)


@mcp.resource("gait://recent")
def gait_resource() -> str:
    """Last 50 entries from the GAIT audit trail."""
    return json.dumps(T.gait_recent_actions(limit=50), indent=2)


@mcp.resource("incidents://active")
def incidents_resource() -> str:
    """Auto-detected incidents in the last 2 hours."""
    return json.dumps(T.postmortem_auto_detect(window_h=2), indent=2)


# ── Prompts: pre-built LLM task templates ───────────────────────────────────

@mcp.prompt()
def diagnose_device(hostname: str) -> str:
    """Compose a diagnosis prompt for a specific device with the right context.

    The returned string is a ready-to-send prompt that instructs the LLM to
    call the relevant inspection tools and synthesize a structured answer.
    """
    return (
        f"Investigate {hostname}.\n\n"
        f"Step 1. Call bgp_status('{hostname}') to read the BGP state.\n"
        f"Step 2. Call gait_recent_actions with target='{hostname}' to see "
        f"recent operator + AI actions.\n"
        f"Step 3. Call netbox_sot_drift() and look for rows where "
        f"hostname='{hostname}'.\n"
        f"Step 4. Synthesize a 4-line summary: state · recent change · drift "
        f"(if any) · recommended next step.\n"
    )


@mcp.prompt()
def write_postmortem(window_minutes: int = 30) -> str:
    """Compose a postmortem-writing prompt.

    The LLM is instructed to call postmortem_auto_detect first, pick the
    most severe incident, then generate a polished report.
    """
    return (
        f"Write an incident report covering the last {window_minutes} minutes.\n\n"
        f"Step 1. Call postmortem_auto_detect(window_h={max(1, window_minutes // 60)}).\n"
        f"Step 2. If incidents are found, pick the most severe (P1 > P2 > P3).\n"
        f"Step 3. Call postmortem_generate(minutes_back={window_minutes}).\n"
        f"Step 4. Return the Markdown report verbatim. Do not paraphrase.\n"
        f"Step 5. After the report, add a 'Next steps' section listing 2-3 "
        f"concrete follow-up actions for the operator.\n"
    )


# ── Entrypoint ──────────────────────────────────────────────────────────────


def main() -> None:
    p = argparse.ArgumentParser(prog="multivendor-ai-mcp")
    p.add_argument("--transport", choices=["stdio", "sse"], default="stdio",
                   help="Transport: stdio (default, for IDE clients) or sse (HTTP).")
    args = p.parse_args()
    if args.transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
