# Multivendor AI Network — MCP Tools Reference

A Model Context Protocol (MCP) server that exposes the multivendor-ai-network lab to any MCP-compatible client (Claude Code, Claude Desktop, Cursor, Cline, VS Code Copilot, OpenCode).

**Vendors covered through one server**: Juniper Junos · Cisco IOS / IOS-XR · Arista EOS · Nokia SR Linux · FRR. One MCP surface, four vendor families, no per-vendor MCP gymnastics.

## Two server entrypoints (reconciliation, 2026-05-26)

| Entrypoint | File | Tools | Status | Use when |
|---|---|---|---|---|
| **`src/mcp_dcn_server.py`** | single file, FastMCP, stdio | **63** (Phase-5 canonical) | **Canonical** — referenced from `docs/PHASE_5_HANDOFF.md` | Default. All operational surfaces exposed: `dcn_run_command`, `mv_clab_status`, `mv_change_closed_loop`, `mv_anomaly_detect`, `mv_forecast_fleet`, `mv_chaos_bgp`, etc. |
| `src/mcp_server/` package (`server.py` + `tools.py`) | 14 tools, FastMCP | Lightweight wrapper, native dict returns | Drop-in for testing / for clients that need native Python dicts (not JSON strings) | Less-used; kept for the composite operational tools with type-rich returns. |

**For all new work, target `src/mcp_dcn_server.py`.** The package form is a parallel surface from an earlier iteration; it stays around because its 14 high-level composites (drift, postmortem, remediation) have a cleaner per-tool schema, but the canonical 63-tool surface in `mcp_dcn_server.py` is the launch surface and the one the Phase 5 handoff references.

---

## Table of Contents

- [What sets this apart](#what-sets-this-apart)
- [Quick Start](#quick-start)
  - [Claude Code (stdio)](#claude-code-stdio)
  - [Claude Desktop (stdio)](#claude-desktop-stdio)
  - [VS Code Copilot / Cursor (HTTP-SSE)](#vs-code-copilot--cursor-http-sse)
- [Tool Reference](#tool-reference)
  - [Tier 1 — Read primitives](#tier-1--read-primitives)
  - [Tier 2 — Operational composites](#tier-2--operational-composites)
  - [Tier 3 — Closed-loop change](#tier-3--closed-loop-change)
  - [Tier 4 — Forensics & audit](#tier-4--forensics--audit)
- [Resources](#resources)
- [Prompts](#prompts)
- [Architecture](#architecture)
- [Security & Guardrails](#security--guardrails)

---

## What sets this apart

Most vendor-shipped MCP servers (e.g. [Juniper junos-mcp-server](https://github.com/Juniper/junos-mcp-server)) wrap one device family's CLI. That solves the *primitive* layer for that vendor only. This server adds two more layers on top, **vendor-agnostic**:

| Layer | Single-vendor MCP | This server |
|---|---|---|
| **Device primitives** | `execute_junos_command`, `get_junos_config` | `run_command`, `get_config` (4 vendor families dispatched by `list_devices.vendor`) |
| **Operational composites** | — | `bgp_status`, `compliance_scan`, `topology_snapshot`, `netbox_sot_drift` |
| **Closed-loop change** | direct commit (no rollback) | `health_gate_apply` (RFC 6241 §8.4 confirmed-commit with auto-revert) |
| **Forensics & audit** | — | `postmortem_auto_detect`, `postmortem_generate`, `gait_recent_actions` |
| **Remediation** | — | `remediation_propose_for_drift`, `remediation_approve` (AI-proposed, human-gated) |

You don't lose primitive access — `run_command` and `get_config` work against any of the four vendor families. You gain operational tools the LLM can chain without learning per-vendor syntax for every workflow.

---

## Quick Start

### Prerequisites

- The DCN_Network_Tool Flask API must be running locally on port 5757 (or wherever `DCN_API_URL` points).
- Python 3.11+ with the project venv active.

```bash
# Start the lab + Flask API
./network-lab/start_lab_tool.sh

# Verify the MCP entrypoint is installed
which multivendor-ai-mcp
# → .../DCN_Network_Tool/venv/bin/multivendor-ai-mcp
```

### Claude Code (stdio)

Add to your project `.mcp.json` (or `~/.claude/mcp_servers.json` for user-scope):

```json
{
  "mcpServers": {
    "multivendor-ai-network": {
      "command": "/absolute/path/to/DCN_Network_Tool/venv/bin/multivendor-ai-mcp",
      "env": {
        "DCN_API_URL": "http://localhost:5757"
      }
    }
  }
}
```

Then in any Claude Code session: ask "what's the BGP state on leaf2?" — Claude calls `bgp_status` directly.

### Claude Desktop (stdio)

Edit `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "multivendor-ai-network": {
      "command": "/absolute/path/to/DCN_Network_Tool/venv/bin/multivendor-ai-mcp",
      "args": ["--transport", "stdio"]
    }
  }
}
```

Restart Claude Desktop. The 14 tools appear in the tools picker.

### VS Code Copilot / Cursor (HTTP-SSE)

Start the server in SSE mode:

```bash
multivendor-ai-mcp --transport sse
# Listens on http://localhost:8080
```

VS Code `mcp.json`:

```json
{
  "servers": {
    "multivendor-ai-network": {
      "url": "http://localhost:8080/sse"
    }
  }
}
```

---

## Tool Reference

### Tier 1 — Read primitives

| Tool | Args | Returns |
|---|---|---|
| `list_devices` | `site?`, `vendor?`, `role?` | `{count, devices[]}` |
| `bgp_status` | `hostname` | `{output, rc, ...}` from `show bgp summary` |
| `run_command` | `hostname`, `command` | raw run result — works on any vendor |
| `get_config` | `hostname`, `section?` | running config — multivendor dispatch |
| `topology_snapshot` | — | `{nodes[], edges[]}` |

#### `list_devices`

Enumerate lab devices, optionally filtered. Filters are case-insensitive; vendor matches either `vendor` or `os` field.

```python
list_devices(site="DE-FRA")
list_devices(vendor="juniper")
list_devices(role="edge")
```

#### `run_command`

Run an arbitrary CLI command against any device. The Flask runner dispatches per vendor — vtysh for FRR, NETCONF for Junos, EOS SSH for Arista, `sr_cli` for Nokia SRL. Read-only intent — for mutating changes, use `health_gate_apply`.

```python
run_command("de-fra-core-01", "show ip ospf neighbor")
run_command("leaf2", "info /network-instance default protocols bgp")
run_command("uk-lon-fw-01", "show interfaces ge-0/0/0 terse")
```

#### `get_config`

Multivendor running-config fetch. Looks up the device's vendor and dispatches:

| Vendor | Command |
|---|---|
| Juniper Junos | `show configuration \| display set` |
| Cisco IOS / IOS-XR | `show running-config` |
| Arista EOS | `show running-config` |
| FRR | `show running-config` |
| Nokia SR Linux | `info` |

Optional `section` argument scopes the dump:

```python
get_config("uk-lon-fw-01", section="protocols bgp")
# → runs: show configuration | display set protocols bgp

get_config("leaf2", section="/network-instance default")
# → runs: info /network-instance default

get_config("de-fra-core-01")
# → runs: show running-config
```

Returns include `vendor` and `command` fields so the LLM can see how the dispatch landed.

### Tier 2 — Operational composites

| Tool | Args | Purpose |
|---|---|---|
| `bgp_status` | `hostname` | normalized `show bgp summary` |
| `compliance_scan` | `site?` | BGP auth, prefix-limits, OSPF timers, router-IDs |
| `topology_snapshot` | — | live BGP graph (nodes, edges, colors) |
| `netbox_sot_drift` | — | severity-tiered drift between NetBox and observed state |

`compliance_scan` defaults to the 10 lab hostnames when no site is given.

`netbox_sot_drift` returns rows tagged `critical` (extra-in-lab), `high` (presence + IP/AS/site), `medium` (vendor/role), `low` (model/os).

### Tier 3 — Closed-loop change

| Tool | Args | Purpose |
|---|---|---|
| `health_gate_apply` | `hostname`, `edit_payload`, `timeout_s` | RFC 6241 §8.4 confirmed-commit with watch window |
| `health_gate_status` | `job_id` | poll verdict: confirmed · abandoned · error |
| `remediation_propose_for_drift` | `drift_row` | AI proposes a runbook; cosmetic drift auto-rejects |
| `remediation_approve` | `proposal_id`, `actor?` | kicks Health Gate execution of an approved proposal |

Mutating changes go through the Health Gate — if any regression appears during the watch window (BGP drop, OSPF loss, error-rate spike), the device auto-reverts via NETCONF confirmed-commit. The LLM never has direct config-push authority.

### Tier 4 — Forensics & audit

| Tool | Args | Purpose |
|---|---|---|
| `gait_recent_actions` | `actor?`, `limit` | append-only audit trail (every action, with token cost) |
| `postmortem_auto_detect` | `window_h` | recent incidents anchored on Health Gate abandons + error clusters |
| `postmortem_generate` | `minutes_back`, `devices?` | Markdown incident report for a time window |

Every mutating MCP call writes a GAIT entry with `actor="mcp"` so LLM actions are distinguishable from human actions in the trail.

---

## Resources

Read-only data the LLM can subscribe to:

| URI | Content |
|---|---|
| `inventory://devices` | all lab devices (JSON) |
| `topology://bgp` | current BGP topology graph (JSON) |
| `gait://recent` | last 50 GAIT entries (JSON) |
| `incidents://active` | auto-detected incidents in the last 2 hours (JSON) |

---

## Prompts

Pre-built task templates that compose the right tool chain:

| Prompt | Args | What it does |
|---|---|---|
| `diagnose_device` | `hostname` | guides the LLM through `bgp_status` → `gait_recent_actions` → `netbox_sot_drift` → 4-line synthesis |
| `write_postmortem` | `window_minutes` | guides `postmortem_auto_detect` → severity rank → `postmortem_generate` → polish |

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│  MCP Client  (Claude Code · Claude Desktop · Cursor · …)   │
└────────────────────────┬───────────────────────────────────┘
                         │ stdio / SSE
                         ▼
┌────────────────────────────────────────────────────────────┐
│  multivendor-ai-mcp  (this server, FastMCP)                │
│  ─ 14 @mcp.tool() decorators                               │
│  ─ 4 @mcp.resource() endpoints                             │
│  ─ 2 @mcp.prompt() templates                               │
└────────────────────────┬───────────────────────────────────┘
                         │ HTTP (DCN_API_URL)
                         ▼
┌────────────────────────────────────────────────────────────┐
│  DCN_Network_Tool Flask API  (port 5757)                   │
│  ─ multivendor dispatch (vtysh / NETCONF / eAPI / sr_cli)  │
│  ─ Health Gate (RFC 6241 §8.4 confirmed-commit)            │
│  ─ GAIT audit · netlog-ai knowledge graph                  │
│  ─ Forecast / Predict / Blast Radius (Phase 5)             │
└────────────────────────┬───────────────────────────────────┘
                         │ SSH / NETCONF / sr_cli
                         ▼
            ┌────────────┴────────────┐
            │  10 FRR DCN routers     │  ← multivendor lab
            │  9 clab Clos-EVPN nodes │     SRL · EOS · FRR
            │  (51/51 BGP up)         │
            └─────────────────────────┘
```

Two-layer separation by design: [tools.py](../src/mcp_server/tools.py) holds the thin HTTP wrappers; [server.py](../src/mcp_server/server.py) holds the MCP decorators with the descriptions the LLM actually sees. Tests can exercise the HTTP layer with mocks (no live Flask needed) and the registry layer via FastMCP's `list_tools()`.

---

## Security & Guardrails

- **No direct device push from MCP.** All mutating changes route through `health_gate_apply`, which uses RFC 6241 §8.4 confirmed-commit. If the change causes regression in the watch window, the device auto-reverts.
- **Cosmetic drift auto-rejects.** `remediation_propose_for_drift` refuses to propose changes for model/site/vendor cosmetic mismatches — they need a human to either fix the SoT or accept the discrepancy.
- **`remediation_approve` is a separate step.** The LLM can propose, but execution requires a deliberate approval call. This stops "while I was investigating, I accidentally fixed it" failure modes.
- **GAIT audit is append-only.** Every action — tool call, proposal, approval, commit, revert — writes a JSONL entry with actor, timestamp, target, payload hash, and token cost.
- **Authentication.** The server has no built-in auth (stdio inherits the user's context; SSE binds localhost by default). For multi-user or remote deployments, front it with a reverse proxy + token auth (same pattern as Juniper's `jmcp_token_manager`).
- **No production endpoints by default.** `DCN_API_URL` defaults to `http://localhost:5757`. Set it explicitly to point at a remote deployment.

---

## Phase 5 additions (2026-05-25) — 13 new tools (50 → 63) in `mcp_dcn_server.py`

| Tool | Wraps |
|---|---|
| `mv_clab_status` | live clab fabric state — per-node BGP + interface counts |
| `mv_fabric_topology` | physical + overlay topology (honors `fabric=clos-evpn\|dcn\|all`) |
| `mv_gnmic_status` | streaming-telemetry sidecar health + per-target freshness |
| `mv_knowledge_correlate` | LLM correlator with knowledge enrichment from netlog-ai |
| `mv_anomaly_detect` | ADTK z-score + flap-count detectors |
| `mv_forecast_fleet` | fleet-wide predictive forecast across 9 routing nodes × 2 metrics |
| `mv_forecast_status` | last fleet forecast summary |
| `mv_change_closed_loop` | submit a 6-stage governed change |
| `mv_change_status` | poll a closed-loop change by `change_id` |
| `mv_change_recent` | list recent + active closed-loop runs |
| `mv_chaos_bgp` | dual-fabric chaos injection (dcn=sim, clab=live docker exec) |
| `mv_napalm_bgp` + `mv_napalm_job` | vendor-aware NAPALM-equivalent (4 vendors via docker exec) |
| `mv_shadow_audit` | NetBox SoT vs running-config drift audit |

Phase 6 will add 5 more (auto-remediation surface) for a total of 68. See `PHASE6_PLAN.md`.

## Running Tests

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
source venv/bin/activate
python -m pytest test_mcp_server.py -v
```

30 tests cover the `src/mcp_server/` package layer: HTTP-mocked tools, per-vendor dispatch for `get_config` (Junos `display set`, EOS/FRR/IOS `show running-config`, SRL `info`), registry layer (decorator presence + schema), resources, prompts, and config env override.

The canonical `src/mcp_dcn_server.py` (63 tools) is validated by the live 41-pass stress test documented in `docs/POST_AUDIT_FIXES_2.md` rather than a unit-test suite — every tool was exercised against the live fabric on 2026-05-25 23:27.

---

## License

Apache 2.0. Same pattern as Juniper's [junos-mcp-server](https://github.com/Juniper/junos-mcp-server) — fork freely, contribute back upstream when the change is generally useful.
