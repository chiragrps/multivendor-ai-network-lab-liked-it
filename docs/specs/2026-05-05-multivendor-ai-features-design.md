# Multivendor AI Network Lab — Phase 3 Feature Pack

**Date:** 2026-05-05
**Author:** Georgi Gaydarov
**Status:** Approved (option C + clever extras)

## Goal

Extract net-new patterns from 4 reference projects and bolt them onto the existing 26-device multivendor lab without rewriting what already works.

## Reference projects

| Source | Pattern extracted |
|---|---|
| codingnetworks.blog (MPLS+MCP) | MCP tool surface for live AI control |
| sands-lab/nika | Eval harness with composable incidents + LLM-as-judge |
| Hugo Tinoco / pydantic-ai | Orchestrator + child agents with structured output validation |
| automateyournetwork/netclaw | GAIT audit, TOON serialization, intent verification, path trace, CVE scan |

## Already shipped (do not redo)

- 26 sanitized devices: 10 Juniper (junos), 6 Arista (eos), 10 FRR live containers
- Flask blueprint `/api/mv/*` with 8 endpoints
- 6 demo UI tabs (MV Inventory, Fleet Audit, SuzieQ, gNMI, Syslog, SNMP)
- `mcp_dcn_server.py` (276 lines, 17 legacy tools)
- `sanitize_configs.py`, `sim_bgp_failure.sh`

## Net-new feature list

### F1 — MCP server expansion

Add `/api/mv/*` endpoints as MCP tools so Claude Code can call them directly. Extends `mcp_dcn_server.py`.

New MCP tools: `mv_list_devices`, `mv_topology`, `mv_fleet_audit`, `mv_suzieq`, `mv_gnmi`, `mv_syslog`, `mv_traps`, `mv_intent_verify`, `mv_path_trace`, `mv_eval_run`.

### F2 — Pydantic-AI orchestrator

New file `04_Scripts_Tools/DCN_Network_Tool/pydantic_ai_orchestrator.py`.

- `OrchestratorAgent` — top-level, decides which child agent
- `RoutingAgent` — BGP/OSPF queries, returns `RoutingDiagnosis(BaseModel)`
- `ACLAgent` — firewall/ACL queries, returns `ACLDiagnosis(BaseModel)`
- `IncidentAgent` — creates `IncidentTicket(BaseModel)` with `TicketId`, `Severity`, `RootCause`, `Remediation`
- Anthropic native (claude-haiku-4-5 default, claude-sonnet-4-6 for hard problems) with optional OpenRouter switch
- Tools wrap existing Flask endpoints, no duplicate logic

### F3 — Intent verification

New endpoint `/api/mv/intent/verify`. Cross-references:
1. **Config-claimed state** — parse static configs in `demo-devices/`
2. **Live-observed state** — SuzieQ-parsed BGP/OSPF/interface state
3. Flag drift: claimed-but-not-observed, observed-but-not-claimed

Returns `{drift: [{device, type, claimed, observed}], score: float}`.

### F4 — Eval harness

New file `eval_harness.py` + `scenarios.json` (10 incidents).

Each scenario:
```json
{
  "id": "bgp-001",
  "title": "FRA core BGP peer down",
  "fault": {"type": "bgp_down", "device": "fra-core-01", "peer": "lon-core-01"},
  "expected_root_cause": "Peer 10.200.0.13 unreachable",
  "expected_remediation": "Verify L1 + restart neighbor"
}
```

Endpoint `/api/mv/eval/run` accepts `{scenario_id, agent: "orchestrator"|"ai_command"}`. Injects fault, asks agent to diagnose, judges via LLM-as-judge (claude-haiku), returns `{score: 0–10, reasoning, agent_trace}`.

### F5 — Path trace + GAIT

`/api/mv/path/trace?src=&dst=` — uses BGP topology from `inventory.json` + SuzieQ to compute hop list. Returns SVG-ready node list with health colors.

`gait_audit.py` — appends every `/api/ai-command`, `/api/mv/eval/run`, `/api/mv/intent/verify` call to `audit/gait.jsonl` with timestamp, prompt, response, tools-called, token-cost.

`/api/mv/gait/recent?limit=N` returns last N events.

### F6 — TOON + CVE

`toon_serializer.py` — Tabular Object Oriented Notation for arrays of homogeneous dicts. Header row + value rows separated by `|`. Demonstrably 40–60% smaller than JSON for `mv/devices`, `mv/topology`.

Toggle: `?fmt=toon` query param on `/api/mv/devices` and `/api/mv/topology`.

`cve_db.json` — static lookup table mapping `(vendor, os_version)` to CVE list. Fleet Audit tab adds CVE column.

### F7 — Vendor command translator (clever)

`vendor_translator.py`. Given canonical task (`bgp_summary`, `interface_status`, `route_lookup`), returns vendor-specific CLI:

```python
TRANSLATE = {
  "bgp_summary": {
    "junos": "show bgp summary",
    "eos":   "show ip bgp summary",
    "frr":   "vtysh -c 'show ip bgp summary'",
  },
  ...
}
```

Used by Pydantic-AI tools and the eval harness.

### F8 — Auto-remediation runbooks (clever)

`runbooks/` directory with YAML playbooks per fault type:

```yaml
id: bgp_peer_down
steps:
  - check: vendor_translator.bgp_summary
  - check: ping_peer
  - remediate: clear_bgp_neighbor   # destructive, gated
```

Endpoint `/api/mv/runbook/execute` runs steps in dry-run by default.

## UI changes

| Tab | Status | Endpoint |
|---|---|---|
| 🤖 Agent Orchestrator | NEW | `/api/mv/orchestrator` |
| 🎯 Intent Verify | NEW | `/api/mv/intent/verify` |
| 🧪 Eval Harness | NEW | `/api/mv/eval/run` |
| 🛣️ Path Trace | NEW | `/api/mv/path/trace` |
| 📜 GAIT Audit | NEW | `/api/mv/gait/recent` |
| 🗄️ MV Inventory | EXTEND | adds CVE + TOON toggle |
| 🔍 Fleet Audit | EXTEND | adds CVE column |

Topology refinement: clean Excalidraw-style SVG, vendor-color-coded badges (Juniper green, Arista blue, FRR purple), no clutter.

## Testing

Playwright MCP smoke test:
1. Navigate `http://localhost:5757/demo/index.html`
2. Click each new tab, take screenshot
3. Verify network requests succeed (200) and payload non-empty
4. Verify zero JS console errors

## Out of scope

- Live protocol participation (scapy speakers) — too risky for demo
- ServiceNow ITSM gating — replaced by simple JSONL approval queue
- 3D Three.js visualization — minimalist 2D SVG is enough

## Files added/modified

```
04_Scripts_Tools/DCN_Network_Tool/
├── multivendor_extensions.py    [EXTEND: F3, F5 endpoints]
├── pydantic_ai_orchestrator.py  [NEW: F2]
├── eval_harness.py              [NEW: F4]
├── gait_audit.py                [NEW: F5]
├── toon_serializer.py           [NEW: F6]
├── vendor_translator.py         [NEW: F7]
├── cve_db.json                  [NEW: F6]
├── runbooks/                    [NEW: F8]
│   ├── bgp_peer_down.yaml
│   ├── interface_down.yaml
│   └── ospf_neighbor_stuck.yaml
├── scenarios.json               [NEW: F4]
└── mcp_dcn_server.py            [EXTEND: F1 — add 10 mv tools]

demo/index.html                  [EXTEND: 5 new tabs]
network-lab/MULTIVENDOR_LAB.md   [UPDATE: document new features]
docs/superpowers/specs/...       [THIS FILE]
```

## Acceptance

- All new endpoints return 200 with valid JSON for 26 devices
- Pydantic-AI orchestrator routes 3 sample queries to correct child agent
- Eval harness scores at least one scenario ≥ 7/10
- Playwright loads all new tabs without console errors
- `sanitize_configs.py` reports 0 leaks
- Single git commit with structured message
