# MCP Server — Day-9

Exposes the closed-loop NetOps tool to MCP clients (Claude Code, Cursor,
Cline, opencode, Claude Desktop). Engineers operate the network in natural
language without leaving their IDE.

## Why it exists

The Flask API is a clean surface — but typing curl in a terminal isn't the
same as asking *"why is BGP flapping on de-fra-core-01 and is the postmortem
ready?"* in your editor. MCP closes that gap by making every operation
discoverable + callable by an LLM with full audit trail.

## What it exposes

- **12 tools** — list_devices · bgp_status · topology_snapshot · compliance_scan
  · health_gate_apply · health_gate_status · netbox_sot_drift
  · remediation_propose_for_drift · remediation_approve · gait_recent_actions
  · postmortem_auto_detect · postmortem_generate
- **4 resources** — `inventory://devices` · `topology://bgp` · `gait://recent`
  · `incidents://active`
- **2 prompts** — `diagnose_device(hostname)` · `write_postmortem(window_minutes)`

Every tool call delegates to the existing Flask API (`DCN_API_URL`, default
`http://localhost:5757`). Mutating actions (`health_gate_apply`,
`remediation_approve`) land in the GAIT audit trail with `actor="mcp"`.

## Run

```bash
# stdio (for IDE / editor clients — Claude Code, Cursor, etc.)
multivendor-ai-mcp

# HTTP / SSE (for remote clients)
multivendor-ai-mcp --transport sse

# Override backend URL
DCN_API_URL=http://prod-host:5757 multivendor-ai-mcp
```

## Client setup

### Claude Code

Edit `~/.claude/settings.json`:

```jsonc
{
  "mcpServers": {
    "multivendor-ai": {
      "command": "multivendor-ai-mcp",
      "env": { "DCN_API_URL": "http://localhost:5757" }
    }
  }
}
```

### Cursor

Edit `~/.cursor/mcp.json`:

```jsonc
{
  "mcpServers": {
    "multivendor-ai": {
      "command": "multivendor-ai-mcp",
      "env": { "DCN_API_URL": "http://localhost:5757" }
    }
  }
}
```

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```jsonc
{
  "mcpServers": {
    "multivendor-ai": {
      "command": "multivendor-ai-mcp"
    }
  }
}
```

## Killer demo

```
You (in Claude Code):
  > "Something feels wrong with de-fra-core-01 — investigate and write me a
     postmortem if needed."

Claude (calls in sequence):
  1. bgp_status('de-fra-core-01')              → BGP peer down detected
  2. gait_recent_actions(target='de-fra-core-01', limit=20)
                                                → finds Health Gate abandon
  3. health_gate_status('hg-abc123')           → verdict=abandoned, regression
  4. postmortem_generate(minutes_back=15,
                          devices=['de-fra-core-01'])
                                                → full Markdown report

Claude responds:
  - Root cause: Health Gate auto-reverted at 14:35 — BGP regression
  - Device already restored, no action needed
  - Attached: full incident report (markdown)
```

Total time: ~6 seconds. Zero panels opened. Zero context switches.

## Architecture

```
       LLM CLIENT (Claude Code / Cursor / opencode)
                          │
                          ▼  MCP stdio (JSON-RPC)
              ┌──────────────────────┐
              │  multivendor-ai-mcp  │  src/mcp_server/server.py
              │  FastMCP server      │  src/mcp_server/tools.py
              └──────────┬───────────┘
                         │  HTTP
                         ▼
       ┌────────────────────────────────────────┐
       │      Flask API (multivendor lab)       │
       │   health_gate · netbox_sot · remediation
       │   gait · inventory · topology · postmortem
       └────────────────────────────────────────┘
```

## Safety

- **Health Gate is the only mutation path** — direct config-push tools were
  intentionally not exposed. Even an over-eager LLM gets a confirmed-commit
  watch + auto-revert.
- **Approval explicitness** — `remediation_approve` requires a proposal ID.
  The LLM has to first propose (or look up an existing proposal), so an
  approval is never an accidental side-effect of investigation.
- **Every call is GAIT-logged** — when Flask handlers route through MCP,
  the audit trail records `actor="mcp"` so the LLM's actions are traceable.
- **No raw shell** — there is no `run_command` tool. Investigation goes
  through structured endpoints (`bgp_status`, `topology_snapshot`, etc.).

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
venv/bin/pip install pytest mcp[cli] requests
venv/bin/python -m pytest test_mcp_server.py -v
```

21 tests in ~0.3s:
- Tool wrappers (HTTP request shape + body)
- Filter logic (site, vendor, role, vendor↔os matching)
- Registry shape (12 tools / 4 resources / 2 prompts)
- Prompt rendering (template interpolation)
- Config (`DCN_API_URL` env honored)

## Key design decisions

1. **FastMCP decorators, not low-level Server** — declarative, schemas
   auto-generated from function signatures. Cut ~150 lines vs Server class.
2. **Thin tool wrappers** — each tool is 1-5 lines that delegate to the
   existing Flask API. MCP can't drift from HTTP — they call the same
   endpoints. Single source of truth.
3. **No new business logic** — anything the LLM can do, an `httpie` user
   can do. MCP is a *transport*, not a feature.
4. **Resources for snapshots, tools for actions** — read-mostly state goes
   through resources (`inventory://`, `topology://`). Anything taking
   arguments is a tool.
5. **Prompts for compound workflows** — `diagnose_device` and
   `write_postmortem` are pre-built sequences the LLM can execute without
   the operator having to enumerate them.

## Related

- `src/mcp_server/server.py` — FastMCP decorators, tool / resource / prompt registration
- `src/mcp_server/tools.py` — HTTP wrappers around Flask endpoints
- `src/jmcp/jmcp_readonly.py` — separate Junos-specific MCP server (older,
  pre-existing, focused on `execute_junos_command` and read-only Junos RPCs)
