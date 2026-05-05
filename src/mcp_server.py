#!/usr/bin/env python3
"""
DCN Network Tool — MCP Server (Feature 2)
Exposes lab topology, device inventory, and network ops as MCP tools
so Claude Code can query the live lab directly.

Usage:
  python3 mcp_server.py          # stdio transport (for Claude Code settings.json)

Register in ~/.claude/settings.json:
  {
    "mcpServers": {
      "dcn-lab": {
        "command": "python3",
        "args": ["/path/to/mcp_server.py"],
        "env": { "DCN_API_URL": "http://localhost:5757" }
      }
    }
  }
"""

import json
import os
import sys
import requests

DCN_API = os.environ.get("DCN_API_URL", "http://localhost:5757")


# ── MCP Protocol helpers ──────────────────────────────────────────────────────

def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _error(id_: int | str | None, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _ok(id_: int | str | None, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


# ── Tool definitions ──────────────────────────────────────────────────────────

TOOLS = [
    {
        "name": "dcn_devices",
        "description": (
            "List all devices in the DCN lab network. "
            "Returns hostname, IP, device type (frr/junos/eos), site, and SSH port."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "site": {"type": "string", "description": "Filter by site code (e.g. 'de-fra', 'uk-lon')"},
            },
        },
    },
    {
        "name": "dcn_run_command",
        "description": (
            "Execute a show command on a lab device via SSH. "
            "Read-only — write/destructive commands are blocked. "
            "Example commands: 'show bgp summary', 'show ip ospf neighbor', 'show version'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Device hostname (e.g. 'de-fra-core-01')"},
                "command":  {"type": "string", "description": "Show command to run"},
            },
            "required": ["hostname", "command"],
        },
    },
    {
        "name": "dcn_ai_command",
        "description": (
            "Ask a natural language question about a device. "
            "The LLM translates the question to CLI, runs SSH, and explains the output. "
            "Example: 'How many BGP peers does de-fra-core-01 have?' or 'Is OSPF healthy on uk-lon-core-01?'"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Natural language question"},
                "hostname": {"type": "string", "description": "Target device hostname"},
            },
            "required": ["query", "hostname"],
        },
    },
    {
        "name": "dcn_topology",
        "description": (
            "Get the live BGP/OSPF topology of the lab. "
            "Discovers nodes and links by querying OSPF neighbors on all devices."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "site": {"type": "string", "description": "Filter by site (optional)"},
            },
        },
    },
    {
        "name": "dcn_nornir",
        "description": (
            "Run a parallel health check across all lab devices. "
            "Tasks: bgp_health, version, interface_check, alarm_check, routing_table."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "task": {
                    "type": "string",
                    "enum": ["bgp_health", "version", "interface_check", "alarm_check", "routing_table"],
                    "description": "Health check task to run",
                },
                "site": {"type": "string", "description": "Limit to a specific site"},
            },
        },
    },
    {
        "name": "dcn_health_card",
        "description": (
            "Get a health card for a device: CPU, memory, BGP peers, OSPF neighbors. "
            "Returns parsed numeric metrics plus raw command output."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Device hostname"},
            },
            "required": ["hostname"],
        },
    },
    {
        "name": "dcn_compliance",
        "description": (
            "Run compliance checks on lab devices: BGP auth, prefix limits, OSPF timers, router-ID. "
            "Returns a per-device compliance score and list of PASS/FAIL findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "site": {"type": "string", "description": "Scan a specific site"},
                "hostnames": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Scan specific hostnames",
                },
            },
        },
    },
    {
        "name": "dcn_remediate",
        "description": (
            "Trigger a BGP remediation action on the lab. "
            "Actions: 'status' (show all BGP), 'fix' (restore all sessions), "
            "'break' (drop de-fra-core-01 ↔ uk-lon-core-01), 'chaos' (random 30s failure)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["status", "fix", "break", "chaos"],
                    "description": "Remediation action",
                },
            },
            "required": ["action"],
        },
    },
    {
        "name": "dcn_docs_search",
        "description": (
            "Search the network vendor documentation knowledge base for error explanations and fixes. "
            "Covers FRR BGP/OSPF errors, Junos rpd issues, Arista BGP states. "
            "Example: 'OSPF neighbor stuck in ExStart' or 'BGP hold timer expired'."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query":    {"type": "string", "description": "Error message or question"},
                "hostname": {"type": "string", "description": "Affected device (optional)"},
            },
            "required": ["query"],
        },
    },
]


# ── Tool dispatch ─────────────────────────────────────────────────────────────

def _call_tool(name: str, args: dict) -> str:
    try:
        if name == "dcn_devices":
            params = {}
            if args.get("site"):
                params["site"] = args["site"].upper()
            r = requests.get(f"{DCN_API}/api/devices", params=params, timeout=10)
            devices = r.json()
            lines = [f"Found {len(devices)} device(s):"]
            for d in devices:
                lines.append(f"  {d['hostname']}  {d['ip']}:{d.get('port',22)}  type={d['type']}  site={d['site']}")
            return "\n".join(lines)

        elif name == "dcn_run_command":
            r = requests.post(f"{DCN_API}/api/run", json={
                "hostname": args["hostname"],
                "raw": args["command"],
            }, timeout=30)
            data = r.json()
            if not data.get("success", True):
                return f"Error: {data.get('error', 'unknown error')}"
            return data.get("output", "(no output)")

        elif name == "dcn_ai_command":
            r = requests.post(f"{DCN_API}/api/ai-command", json={
                "query": args["query"],
                "hostname": args["hostname"],
            }, timeout=60)
            data = r.json()
            parts = [f"CLI: {data.get('cli', '?')}"]
            if data.get("output"):
                out = data["output"]
                output_text = out.get("output", str(out)) if isinstance(out, dict) else str(out)
                parts.append(f"Output:\n{output_text[:2000]}")
            if data.get("explanation"):
                parts.append(f"Explanation: {data['explanation']}")
            return "\n\n".join(parts)

        elif name == "dcn_topology":
            payload = {}
            if args.get("site"):
                payload["site"] = args["site"]
            r = requests.post(f"{DCN_API}/api/topology/discover", json=payload, timeout=60)
            data = r.json()
            nodes = data.get("nodes", [])
            links = data.get("links", [])
            lines = [f"Topology: {len(nodes)} nodes, {len(links)} links"]
            for n in nodes:
                lines.append(f"  NODE  {n['hostname']}  ({n['type']})  {n['ip']}")
            for lnk in links:
                lines.append(f"  LINK  {lnk['source']} ↔ {lnk['target']}  [{lnk['protocol']}  {lnk['state']}]")
            return "\n".join(lines)

        elif name == "dcn_nornir":
            payload = {"task": args.get("task", "bgp_health")}
            if args.get("site"):
                payload["site"] = args["site"]
            r = requests.post(f"{DCN_API}/api/nornir/run", json=payload, timeout=120)
            data = r.json()
            lines = [
                f"Task: {data.get('task')}  ok={data.get('ok')}  warn={data.get('warn')}  err={data.get('error')}  elapsed={data.get('elapsed_s')}s"
            ]
            for res in (data.get("results") or []):
                lines.append(f"  {res['hostname']}  [{res['status'].upper()}]  {res.get('output','')[:120]}")
            return "\n".join(lines)

        elif name == "dcn_health_card":
            r = requests.post(f"{DCN_API}/api/device/health-card",
                              json={"hostname": args["hostname"]}, timeout=60)
            data = r.json()
            metrics = data.get("metrics", {})
            lines = [f"Health card: {data.get('hostname')}  ({data.get('type')})  {data.get('ip')}"]
            if metrics:
                for k, v in metrics.items():
                    lines.append(f"  {k}: {v}")
            raw = data.get("raw", {})
            for key in ("bgp", "ospf"):
                if raw.get(key):
                    lines.append(f"\n--- {key.upper()} ---\n{raw[key][:500]}")
            return "\n".join(lines)

        elif name == "dcn_compliance":
            payload = {}
            if args.get("site"):
                payload["site"] = args["site"]
            if args.get("hostnames"):
                payload["hostnames"] = args["hostnames"]
            r = requests.post(f"{DCN_API}/api/compliance/scan", json=payload, timeout=120)
            data = r.json()
            lines = [
                f"Compliance scan: {data['scanned']} devices  overall_score={data['overall_score']}%  "
                f"pass={data['total_passed']} fail={data['total_failed']}"
            ]
            for dev in data.get("devices", []):
                lines.append(f"  {dev['hostname']}  score={dev.get('score')}%  fail={dev.get('failed')}")
                for f in dev.get("findings", []):
                    if f["status"] == "FAIL":
                        lines.append(f"    ✗ [{f['rule_id']}] {f['name']}")
                        if f.get("remediation"):
                            lines.append(f"      Fix: {f['remediation']}")
            return "\n".join(lines)

        elif name == "dcn_remediate":
            r = requests.post(f"{DCN_API}/api/remediate",
                              json={"action": args["action"]}, timeout=60)
            data = r.json()
            lines = [f"Remediation '{data.get('action')}': {data.get('message', '')}"]
            for line in (data.get("output") or []):
                lines.append(f"  {line}")
            return "\n".join(lines)

        elif name == "dcn_docs_search":
            r = requests.post(f"{DCN_API}/api/docs/search", json={
                "query": args["query"],
                "hostname": args.get("hostname", ""),
            }, timeout=30)
            data = r.json()
            lines = [f"Found {data.get('docs_found', 0)} doc(s) for: {data.get('query')}"]
            for doc in (data.get("docs") or []):
                lines.append(f"\n[{doc['vendor']}] {doc['topic']}\n{doc['text']}")
            if data.get("llm_answer"):
                lines.append(f"\nLLM Answer:\n{data['llm_answer']}")
            return "\n".join(lines)

        else:
            return f"Unknown tool: {name}"

    except requests.exceptions.ConnectionError:
        return f"Error: DCN Tool not running at {DCN_API} — start it with ./network-lab/start_lab_tool.sh"
    except Exception as exc:
        return f"Error calling {name}: {exc}"


# ── MCP stdio event loop ──────────────────────────────────────────────────────

def main() -> None:
    for raw_line in sys.stdin:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            msg = json.loads(raw_line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method", "")
        id_ = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            _send(_ok(id_, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "dcn-lab", "version": "1.0.0"},
            }))

        elif method == "tools/list":
            _send(_ok(id_, {"tools": TOOLS}))

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}
            content = _call_tool(tool_name, tool_args)
            _send(_ok(id_, {
                "content": [{"type": "text", "text": content}],
                "isError": content.startswith("Error:"),
            }))

        elif method == "notifications/initialized":
            pass  # no response needed

        else:
            if id_ is not None:
                _send(_error(id_, -32601, f"Method not found: {method}"))


if __name__ == "__main__":
    main()
