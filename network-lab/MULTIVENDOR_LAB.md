# Multivendor AI Network Lab — Architecture & Operations Guide

## Overview

The lab has been upgraded from a 10-device FRR-only lab to a **26-device multivendor platform** supporting Juniper JunOS, Arista EOS, and FRRouting — all from a single AI-driven interface.

```
Total Devices : 26
Vendors       : Juniper (10) · Arista (6) · FRR Live (10)
Sites         : DE-FRA · UK-LON · NL-AMS · EU-CDG · US-NYC
Demo URL      : http://localhost:8080
Flask API     : http://localhost:5757
```

---

## Device Inventory

### Juniper SRX Firewalls (4 × static config)
| Hostname   | Site   | Model  | Config file                  |
|------------|--------|--------|------------------------------|
| fra-fw-01  | DE-FRA | SRX345 | demo-devices/junos/fra-fw-01.txt |
| lon-fw-01  | UK-LON | SRX345 | demo-devices/junos/lon-fw-01.txt |
| ams-fw-01  | NL-AMS | SRX345 | demo-devices/junos/ams-fw-01.txt |
| nyc-fw-01  | US-NYC | SRX345 | demo-devices/junos/nyc-fw-01.txt |

### Juniper MX Core Routers (2 × static config)
| Hostname   | Site   | Model  | Config file                  |
|------------|--------|--------|------------------------------|
| fra-mx-01  | DE-FRA | MX204  | demo-devices/junos/fra-mx-01.txt |
| cdg-mx-01  | EU-CDG | MX960  | demo-devices/junos/cdg-mx-01.txt |

### Juniper EX Switches (4 × static config)
| Hostname   | Site   | Model  | Config file                  |
|------------|--------|--------|------------------------------|
| fra-ex-01  | DE-FRA | EX4600 | demo-devices/junos/fra-ex-01.txt |
| fra-ex-02  | DE-FRA | EX4600 | demo-devices/junos/fra-ex-02.txt |
| lon-ex-01  | UK-LON | EX4600 | demo-devices/junos/lon-ex-01.txt |
| ams-ex-01  | NL-AMS | EX4600 | demo-devices/junos/ams-ex-01.txt |

### Arista DCS-7280CR3K Routers (4 × static config)
| Hostname      | Site   | Model          | Config file                       |
|---------------|--------|----------------|-----------------------------------|
| fra-eos-rt-01 | DE-FRA | DCS-7280CR3K   | demo-devices/eos/fra-eos-rt-01.txt |
| ams-eos-rt-01 | NL-AMS | DCS-7280CR3K   | demo-devices/eos/ams-eos-rt-01.txt |
| cdg-eos-rt-01 | EU-CDG | DCS-7280CR3K   | demo-devices/eos/cdg-eos-rt-01.txt |
| nyc-eos-rt-01 | US-NYC | DCS-7280CR3K   | demo-devices/eos/nyc-eos-rt-01.txt |

### Arista DCS-7050CX3 Switches (2 × static config)
| Hostname      | Site   | Model        | Config file                       |
|---------------|--------|--------------|-----------------------------------|
| fra-eos-sw-01 | DE-FRA | DCS-7050CX3  | demo-devices/eos/fra-eos-sw-01.txt |
| ams-eos-sw-01 | NL-AMS | DCS-7050CX3  | demo-devices/eos/ams-eos-sw-01.txt |

### FRR Live Containers (10 × SSH)
| Hostname        | Site   | Port | AS    | Role        |
|-----------------|--------|------|-------|-------------|
| de-fra-core-01  | DE-FRA | 2201 | 65001 | Core Router |
| de-fra-core-02  | DE-FRA | 2202 | 65002 | Core Router |
| de-fra-edge-01  | DE-FRA | 2205 | 65006 | Edge Router |
| de-fra-dist-01  | DE-FRA | 2210 | 65009 | Dist Switch |
| uk-lon-core-01  | UK-LON | 2203 | 65003 | Core Router |
| uk-lon-edge-01  | UK-LON | 2208 | 65007 | Edge Router |
| uk-lon-dist-01  | UK-LON | 2206 | 65010 | Dist Switch |
| nl-ams-core-01  | NL-AMS | 2204 | 65004 | Core Router |
| nl-ams-edge-01  | NL-AMS | 2209 | 65008 | Edge Router |
| us-nyc-core-01  | US-NYC | 2207 | 65005 | Core Router |

---

## Config Sanitization

All 16 static configs were sanitized from real production backups:
- Company names replaced with generic equivalents
- Real BGP AS numbers replaced with RFC 6996 private ASNs (65000+)
- Real usernames replaced with netadmin1–6
- SSH public keys removed
- Real IPs replaced with RFC 5737 / RFC 1918 ranges
- Passwords replaced with hashed placeholders

Script: `network-lab/demo-devices/sanitize_configs.py`

---

## Flask API Endpoints

### Core (legacy)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/devices` | GET | List FRR lab devices |
| `/api/run` | POST | SSH exec on FRR containers |
| `/api/ai-command` | POST | NL → CLI → SSH → explain |
| `/api/nornir/run` | POST | Parallel audit across FRR |

### Multivendor Extensions (`/api/mv/*`)
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/mv/devices` | GET | All 26 devices from inventory.json |
| `/api/mv/topology` | GET | BGP session topology for diagram |
| `/api/mv/batfish/fleet` | POST | Config audit across all 16 static devices |
| `/api/mv/suzieq/analyze` | GET | BGP/OSPF/interface parsing (offline) |
| `/api/mv/gnmi/query` | POST | OC path → vtysh on FRR containers |
| `/api/mv/syslog/recent` | GET | Syslog events from UDP :5140 receiver |
| `/api/mv/snmp/traps` | GET | SNMP traps from UDP :1162 receiver |
| `/api/mv/junos/netconf` | POST | NETCONF/PyEZ for real Juniper devices |

---

## Demo UI Tabs

### Tier 1 (P1)
- **💬 AI Command** — NL → LLM → CLI → SSH → explain
- **🔍 Pre-Deploy** — Batfish-style config analysis (single config paste)
- **⚡ Nornir Engine** — Parallel BGP/OSPF health across FRR containers

### Tier 2 (P2)
- **📡 State Diff** — Pre/post change comparison (pyATS-style)
- **🔔 Alert Correlation** — KEEP engine noise reduction
- **📡 Streaming Telemetry** — Simulated gNMI sparklines

### Multivendor (MV)
- **🗄️ MV Inventory** — All 26 devices with vendor badges + live/config mode
- **🔍 Fleet Audit** — Rule-based audit across all 16 Junos/EOS static configs
- **📊 SuzieQ** — Offline BGP/OSPF/interface observability parsing
- **📡 gNMI Telemetry** — OpenConfig path → vtysh mapping on FRR
- **📝 Syslog** — Live UDP :5140 receiver + auto-refresh
- **⚠️ SNMP Traps** — Live UDP :1162 receiver + auto-refresh

---

## Quick Start

```bash
# 1. Start FRR lab containers
cd network-lab
docker-compose up -d

# 2. Start Flask API (port 5757)
cd 04_Scripts_Tools/DCN_Network_Tool
source venv/bin/activate
python3 app.py

# 3. Open demo
open http://localhost:5757/demo/index.html
# or serve static:
python3 -m http.server 8080 --directory demo/
```

## BGP Simulation

```bash
./network-lab/sim_bgp_failure.sh status   # show all BGP states
./network-lab/sim_bgp_failure.sh break    # simulate failure
./network-lab/sim_bgp_failure.sh fix      # restore all sessions
./network-lab/sim_bgp_failure.sh chaos    # random 30s failure
```

---

## Design Pattern

```
Existing capability  +  AI translation layer  +  UI tab  =  New tool
─────────────────────────────────────────────────────────────────────
16 static configs        Rule-based engine        Fleet Audit
Batfish scripts          analyze endpoint          Pre-Deploy
Netmiko loops            Nornir parallel           Nornir Engine
LibreNMS + Kibana        Keep correlation          Alert Correlation
SNMP polling             gNMI + vtysh              Streaming Telemetry
Syslog UDP recv          ring buffer               Syslog tab
SNMP trap UDP recv       ring buffer               SNMP Traps tab
```

---

## Phase 3 — AI Operations Pack (2026-05-05)

Inspired by codingnetworks.blog (MCP+MPLS), sands-lab/nika, Hugo Tinoco's
pydantic-ai post, and automateyournetwork/netclaw. Net-new capabilities
on top of the 26-device base lab — all vendor-agnostic.

### New endpoints (12)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/mv/orchestrator` | POST | Pydantic-AI multi-agent — auto-routes to RoutingAgent / ACLAgent / IncidentAgent with structured BaseModel outputs |
| `/api/mv/intent/verify` | GET | Cross-references inventory.json BGP claims vs config-parsed observations; flags drift |
| `/api/mv/path/trace` | GET | BFS hop-by-hop path between any two devices, returns SVG-ready node list with vendor colors |
| `/api/mv/eval/scenarios` | GET | List the 10 pre-defined incident scenarios |
| `/api/mv/eval/run` | POST | Run a scenario through an agent; returns keyword + LLM-judge scores (0–10) |
| `/api/mv/gait/recent` | GET | Immutable JSONL audit trail of every AI action — actor, prompt, response, tools, tokens |
| `/api/mv/gait/stats` | GET | Aggregated GAIT counters per actor and status |
| `/api/mv/runbooks` | GET | List auto-remediation playbooks (BGP/OSPF/Interface/ACL) |
| `/api/mv/runbook/execute` | POST | Dry-run a runbook on a target device — emits canonical steps + per-vendor CLI |
| `/api/mv/cve` | GET | Static CVE scan by `(vendor, OS version)`; returns critical/high counts |
| `/api/mv/translator` | GET/POST | Vendor-agnostic command translator — one canonical task → vendor-specific CLI for junos/eos/frr/ios/nxos |
| `/api/mv/toon` | GET | Serialize an array as TOON (Tabular Object Oriented Notation); ~60% smaller than JSON |

### New UI tabs (5)

| Tab | Color tag | What it does |
|---|---|---|
| 🤖 Orchestrator | P3 | Type a symptom; orchestrator auto-classifies and delegates to the right child agent. Shows rendered diagnosis + structured Pydantic JSON side-by-side. |
| 🎯 Intent Verify | P3 | One click — runs the drift detector across all 10 BGP sessions in `inventory.json`. Shows score + list of `claimed_peer_missing` / `undeclared_peer` events. |
| 🧪 Eval Harness | P3 | Pick scenario + agent, click Run (or Run All for the whole 10-scenario suite). Reports keyword score, LLM-judge score, latency. |
| 🛣️ Path Trace | P3 | Pick src + dst, BFS over BGP sessions. Renders a minimalist Excalidraw-style SVG with vendor-colored nodes (Juniper green / Arista blue / FRR purple). |
| 📜 GAIT Audit | P3 | Live view of `audit/gait_YYYY-MM-DD.jsonl` — every AI action timestamped, classified by actor (orchestrator / eval_harness / runbook). Filterable. |

### New backend modules

```
04_Scripts_Tools/DCN_Network_Tool/
├── pydantic_ai_orchestrator.py   # Routing/ACL/Incident agents with BaseModel outputs
├── eval_harness.py               # synthesize_symptom + keyword_score + llm_judge
├── gait_audit.py                 # JSONL append-only audit log
├── toon_serializer.py            # ~60% smaller than JSON for tabular data
├── vendor_translator.py          # canonical task → vendor CLI map (5 vendors, 12 tasks)
├── cve_db.json                   # static (vendor, os_version) → [CVE] lookup
├── scenarios.json                # 10 incident scenarios (BGP/OSPF/intf/MTU/ACL/CVE/intent/perf)
└── runbooks/
    ├── bgp_peer_down.yaml
    ├── interface_down.yaml
    ├── ospf_neighbor_stuck.yaml
    └── acl_block.yaml
```

### Vendor-agnostic command translator

12 canonical tasks mapped to 5 vendors (junos / eos / frr / ios / nxos):

```
bgp_summary       ospf_neighbors     interface_status
route_lookup      version            running_config
arp_table         mac_table          lldp_neighbors
system_health     log_recent
clear_bgp_neighbor (destructive — gated)
shutdown_interface (destructive — gated)
```

Used internally by Pydantic-AI tools, eval scenarios, and runbook execution.
The orchestrator never emits a hard-coded vendor command — it always goes
through `vendor_translator.translate(task, vendor)`.

### MCP server expansion

`mcp_dcn_server.py` now exposes 15 new MV tools so Claude Code (or any MCP
client) can call them directly:

```
mv_list_devices, mv_topology, mv_fleet_audit, mv_suzieq, mv_gnmi,
mv_intent_verify, mv_path_trace, mv_eval_scenarios, mv_eval_run,
mv_orchestrator, mv_runbooks, mv_runbook_execute, mv_cve_scan,
mv_translate, mv_gait_recent
```

### Sanitization audit (re-run 2026-05-05)

- 0 internal hostnames, usernames, real AS numbers, or company-specific tokens
- 0 real SSH public keys (10 leaked nistp384 keys replaced with placeholder)
- `sanitize_configs.py` patched to catch nistp384 and ed25519 going forward

### Smoke-test results

Playwright MCP across all 5 new tabs: **0 console errors, 0 warnings**.

| Capability | Measured |
|---|---|
| Orchestrator latency (offline fallback) | 17 ms |
| Eval harness avg score (10 scenarios, offline) | 6.0 / 10 |
| Intent verification score | 100% (no drift) |
| Path trace fra-core-01 → nyc-core-01 | 1 hop, 1 vendor |
| TOON savings vs JSON for /api/mv/devices | 59.5 % |
| CVE scan over 16 static configs | 7 devices flagged, 8 high-severity findings |

When `ANTHROPIC_API_KEY` is set in `.env`, the orchestrator uses Claude
Haiku 4.5 by default and the eval harness adds an LLM-as-judge score.

### Quick demo

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
./venv/bin/python app.py &
open http://localhost:5757/demo/index.html
# Click any of the 5 new yellow ⚡ MV Features buttons in the top bar.
```
