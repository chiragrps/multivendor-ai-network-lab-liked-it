# Phase 5 → Phase 6 Handoff (2026-05-25)

For the next agent picking up this codebase. Read this first.

## TL;DR

Phase 5 is **COMPLETE**. All 5 roadmap items (#1 netlog-ai RAG, #2 gNMI
streaming for SRL, #3 ADTK anomaly detection, #4 closed-loop change pipeline,
#5 predictive forecast alerts) shipped. Plus a 9-item audit fix pass + a
13-item round-2 audit fix pass + 13 new MCP tools + persistent docker-exec
session pool. **41 PASS / 0 FAIL** stress test.

Phase 6 is **event-initiated automation + production hardening** — see
`docs/ARCHITECTURE_PHASE_5.md` §"Phase 6 — what's next" for the prioritized list.

## What you're inheriting

### Live fabrics

- **DCN lab** — 10 FRR containers across DE-FRA / UK-LON / NL-AMS / US-NYC.
  Each is a docker container with the hostname as container name (e.g.
  `de-fra-core-01`). SSH on ports 2201-2210. **36/36 BGP up** at handoff.
- **Clos-EVPN clab** — 9 routing + 6 hosts under containerlab. Mixed
  vendors: 3 Nokia SR Linux (spine1, leaf2, leaf5) · 3 Arista cEOS
  (spine2, leaf1, leaf4) · 3 FRR (spine3, leaf3, leaf6). Container names
  prefixed `clab-clos-evpn-`. **51/51 BGP up** at handoff.

### Live services

- Flask `:5757` — main API, 200+ endpoints, started via
  `cd 04_Scripts_Tools/DCN_Network_Tool && ./venv/bin/python3 src/app.py`
- Demo UI `:8080` — served from `demo/index.html`
- InfluxDB `:8086` — `network-telemetry` bucket, org `dcn-lab`,
  token `dcn-lab-token-secret`
- Grafana `:3000` — admin/admin, 2 provisioned dashboards
- gnmic sidecar `:7890` — 3 SRL targets streaming
- netlog-ai `:6060` — sanitized configs + RAG
- **clab_collector.py** — under launchd `com.geshlab.clab-collector`
  KeepAlive=true. Writes `/tmp/clab_status.json` every 15 s.

## What Phase 5 shipped (in chronological order)

### 1. Initial audit (`docs/POST_AUDIT_2026-05-25.md`)

Closed 9/11 gaps:
- Stale collector daemon → launchd KeepAlive supervision
- KPI strip lied about counts → wired to live `mv_devices.live_containers`
- gNMI freshness false-green → filter on `source` tag
- `/api/mv/fabric-topology?fabric=dcn` returned clab data → fixed
- Duplicate collector → retired (`.deprecated-2026-05-25`)
- Param naming inconsistency → 7 napalm + 3 mv endpoints accept aliases
- Dropdowns included host1-6 (un-callable) → filtered
- Site dropdowns included dead EU-CDG → filtered
- Misc: `ReferenceError` in `refreshOverviewKpis`

### 2. Roadmap #4 — closed-loop pipeline (`docs/CHANGE_PIPELINE.md`)

`POST /api/change/closed-loop` chains 6 stages — Predict → Batfish → Apply
(Health Gate) → Watch → POST diff → Intent verify — into one async API call
with `change_id` polling. Auto-rollback on regression. Verified live:
- **APPROVED in 12 s** (Test A)
- **ROLLED_BACK in 6 s** (Test B with `induce_regression_after_s:3`)
- **REJECTED at Batfish** (Test C with invalid BGP snippet)

UI: "Run Closed-Loop Change" panel in Change Pipeline tab with 7 stage pills.

### 3. Round-2 audit (`docs/POST_AUDIT_FIXES_2.md`)

After user clicked every button against the real fabrics, 9 more issues:
- NAPALM endpoints returned only `{job_id}` (FRR/clab got `driver=junos`)
  → 3 new vendor-aware collectors (`_frr_collect`, `_clab_srl_collect`,
  `_clab_eos_collect`) over docker exec. **60 clab peers + 18 DCN peers**
  now flowing.
- Nornir LLDP / Config Compliance errored everywhere → added per-vendor
  task templates including `cmd_srl` + `cmd_ceos`; aliased UI shortcuts.
- Auto-Remediation `HTTP PROXY UNREACHABLE` → rewired to `/api/nornir/run`.
- Chaos Monkey only DCN → new `_clab_chaos()` with docker exec, UI
  fabric/target selector. **48/48 BGP** tracked live on clab.
- Shadow Auditor "Could not read running config" 10/10 →
  `_read_running_config()` 3-tier fallback (docker → disk → SSH); 0
  unreachable across 19+9+4 device scans.
- Postmortem + AI Insights had no fabric/device selectors → added.
- Dead `🪢 CLOS-EVPN FABRIC →` link → replaced with live-topology button.

### 4. Roadmap #3 — ADTK anomaly detection

`detect_anomalies()` in `src/app.py:detect_anomalies` runs Z-score
(threshold=3.0) + flap-count detectors over `bgp_session_count.established`
and `interface_count.up` from InfluxDB. New `/api/anomaly/detect` endpoint;
merged into `/api/keep/correlate` alongside rule-based alerts.

### 5. Roadmap #5 — Predictive TimesFM alerts

`run_fleet_forecast()` in `src/multivendor_extensions.py` queries InfluxDB
history per (host, measurement, field), runs `forecast_engine.predict()`,
records anomaly alerts. New endpoints `/api/mv/forecast/run-fleet` +
`/api/mv/forecast/fleet-status`. Merged into `/api/keep/correlate` via
`get_recent_predictive_alerts()`. Opt-in background loop via
`DCN_FORECAST_LOOP_S=N` env var.

### 6. MCP expansion (`src/mcp_dcn_server.py`)

13 new tools take MCP tool count to **63**:
- `mv_clab_status`, `mv_fabric_topology`, `mv_gnmic_status`
- `mv_knowledge_correlate`, `mv_anomaly_detect`
- `mv_forecast_fleet`, `mv_forecast_status`
- `mv_change_closed_loop`, `mv_change_status`, `mv_change_recent`
- `mv_chaos_bgp`, `mv_napalm_bgp`, `mv_napalm_job`, `mv_shadow_audit`

Run: `python src/mcp_dcn_server.py` (FastMCP server, stdio transport).
Claude Code config: add to `~/Library/Application Support/Claude/claude_desktop_config.json`.

### 7. #2 follow-ups (`docs/STREAMING_TELEMETRY_GAPS.md` + `scripts/migrate_streaming_telemetry.sh`)

cEOS gNMI is blocked by 4.33.1F-Lab image quirk; FRR has no native gNMI.
Documented 3 options each (image swap, Octa sidecar, eAPI bridge for cEOS;
FRR gRPC plugin, openconfigd, gnmi-gateway for FRR) + recommended path
+ migration script with `ceos-image`, `frr-grpc`, `redeploy`, `verify`
subcommands.

### 8. Persistent docker-exec session pool

`network-lab/telemetry/clab_collector.py:docker_run` now opens one
long-running `docker exec -i sh` per container and pipes commands through
stdin. Cuts ~30-50 ms of docker CLI startup per call. Auto-recovers on
session death. Backward-compatible fallback to one-shot subprocess.run.

## Files changed

### New files

```
docs/POST_AUDIT_2026-05-25.md
docs/POST_AUDIT_FIXES_2.md
docs/CHANGE_PIPELINE.md
docs/STREAMING_TELEMETRY_GAPS.md
docs/ARCHITECTURE_PHASE_5.md
docs/PHASE_5_HANDOFF.md                    ← you are here
docs/ARCHITECTURE_HARDENED.md              ← mid-Phase-5 snapshot
scripts/migrate_streaming_telemetry.sh
network-lab/telemetry/com.geshlab.clab-collector.plist
```

### Major-edit files

```
src/app.py                       (orchestrator + vendor collectors + ADTK + correlate)
src/multivendor_extensions.py    (fabric topology + forecast fleet loop + run_fleet_forecast)
src/mcp_dcn_server.py            (13 new MCP tools)
network-lab/telemetry/clab_collector.py   (persistent session pool)
demo/index.html                  (fabric selectors · KPI strip · stage pills · scanBgpFaults)
README.md
OPTIMIZATION_ROADMAP.md
```

## Stress test for handoff verification

Run this exact command to verify the inherited state:

```bash
# 1. Confirm collector is alive
launchctl list | grep clab-collector
# Expect PID > 0

# 2. Confirm fabric is healthy
curl -s http://localhost:5757/api/mv/clab-status | jq '{age_sec, healthy:[.nodes[]|select(.healthy)]|length}'
# Expect age_sec < 30, healthy = 9

# 3. Confirm all 41 stress-test items pass — see docs/POST_AUDIT_FIXES_2.md
#    "Stress-test final state" block has the full transcript
```

## Phase 6 starting points

The highest-leverage move is **event-initiated remediation** — see Phase 5
architecture doc §"Phase 6 — what's next" item 1.

Concretely:
1. Add a background loop that polls `/api/anomaly/detect` every 5 minutes
   and `/api/mv/forecast/run-fleet` every 15 minutes.
2. For each new anomaly, look up a runbook (extend `src/runbooks/*.yaml`
   with anomaly→remediation mappings).
3. POST to `/api/change/closed-loop` with the matched runbook. Set
   `approval_status` based on a per-runbook risk tier so high-risk changes
   route through `/api/mv/change/approve` first.
4. Surface in UI: new "Auto-Remediation Queue" panel showing pending +
   recent auto-runs.

This is what closes the AI-SRE 5/5 rubric. Per the Itential research,
event-initiated execution is the single capability that distinguishes a
real agentic NetOps tool from a copilot.

## Operational notes

| Concern | Status |
| --- | --- |
| Secrets | Still in `.env` (`INFLUXDB_TOKEN=dcn-lab-token-secret`, etc.). Production-blocking. Move to Vault before any external deployment. |
| Multi-worker | Flask runs single-process. `_FABRIC_TOPOLOGY_CACHE` + closed-loop state are in-memory. Redis migration is item #6 on the Phase 6 list. |
| Eval coverage | No golden-trace regression suite for the LLM correlator. Item #3 on Phase 6. |
| FRR streaming | Polling-based for now. Docs+script ready; rebuild Dockerfile is required. |
| cEOS streaming | Polling-based for now. `clab destroy && deploy` after image bump is required. |

## Where to look in the code

| Want to understand | Read |
| --- | --- |
| How a closed-loop change runs | `src/app.py:_cl_run` |
| How vendor-aware NAPALM dispatch works | `src/app.py:_napalm_collect` |
| How predictive forecast aggregates fleet-wide | `src/multivendor_extensions.py:run_fleet_forecast` |
| How the LLM correlator merges signal sources | `src/app.py:api_keep_correlate` |
| Collector persistent session pool | `network-lab/telemetry/clab_collector.py:docker_run` |
| New MCP tools surface | `src/mcp_dcn_server.py` (search "Phase-5 additions") |

## Contact + state

User: Georgi Gaydarov. Lab is on his Mac (Apple Silicon). All services
are local Docker containers + launchd-supervised Python processes. No
cloud / no external network deps for the lab itself (only the LLM
backend talks to Anthropic, set via `ANTHROPIC_API_KEY` in `~/.env`).
