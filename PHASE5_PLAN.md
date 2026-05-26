# Phase 5 — Predict / Forecast / Guard

**Status:** local development · target launch **next week** (after Phase 4 settles)
**Theme:** *the lab learns to see the future and refuses to break the network*

---

## TL;DR

Phase 4 closed the loop: observe → diagnose → remediate → verify, with auto-revert.
**Phase 5 adds three predictive capabilities** that turn the lab from reactive to proactive:

| Feature | Pattern source | LinkedIn hook |
|---|---|---|
| **A · Traffic Forecast** | Cisco TimesFM 1.0 (250M-param Hugging Face model, Nov 2025) | *"AI predicts FRA-CORE-01 will hit 80% CPU in 23 minutes"* |
| **B · Predict Mode** | Forward Networks "Forward Predict" (May 21, 2026) | *"Forward charges $250K/yr for what-if. Here's the same pattern, MIT, on a laptop."* |
| **C · Blast Radius Guard** | NetAI Inc. GNN-style impact analysis + Nova AI Ops pattern | *"Health Gate now refuses to apply if blast radius isn't approved."* |

All three integrate **before** Health Gate as new pre-checks in the closed loop:

```
Observe → Diagnose → [A forecast] → [B predict] → [C blast radius] → Health Gate → Verify
                                                                    ↑
                                                              if any reject,
                                                              proposal goes back
                                                              to human approval
```

---

## A · Cisco TimesFM Traffic Forecast

### Goal

For any monitored metric on any device — CPU, memory, throughput, error rate, BGP-route-count — produce a **128-step forecast with 95% confidence intervals** in <200 ms on CPU.

### Why Cisco TimesFM

- **Zero-shot** — no per-device training, works immediately on any new time-series
- **Multi-resolution** — feed 512 minutes (fine) + 512 hours (coarse), get 128 future points
- **Production-grade benchmark** — Cisco reports 8.57% MASE improvement over previous release
- **MIT-compatible** — Apache 2.0 license, pip-installable
- **Small** — 250M params, runs on Apple Silicon CPU in ~150 ms per forecast

### Endpoint surface

```
POST /api/mv/forecast/predict
  body: {
    "device":   "de-fra-core-01",
    "metric":   "cpu_pct",           // cpu_pct | mem_pct | bgp_route_count | iface_in_bps
    "horizon":  128,                  // points to forecast (max 128)
    "context":  null                  // optional: explicit history; else read SuzieQ/gNMI
  }
  returns: {
    "device": "de-fra-core-01",
    "metric": "cpu_pct",
    "history":  [...],                // last 128 points used
    "forecast": [...],                // 128 predicted points
    "quantiles": {                    // 15 quantile bands (Cisco model gives 0.01-0.99)
      "q01": [...], "q05": [...], "q10": [...], "q25": [...],
      "q50": [...], "q75": [...], "q90": [...], "q95": [...], "q99": [...]
    },
    "anomaly_alerts": [
      {"step": 23, "predicted": 0.82, "threshold": 0.80, "kind": "cpu_high"}
    ],
    "ms": 142,
    "model": "cisco-time-series-model-1.0"
  }

GET  /api/mv/forecast/history/<device>/<metric>?window=4h
GET  /api/mv/forecast/anomalies?since=10m  # latest alerts across fleet
GET  /api/mv/forecast/status              # model loaded, last inference time, p95 latency
```

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│   Flask API (mv_bp.forecast)                                 │
│   ┌──────────────────────────────────────────────────────┐   │
│   │  forecast_engine.py (new module)                     │   │
│   │  ┌────────────────────────────────────────────────┐  │   │
│   │  │  CiscoTimesFM (singleton, lazy-loaded)         │  │   │
│   │  │   - load model on first request                │  │   │
│   │  │   - hold in memory; inference via .forecast()  │  │   │
│   │  │   - thread-safe (asyncio.Lock or threading.RLock)│ │   │
│   │  └────────────────────────────────────────────────┘  │   │
│   │   - read history from SuzieQ table OR ring buffer    │   │
│   │   - normalize, build coarse+fine context             │   │
│   │   - run inference, detect anomalies vs thresholds    │   │
│   │   - cache results (60s TTL) keyed by (device,metric) │   │
│   └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
       ↓                                       ↑
  ┌──────────┐                         ┌──────────────┐
  │ SuzieQ   │                         │  Demo UI      │
  │ /gNMI    │   30s polling           │ "Forecast     │
  │  cache   │   ─────────►            │  Panel" with  │
  └──────────┘                         │  sparkline    │
                                       │  + 95% CI band│
                                       └──────────────┘
```

### Implementation

- **New module:** `src/forecast_engine.py` (~250 lines)
- **Model dependency:** `pip install torch transformers` (CPU-only build acceptable for Apple Silicon)
- **Model cache:** `~/.cache/huggingface/hub/` (8-bit quantized if available)
- **Test scaffold:** synthetic CPU series with known periodicity to validate forecast accuracy
- **Demo UI panel:** new tab `Forecast` in Diagnose group with device picker, metric picker, sparkline showing history + forecast + CI band

### Risks & mitigations

| Risk | Mitigation |
|---|---|
| Model download 500MB+ first run | Lazy-load with progress logged; cache in HF dir |
| Cold-start latency 2-3s | Singleton load on Flask startup (background thread) |
| Memory ~1.5GB resident | Document; offer 8-bit quantized variant |
| Forecast garbage on flat series | Fall back to "no signal" badge, hide CI band |
| LLM availability not required | Pure local inference; no API calls |

### Stress tests

- 100 concurrent `POST /api/mv/forecast/predict` → p95 latency, model-lock contention
- Synthetic history with known sin-wave → MSE < 0.05 on quantile-median
- Empty history (cold device) → returns `{"forecast": null, "reason": "insufficient_history"}` with 200 OK
- 24-hour soak with periodic 30s polls → no memory growth

---

## B · Predict Mode (digital-twin what-if)

### Goal

Take a **proposed config change** (Junos / EOS / FRR snippet), feed it to a digital-twin simulation, and return the **predicted before/after state** of the fleet — BGP/OSPF adjacencies, reachability, ACL effects, route table deltas — **before Health Gate ever applies anything**.

This is Forward Networks' "Forward Predict" pattern, open-sourced.

### Endpoint surface

```
POST /api/mv/predict/run
  body: {
    "target_device": "uk-lon-core-01",
    "proposed_change": "router bgp 65003\n no neighbor 10.200.0.11\n!",
    "scope":          "fleet",   // device | site | fleet
    "checks":         ["reachability", "bgp_adjacencies", "ospf_state", "acl_deltas"]
  }
  returns: {
    "predicted_state": {
      "bgp_adjacencies": {
        "before": [...], "after": [...], "lost": [...], "gained": []
      },
      "reachability":  {"before_ok": 26, "after_ok": 24, "broken_flows": [...]},
      "ospf_state":    {...},
      "acl_deltas":    {...}
    },
    "verdict":         "REJECT",
    "rejection_reason":"2 BGP sessions would drop, reachability broken for 2 devices",
    "blast_radius":    {...},  // pre-computed for Feature C integration
    "ms":              1842
  }

GET  /api/mv/predict/history?device=uk-lon-core-01&limit=10
POST /api/mv/predict/approve/<predict_id>  # operator overrides REJECT
```

### Architecture

Builds on existing Batfish integration but adds **control-plane simulation**:

```
┌──────────────────────────────────────────────────────────────┐
│   predict_engine.py                                          │
│   ┌────────────────────────────────────────────────────┐    │
│   │   1. SNAPSHOT CURRENT STATE                        │    │
│   │     - read all live configs (SuzieQ cache)         │    │
│   │     - read live BGP/OSPF state (gNMI)              │    │
│   │     - build "before" Batfish snapshot              │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   2. APPLY PROPOSED CHANGE (in-memory)             │    │
│   │     - patch target device's config                 │    │
│   │     - build "after" Batfish snapshot               │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   3. RUN CONTROL-PLANE QUERIES                     │    │
│   │     - Batfish: reachability, ACL, NAT, routing     │    │
│   │     - Custom: BGP graph traversal (existing)       │    │
│   │     - Custom: OSPF adjacency simulation            │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   4. DIFF BEFORE/AFTER → STRUCTURED VERDICT        │    │
│   │     - REJECT if mandatory checks fail              │    │
│   │     - WARN  if optional checks degrade             │    │
│   │     - APPROVE if all pass                          │    │
│   └────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
                       ↓
              Plugs INTO Health Gate as
              a pre-flight check. If Predict
              says REJECT, Health Gate refuses
              to even start its watch window.
```

### Implementation

- **New module:** `src/predict_engine.py` (~400 lines)
- **Reuses:** `batfish_runner.py` (already exists), `topology_graph.py` (existing)
- **New:** OSPF adjacency simulator (lightweight, just neighbor matrix diff)
- **Demo UI:** new tab `Predict` in Change Control group — paste config diff, click Run, see before/after side-by-side
- **MCP tool:** `predict.run` exposed so Claude Code can pre-flight changes from chat

### Risks & mitigations

| Risk | Mitigation |
|---|---|
| Batfish container slow (8-30s) | Background pre-warm; reuse snapshots when configs unchanged |
| Multi-vendor parsing gaps in Batfish | Document supported subset; reject unparseable configs with clear error |
| Concurrent predict requests | Queue with `concurrent.futures`, return job_id for >2s requests |
| False-positive REJECTs | Operator override endpoint + audit trail |

### Stress tests

- 20 sequential predict calls against same target → cache hits should hit p50 < 500ms
- Cold cache predict → p95 < 5s
- Malformed config snippet → returns 400 with parser error, doesn't crash
- Predict + parallel Health Gate apply on different devices → no global lock contention

---

## C · Blast Radius Guard

### Goal

Given any proposed change, **traverse the BGP + OSPF + LLDP graph** to enumerate **every downstream service** that could be affected. Health Gate becomes the gate; Blast Radius Guard is the **mandatory pre-check**.

### Endpoint surface

```
POST /api/mv/blast-radius/compute
  body: {
    "action": "shutdown_interface",   // shutdown_interface | drop_bgp_peer | modify_acl | revoke_route
    "target_device":  "de-fra-core-01",
    "target_object":  "ge-0/0/1",     // depends on action
    "depth":          3                // BFS hops (default 3)
  }
  returns: {
    "blast_radius": {
      "direct_neighbors":   ["uk-lon-core-01", "us-nyc-core-01"],
      "second_hop":         ["uk-lon-edge-01", "us-nyc-edge-01"],
      "third_hop":          ["uk-lon-dist-01"],
      "affected_devices":   8,
      "affected_sessions":  ["de-fra-core-01<->uk-lon-core-01", ...],
      "affected_services":  ["customer-vrf-01", "mgmt-network"],
      "graph_dot":          "<dot source for visualization>",
      "risk_score":         "HIGH"
    },
    "approval_required":    true,
    "explanation":          "Shutdown will break 2 BGP sessions and isolate 8 devices ...",
    "ms":                   23
  }

GET  /api/mv/blast-radius/graph?device=de-fra-core-01  # render full impact graph
POST /api/mv/blast-radius/approve/<job_id>             # operator accepts the radius
```

### Architecture

```
┌──────────────────────────────────────────────────────────────┐
│   blast_radius.py                                            │
│   ┌────────────────────────────────────────────────────┐    │
│   │   1. BUILD MULTI-LAYER GRAPH                       │    │
│   │     - L2: LLDP adjacencies (SuzieQ.lldp table)     │    │
│   │     - L3: OSPF adjacencies, BGP sessions           │    │
│   │     - L7: services-to-device mapping (NetBox SoT)  │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   2. BFS FROM TARGET                               │    │
│   │     - apply action-specific edge filter            │    │
│   │     - depth-limited (configurable)                 │    │
│   │     - returns affected nodes + edges per layer     │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   3. SCORE RISK                                    │    │
│   │     - LOW:    < 3 devices, no customer-VRF        │    │
│   │     - MEDIUM: 3-7 devices, no critical svc        │    │
│   │     - HIGH:   8+ devices OR customer-VRF impact   │    │
│   │     - CRIT:   loss of redundancy on uplinks       │    │
│   ├────────────────────────────────────────────────────┤    │
│   │   4. PRE-HEALTH-GATE HOOK                          │    │
│   │     - Health Gate refuses to apply unless         │    │
│   │       blast_radius.risk_score ∈ {LOW} OR          │    │
│   │       blast_radius.approval_id is valid           │    │
│   └────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### Implementation

- **New module:** `src/blast_radius.py` (~300 lines)
- **Reuses:** existing topology graph + NetBox SoT
- **New:** action-specific edge filters (e.g., "drop_bgp_peer" only traverses BGP edges from target)
- **Integration:** Health Gate `/api/mv/health-gate/apply` adds a `blast_radius_approval_id` field, refuses to apply without it (unless score is LOW)
- **Demo UI:** modal popup before "Apply" button — shows interactive graph with affected devices highlighted in red, requires explicit "Acknowledge" before Health Gate proceeds
- **MCP tool:** `blast_radius.compute` so Claude Code can pre-flight in chat

### Risks & mitigations

| Risk | Mitigation |
|---|---|
| Graph stale | Lazy-rebuild on every compute; cache 30s |
| Performance on large fleets | BFS with depth cap (default 3); typical < 30ms |
| False LOW for hidden dependencies | Add NetBox SoT service mapping as required layer; flag if absent |

### Stress tests

- Blast radius on every device sequentially → all complete < 100ms
- Concurrent 10 radius calls → no graph rebuild thrashing
- Health Gate apply WITHOUT radius approval → returns 412 Precondition Failed
- Health Gate apply WITH stale radius approval (>5min old) → rejected with "approval expired"

---

## Stress test plan — ALL features

After A/B/C ship, run a comprehensive regression suite against EVERY feature, old + new:

### Test surfaces

| Layer | Test |
|---|---|
| **Forecasting (new A)** | `tests/test_forecast.py` — synthetic series, anomaly detection, cold start, memory |
| **Predict (new B)** | `tests/test_predict.py` — REJECT/APPROVE paths, cache, parser errors |
| **Blast radius (new C)** | `tests/test_blast_radius.py` — BFS correctness, risk scoring, gate integration |
| **Existing pytest** | run all 137 existing → must stay 137/137 green |
| **Closed-loop integration** | new `tests/test_phase5_integration.py` — full cycle: drift → forecast → predict → blast radius → health gate → verify |
| **Load test** | locust file targeting `/api/mv/*` with 50 concurrent users for 10 minutes |
| **Memory soak** | 24h continuous polling → RSS growth < 50 MB |
| **Eval harness** | existing 10 scenarios + 5 new Phase-5 scenarios (capacity-spike, predict-rejected-change, blast-radius-deny) |

### Acceptance criteria

- All 137 existing tests still pass
- ≥30 new tests across A/B/C
- p95 latency on `/api/mv/*` < 500ms (excluding Predict which is allowed up to 5s)
- Eval harness avg score ≥ 7.5 / 10 with LLM-judge
- No regressions in Health Gate behavior

---

## Real DCN site integration (60 sites)

Currently the lab tool ships with sanitized lab data + 26 demo devices. Phase 5 brings the **real DCN data** into the loop — privacy-safe, audit-friendly.

### Two integration paths

#### Path 1 — Via netlog-ai sidecar (preferred)

netlog-ai already has a sanitizer that reduces real configs → safe text + manifest.json. To add the 60 DCN sites:

```
01_Device_Configurations/junos/*.txt   (384 configs)
01_Device_Configurations/eos/*.txt     (45 configs)
            │
            ▼
   sanitize_to_netlog.py (new script)
            │
            ▼
   netlog-ai/sites/<site-id>/
      ├── manifest.json
      ├── <device>-fw-01.txt   (sanitized)
      └── ...
```

`sanitize_to_netlog.py` (new, ~150 lines):
- Group configs by site code (`fra4`, `lhr3`, ...) using existing hostname pattern
- Run each through netlog's existing redactor (`netlog-ai/sanitizer.py`)
- Auto-generate `manifest.json` from filename pattern
- Output to `netlog-ai/sites/<site>/`

#### Path 2 — Direct in lab tool (optional, post-Phase-5)

Add a site-aware data layer to the lab tool that reads sanitized configs directly. Skip for Phase 5 unless we discover blockers with Path 1.

### Acceptance criteria

- ≥ 30 sites successfully sanitized and importable
- Zero PII / secrets in any output (auto-grep checks: passwords, IPs in 10.x.x.x non-RFC1918, real ASNs ≠ 65000-65535 reserved)
- Per-site Batfish parse succeeds for ≥ 80% of sites
- Lab tool's NetBox SoT view can be pivoted to a real site
- Forecast model can be trained/tested on real CPU/memory series (anonymized)

---

## Documentation deliverables

Each phase 5 feature ships with:

- **Feature doc** (`FORECAST.md`, `PREDICT.md`, `BLAST_RADIUS.md`) — endpoint contract, examples, troubleshooting
- **Test report** (auto-generated by pytest → `docs/phase5-test-report.html`)
- **Architecture diagram** (`docs/img/phase5-*.svg`) — single page per feature
- **Updated `FEATURES.md`** — new rows for Day-23 / Day-24 / Day-25
- **Updated animated hero** — `demo/phase5-hero.html` with three more quadrants OR an extended loop showing forecasts + predict + blast radius

---

## Sequencing (rough · 1 work-week target)

| Day | Work |
|---|---|
| 1 | A — module + endpoint, pytest, demo UI sparkline (forecast) |
| 2 | A — anomaly detection thresholds; stress tests |
| 3 | B — predict_engine.py + Batfish integration + simple before/after diff |
| 4 | B — control-plane sim for BGP/OSPF; predict UI tab |
| 5 | C — blast_radius.py + Health Gate hook + UI modal |
| 6 | Real DCN sanitization (Path 1) + at least 5 real sites loaded |
| 7 | Full stress test sweep, update FEATURES.md + phase5-hero diagram + LinkedIn post draft |

---

## Out of scope for Phase 5 (deferred)

- **GNN-based RCA** (NetAI Inc. pattern) — would require PyTorch Geometric + training data. Defer to Phase 6.
- **NL runbook authoring** (Nova AI Ops pattern) — useful, but requires LLM with structured output + safety review. Defer.
- **3D multi-layer topology** (NetAI Inc.) — pure UX upgrade, no new operational value. Defer.
- **Forward Predict full parity** — Forward's actual product has years of work; we ship the 80/20 version.

---

## Phase 5 launch checklist (next week)

- [ ] All 3 features (A/B/C) have endpoints, tests, UI tabs, MCP tools
- [ ] 137 + N pytest passing (target ≥ 170 total)
- [ ] `phase5-hero.html` animated diagram done
- [ ] `FEATURES.md` reflects Day-22 through Day-30 timeline
- [ ] `COMPARISON.md` updated with three new rows
- [ ] At least 5 real DCN sites importable
- [ ] LinkedIn Phase 5 post draft (mirror Phase 4 voice)
- [ ] 60-second demo video showing forecast → predict → blast radius → safe apply
