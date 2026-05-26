# Phase 6 — Event-Initiated Remediation (Agentic NetOps)

**Launch slot:** Thursday June 11, 2026 · 10:30 AM ET (one week after Phase 5)
**Theme:** Phase 5 shipped the *capabilities*. Phase 6 wires them into a *closed loop* — anomalies auto-trigger remediation through the existing pipeline, with human-approval gates by risk tier.
**Status:** Local · sequenced behind Phase 4 (May 28) and Phase 5 (Jun 4) launches.

> **Reframed 2026-05-26.** Original Phase 6 plan framed the MCP expansion as the launch theme. That work landed inside Phase 5 (50→63 MCP tools, see `docs/PHASE_5_HANDOFF.md`). Phase 6 now picks up the actual remaining gap — the only capability still missing from a 5/5 AI-SRE rubric: event-initiated execution.

---

## TL;DR

Today the lab can:

- **Detect** anomalies (ADTK z-score + flap-count, predictive forecast via Holt-Winters / TimesFM, LLM correlator with knowledge enrichment from netlog-ai).
- **Decide** what to change (Predict engine pre-flight, Batfish blast-radius, Health Gate approval).
- **Execute** changes safely (`POST /api/change/closed-loop` — 6-stage pipeline with auto-revert on regression, verified APPROVED in 12s / ROLLED_BACK in 6s / REJECTED at Batfish on live runs).

What it can't do: **trigger that pipeline from a detected anomaly without a human pressing the button.** Phase 6 closes that gap.

Per Itential's "Real vs Theater" rubric — event-initiated execution is the single capability that separates an AI copilot from an agentic NetOps tool. Per the AI-SRE 5/5 test, this is the one remaining hole.

---

## What ships in Phase 6

### A — Auto-trigger background loop (`src/auto_remediate.py`, NEW)

Background task started by `src/app.py` (opt-in via `DCN_AUTO_REMEDIATE_S=N` env var, mirrors the existing `DCN_FORECAST_LOOP_S` pattern):

1. Every 5 min: poll `/api/anomaly/detect` (ADTK).
2. Every 15 min: poll `/api/mv/forecast/run-fleet` (predictive).
3. For each new anomaly above its severity threshold:
   - Look up a runbook by `(anomaly_type, vendor)` from `src/runbooks/auto.yaml`.
   - Compute risk tier (LOW · MEDIUM · HIGH · CRIT) via Blast Radius BFS.
   - If `LOW` → auto-execute via `POST /api/change/closed-loop`.
   - If `MEDIUM` / `HIGH` → queue with `approval_status="pending"`, surface in UI banner.
   - If `CRIT` → write GAIT entry, page-out via webhook (no auto-action).
4. Track each auto-trigger in a new measurement `auto_remediations` in InfluxDB so we can plot "how often anomaly → fix" over time.

### B — Runbook catalog (`src/runbooks/auto.yaml`, NEW)

Initial 8-runbook catalog seeded from `docs/PHASE_5_HANDOFF.md` audit work. Each entry:

```yaml
- id: bgp_flap_reset
  match:
    anomaly_type: flap_count
    metric: bgp_session_count
    threshold: 5_per_15min
    vendor: [frr, arista_eos, nokia_srl]
  runbook:
    description: "Soft-clear BGP peer after >5 flaps in 15 min"
    edit_payload: "clear bgp neighbor {peer_ip} soft"
    timeout_s: 30
  risk_tier: LOW                # auto-execute
```

8 patterns covered: BGP flap, OSPF area mismatch, interface error-rate spike, MTU drift, route-leak (prefix count anomaly), CPU spike, MAC flap, port admin-down drift.

### C — UI: "Auto-Remediation Queue" panel (`demo/index.html` new tab)

- Live queue: pending / running / completed runs in last 24h.
- Approval workflow: MEDIUM/HIGH items show a green "Approve" + red "Decline" button. Approval triggers `POST /api/change/closed-loop` immediately.
- History view: each run links to its closed-loop `change_id` → existing Change Pipeline tab.
- Per-runbook success rate panel (success_count / attempt_count) over rolling 7 days.

### D — New API endpoints

| Endpoint | Verb | Purpose |
|---|---|---|
| `/api/auto-remediate/status` | GET | Background loop health + last tick |
| `/api/auto-remediate/queue` | GET | Pending + recent runs |
| `/api/auto-remediate/approve/<id>` | POST | Approve a queued MEDIUM/HIGH item |
| `/api/auto-remediate/decline/<id>` | POST | Decline + write reason to GAIT |
| `/api/auto-remediate/runbook` | GET | List loaded runbook catalog |

### E — MCP additions (`src/mcp_dcn_server.py`, +5 tools → **68 total**)

| Tool | Wraps |
|---|---|
| `mv_auto_status` | `/api/auto-remediate/status` |
| `mv_auto_queue` | `/api/auto-remediate/queue` |
| `mv_auto_approve` | `/api/auto-remediate/approve/<id>` |
| `mv_auto_decline` | `/api/auto-remediate/decline/<id>` |
| `mv_auto_runbooks` | `/api/auto-remediate/runbook` |

---

## What does NOT ship in Phase 6

Keep the scope tight:

- **Production NetBox-as-SoT** wiring. Item #4 on the Phase 5 backlog — defer to Phase 7.
- **Eval corpus / golden traces.** Item #3 — defer to Phase 7. Phase 6 ships behavior; Phase 7 measures it.
- **Web-UI SPA refactor.** Defer indefinitely — not a value driver for the launch story.
- **cEOS image swap + FRR gRPC build.** Already documented in `docs/STREAMING_TELEMETRY_GAPS.md` + `scripts/migrate_streaming_telemetry.sh`. Execution is a clab destroy/deploy event — handle out-of-band, not as part of Phase 6 itself.
- **Secrets manager + Redis cache.** Production hardening items #5–#6 — Phase 7+.

---

## Sequencing

| Date | Event |
|---|---|
| Thu 2026-05-28 10:30 ET | Phase 4 launches (closed-loop pipeline) |
| Sat 2026-05-30 | Phase 4 settles · 48h clearance complete · push Phase 5 to public repo |
| Tue 2026-06-02 17:00 ET | T-48h Phase 5 checklist (already scheduled) |
| Thu 2026-06-04 10:30 ET | Phase 5 launches (Forecast / Predict / Blast Radius / ADTK / 63 MCP tools) |
| Fri 2026-06-06 | Phase 5 cleared 48h |
| Sat-Sun 2026-06-06/07 | Build auto-remediate loop · runbook catalog v1 · UI queue panel |
| Mon-Tue 2026-06-08/09 | Live-test on lab: induce flap → confirm auto-fix · induce spike → confirm queued |
| Tue 2026-06-09 17:00 ET | T-48h Phase 6 checklist (already scheduled) |
| Wed 2026-06-10 | Record demo · push to public · final test sweep |
| **Thu 2026-06-11 10:30 ET** | **Phase 6 launches** |

---

## Pre-launch checklist (T-48h before Jun 11)

- [ ] Phase 5 launch landed cleanly, no outstanding issues filed against it
- [ ] Phase 5 has cleared its 48h post-launch window (≥Sat Jun 6)
- [ ] `src/auto_remediate.py` running clean for 24h without throwing
- [ ] At least 3 successful auto-runs visible in `/api/auto-remediate/queue`
- [ ] At least 1 queued-then-approved MEDIUM run visible (manual approval verified)
- [ ] Runbook catalog `src/runbooks/auto.yaml` linted + tested (each runbook fires correctly on its trigger)
- [ ] `demo/phase6-hero.html` opens cleanly in Safari + Chrome
- [ ] MCP server still registers 68 tools (`grep -c '@mcp.tool' src/mcp_dcn_server.py` → 68)
- [ ] `PHASE6_PLAN.md` reflects what actually shipped
- [ ] Hero URL returns HTTP 200 from `gesh75.github.io`
- [ ] Calendar reminders confirmed for T-1h + T-0

---

## Demo journey to record (T-48h)

**Single take, ~2 minutes, no human clicks during the auto-fix.**

1. Operator opens the Auto-Remediation Queue tab — shows it idle ("0 pending").
2. Operator runs `./network-lab/sim_bgp_failure.sh chaos` — induces a BGP flap on a random peer.
3. ~30 s later, ADTK detector fires. Anomaly appears in queue with `LOW` risk tier.
4. Within 5 s, auto-trigger fires `POST /api/change/closed-loop`. Pills cascade through 6 stages.
5. Verdict: **APPROVED · BGP restored.** Total elapsed: ~45 s with zero human input.
6. Operator runs a second simulated event with `HIGH` risk tier (interface admin-down on a core link). It queues with `pending` status. Operator clicks Approve. Closed-loop fires, completes, verdict APPROVED.
7. Operator opens GAIT recent actions — shows both runs tagged `actor="auto-remediate"` + `actor="mcp-approved"`.

This is the hero clip. It demonstrates the loop is real and bidirectional (auto + human-gated).

---

## Eval criteria (when is Phase 6 "done"?)

| Criterion | Target |
|---|---|
| Background loop running clean | ≥24h without throwing |
| Successful auto-fixes (LOW tier) | ≥3 demonstrated |
| Successful queued-then-approved (MEDIUM tier) | ≥1 demonstrated |
| Runbook catalog | ≥8 patterns loaded |
| New MCP tools registered | 5 (68 total) |
| Itential "Real vs Theater" rubric | **5/5** (event-initiated execution now complete) |
| AI-SRE 5-Capability test | **5/5** |
| TM Forum ANL | **L4** (closed-loop self-optimization) |

---

## Post-launch follow-ups (Phase 7+ candidates)

Surfaced during Phase 6 prep; not committed:

- **Eval corpus + golden traces** (Aether-style). Build N labelled anomaly → expected runbook pairs so the auto-remediate loop has a regression suite.
- **Reinforcement signal on runbook success rate.** If a runbook's success rate drops below 70% over 30 days, automatically demote it from `LOW` to `MEDIUM` (require human approval).
- **Production NetBox SoT wiring** (item #4 from Phase 5 backlog).
- **Secrets manager + Redis** (items #5–#6 from Phase 5 backlog).
- **Cross-MCP composition demo** — Juniper `junos-mcp-server` + our 68-tool server + netlog-ai's MCP all running in the same Claude session.

---

## Out-of-band: what to NOT do

Mirrored from Phase 3/4/5 launch hygiene:

- **Don't post to multiple platforms simultaneously.** LinkedIn first. Reddit / HN can wait until Day 2 if LinkedIn crosses 3K impressions.
- **Don't tag people who didn't engage with prior phases.** Cold tagging hurts reach.
- **Don't crosspost to non-technical audiences.** Target = network engineers + ops architects.
- **Don't ship Phase 7 or hint at it heavily in Phase 6 post.** One launch, one promise.
- **Don't claim "first agentic NetOps."** Unverifiable + temporal. Lead with the *capability completion* angle ("5/5 AI-SRE rubric"), which is durable and provable.
- **Don't auto-remediate `CRIT` tier.** Hardcoded webhook-only path. Resist requests to "just let it try."
