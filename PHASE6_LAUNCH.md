# Phase 6 — LinkedIn Launch Pack

**Launch slot:** Thursday June 11, 2026 · 10:30 AM ET (one week after Phase 5)
**Cadence:** mirrors Phase 3/4/5 single-comment pattern (7K-impression proven)
**Status:** local — DO NOT PUSH until Phase 5 settles (Thu Jun 4, 10:30 AM ET) + 48h clearance
**Theme:** Agentic NetOps — anomalies fix themselves, with a human-approval gate by risk tier.

> **Reframed 2026-05-26.** Phase 5 already shipped the MCP expansion (50→63 tools), the closed-loop pipeline, ADTK, predictive forecast, and the entire AI/Detection layer. Phase 6 wires those capabilities into a closed loop — anomaly → matched runbook → closed-loop pipeline → verdict → audit, with zero human input for LOW-risk events and a one-click approval gate for MEDIUM/HIGH.

---

## Main post (LinkedIn, ≤230 words)

> Five phases ago this was a Flask app that pinged routers. Tonight the lab fixes itself.
>
> Phase 6 wires the last piece — **event-initiated remediation**. Anomalies trigger the closed-loop pipeline automatically. Humans gate the risky ones.
>
> Pipeline today:
>
> 🔬 **Detect** — ADTK z-score + flap-count + predictive TimesFM forecast + LLM correlator (rules + anomalies + RAG over sanitized configs)
>
> 🧭 **Decide** — Predict pre-flight (vendor-aware what-if), Batfish blast-radius, Health Gate confirmed-commit, Blast Radius BFS for risk tier
>
> 🛠️ **Execute** — `POST /api/change/closed-loop` chains 6 stages with auto-revert on regression. Verified live: APPROVED 12s · ROLLED_BACK 6s · REJECTED at Batfish
>
> 🔁 **Auto-trigger (NEW)** — anomalies tagged LOW risk → auto-execute. MEDIUM/HIGH → queue with Approve/Decline buttons. CRIT → webhook-only (humans page-out)
>
> Demo: BGP flap induced on a clab leaf. ADTK detects in 30s. Runbook matched. Closed-loop fires. Peer restored. **45 seconds end-to-end, zero clicks.** Then a HIGH-risk simulated drift queues for one-click approval.
>
> 8 seed runbooks · 68 MCP tools · 200+ Flask endpoints · 51/51 BGP across 4 vendors (Juniper · Cisco · Arista · Nokia SR Linux · FRR) · Apache 2.0 · local-only · no SaaS.
>
> AI-SRE rubric now 5/5. Itential "Real vs Theater" 5/5. TM Forum ANL → L4.
>
> Demo: {PHASE6_HERO_PAGES_URL}
> Repo: github.com/gesh75/multivendor-ai-network-lab
>
> Built for operators who still want their pager to ring less often.

---

## First comment (longer technical breakdown)

> The trap with "AI fixes the network" is over-trust. Most autonomous remediation demos show a happy path and skip the failure modes. Here's what Phase 6 actually does on the unhappy paths:
>
> **1. Runbook lookup miss.** Anomaly fires but no runbook matches `(anomaly_type, vendor)` → write to GAIT with `result=no_match`, surface in UI as "investigate manually". No silent failure.
>
> **2. Blast Radius CRIT.** Even if the runbook is `LOW`-tagged, if the Blast Radius BFS scores the proposed change as CRIT (e.g. touching a route-reflector that 8 sessions depend on), the auto-trigger demotes to webhook-only. No "small fix" silently nuking the fabric.
>
> **3. Closed-loop ROLLED_BACK.** The pipeline already auto-reverts on regression (RFC 6241 §8.4 confirmed-commit). When this happens during an auto-trigger, the runbook's success rate drops. If it falls below 70% over 30 days, the runbook gets auto-demoted from LOW → MEDIUM (requires human approval going forward). The loop has a built-in trust-decay signal.
>
> **4. Same anomaly fires repeatedly.** Rate-limit per `(host, anomaly_type)` — at most one auto-trigger per 30 min. Beyond that, queue with `result=rate_limited`. Stops a flapping detector from hammering the pipeline.
>
> The runbook catalog ships with 8 seed patterns: BGP flap soft-reset, OSPF area mismatch, interface error-rate spike, MTU drift, route-leak (prefix count anomaly), CPU spike, MAC flap, port admin-down drift. Each YAML entry declares trigger, matched vendors, risk tier, and the edit_payload. Adding a 9th is one PR.
>
> 5 new MCP tools (`mv_auto_status`, `mv_auto_queue`, `mv_auto_approve`, `mv_auto_decline`, `mv_auto_runbooks`) make this accessible from Claude Code / Cursor / Claude Desktop — same surface as the 63 Phase-5 tools.
>
> Every auto-trigger writes a GAIT entry with `actor="auto-remediate"`. Approved-by-human runs are tagged `actor="mcp-approved"` or `actor="ui-approved"`. The append-only audit trail is the ground-truth log of what the agent did, when, why, and at what token cost.
>
> Architecture doc: {ARCHITECTURE_PHASE_6_URL}
> Phase 5 launch (Forecast/Predict/Blast Radius/ADTK): {PHASE5_HERO_PAGES_URL}
>
> Phase 7 is on paper — eval corpus + golden traces (Aether pattern), then production NetBox-SoT wiring + secrets manager hardening for any real deployment.

---

## Engagement script (first 60 minutes after posting)

| Minute | Action |
|---|---|
| 0–5 | Post main post. Pin first comment immediately. |
| 5–15 | Reply to first 3 comments. Don't wait for them to pile up. |
| 15–30 | DM 5 people who liked Phase 5 — "Phase 6 went live, this is the auto-trigger angle." |
| 30–60 | Engage with 5 adjacent posts (network automation, AIOps, AI-SRE). Substantive comments only — no "Great post!". |
| 60+ | Monitor for the next 6 hours. Reply within 30 min to anything technical. |

LinkedIn weights engagement velocity in the first hour disproportionately — same lever that worked for Phases 3, 4, 5.

---

## Hero / demo URLs (post-Phase-5-merge)

To be filled in once Phase 5 lands and Phase 6 is pushed:

- `{PHASE6_HERO_PAGES_URL}` → `https://gesh75.github.io/multivendor-ai-network-lab/demo/phase6-hero.html`
- `{ARCHITECTURE_PHASE_6_URL}` → `https://github.com/gesh75/multivendor-ai-network-lab/blob/main/docs/ARCHITECTURE_PHASE_6.md`
- `{PHASE5_HERO_PAGES_URL}` → `https://gesh75.github.io/multivendor-ai-network-lab/demo/phase5-hero.html`

GitHub Pages already enabled from Phase 4 launch — no extra config needed.

---

## Demo journey to record (T-48h)

**Single take, ~2 minutes, the auto-fix happens with zero clicks.**

1. Operator opens the Auto-Remediation Queue tab — shows "0 pending".
2. Operator runs `./network-lab/sim_bgp_failure.sh chaos` — induces BGP flap on a random peer.
3. ~30s later, ADTK detector fires. Anomaly enters queue with `LOW` risk tier.
4. Within 5s, auto-trigger fires `POST /api/change/closed-loop`. 6 stage pills cascade through Predict → Batfish → Apply → Watch → POST diff → Verify.
5. Verdict: **APPROVED · BGP restored.** Total elapsed: ~45s. Zero human input.
6. Operator induces a second simulated event (interface admin-down on a core link) with `HIGH` risk tier. It queues with `pending` + green Approve button + red Decline button.
7. Operator clicks Approve. Closed-loop fires, completes, verdict APPROVED.
8. Operator opens GAIT recent actions. Both runs visible — first tagged `actor="auto-remediate"`, second tagged `actor="ui-approved"`.

This is the hero clip. It demonstrates the loop is real, bidirectional (auto + human-gated), and honest about its limits (LOW auto / MEDIUM-HIGH queued / CRIT page-out).

---

## Pre-launch checklist (T-48h before Jun 11 10:30 ET)

- [ ] Phase 5 launch landed cleanly, no outstanding issues filed against it
- [ ] Phase 5 has cleared its 48h post-launch window (≥Sat Jun 6)
- [ ] `src/auto_remediate.py` background loop running clean for 24h
- [ ] At least 3 LOW-tier auto-runs visible in queue history
- [ ] At least 1 MEDIUM/HIGH-tier queued-then-approved run visible
- [ ] Runbook catalog `src/runbooks/auto.yaml` has 8+ patterns, all unit-tested
- [ ] MCP server registers 68 tools (5 new auto-remediate tools)
- [ ] Demo journey recorded (single take, ≤2min, zero clicks for the LOW path)
- [ ] `demo/phase6-hero.html` opens cleanly in Safari + Chrome
- [ ] `PHASE6_PLAN.md` reflects what shipped
- [ ] README has a 1-line callout linking to Phase 6 features
- [ ] Hero URL returns HTTP 200 from `gesh75.github.io`
- [ ] Calendar reminder set for T-1h to draft the post and T-0 to publish

---

## Sequencing window

- **Sun 2026-05-25**: Phase 5 sealed (5/5 done, 41-pass stress, 63 MCP tools, 51/51 BGP). Phase 6 plan reframed.
- **Mon–Wed 2026-05-25/27**: monitor Phase 4 prep
- **Thu 2026-05-28 10:30 ET**: Phase 4 launches — observe engagement
- **Sat 2026-05-30**: Phase 4 cleared 48h · push Phase 5 to public repo
- **Tue 2026-06-02 17:00 ET**: T-48h Phase 5 checklist (scheduled)
- **Thu 2026-06-04 10:30 ET**: Phase 5 launches
- **Fri 2026-06-06**: Phase 5 cleared 48h
- **Sat–Sun 2026-06-06/07**: build auto-remediate loop + runbook catalog + UI queue
- **Mon–Tue 2026-06-08/09**: live-test on lab, record demo
- **Tue 2026-06-09 17:00 ET**: T-48h Phase 6 checklist (scheduled)
- **Wed 2026-06-10**: T-1 hero verification + URL fill-in + final test sweep
- **Thu 2026-06-11 10:30 ET**: Phase 6 launches

---

## Out-of-band: what to NOT do

Lessons mirrored from Phase 3/4/5 prep:

- **Don't post to multiple platforms simultaneously.** LinkedIn first. Reddit / HN can wait until Day 2 if LinkedIn crosses 3K impressions.
- **Don't tag people who didn't engage with prior phases.** Cold tagging hurts reach.
- **Don't crosspost to non-technical audiences.** Target = network engineers + ops architects.
- **Don't ship Phase 7 or hint at it heavily in Phase 6 post.** One launch, one promise.
- **Don't claim "first agentic NetOps."** Unverifiable + temporal. Lead with the **5/5 rubric completion** angle (Itential + AI-SRE) — durable and provable on the day.
- **Don't position this as "no humans needed."** The MEDIUM/HIGH queue + approval UI is the *point*. Lead with the trust ladder (LOW auto / MEDIUM-HIGH queue / CRIT page-out), not the autonomy story.
- **Don't auto-remediate CRIT.** Hardcoded webhook-only. Resist requests to "just let it try."
