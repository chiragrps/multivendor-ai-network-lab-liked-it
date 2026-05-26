# Phase 5 — LinkedIn Launch Pack

**Launch slot:** Thursday June 4, 2026 · 10:30 AM ET (one week after Phase 4)
**Cadence:** mirrors Phase 3/4 single-comment pattern (7K-impression proven)
**Status:** local — DO NOT PUSH until Phase 4 settles (Thu May 28, 10:30 AM ET)

---

## Main post (LinkedIn, ≤230 words)

> Phase 4 closed the loop. Phase 5 looks one step ahead.
>
> The lab tool now refuses bad changes **before** they touch a device — and forecasts the conditions that usually cause them.
>
> Three new guards, all running locally, no cloud:
>
> 🔮 **Forecast** — 24-step traffic / CPU / BGP-route projections with a 95% confidence band. Holt-Winters by default; Cisco TimesFM as an opt-in backend. ~15 ms p50.
>
> 🧪 **Predict** — paste a Junos/IOS/EOS/FRR config snippet, get a verdict before commit: APPROVE · WARN · REJECT, with the BGP/OSPF peers it would drop or break. <1 ms.
>
> 💥 **Blast Radius Guard** — BFS over the topology graph: how many devices, how many sites, which services would feel this change. LOW / MEDIUM / HIGH / CRIT, with isolation + redundancy-loss detection.
>
> All three run **before** the Health Gate's confirmed-commit step. If Predict says REJECT or Blast Radius says CRIT, the change never reaches the rollback timer.
>
> 11 new endpoints. 52 MCP tools. 118 new tests (100 unit + 18 stress, all green).
>
> Pre-apply pipeline: **Forecast → Predict → Blast Radius → Health Gate → Verify**
>
> Animated hero (single HTML, no JS framework): {PHASE5_HERO_PAGES_URL}
> Repo: github.com/gesh75/multivendor-ai-network-lab
>
> Built for operators. MIT. No SaaS. No telemetry leaving your lab.

---

## First comment (longer technical breakdown)

> Why these three and not 30?
>
> Every Phase 5 feature had to answer one question: *would this prevent the last outage I worked?*
>
> **Forecast** exists because anomalies almost always have a 30-minute warning window in CPU or route-count metrics. The default backend is stdlib (Holt-Winters triple exponential smoothing). The opt-in backend is Cisco TimesFM 1.0 (250M-param HF model), gated behind `DCN_FORECAST_PROVIDER=cisco-timesfm`. Most users will never need TimesFM. It's there if you want it.
>
> **Predict** is a regex + topology simulator, not Batfish. The full Batfish stub exists (`BatfishPredictor`) for users who want CDP/JNCP-grade analysis, but the rule-based default handles the 14 most common change patterns across Junos-set, Cisco IOS, FRR, and Arista EOS in under a millisecond. Zero dependencies.
>
> **Blast Radius Guard** runs BFS over the live BGP/OSPF/LLDP adjacency graph and scores risk on four dimensions: device count, site count, service impact, structural integrity (isolation + redundancy loss). A CRIT verdict is hard-stop — the user gets an approval token with a 5-minute expiry before the change can proceed.
>
> The pre-apply pipeline composes:
>
> Forecast (will this stress what's already loaded?) → Predict (will this drop sessions?) → Blast Radius (how far does this reach?) → Health Gate (RFC 6241 §8.4 confirmed-commit with auto-revert) → Verify
>
> Every guard is independently testable. Every guard is independently bypassable (for emergency ops). Every guard emits a GAIT audit entry with token cost.
>
> Demo (full UI, 10-container FRR topology): {DEMO_PAGES_URL}
> Phase 4 closed-loop hero (last week's launch): {PHASE4_HERO_PAGES_URL}
>
> Phase 6 is on paper — eval scenario expansion from 10 → ~25 by porting the NIKA fault taxonomy (MAC flap, MTU mismatch, BGP hijacking, microbursts, DHCP/DNS spoof). No NIKA code reuse — just the catalog. Honest credit where it's due.

---

## Engagement script (first 60 minutes after posting)

| Minute | Action |
|---|---|
| 0–5 | Post main post. Pin first comment immediately. |
| 5–15 | Reply to first 3 comments. Don't wait for them to pile up. |
| 15–30 | DM 5 people who liked Phase 4 — "Phase 5 went live, would love your take." |
| 30–60 | Engage with 5 adjacent posts (network automation, AI ops). Substantive comments only — no "Great post!". |
| 60+ | Monitor for the next 6 hours. Reply within 30 min to anything technical. |

LinkedIn's algorithm weights engagement velocity in the first hour disproportionately — research consistently flags this as the single largest controllable lever for reach.

---

## Hero / demo URLs (post-Phase-4-merge)

These get filled in once Phase 4 lands and Phase 5 is pushed:

- `{PHASE5_HERO_PAGES_URL}` → `https://gesh75.github.io/multivendor-ai-network-lab/demo/phase5-hero.html`
- `{DEMO_PAGES_URL}` → `https://gesh75.github.io/multivendor-ai-network-lab/demo/`
- `{PHASE4_HERO_PAGES_URL}` → `https://gesh75.github.io/multivendor-ai-network-lab/demo/phase4-hero.html`

GitHub Pages is already enabled from Phase 4 launch — no extra config needed.

---

## Pre-launch checklist (T-48h before Jun 4 10:30 ET)

- [ ] Phase 4 launch landed cleanly, no outstanding issues filed against it
- [ ] All Phase 5 tests still green after a clean `git pull && pytest` on a fresh venv
- [ ] `demo/phase5-hero.html` opens cleanly in Safari + Chrome on macOS
- [ ] `demo/index.html` shows all 3 new tabs (Forecast, Predict, Blast Radius) under nav-items
- [ ] Terminal dock X/Escape works (was bug pre-Phase-5 — fix already committed locally)
- [ ] `PHASE5_PLAN.md` is up to date with what actually shipped
- [ ] README has a 1-line callout linking to Phase 5 features and hero diagram
- [ ] Hero URL returns HTTP 200 from `gesh75.github.io` (verified via `curl -I`)
- [ ] Calendar reminder set for T-1h to draft the post and T-0 to publish

---

## Sequencing window

- **Sat 2026-05-23** (today): tests green, launch pack drafted, calendar event scheduled
- **Mon–Wed 2026-05-25/27**: monitor Phase 4 prep (Tuesday multi-command tool post lands first)
- **Thu 2026-05-28 10:30 ET**: Phase 4 launches — observe engagement, reply window
- **Fri–Tue 2026-05-29 to 06-02**: Phase 4 post-launch momentum + commit Phase 5 to public repo (after Phase 4 has cleared 48h)
- **Wed 2026-06-03**: T-1 hero verification + URL fill-in + final test sweep
- **Thu 2026-06-04 10:30 ET**: Phase 5 launches

---

## Out-of-band: what to NOT do

Lessons mirrored from Phase 4 prep:

- **Don't post to multiple platforms simultaneously.** LinkedIn first. Reddit / HN can wait until Day 2 if the LinkedIn post crosses 3K impressions.
- **Don't tag people who didn't engage with prior phases.** Cold tagging hurts reach.
- **Don't crosspost to non-technical audiences.** The audience that converts is operators and architects, not generic AI hype.
- **Don't ship Phase 6 or hint at it heavily in Phase 5 post.** One launch, one promise.
