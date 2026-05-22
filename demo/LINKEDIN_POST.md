# LinkedIn launch — Phase 4 (the closed-loop phase)

> Attach to post: **`linkedin-demo.mp4`** (0:52 · 1.9 MB · 1280×720 · H.264 · tight cut of the closed loop).
> Deep-dive companion (2:51 · 6.4 MB · every panel + every primary CTA + captions): see "First comment strategy" below — *don't* link the blob URL on GitHub, it exceeds GitHub's inline preview cap and lands viewers on a dead-end page.
> Repo: https://github.com/gesh75/multivendor-ai-network-lab
> Prior post: [Phase 3 on LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7458139826265939968/)

The previous post (Phase 3) introduced the brain — Pydantic-AI orchestrator, LLM switcher, NIKA harness, path trace, GAIT audit, 49-tool MCP. This post must NOT re-list those. **Phase 4 is the safety + autonomy layer** — the part that lets the lab take an action and take it back if it goes wrong.

---

## 🥇 Recommended — matches Phase 3 voice exactly

Phase 4 ships on the multivendor AI network ops lab.

Phase 3 gave the lab a brain. Phase 4 gave it hands — and a way to take them back if something goes wrong.

What's new since the last update:

• **Health Gate** — every config push now flows through RFC 6241 §8.4 confirmed-commit. The module watches BGP peers, interface state, and alert count for the entire window. If any signal degrades, the device auto-reverts at the NETCONF timeout. The tool literally cannot leave a router worse than it found it.
• **NetBox SoT drift detector** with severity tiers — wrong AS or IP is high, extra device in the lab is critical, wrong model is low. SoT-side None suppresses drift on optional metadata so the dashboard stays quiet on noise.
• **Auto-Remediate** proposal state machine — pending → approved → executing → done | error. Each drift row maps to a runbook via a deterministic table. AI proposes, cosmetic drift auto-rejects, real drift queues for human approval.
• **Auto-Postmortem** writer — heuristic root-cause priority (chaos > HG-abandon > remediation > cluster > local). Stitches the GAIT audit trail + Health Gate verdict + remediation history into structured Markdown. ~0.2 s to generate a report.
• **CLI Reference BM25** — 9,802 commands across Cisco / Juniper / Arista, pure stdlib Okapi BM25 in ~40 lines, sub-millisecond at 10k entries. No embedding model, no API calls, deterministic.
• **MCP layer extended** — the existing MCP server now exposes the full closed loop (drift.scan, remediation.approve, health_gate.apply, postmortem.generate), so Claude Code can drive the entire workflow without a browser.
• **GUI sprint** — persistent dock with live BGP-session badge, vendor color tokens, mode chords (m+o = observe, m+d = diagnose), nav chords (g+i = inventory + focus filter), Change Pipeline as a 5-step view, breadcrumb, P1 dominance pill, NEW-badge with 30-day auto-expiry. 4 deep accessibility audits absorbed. 0 unlabelled buttons across 185 surfaces.

The lab is unchanged: 26 devices (Juniper SRX/MX/EX, Arista 7280/7050, 10 live FRR Docker containers), 5 sites, 40 REST endpoints, 137/137 pytest. Still MIT, still a single laptop, still no cloud.

Patterns adapted from @automateyournetwork's NetClaw, sands-lab/NIKA, Hugo Tinoco's pydantic-ai work, and codingnetworks.blog MPLS+MCP. The confirmed-commit pattern is verbatim from RFC 6241 §8.4.

Built solo over 20 focused days. Open source.
github.com/gesh75/multivendor-ai-network-lab

Always open to discussions about closed-loop NetOps and confirmed-commit safety patterns. Reach out.

#NetworkAutomation #AIOps #ClaudeAI #NetOps #ClosedLoop

---

## 🥈 Variant — shorter / "one idea" version

Phase 4 ships on the multivendor AI network ops lab.

One idea this time: **a config push that watches itself**.

Every change now flows through RFC 6241 §8.4 confirmed-commit. The Health Gate module watches BGP peers, interface state, and alert count for the duration of the window. If any signal degrades, the device auto-reverts at the NETCONF timeout. The tool cannot leave a router worse than it found it.

Around that core, four more pieces landed:

• NetBox SoT drift detector — severity-tiered (critical / high / medium / low), SoT-side None suppression to keep the dashboard quiet.
• Auto-Remediate — proposal state machine, deterministic runbook table, AI proposes / human approves.
• Auto-Postmortem — heuristic root-cause priority, stitches GAIT audit + HG verdict + remediation history into Markdown in ~0.2 s.
• CLI Reference BM25 — 9,802 commands (Cisco / Juniper / Arista), pure stdlib, sub-millisecond. No embedding model, no API calls.

The MCP server now exposes the full loop, so Claude Code can run the whole thing without a browser.

Same lab as before — 26 devices, 5 sites, 10 live FRR containers, 137/137 pytest, MIT, no cloud. Built solo over 20 focused days.

github.com/gesh75/multivendor-ai-network-lab

#NetworkAutomation #AIOps #NetOps #ClosedLoop #ClaudeAI

---

## 🥉 Variant — engineer-to-engineer (depth, less "ship" framing)

Closed-loop NetOps without the buzzword soup. What's actually inside Phase 4:

**Health Gate** — submit a config edit. The module reads a pre-snapshot (BGP peers + interfaces up + alert count), opens a NETCONF `<commit confirmed timeout="N"/>` session, polls signals every 5 s. If any tolerance threshold is breached → no confirm → device auto-reverts at NETCONF timeout. RFC 6241 §8.4. Two paths: real (PyEZ + Juniper devices) and simulated (FRR lab + everything else). 20 pytest, ~0.5 s.

**NetBox SoT drift** — severity-tiered comparison. Wrong AS/IP = high. Extra device in lab = critical. Wrong model = low. SoT-side None suppresses drift to avoid false positives on optional metadata. 25 pytest.

**Auto-Remediate** — proposal state machine: pending → approved → executing → done | error. Each drift row maps to a runbook via a deterministic table. Background watcher mirrors Health Gate verdict into the Proposal so the UI polls one endpoint, not two. 25 pytest.

**Auto-Postmortem** — heuristic root-cause priority: chaos > HG-abandon > remediation > fleet-cluster > local > unknown. Anchors on Health Gate abandons + clusters of 3+ error events in 60 s. 22 pytest. ~0.2 s to generate a report.

**MCP layer extended** — the Phase-3 MCP server picked up four new tools (drift.scan, remediation.approve, health_gate.apply, postmortem.generate), so the full loop is drivable from Claude Code without a browser.

**CLI Reference BM25** — pure stdlib Okapi BM25 in ~40 lines. 9,802 commands from sibling `multivendor-cli-configurator` (Cisco / Juniper / Arista). Sub-millisecond at 10k entries. No embedding model, no API calls, deterministic.

**GUI sprint** — single-row top bar · persistent dock with live BGP-session badge · vendor color tokens · mode-aware canvas navigation · Change Pipeline as 5-step view · device-context strip with mini-metrics · breadcrumb · P1 dominance pill · NEW-badge 30-day auto-expiry. 4 deep accessibility audits absorbed.

26 devices · 5 sites · 40 REST endpoints · 137/137 pytest · MIT · no cloud.

github.com/gesh75/multivendor-ai-network-lab

#NetOps #Python #FastAPI #FastMCP #RFC6241 #BGP #Networking #SRE

---

## 🎥 Companion video — recommendation

The Phase 3 post used a compact tour video. Phase 4 has one story and it should drive the video: **the closed loop**. Don't show every panel — show one round trip.

| Option | Length | What it shows | Why |
| --- | --- | --- | --- |
| **A. Tight loop cut** ⭐ | 60–75 s | break → drift → propose → approve → Health Gate → recover → postmortem | Matches the "one idea" of the post. Mirrors Phase 3's pacing. **First choice.** |
| B. Master demo as-is | 1:52 | the existing 5-act `linkedin-demo.mp4` | Already produced. Use if there's no time to recut. |
| C. Pure Health Gate clip | 30–40 s | confirmed-commit window + auto-revert under chaos | Strongest single visual. Great for a follow-up comment / second slide. |

### Storyboard for Option A (60–75 s tight cut)

1. **0:00 – 0:08** — Topology view, BGP sessions green. Caption: *"Phase 4. Watch a router fix itself."*
2. **0:08 – 0:18** — Click Chaos Monkey ⚡ Break. One link flips red. Caption: *"Break a session."*
3. **0:18 – 0:32** — Open NetBox Drift. Severity-tier list populates. AI proposes the runbook. Caption: *"Drift detected · runbook proposed."*
4. **0:32 – 0:48** — Click Approve. Health Gate window opens with the conic-gradient countdown ring. BGP signal swings, then settles green. Caption: *"Confirmed-commit · auto-revert armed · BGP recovered."*
5. **0:48 – 0:62** — Click "Generate Postmortem". Markdown scrolls. Caption: *"~0.2 s — incident report written. Ready to paste into a ticket."*
6. **0:62 – 0:70** — End frame: repo URL + "github.com/gesh75/multivendor-ai-network-lab · MIT · single laptop"

Existing `record-linkedin.cjs` already covers acts 2–4 — recut by trimming the cold-open and the CLI Reference tour, then re-encoding from the existing `linkedin-demo.webm` source.

### Recut command (no re-record needed)

```bash
# trim master to the loop-only segment (~22s in to ~95s in = 73s)
ffmpeg -ss 22 -to 95 -i demo/linkedin-demo.webm \
  -c:v libx264 -crf 22 -preset slow -pix_fmt yuv420p \
  -movflags +faststart \
  demo/linkedin-demo-loop.mp4
```

---

## Posting checklist

- [ ] Upload **`linkedin-demo.mp4`** (the 0:52 tight cut) as the post's primary video — better LinkedIn compression + autoplay
- [ ] Thumbnail: a frame showing the Change Pipeline 5-step or the Health Gate countdown ring
- [ ] First comment — pin these (see "First comment strategy" below for the full-tour link tradeoffs):
      1. Repo: `github.com/gesh75/multivendor-ai-network-lab`
      2. Full tour link — **pick ONE of the three strategies below**
      3. Phase 3 permalink so readers can see the arc
- [ ] Tag the people whose work seeded the patterns: NetClaw author, NIKA team, Hugo Tinoco, codingnetworks.blog
- [ ] Reply to the first 5 comments within an hour

## First comment strategy — the full-tour link problem

GitHub's blob view refuses to render MP4s over ~5 MB inline, so the obvious
`/blob/main/demo/full-tour-demo.mp4` URL lands viewers on a "Sorry, can't show
files that are this big" page with just a Download button. That's a friction
wall most LinkedIn readers won't push through. Three workarounds, ranked:

### 🥇 Option A — YouTube unlisted (best · 5 min setup)

Upload `demo/full-tour-demo.mp4` as an **unlisted** YouTube video. Unlisted =
only people with the link see it, no public discoverability. LinkedIn renders
an inline play card in the comment. Highest click-through, lowest friction.

Copy-paste-ready upload metadata:

```text
Title:        Multivendor AI Network Lab — full feature tour (Phase 4)
Visibility:   Unlisted
Description:  Full 2:51 walkthrough of all 40 panels in the Multivendor AI
              Network Lab — telemetry, audit, AI surfaces, the closed-loop
              change pipeline (Health Gate · NetBox SoT drift · Auto-Remediate
              · Auto-Postmortem), topology, path trace, and the eval/chaos
              surfaces. Captioned, no narration. Open source, MIT.

              Repo: https://github.com/gesh75/multivendor-ai-network-lab
              Tight 0:52 cut for the LinkedIn post:
              https://github.com/gesh75/multivendor-ai-network-lab/blob/main/demo/linkedin-demo.mp4

Tags:         networking, network automation, multivendor, aiops, claude,
              juniper, arista, frr, bgp, netconf, rfc6241, closed loop,
              netops, mcp, open source
```

Then paste the YouTube URL into the LinkedIn first comment.

### 🥈 Option B — Link the repo root (simplest · zero new infra)

Don't link the video file at all. Link the repo root and write the comment
copy to do the work:

> Full code, architecture diagram, and a 2:51 captioned feature tour video
> are all in the repo →
> github.com/gesh75/multivendor-ai-network-lab

LinkedIn renders a clean OpenGraph card for the repo. Anyone who wants the
video clicks into `demo/full-tour-demo.mp4`, where GitHub *will* offer a
Download button — but framed as "explore the repo," the friction makes sense.
This sidesteps the blob-preview problem entirely.

### 🥉 Option C — Raw GitHub URL (functional but ugly)

```text
https://github.com/gesh75/multivendor-ai-network-lab/raw/refs/heads/main/demo/full-tour-demo.mp4
```

Serves the raw MP4 bytes. Modern desktop browsers will play it in their
built-in video player. **Mobile browsers often prompt a download instead of
playing.** No LinkedIn preview card — just a bare URL in the comment.

Use only if you can't be bothered with YouTube and want the video to be the
first thing the user sees. Otherwise Option B is cleaner.

**Recommendation: Option A if you have 5 minutes. Option B otherwise.**

## Hashtag pool (pick 4–5)

`#NetworkAutomation` `#AIOps` `#NetOps` `#ClosedLoop` `#ClaudeAI` `#RFC6241` `#BGP` `#OpenSource`
