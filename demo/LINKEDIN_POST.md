# LinkedIn launch — Phase 4 (the closed-loop phase)

> **Post video:** [`demo/linkedin-demo.mp4`](./linkedin-demo.mp4) · 0:52 · 1.9 MB · 1280×720 · H.264.
> **First-comment link:** [YouTube — full feature tour](https://youtu.be/wWPJTiRm5qs) · 2:51 · every panel + captions.
> **Repo:** <https://github.com/gesh75/multivendor-ai-network-lab>
> **Prior post:** [Phase 3 on LinkedIn](https://www.linkedin.com/feed/update/urn:li:activity:7458139826265939968/)

---

## 📋 The post (paste this into LinkedIn)

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

## ✅ Posting steps

### Step 1 — Create the LinkedIn post

1. Open LinkedIn → Start a post.
2. Click the **video icon** → upload `demo/linkedin-demo.mp4`.
3. Paste the post copy from the section above into the body.
4. Wait for the video to finish uploading (the progress bar fills, thumbnail appears).

### Step 2 — Set the thumbnail

1. Click the video preview → **Edit** → **Thumbnail**.
2. Scrub to a frame showing either the **Change Pipeline 5-step** view or the **Health Gate countdown ring** — either reads strongly at thumbnail size.
3. Save.

### Step 3 — Publish

1. Click **Post**.
2. Stay on the post page — you need to add the first comment immediately after publish so it locks in as the top comment.

### Step 4 — Add the first comment (do this within 30 seconds of publishing)

Paste this exact text as a single comment:

```text
🎥 Full feature tour (2:51 · every panel + captions): https://youtu.be/wWPJTiRm5qs

📦 Repo, architecture diagram, all docs: https://github.com/gesh75/multivendor-ai-network-lab

🔁 Phase 3 (the brain) for context: https://www.linkedin.com/feed/update/urn:li:activity:7458139826265939968/
```

Then click the `⋮` on your own comment → **Pin to top of comments**.

### Step 5 — Tag + engage (first hour matters most for reach)

1. Tag in a reply (not the post body — keeps the post clean):
   - the NetClaw author (`@automateyournetwork`)
   - the sands-lab / NIKA team
   - Hugo Tinoco
   - codingnetworks.blog
2. Reply to every comment in the first hour. LinkedIn boosts reach when the post has comment velocity in the first 60 minutes.
3. Re-share the post to your own feed from a different angle ~24 hours later if engagement is strong.

---

## 🏷 Hashtag pool (the post uses 5 — swap if needed)

`#NetworkAutomation` `#AIOps` `#ClaudeAI` `#NetOps` `#ClosedLoop` · spares: `#RFC6241` `#BGP` `#OpenSource` `#FastMCP` `#SRE`
