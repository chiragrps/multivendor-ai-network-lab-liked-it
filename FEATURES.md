# AI Network Tool v4.0 — Feature Map

> **Public repo:** https://github.com/gesh75/multivendor-ai-network-lab
> **Demo video:** [`multivendor-ai-network-tool-demo-r27.mp4`](./multivendor-ai-network-tool-demo-r27.mp4) (60 s · 1920×1080)
> **Lab:** 26 devices · 5 sites · 36 BGP sessions · multivendor (Juniper · Arista · FRR)

---

## At a glance

| Metric | Value |
|---|---|
| Panels / features | **34** |
| Interactive buttons | **185** (all labelled) |
| Form inputs | **44** (all labelled) |
| Lab devices | **26** across 5 sites — DE-FRA · UK-LON · NL-AMS · EU-CDG · US-NYC |
| BGP sessions | 36 (10 FRR live containers · 16 sanitised real configs) |
| Accessibility audit | **0 unlabelled elements** · 16 consecutive rounds |
| Inspection rounds | 27 |
| Hostname convention | Universal `{site}-{vendor-role}-{nn}` (e.g. `de-fra-core-01`) |
| Keyboard mode chords | 5 (`m o/d/p/u/l`) + 7 nav chords (`g h/s/t/o/a/c/i`) |

---

## 34 panels grouped by workflow

### 👁  Observe — telemetry + alerts (7 panels)

| # | Panel | What it does |
|---|---|---|
| 1 | **Home / Health** | Per-device health cards · CPU · memory · BGP · OSPF · auto-fetch on landing · click hostname/IP to jump to CLI |
| 2 | **gNMI Telemetry** | OpenConfig telemetry pulled from the 10 FRR containers via vtysh-backed gNMI shim |
| 3 | **Streaming Telemetry** | High-rate metric stream with per-device sparklines |
| 4 | **Syslog** | UDP :5140 receiver · severity tiles click-to-filter · device column · host + severity dropdowns · CSV export |
| 5 | **SNMP Traps** | UDP :1162 receiver · per-site filter · OID + binding column · "unmanaged source" badge |
| 6 | **Alert Correlation** | Multi-source alert dedup + correlation with remediation guidance |
| 7 | **Noise Floor** | 5-site sparklines (raw · suppressed · incidents) · suppression efficiency per region |

### 🗄  Inventory & Audit (7 panels — Day-3/4: NetBox SoT, Day-8: Auto-Postmortem)

> 📖 **NetBox SoT** — Source-of-truth drift detector. Compares NetBox view
> against running lab. Severity-tiered (critical / high / medium / low) with
> presence + field-level drift. 25 pytest cases, simulated + real (pynetbox)
> modes. See [NETBOX_SOT.md](NETBOX_SOT.md) and
> `GET /api/mv/netbox-sot/drift`.
>
> 📋 **Auto-Postmortem** — Correlates GAIT + Health Gate + Remediation events
> into structured incident reports. Deterministic root-cause heuristics,
> auto-detects P1 anchors on Health Gate abandons, markdown output ready to
> paste into a ticket. 22 pytest cases. See [POSTMORTEM.md](POSTMORTEM.md)
> and `POST /api/mv/postmortem/generate`.
>
> 📖 **CLI Reference** *(Day-10)* — BM25 retrieval over the sibling
> `multivendor-cli-configurator` corpus. Paste a CLI snippet, get matching
> documented entries ranked + citation-linked. Pure stdlib BM25 — no
> embedding model, no API calls, <2ms latency at 7.7k entries. 24 pytest
> cases. See [CLI_RAG.md](CLI_RAG.md) and `GET /api/mv/cli-rag/search`.



| # | Panel | What it does |
|---|---|---|
| 8 | **Inventory** | 26-device table · free-text filter across hostname / site / vendor / role / model · sortable columns · `aria-grid` |
| 9 | **Fleet Audit** | Batfish-style fleet config analysis · per-device score · errors / warnings / passed |
| 10 | **Compliance** | Scans configs for BGP MD5 auth · prefix-limits · OSPF fast timers · explicit router-ID · backbone area |
| 11 | **GAIT Audit** | Immutable append-only AI audit trail · clickable target hostnames → Inventory · tokens-in / tokens-out · download today's log |
| 12 | **Shadow Auditor** | Asynchronous second-opinion audit channel running in parallel with the orchestrator |

### 🧠 Diagnose — AI surfaces (6 panels)

| # | Panel | What it does |
|---|---|---|
| 13 | **Agent Chat** | "AI Coordinator" routes natural-language questions to one of 10 specialist agents (diagnosis · remediation · verification · compliance · discovery · forecast · correlation · knowledge · nornir · batfish) |
| 14 | **AI Command (NL → CLI)** | Translates English to vendor CLI · live device-context chip mirrors sidebar selection · gemma3 / claude-haiku fallback |
| 15 | **Orchestrator** | Pydantic-AI router for Routing / ACL / Incident workflows |
| 16 | **AI Insights** | Deep analysis · log intelligence · config drift · security audit |
| 17 | **Doc Search** | Vendor documentation RAG over OSPF / BGP / Junos / EOS manuals — grounded answers |
| 18 | **SuzieQ** | Offline config parsing fleet observability · vendor quick-filter chips (All / Juniper / Arista / FRR) |

### ⌨  Operate — hands-on CLI (5 panels)

| # | Panel | What it does |
|---|---|---|
| 19 | **CLI / Terminal** | Raw SSH execution against the lab · quick BGP / ARP / Interfaces / Routes command chips |
| 20 | **Collect** | Quick Snapshot · Full Investigation · disabled until a device is selected (visible target chip) |
| 21 | **CLI Transport** | Side-by-side benchmark: SSH · NETCONF · gNMI · REST |
| 22 | **NAPALM** | Multi-vendor abstraction · per-site batch collection |
| 23 | **Nornir Engine** | Parallel fleet tasks · ~10× faster than sequential Netmiko · BGP health · version · interface check |

### ✅ Change Control (7 panels — Day-1: Health Gate, Day-5/6: Auto-Remediate)

> 🛡 **Health Gate** — Observe → Decide → Act → Verify orchestrator. RFC 6241 §8.4
> confirmed-commit. Clean window → confirm; any regression in BGP / interfaces /
> alerts → device auto-reverts at NETCONF timeout. 20 pytest cases, simulated +
> real (PyEZ) modes. See [HEALTH_GATE.md](HEALTH_GATE.md) and
> `POST /api/mv/health-gate/apply`.
>
> 🤖 **Auto-Remediate** — Closed loop on top of Health Gate + NetBox SoT.
> Drift → AI proposes runbook → human approves → executes *through* Health
> Gate (so the fix gets its own confirmed-commit watch). Auto-rejects cosmetic
> drift; full GAIT lineage on every proposal. 25 pytest cases.
> See [REMEDIATION.md](REMEDIATION.md) and `POST /api/mv/remediation/propose-for-drift`.

| # | Panel | What it does |
|---|---|---|
| 24 | **Change Approval** | AI proposes a change · human approves · pyATS diffs pre/post |
| 25 | **State Diff** | Pre/post snapshot · BGP + interface deltas · routing-table reconciliation |
| 26 | **Observer-Actor** | Auto-rollback proposals when Chaos Monkey or telemetry detects regressions |
| 27 | **Pre-Deploy Analysis** | What-if config simulation before rollout (Batfish-backed) |
| 28 | **Blast Radius** | Predicted impact of a proposed change · affected devices + sessions |

### 🗺  Topology (3 panels)

| # | Panel | What it does |
|---|---|---|
| 29 | **BGP Topology** | SVG canvas · 26 devices · 5 sites · 36 sessions · live up/down via `/api/telemetry/metrics` · click node → CLI |
| 30 | **OSPF Discover** | Live LLDP/OSPF neighbor walk auto-discovery |
| 31 | **Path Trace** | Hop-by-hop BFS over the inventory graph · multi-vendor edges · inline src=dst validation |

### 🧪 Verify & Test (3 panels)

| # | Panel | What it does |
|---|---|---|
| 32 | **Intent Verify** | Config-claimed BGP sessions vs observed · drift detection · last-run timestamp |
| 33 | **Eval Harness** | 10 incident scenarios (BGP / OSPF / MTU / interface / performance) · dual-scored: keyword match + LLM-as-judge · Run All progress counter |
| 34 | **Chaos Monkey** | Break BGP sessions · Observer-Actor self-heal · stress-tests auto-remediation logic |

---

## Cross-cutting capabilities

### ⌨  Keyboard system

| Chord | Action |
|---|---|
| `?` | Open keyboard shortcut overlay |
| `m` + `o` / `d` / `p` / `u` / `l` | Workflow mode — Observe / Diagnose / Operate / Audit / All |
| `g` + `h` / `s` / `t` / `o` / `a` / `c` / `i` | Navigate — Health / Syslog / Topology / Orchestrator / Alerts / CLI / Inventory |
| `/` | Focus search (context-aware: Inventory filter on Inventory tab, device search elsewhere) |
| `a` | Toggle AI side panel |
| `n` | Toggle NOC Wall mode |
| `t` | Toggle light / dark theme |
| `←` / `→` | (NOC Wall only) cycle Health / Topology / Syslog |
| `Esc` | Close topmost overlay / panel / mode |

### ♿ Accessibility (16 rounds at 0 unlabelled)

- Every `<button>` has `aria-label` or visible text
- All 8 nav sections expose `role="button"` + `aria-expanded` with a chevron affordance
- All 6 inventory column headers expose `role="columnheader"` + keyboard sort
- All 5 mode chips carry visible `m o`-style kbd badges + descriptive aria-label
- All 49 stat cards auto-labelled via MutationObserver (`"Critical: 0"`, `"Raw Alerts: 12"`, etc.)
- Empty stat cards visually distinct via `.is-empty` class (muted grey + smaller font)
- ARIA live regions on mode-restore toast and sidebar mode caption
- Skip-friendly: Enter / Space activate every `div[role="button"]`

### 🖥  NOC Wall mode

- Full-screen view that hides nav + sidebar + tab strip
- 3-tab strip pinned top-left (Health / Topology / Syslog) — operationally critical only
- `←` / `→` keyboard cycles the active tab
- `↻ 30s` auto-rotate button — rotates panels every 30 seconds
- Persists across reloads: `ui.nocWall` · `ui.nocCycle` · `ui.nocLastTab` in localStorage
- Red `✕ Exit NOC Mode` button stays floating top-right

### 🤖 AI Coordinator routing

10 specialist agents the Coordinator can dispatch to:

| Agent | Specialism |
|---|---|
| diagnosis | Root-cause analysis on BGP / OSPF / link issues |
| remediation | Generate + propose fixes |
| verification | Pre/post intent verification |
| compliance | Config policy compliance scan |
| discovery | LLDP / OSPF neighbour discovery |
| forecast | Bandwidth + flap forecasting |
| correlation | Multi-source alert correlation |
| knowledge | Vendor doc RAG |
| nornir | Parallel fleet task execution |
| batfish | What-if config simulation |

### 🔧 Self-healing demo loop (Chaos → Detect → Fix)

1. **Chaos Monkey** breaks a BGP session in the live FRR lab
2. **BGP Topology** turns the affected link red dashed within 15 s
3. **AUTO-REMEDIATION** panel detects the fault via HTTP-proxy scan of all 10 devices
4. **Observer-Actor** proposes a rollback / fix
5. **Approval** required (human gate) before applying
6. **Scan history** logs the cycle: timestamp · device · action · result

### 🏷  Hostname convention

Universal site-prefixed form across all vendors:

```
{site-code}-{vendor-role}-{nn}

de-fra-core-01   uk-lon-core-01   nl-ams-core-01   us-nyc-core-01
de-fra-fw-01     uk-lon-fw-01     nl-ams-fw-01     us-nyc-fw-01
de-fra-mx-01     eu-cdg-mx-01
de-fra-eos-rt-01 uk-lon-ex-01     nl-ams-eos-sw-01 us-nyc-eos-rt-01
```

`window.HOST_ALIAS` map preserves backward compatibility with legacy log entries — old short-form names still resolve correctly.

### 🎛  Workflow modes

| Mode | Filters nav to | Dims in sidebar |
|---|---|---|
| **All** | every section | nothing |
| **Observe** | Overview · Observe · Topology | Juniper / Arista (highlights FRR) |
| **Diagnose** | Overview · Diagnose · Topology · Verify | nothing |
| **Operate** | Overview · Operate · Change Control · Verify | FRR (highlights Juniper / Arista) |
| **Audit** | Overview · Inventory & Audit · Verify | nothing |

Restored mode shows a top-center toast on every load: *"Restored to Operate mode · press `m` `l` to show all"*.

### 📊 Data surfaces

- `/api/devices` · `/api/mv/devices` · `/api/mv/topology` — inventory + topology
- `/api/mv/syslog/recent` · `/api/mv/snmp/traps` — ring-buffered receivers
- `/api/mv/gnmi/query` — OpenConfig telemetry via vtysh
- `/api/mv/eval/scenarios` · `/api/mv/eval/run` — regression harness
- `/api/mv/gait/recent` · `/api/mv/gait/stats` — AI audit trail
- `/api/keep/trend` · `/api/keep/correlate` — noise floor + alert correlation
- `/api/chaos/bgp` — chaos monkey control
- `/api/remediate` · `/api/cli-fleet` — auto-remediation
- `/api/mv/path/trace` — BFS path finder
- `/api/mv/intent/verify` — drift detection
- `/api/mv/junos/netconf` — Juniper PyEZ / NETCONF
- `/api/mv/batfish/fleet` — Batfish-style fleet analysis
- `/api/mv/suzieq/analyze` — SuzieQ-style offline parser

---

## Demo video — what's in it

| Time | Scene |
|---|---|
| 0:00–0:03 | Title card — "34 panels · 185 buttons · 0 unlabelled" |
| 0:03–0:10 | Keyboard tour — `?` overlay · `m o` mode chord · `m l` reset |
| 0:10–0:48 | 34-panel feature tour — 1.1 s/panel · cursor follows tab strip |
| 0:48–0:56 | Highlight reel — NOC Wall (`n` + arrow cycling) · `g i` + filter "SRX" |
| 0:56–1:00 | End frame — repo URL |

---

## Quick-start

```bash
git clone https://github.com/gesh75/multivendor-ai-network-lab
cd multivendor-ai-network-lab

# Start the 10-FRR Docker lab + Flask API
./network-lab/start_lab_tool.sh

# Open the demo
open http://localhost:8080/
```

Built by [Georgi Gaydarov](https://linkedin.com/in/gesh75) · 20+ yrs network engineering · open source.
