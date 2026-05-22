# How does this tool compare?

Most "network config management" tools fall into one of two camps:

- **Config backup + diff** — RANCID, Oxidized, SolarWinds NCM. Great at archiving,
  zero understanding of what the config actually does.
- **Formal verification at enterprise scale** — Forward Networks, Veriflow. Powerful,
  but priced for Fortune 500 procurement cycles.

A new generation of **SaaS config analyzers** (NetSpectraAI, others) bolt an LLM on
top of the first camp and sell it per-seat.

This tool is in a different category: a **live closed-loop NetOps platform** with
agent orchestration, confirmed-commit safety, and auto-postmortems. Static config
review is one feature out of many — not the whole product.

## Side-by-side

| Capability | RANCID | Oxidized | SolarWinds NCM | Forward Networks | NetSpectraAI | **multivendor-ai-network-lab** |
|---|---|---|---|---|---|---|
| **Operating mode** | Backup + diff | Backup + diff | Backup + diff + change mgmt | Formal verification on snapshots | Static analysis on uploaded configs | **Live closed loop** (observe → diagnose → remediate → verify) |
| **Pricing** | Free (CVS-era) | Free (open source) | Enterprise license | 6-figure contracts | $0–$1,499/mo SaaS | **Free, MIT, self-hosted** |
| **Deployment** | On-prem | On-prem | On-prem appliance | Cloud or on-prem | SaaS only | **Single laptop, no cloud** |
| **Multi-vendor** | Cisco, Juniper, others (CLI scrape) | 100+ models | 60+ models | Cisco/Juniper/Arista/Cumulus/+ | Cisco/Juniper/Arista | Juniper SRX/MX/EX/QFX, Arista 7280/7050, FRR |
| **Config archiving** | ✅ | ✅ | ✅ | ✅ | ✅ NetVault | NetBox + git (delegated) |
| **Config diff** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ via pyATS state diff + GAIT audit |
| **AI / NL config review** | ❌ | ❌ | ⚠️ rule-based | ⚠️ logic-engine, not LLM | ✅ LLM-powered | ✅ Batfish + AI Coordinator + 10 specialist agents |
| **Topology discovery** | ❌ | ❌ | ✅ via SNMP/CDP | ✅ from configs | ✅ CDP/LLDP | ✅ Live BGP/OSPF + LLDP, 26-device topology |
| **Compliance (SOC2/PCI/HIPAA)** | ❌ | ❌ | ⚠️ basic | ✅ enterprise | ✅ NetAudit | ⚠️ Audit-evidence workflow exists, not productized |
| **Source-of-truth drift detection** | ❌ | ❌ | ❌ | ✅ verification | ⚠️ rule-based | ✅ **NetBox SoT drift detector** with severity tiers (CRITICAL/HIGH/LOW), None-suppression |
| **Auto-remediation** | ❌ | ❌ | ⚠️ scripted | ❌ (analysis only) | ⚠️ "NetFix — Coming Soon" | ✅ **Shipped** — proposal state machine pending→approved→executing→done |
| **Confirmed-commit safety (RFC 6241 §8.4)** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ **Health Gate** — watches BGP peers + interfaces + alerts, auto-reverts on regression |
| **Auto-postmortem generator** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ Heuristic root-cause priority + structured Markdown in ~0.2s |
| **CLI reference search** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 9,802 commands, BM25, sub-ms at 10k entries |
| **NL chat / agent interface** | ❌ | ❌ | ❌ | ⚠️ search UI | ⚠️ "AI recommendations" wrapper | ✅ AI Coordinator routes to 10 specialist agents |
| **MCP / Claude Code integration** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 49 MCP tools, 12 for the closed loop |
| **Eval harness (LLM regression testing)** | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ 10 incident scenarios, dual-scored (keyword + LLM-judge) |
| **Open source** | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ MIT |

## Why each camp falls short

### RANCID / Oxidized

You can SSH into a box and run `git diff` on the config. That's it. No
understanding of *what* changed, no risk score, no remediation suggestion.
If your team is running `for d in $(cat devices.txt); do ssh $d "show
configuration | display set"; done`, you've already outgrown RANCID and just
don't want to admit it.

### SolarWinds NCM

Enterprise price tag for what is fundamentally a more polished version of
RANCID. The "AI" features are rule-based pattern matching dressed up in
marketing copy. Strong at compliance reporting if you have an audit deadline
and a budget; weak at actually preventing bad changes.

### Forward Networks

Genuinely impressive technology — they ingest configs and build a formal
mathematical model of the network. If you can afford it (six-figure deals,
multi-month POC), it's the right tool for very large networks where every
hop matters. For everyone else: the cost of a Forward Networks contract is
larger than the team's entire automation budget.

### NetSpectraAI

A SaaS-funnel build of "RANCID + GPT": upload your config, get an AI review.
Useful for IT shops with 50–500 devices that don't have an automation team.
Doesn't see live network state, doesn't propose remediation, doesn't
auto-revert bad changes, doesn't integrate with agent runtimes. Pricing
$0–$1,499/mo lets it undercut SolarWinds, but you're still shipping
configs to a cloud — a non-starter for regulated environments.

## Where this tool fits

Built for **mid-sized multi-vendor networks (50–500 devices)** run by an
engineer who wants the **closed loop**:

1. **Watch** live state — BGP peers, interfaces, alerts, syslog, gNMI telemetry.
2. **Detect** drift — NetBox SoT vs. observed live config, with severity tiers.
3. **Diagnose** with AI — natural-language → 10 specialist agents → structured proposal.
4. **Apply safely** — Health Gate watches the device through a confirmed-commit window; bad changes auto-revert.
5. **Document** what happened — auto-postmortem in ~0.2s, structured Markdown.

A companion tool, [netlog-ai](https://github.com/gesh75/netlog-ai) (same
author, same MIT license), handles sanitized log + config analysis as a
separate sidecar — useful on its own without the lab tool running.

## When NOT to use this tool

- You only need config backup. RANCID or Oxidized is simpler.
- You have a Fortune 500 budget and need formal verification on a 10k-node fabric. Buy Forward Networks.
- Your compliance team requires a vendor-supported SaaS with an SLA. Use NetSpectraAI or SolarWinds.
- Your devices are exclusively Cisco IOS. This tool's parsers are tuned for Juniper / Arista / FRR.

For the middle 80% — a multi-vendor lab or production network where the team
wants real-time visibility, AI-assisted remediation, and safety nets that
auto-revert when something breaks — this tool was built exactly for that.
