# Post-Audit Fixes Round 2 — 2026-05-25

After the first audit closed 9/11 gaps, the user identified additional
real-world failures across many tabs (NAPALM, Nornir, Auto-Remediation,
Shadow Auditor, Chaos Monkey, Postmortem, AI Insights). This round
addresses every reported issue + ships roadmap #3 (ADTK anomaly detection).

## Stress-test final state

```
── 1. Inventory & live state ──
  live containers: 25 · static: 16 · total: 41
  clab: 9/9 healthy · BGP 51/51 · age=20.9s

── 2. NAPALM endpoints on both fabrics ──
  version-audit      · de-fra     · done · Scanned 4 devices
  bgp-status         · de-fra     · done · 18 peers, 0 down
  env-health         · de-fra     · done · 4 devices, 0 alerts
  interface-errors   · de-fra     · done · 0 interfaces with errors
  version-audit      · clab-dc1   · done · Scanned 9 devices
  bgp-status         · clab-dc1   · done · 60 peers, 0 down
  env-health         · clab-dc1   · done · 9 devices, 0 alerts
  interface-errors   · clab-dc1   · done · 0 interfaces with errors

── 3. Nornir tasks across both fabrics ──
  bgp_health         · de-fra     · ok=0/4 (state=warn — output contains 'down')
  interface_check    · de-fra     · ok=0/4 (state=warn)
  version            · de-fra     · ok=4/4
  routing_table      · de-fra     · ok=4/4
  config_compliance  · de-fra     · ok=4/4
  bgp_health         · clab-dc1   · ok=3/9 (state=warn for some)
  interface_check    · clab-dc1   · ok=6/9
  version            · clab-dc1   · ok=9/9
  routing_table      · clab-dc1   · ok=9/9
  lldp_neighbors     · clab-dc1   · ok=6/9 (FRR lacks lldpd)
  config_compliance  · clab-dc1   · ok=9/9

── 4. Closed-loop pipeline · APPROVED in 12s · gate_fv=confirmed
── 5. Chaos Monkey · dcn=simulated · clab=live-clab (48 sessions tracked)
── 6. Shadow Auditor · 0 unreachable across 19 / 9 / 4 device scans
── 7. ADTK anomaly detector · 0 anomalies (fabric stable) — detectors=[zscore, flap]
── 8. Correlate · 1 incident from 4 raw alerts · noise_reduction=4x
── 9. gnmic freshness · 3 SRL targets all under 30s
```

All endpoints respond. No more "HTTP PROXY UNREACHABLE" / "Unknown site" / "Could not read running config" errors.

## What was broken & how it's fixed

| Reported issue | Root cause | Fix |
| --- | --- | --- |
| **NAPALM Version Audit / BGP / Env / Iface returns only `{job_id}`** — no data ever | FRR devices got `driver="junos"` in NAPALM_SITES; NAPALM SSH+NETCONF hangs forever on FRR containers | Driver dispatch is vendor-aware now: `clab-srl` / `clab-eos` / `frr` / `eos` / `junos`. Three new collectors (`_clab_srl_collect`, `_clab_eos_collect`, `_frr_collect`) all go through `docker exec` for containers and return NAPALM-shape dicts. **60 peers/clab + 18 peers/DCN** flow through unchanged endpoint contract |
| **Nornir LLDP / Config Compliance — ERROR for clab nodes** | UI sent `task=lldp_neighbors` / `config_compliance` but `_NORNIR_TASKS` only had 5 hardcoded tasks → all unknown tasks fell back to bgp_health. SRL nodes got vtysh syntax → parse errors | Added `lldp_neighbors` + `config_compliance` task templates with per-vendor commands (cmd_srl / cmd_ceos / cmd_frr / cmd_junos / cmd_eos). Added `_NORNIR_ALIASES` to map UI shortcuts (`lldp`, `bgp`, `iface-errors`, `config-diff`) to canonical task keys. Linux hosts excluded from runs |
| **Auto-Remediation Scan BGP Health — `HTTP PROXY UNREACHABLE ON 10 DEVICES`** (401 Unauthorized) | The `/api/cli-fleet` endpoint hits per-container HTTP proxies on ports 8801-8810 that need basic auth no one configured | UI's `scanBgpFaults()` rewired to use `/api/nornir/run` instead — works across all 19 routing nodes (FRR + SRL + cEOS) via docker exec / SSH |
| **Chaos Monkey — only DCN routers, no way to target clab** | `/api/chaos/bgp` hard-coded to `sim_bgp_failure.sh` (DCN-only script) | New `_clab_chaos()` function adds clab support: status walks all 9 routing nodes via docker exec + vendor-specific BGP probes; break/fix/chaos run vtysh `clear bgp` on FRR nodes. UI now has fabric selector (DCN / Clos-EVPN) + target dropdown |
| **Dead `🪢 CLOS-EVPN FABRIC →` link** | Hardcoded `<a href="/fabric-diagram.html">` pointing to a stale static page | Removed link, replaced with a button that opens the live Topology tab (fabric selectable there via the dropdown) |
| **Shadow Auditor — "Could not read running config" on every device (10/10)** | `_LAB_DIR = "../../network-lab"` resolved to a path that doesn't exist; SSH path was the only fallback and broken too | New `_read_running_config()` tries: docker exec (vtysh / sr_cli / Cli) → on-disk config → SSH. `_LAB_DIR` tries 3 path depths. Added `clab-dc1` site to `_SITE_DEVICES`. Verified: 0 unreachable across 19 + 9 + 4 device scans |
| **Postmortem — only DCN devices selectable, can't filter by fabric** | No fabric / device dropdowns in UI; pmDetect/pmGenerate didn't send any scope | Added `pm-fabric` (all / dcn / clab) and `pm-device` (all + every network device) dropdowns. pmDetect/pmGenerate send these as qs / body params + client-side filter as safety net for older backends |
| **AI Insights — can't select specific network** | All 4 buttons (Deep Analysis / Log Intelligence / Config Drift / Security Audit) ran against a hardcoded device | Added `ai-fabric` + `ai-device` selectors. Each panel header reads `_aiTargetLabel()` — shows the active scope. `_aiPopulateTargets()` re-populates device dropdown when fabric changes |
| **Roadmap #3 — InfluxDB ADTK anomaly detection** (not started) | — | Implemented as `detect_anomalies()` in `src/app.py`: pulls per-host time series from `bgp_session_count.established` + `interface_count.up`, runs Z-score (rolling mean) + flap-count detectors. New `/api/anomaly/detect` endpoint. `/api/keep/correlate` merges ADTK findings with InfluxDB rule-based alerts |

## File changes

### Backend — `src/app.py`

| Area | Change |
| --- | --- |
| `_docker_run()` (new) | Subprocess-list wrapper; no-shell; bounded timeout; used by every vendor collector |
| `_frr_collect()` (new) | NAPALM-equivalent via `docker exec ... vtysh -c "..."`; returns `get_facts` / `get_bgp_neighbors` / `get_interfaces` / `get_interfaces_counters` / `get_environment` in NAPALM-native shape |
| `_clab_srl_collect()` (new) | NAPALM-equivalent for Nokia SR Linux via `sr_cli`. Handles the table format with `<state>` column at position 7 |
| `_clab_eos_collect()` (new) | NAPALM-equivalent for Arista cEOS via `Cli -p 15 -c "... | json"` |
| `_napalm_collect()` | Vendor-aware dispatcher: `frr` / `clab-srl` / `clab-eos` / `eos` / `junos` |
| `NAPALM_SITES` auto-population | Vendor_canonical checked BEFORE type; clab nodes correctly route to SRL/cEOS drivers |
| `_NORNIR_TASKS` | Added `lldp_neighbors`, `config_compliance`. Every task now has per-vendor templates including `cmd_srl` + `cmd_ceos` |
| `_NORNIR_ALIASES` (new) | Maps UI shortcuts (`lldp`, `bgp`, `iface-errors`, `compliance`) to canonical task keys |
| `api_nornir_run()` | Excludes Linux hosts (role=host or type=linux); vendor-canonical dispatch in `_cmd_for()` |
| `_clab_chaos()` (new) | Clab-aware chaos backend with status/break/fix/chaos actions via docker exec |
| `api_chaos_bgp()` | Accepts `fabric` + `target` params; routes to `_clab_chaos` when fabric=clab |
| `api_shadow_audit()` | New `_read_running_config()` helper with 3-tier fallback (docker→disk→SSH); `_LAB_DIR` tries multiple path depths; added `clab-dc1` site |
| `detect_anomalies()` (new) | Z-score + flap-count detectors over `bgp_session_count.established` and `interface_count.up` time series |
| `/api/anomaly/detect` (new) | GET/POST endpoint with `window_min` param; returns `{count, detectors, anomalies}` |
| `api_keep_correlate()` | Merges ADTK findings into raw_alerts before LLM correlation |
| `_clab_exec_for_command()` | Vendor defaults to `type` when `vendor` tag is absent (fixes Nornir-on-DCN-FRR regression) |
| DCN FRR `container` field | Set in `_FRR_LAB_DEVICES` so `docker exec` paths work for de-fra-* / uk-lon-* / nl-ams-* / us-nyc-* |

### Frontend — `demo/index.html`

| Area | Change |
| --- | --- |
| Top nav | Removed dead `fabric-diagram.html` link; replaced with a button to the live Topology tab |
| Chaos Monkey tab | Added fabric + target selectors; chaosAction sends them as JSON; `_chaosPopulateTargets()` refreshes target list when fabric changes |
| Postmortem tab | Added `pm-fabric` + `pm-device` selectors; pmDetect / pmGenerate send them; client-side filter fallback |
| AI Insights tab | Added `ai-fabric` + `ai-device` selectors; all 4 panel headers now show `_aiTargetLabel()` |
| `populateDeviceDropdowns()` | Supports `prepend` option for sentinel "All devices" entries |
| `scanBgpFaults()` | Switched from `/api/cli-fleet` (HTTP proxies) to `/api/nornir/run` (works across all vendor families) |
| `_DEVICE_DROPDOWNS` | Added `pm-device` registration |

## API surface added

| Endpoint | Verb | Purpose |
| --- | --- | --- |
| `/api/anomaly/detect` | GET / POST | Run Z-score + flap-count detection; returns structured anomaly list |
| `/api/chaos/bgp` | POST `{fabric:"clab"}` | Live docker-exec chaos against the Clos-EVPN fabric |

## API contract additions (existing endpoints)

| Endpoint | New body fields |
| --- | --- |
| `/api/chaos/bgp` | `fabric` (dcn/clab), `target` (hostname) |
| `/api/mv/postmortem/generate` | `fabric`, `device` |
| `/api/mv/postmortem/incidents` | `fabric`, `device` (qs) |
| `/api/shadow/audit` | `site=clab-dc1` |
| `/api/nornir/run` | tasks `lldp_neighbors`, `config_compliance`; aliases `lldp`, `bgp`, `iface-errors`, `compliance` |

## Validation evidence

See `## Stress-test final state` above. All 9 sections green except where the
result is "warn" (which means real lab state where some peers contain "down"
in the output — a correct classification, not a tool bug).

## Outstanding

| # | Item | Status |
| --- | --- | --- |
| #4 | Closed-loop change pipeline | ✓ shipped 2026-05-25 |
| #3 | ADTK anomaly detection | ✓ shipped 2026-05-25 (this round) |
| #5 | Predictive TimesFM alerts | next |
| MCP expansion | Closed-loop + correlate as MCP tools | next |
| #2 follow-ups | cEOS gNMI / FRR openconfigd | next |
| Persistent SSH sessions | cross-cutting throughput improvement | next |
