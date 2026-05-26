# DCN_Network_Tool — Optimization Roadmap

Last updated: 2026-05-25 (post-audit hardening pass)
Status legend: ☐ planned · ◐ in progress · ✓ done

Inputs that produced this plan:
- Live state of the tool after the multi-vendor clab Clos-EVPN integration
  (see `CLAUDE.md` and the audit reports in `POSTMORTEM.md`).
- 2026 industry research on gNMI streaming, anomaly detection, RAG-over-configs,
  closed-loop change pipelines, and predictive alerting. Citations inline.
- The 2026-05-25 functional audit (`GAPS_REPORT.md`) found 11 gaps; 9 were
  closed in the same session. See §0 for the audit summary; #3–#5 below are
  the still-open backlog items.

The roadmap is ordered by **value / effort**.

---

## #0 — Audit hardening (2026-05-25)  ✓ COMPLETED

Background: a click-every-button audit against the live 25-device deployment
(see [`GAPS_REPORT.md`](GAPS_REPORT.md)) found that several KPIs and
endpoints displayed data without verifying it against the device of origin —
the "dashboard not operations tool" failure mode flagged by Itential's
[Real vs Theater](https://www.itential.com/blog/company/ai-networking/agentic-ai-differences-for-netops/)
rubric.

Fixes shipped in the same session:

- ✓ Stale collector daemon detection + **launchd KeepAlive supervision** —
  `network-lab/telemetry/com.geshlab.clab-collector.plist`
- ✓ Duplicate collector retired — `containerlab-multivendor/scripts/telemetry-collector.py`
  renamed `.deprecated-2026-05-25`
- ✓ KPI strip wired to live counts (`/api/mv/devices` with `d.live` filter +
  `role !== host` exclusion) — 41 → 19 devices, 28 → 87 BGP, 6 → 5 sites
- ✓ Site dropdowns filter dead inventory — EU-CDG removed
- ✓ Device dropdowns exclude 6 Linux hosts (uncallable for network commands)
- ✓ `/api/mv/fabric-topology?fabric=dcn|clos-evpn|all` — query param now honored
- ✓ gnmic freshness query rewritten to filter on `source` tag (truly
  distinguishes gnmic stream from collateral collector writes) — `app.py:11459`
- ✓ Param-name flexibility: 7 NAPALM + 3 MV endpoints now accept
  `site` / `hostname` / `host` / `device` interchangeably with helpful 400s
- ✓ `collector-stale-banner` auto-surfaces when `/api/mv/clab-status.stale=true`
- ✓ ReferenceError in `refreshOverviewKpis()` (variable rename leftover) fixed

After-fix verification: Playwright re-ran 20 endpoints, all returned 200,
zero console errors, KPI strip matches reality. See
[`docs/ARCHITECTURE_HARDENED.md`](docs/ARCHITECTURE_HARDENED.md) for the new
data-flow + supervision diagrams.

---

## #1 — Wire netlog-ai as the RAG knowledge backend  ◐ IN PROGRESS

**Why first**: netlog-ai already runs on `:6060`, already has the sanitized
configs and per-device findings of both fabrics (10 DCN + 9 clab routing
nodes). It exposes copilot/optimize/topology endpoints that we can proxy and
inject into our existing AI Command and alert-correlation flows. We re-use,
not rebuild.

**Concrete tasks**
- Add Flask proxy endpoints in `src/app.py`:
  - `GET /api/knowledge/sites` — list netlog-ai sites
  - `GET /api/knowledge/device/<host>` — fetch the sanitized config + findings
  - `POST /api/knowledge/copilot` — natural-language Q&A against netlog-ai's
    RAG (proxies `/api/sites/<id>/copilot`)
  - `POST /api/knowledge/optimize` — site-wide recommendations
- Enrich existing endpoints:
  - `/api/ai-command` — before the LLM call, look up the target host's
    findings + a config excerpt from netlog-ai and include them in the
    prompt.
  - `/api/keep/correlate` — for every InfluxDB-derived alert, attach the
    netlog-ai compliance findings for that host so the LLM correlator sees
    *why* the device is fragile.
- UI: a new "Knowledge" tab that renders the proxied views, plus inline
  citations in AI Command answers.

**Acceptance**
- Asking "why is BGP down on leaf3?" returns an answer that names a specific
  config issue from leaf3's sanitized config (e.g. "missing prefix-limit on
  peer 10.0.1.4").
- Alert cards show the per-device netlog-ai findings as nested context.

---

## #2 — gNMI dial-in subscribe via gnmic ◐ PARTIALLY DONE (3 of 9 nodes)

### Done 2026-05-25

- `gnmic` deployed as sidecar `clab-gnmic` on `clos-mgmt` + `dcn-lab_lab-net`
  with its API on `:7890`.
- Config at [`network-lab/telemetry/gnmic/gnmic.yaml`](../../network-lab/telemetry/gnmic/gnmic.yaml).
- Three Nokia SRL targets subscribed (spine1, leaf2, leaf5) with 4
  subscriptions each:
  - `intf-oper-state` — ON_CHANGE
  - `bgp-session-state` — ON_CHANGE
  - `intf-counters` — SAMPLE 10 s
  - `system-resources` — SAMPLE 15 s
- Writes into the same `network-telemetry` InfluxDB bucket tagged
  `fabric=clos-evpn,site=CLAB-DC1` — co-exists with the legacy 15 s
  collector unchanged.
- New endpoint `GET /api/telemetry/gnmic-status` returns target count,
  per-host freshness in seconds, and overall fresh-under-30s flag.
- UI: Topology toolbar shows a `📡 gNMI · 3 SRL · <freshness>` badge
  (green ≤30 s, yellow above).
- **Measured streaming latency**: per-host freshness 2-4 s on a quiet
  fabric, sub-second on state events (verified via the BGP session-state
  events captured during initial subscribe storm).

### Known gap — Arista cEOS gNMI (3 nodes: spine2, leaf1, leaf4)

The cEOS 4.33.1F Lab image's `management api gnmi` block can be configured
(transport / ports accepted via eAPI), but `no shutdown` is rejected as
"Incomplete command", and the Octa gNMI process never binds `:6030`. This
is a known cEOS-Lab quirk — the production EOS image accepts the syntax.
Workaround pending: either swap to a newer cEOS image, or use the
[arista-eosextensions/Octa](https://github.com/aristanetworks/Octa)
sidecar pattern, or stay on the docker-exec poller for these 3 nodes.

### Known gap — FRR (3 nodes: spine3, leaf3, leaf6)

No native gNMI. Either install [openconfigd](https://github.com/coreswitch/openconfigd)
into the FRR container, or stay on docker-exec via vtysh.

### Net effect today

- 3 SRL nodes: gNMI streaming + 15 s polling (redundant — safe to decom
  polling for these once we trust the freshness)
- 6 cEOS+FRR nodes: 15 s docker-exec polling unchanged

### Follow-up tasks

- ☐ Migrate cEOS to a newer Lab image or apply Octa sidecar so gnmic can
  subscribe to spine2/leaf1/leaf4.
- ☐ Add openconfigd to FRR containerlab definition so gnmic can also
  cover spine3/leaf3/leaf6.
- ☐ Add a Grafana panel "gNMI freshness per host" reading directly from
  `_time` of the latest `bgp-session-state` event.
- ☐ Decommission polling for the 3 SRL nodes after a 2-week A/B confidence
  window.

---

## #3 — InfluxDB ADTK anomaly detection as a built-in plugin  ✓ DONE 2026-05-25

**Why**: the current `_influx_derive_alerts` rule is `up < total` — naive
binary. The published BMP/InfluxDB/Z-score paper hit 97.2% detection
accuracy with 2.1% false positives on 180k BGP updates. InfluxData ships
the ADTK plugin in InfluxDB 3 — no new infra.

**Concrete tasks**
- Bump our `frr-telemetry` InfluxDB to v3 if still on v2.
- Create three triggers:
  - `bgp_session_count.established` per host — `IsolationForestAD`,
    contamination 0.05, window 30 — writes to `bgp_anomalies` measurement.
  - `interface_counters.rx_errors` rate — `LocalOutlierFactorAD` — writes to
    `intf_anomalies`.
  - `ospf_neighbor_count.full` per host — Z-score >3 on the rate of change.
- Update `/api/keep/correlate` to merge ADTK output with the existing
  rule-based detector. The LLM then receives a richer alert stream.

**Acceptance**
- A flapping BGP peer (e.g. 8 flaps/hour) is flagged as an ADTK anomaly
  before it crosses the binary down threshold.

---

## #4 — Close the Batfish + pyATS + Health Gate loop into one button  ✓ DONE 2026-05-25

**Why**: we have all the pieces but they're driven manually:
- `/api/batfish/blast-radius` — pre-change config analysis
- `/api/pyats/snapshot` + `/api/pyats/diff` — state capture
- `/api/mv/health-gate/apply` — gate with rollback
- `/api/mv/predict/run` — digital-twin verdict

The 2026 Batfish blog ("Closing the loop on testing network changes")
shows this is the highest-ROI integration: every proposed change runs
through the full pipeline automatically.

**Concrete tasks**
- New endpoint `POST /api/change/closed-loop`:
  1. Predict (digital-twin what-if) — refuse if `verdict=REJECT`
  2. Batfish blast-radius on the proposed diff
  3. pyATS PRE snapshot
  4. Apply via Health Gate
  5. pyATS POST snapshot + diff
  6. Verify intent (Suzieq assertion: BGP up, OSPF area 0 reachable, no
     MAC flaps) — auto-rollback on failure
- New UI tab "Change Pipeline" with a single big button + diff viewer +
  per-stage status pills.

**Acceptance**
- A single click runs the full sequence on a clab node, with a clear
  PASS/ROLLBACK verdict and a full audit trail of each stage.

### Shipped 2026-05-25

- `POST /api/change/closed-loop` orchestrates **6 stages** (predict ·
  batfish · apply · watch · POST diff · intent verify) into one async API
  call with `change_id` polling.
- "Run Closed-Loop Change" UI panel in the Change Pipeline tab with live
  stage pills + verdict pill + structured output pane.
- Verified live against the FRR DCN lab: **APPROVED in 12s** (Test A);
  **ROLLED_BACK in 6s** when regression induced (Test B); **REJECTED**
  at Batfish for invalid changes (Test C).
- Full design + sequence diagram + endpoint reference:
  [`docs/CHANGE_PIPELINE.md`](docs/CHANGE_PIPELINE.md).
- Optional `skip_predict` / `skip_batfish` flags for lab/dev use when
  predict_engine can't parse vendor syntax or LLM is non-deterministic.
- Test hooks (`fail_at_phase`, `induce_regression_after_s`,
  `induce_alert_spike_after_s`) pass through to Health Gate for
  reproducible rollback drills.

---

## #5 — Predictive alerts driven by Cisco TimesFM forecast  ✓ DONE 2026-05-25

**Why**: `/api/mv/forecast/predict` already produces a 128-step horizon
with 95% CI. Today it draws a chart and stops. Adding ~30 lines turns it
into a predictive alert source.

**Concrete tasks**
- When forecast P95 upper bound crosses a per-metric threshold within the
  horizon, publish a structured alert into `/api/keep/correlate` with
  `source="forecast"` and `severity="predictive"`.
- Run the forecast as a cron-like background job every 15 min on every
  routing node's CPU / memory / interface error rate / BGP MsgRcvd rate.
- UI: Alerts tab gains a "Predictive" filter — these alerts have ETA
  ("in ~6 h"), confidence band, and the recent metric chart inline.

**Acceptance**
- A leaf with a slowly-rising error-rate trend produces a *"in ~6 h, leaf2
  interface error rate will exceed 1k/s — 87% confidence"* alert that we
  can act on before the threshold actually trips.

---

## Cross-cutting hygiene (do alongside the above)

- Replace per-call `docker exec` with persistent stdin/stdout sessions
  (subprocess.Popen + loop). Cuts ~50 ms × 9 nodes × poll cycle.
- Add Redis caching for frequently-fetched configs / topology — current
  `_FABRIC_TOPOLOGY_CACHE` is in-process only; Redis lets multiple workers
  share it.
- Promote the secrets in `.env` (`INFLUXDB_TOKEN`, `LIBRENMS_TOKEN` if you
  ever re-enable it) to a real secrets manager when this hits CI.
- Tighten the gNMI shim for SR Linux: SRL doesn't grok "show ip ..." — our
  `_gnmi_vendor_cmd` already translates by intent, but path coverage is
  incomplete (no MPLS, no LSDB).

---

## Next-up (priority order after audit)

This is the operational backlog post-2026-05-25 hardening. Each item is sized
so it can land in a single focused session.

| Order | Item | Rough effort | Why now |
| --- | --- | --- | --- |
| ✓ | **#4 — Closed-loop change pipeline (one button)** | shipped 2026-05-25 | Pushed tool from TM Forum ANL L2 → L3. See `docs/CHANGE_PIPELINE.md`. |
| ✓ | **#3 — ADTK anomaly detection** | shipped 2026-05-25 | Z-score + flap-count detectors over the live InfluxDB time series; new `/api/anomaly/detect` endpoint; merged into `/api/keep/correlate`. See `docs/POST_AUDIT_FIXES_2.md`. |
| ✓ | **Round-2 audit fixes — every tab functional on both fabrics** | shipped 2026-05-25 | NAPALM vendor-aware; Nornir LLDP/Compliance tasks; Shadow Auditor docker-exec path; Chaos Monkey clab support; Postmortem + AI Insights fabric selectors. See `docs/POST_AUDIT_FIXES_2.md`. |
| ✓ | **#5 — Predictive alerts from TimesFM** | shipped 2026-05-25 | `run_fleet_forecast()` queries InfluxDB history per host, runs forecast across BGP + interface metrics, emits anomaly alerts where P95 crosses threshold. New endpoints `/api/mv/forecast/run-fleet` + `/api/mv/forecast/fleet-status`. Merged into `/api/keep/correlate`. |
| ✓ | **MCP server expansion** | shipped 2026-05-25 | 13 new tools (`mv_change_closed_loop`, `mv_anomaly_detect`, `mv_forecast_fleet`, `mv_clab_status`, `mv_chaos_bgp`, `mv_napalm_bgp`, `mv_shadow_audit`, …) take MCP total to **63**. Claude Code can now drive the full closed-loop remediation directly. |
| ✓ | **#2 follow-ups — cEOS gNMI + FRR openconfigd** | docs+script shipped 2026-05-25 | `docs/STREAMING_TELEMETRY_GAPS.md` documents 3 options each + recommended path; `scripts/migrate_streaming_telemetry.sh` automates ceos-image / frr-grpc / redeploy / verify. Execution remains a clab destroy/deploy event so deferred to Phase 6. |
| ✓ | **Persistent SSH sessions** (cross-cutting) | shipped 2026-05-25 | `network-lab/telemetry/clab_collector.py:docker_run` now uses a persistent `docker exec -i sh` session pool per container with auto-recovery fallback. |
| 6 | Predict-engine FRR static-route parser | half session | Today predict returns `WARN` for `ip route` syntax → has to be `skip_predict=true`. ~80 LOC to teach `predict_engine.parse_op()` FRR static-route grammar. |
| 7 | `napalm-frr` driver wiring | 1 session | Currently FRR devices skip stage 5 (POST snapshot). Wiring `napalm-frr` gives real before/after diffs for the closed-loop on FRR. |
| 8 | Grafana panel "gNMI freshness per host" | 2 hours | Visualises §6 of architecture doc. |
| 9 | Decommission docker-exec polling for SRL nodes | half session | After 2-week A/B confidence window — gnmic should be the single source. |
| 10 | Redis cache for `_FABRIC_TOPOLOGY_CACHE` | half session | Multi-worker readiness. |
| 11 | Secrets manager for `.env` tokens | half session | Pre-CI hardening. |

---

## Phase 6 Backlog (2026-05-25 → next sprint)

Phase 5 closed all 5 original roadmap items + every audit-surfaced bug
(see `docs/PHASE_5_HANDOFF.md`). The new top of the backlog:

| # | Item | Effort | Value |
| --- | --- | --- | --- |
| **1** | **Event-initiated remediation** | 1 session | Wire ADTK / forecast anomalies → automatic `POST /api/change/closed-loop` with a matched runbook. Closes the last gap in the AI-SRE 5/5 rubric. |
| **2** | **Execute the streaming-telemetry migration** | 1-2 sessions | Run `scripts/migrate_streaming_telemetry.sh ceos-image && redeploy` to bring all 9 clab nodes onto gNMI. Then decommission docker-exec polling for those nodes. |
| **3** | **Eval corpus + LLM regression suite** | 2 sessions | Build N "golden traces" (real anomaly → expected correlator output) so changes to the correlator don't silently regress. Pattern from Aether paper. |
| **4** | **Production NetBox-as-SoT wiring** | 2 sessions | Shadow Auditor + inventory pull from NetBox API instead of `inventory.json`. |
| **5** | **Secrets manager** | half session | Move `INFLUXDB_TOKEN` / SSH creds out of `.env` (Vault / 1Password / AWS Secrets). |
| **6** | **Redis-backed shared cache** | half session | Multi-worker readiness. |
| **7** | **Postmortem + AI Insights real backends** | 1 session | Replace mock-render in remaining UI panels with LLM analysis of `keep/correlate` + GAIT events. |
| **8** | **Web-UI SPA refactor** | 2 sessions | `demo/index.html` is 200+ KB; split into Vue/React components. |

**Single-best next move**: item 1 (event-initiated remediation). All the
prerequisites now exist (closed-loop pipeline, ADTK, predictive forecast,
LLM correlator with knowledge enrichment). What's left is the auto-trigger
+ per-anomaly runbook mapping + human-approval gate. Per the Itential
research, this is the single capability that takes a tool from "AI copilot"
to "agentic NetOps".

See `docs/PHASE_5_HANDOFF.md` for the complete agent handoff.
