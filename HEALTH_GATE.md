# Health Gate — Observe → Decide → Act → Verify

Day-1 orchestrator that puts a real audit gate in front of every config change.
Inspired by RFC 6241 §8.4 `<commit confirmed/>` and NetClaw's intent layer.

## Why it exists

Static configuration replays (Nornir, Ansible, even Salt) all assume the device
state after `commit` matches intent. In production, that's a coin flip:
a clean syntax check tells you nothing about whether BGP peers stayed up,
whether the data plane kept forwarding, or whether alert volume spiked.

The Health Gate captures a baseline, applies with a confirmed-commit timeout,
watches health signals inside the window, and either **confirms** the change
or lets the device **auto-revert** at the NETCONF timeout.

## Lifecycle

```
idle ──▶ snapshot_pre ──▶ applying ──▶ watching ──▶ deciding ──▶ done
                                          │              │
                                          │              ├──▶ confirmed (clean)
                                          ▼              │
                                     regression       └──▶ abandoned (rollback)
```

Each phase is recorded in the GAIT audit trail as a separate JSONL entry,
so post-incident review can reconstruct the full timeline.

## What it watches

| Signal | Source (simulated) | Source (real) | Default tolerance |
|--------|---------------------|---------------|-------------------|
| `bgp_peers_up` | Lab profile | PyEZ `show bgp summary` parsed via xml | 0 lost |
| `interfaces_up` | Lab profile | PyEZ `show interfaces terse` filtered to `up/up` | 0 lost |
| `alerts_count` | Lab profile | LibreNMS / Keep correlator | 0 added |

Tolerances are passed per-request — `{"bgp_peers_lost": 1}` accepts a
known-flapping peer without aborting the change.

## Modes

`_detect_mode(hostname)` chooses one of two paths:

- **real** — hostname matches Juniper FW/router pattern (`*-fw-*`, `*-rt-*`)
  AND PyEZ (`junos-eznc`) is importable AND `HEALTH_GATE_FORCE_SIMULATE`
  is unset. Uses `<edit-config>` + `<commit confirmed timeout="N"/>`.
- **simulated** — everything else (FRR lab containers, Arista, missing libs).
  Generates deterministic snapshots from a built-in lab profile.

Forcing the simulated path for tests:

```bash
export HEALTH_GATE_FORCE_SIMULATE=1
```

## API

### `POST /api/mv/health-gate/apply`

```json
{
  "hostname": "de-fra-core-01",
  "edit_payload": "<configuration>...</configuration>",
  "timeout_s": 30,
  "tolerance": { "bgp_peers_lost": 0, "interfaces_lost": 0, "alerts_added": 0 }
}
```

Returns:

```json
{
  "job_id": "hg-7fc774b6507a",
  "hostname": "de-fra-core-01",
  "mode": "simulated",
  "phase": "snapshot_pre",
  "timeout_s": 30
}
```

Demo-only fields (whitelisted in the endpoint, forwarded to `_run_job`):
`induce_regression_after_s`, `induce_alert_spike_after_s`, `fail_at_phase`.

### `GET /api/mv/health-gate/status/<job_id>`

Returns the full job snapshot — phase, progress_pct, pre_snapshot, last_snapshot,
watch_samples[], regressions[], final_verdict, error, started_at, finished_at.

### `GET /api/mv/health-gate/recent?limit=20`

Newest-first list of recent jobs.

## Python contract

```python
import health_gate as hg

job = hg.submit(
    hostname="de-fra-core-01",
    edit_payload="<configuration>...</configuration>",
    timeout_s=30,
    tolerance={"bgp_peers_lost": 0},
    block=False,
)
print(job.job_id, job.mode, job.phase)
```

`block=True` runs synchronously (test-only). Otherwise the worker runs in a
daemon thread; poll `hg.get_job(job_id)` until `phase == "done"`.

## UI panel

Tab: `Health Gate` (visible in `operate` and `audit` workflow modes).

- **Device picker** — 6 FRR lab cores/edges
- **Timeout selector** — 10 / 30 / 60 / 120s
- **Scenario selector** —
  - `Clean window (confirms)` → no test hook, snapshot stable → verdict `confirmed`
  - `BGP peer drop (abandons)` → `induce_regression_after_s=1` → verdict `abandoned`
  - `Alert spike (abandons)` → `induce_alert_spike_after_s=1` → verdict `abandoned`
- **4 phase tiles** — pre-snapshot / commit-confirmed / watching / verdict
- **Progress bar** — tracks `progress_pct` from the job
- **Scroll area** — GAIT audit trail, pre-snapshot, regressions, watch samples table

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
pytest test_health_gate.py -v
```

Coverage: 20 tests across `Snapshot`, `ModeDetection`, `Submit`, `HappyPath`,
`SadPath`, `Tolerance`, `ErrorHandling`, `ListRecent`. Runs in ~0.5s
because tests use `snapshot_fn` injection — no real network or NETCONF.

## Key design decisions

1. **In-memory registry** — single-worker assumption matches the rest of `app.py`.
   Job state is lost on restart; only GAIT trail persists.
2. **Wall-clock + iter guard** in the watch loop — guarantees termination even
   when `DEFAULT_POLL_INTERVAL_S=0` (test scenarios).
3. **ms-resolution timestamps** — `list_recent_jobs` ordering is stable across
   same-second submissions.
4. **Test-hook whitelist** at the endpoint — only `induce_regression_after_s`,
   `induce_alert_spike_after_s`, `fail_at_phase` cross the network boundary.
   Everything else gets a 400 via `TypeError` handling.
5. **Lazy module import** — `_import_helper("health_gate")` avoids slowing
   `app.py` startup if the module isn't used.

## Related

- `network-lab/sim_bgp_failure.sh` — the *manual* version of what the Health
  Gate watches automatically.
- GAIT audit trail (`gait_audit.record`) — append-only JSONL backing the
  audit tab.
- Day 3-4 NetBox SoT panel — the source-of-truth half of the same gate.
