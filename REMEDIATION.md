# Closed-Loop Remediation — Day-5/6

Composes Day-1 (Health Gate) and Day-3/4 (NetBox SoT) into one workflow:
**drift detected → AI proposes a runbook → human approves → the fix runs
through Health Gate** (so the remediation itself gets the confirmed-commit
watch, and auto-reverts if it makes things worse).

## Why it exists

The first two features each answered half a question:

- **Health Gate** — *Did this change keep the network healthy?*
- **NetBox SoT** — *Does the running network match what it should be?*

Neither closes the gap. If SoT flags drift, what fixes it? If a runbook
proposes a fix, who watches that the fix actually helps? Closed-loop
remediation joins the two surfaces with an approval gate in the middle —
so every auto-fix is **proposed by AI, approved by a human, executed by
Health Gate, and audited by GAIT**.

## State machine

```
                          ┌───────────────────┐
       propose_for_drift   │                   │      reject()
   ─────────────────────▶  │      pending      │  ────────────────▶ rejected
       (or manual propose) │                   │
                          └─────────┬─────────┘
                                    │ approve()
                                    ▼
                          ┌───────────────────┐
                          │     approved      │
                          └─────────┬─────────┘
                                    │ Health Gate submit
                                    ▼
                          ┌───────────────────┐
                          │    executing      │   ◀── HG watching window
                          └─────────┬─────────┘
                                    │ HG done
                          ┌─────────┴─────────┐
                          ▼                   ▼
                  verdict=confirmed   verdict=abandoned
                          │                   │
                          ▼                   ▼
                        done                 done
                                              │
                                              ▼
                                   device auto-reverts
                                   at NETCONF timeout
```

## Drift → runbook mapping

The proposer maps each drift row to a runbook (or auto-rejects if no
remediation is appropriate). The default table:

| Field | SoT | Observed | Runbook | Severity rationale |
|-------|-----|----------|---------|---------------------|
| `presence` | missing | present | *(none)* | Extra-in-lab → human triage |
| `presence` | present | missing | *(none)* | Planned-but-not-deployed → provisioning, not a runbook |
| `ip` | * | * | `bgp_peer_down` | IP drift on a router commonly breaks BGP sessions |
| `as` | * | * | `bgp_peer_down` | ASN drift breaks BGP |
| `site` | * | * | *(none)* | Metadata error, not runtime |
| `vendor` | * | * | *(none)* | Inventory bug, not runtime |
| `role` | * | * | *(none)* | Metadata error |
| `model` | * | * | *(none)* | Cosmetic |
| `os` | * | * | *(none)* | Cosmetic |

When no runbook fits, the proposal is **still created** with state `rejected`
and `rejected_by=auto`. This gives the audit trail a record that the system
*considered* the drift — important for compliance reviews.

## API

### `POST /api/mv/remediation/propose-for-drift`

```json
{ "drift_row": {
    "hostname": "de-fra-core-01",
    "field": "ip",
    "sot": "10.200.0.99",
    "observed": "10.200.0.11",
    "severity": "high"
  }
}
```

Returns the new `Proposal` dict. `state` is `pending` if a runbook was
matched, `rejected` if no auto-remediation applies.

### `POST /api/mv/remediation/propose`

```json
{ "runbook_id": "bgp_peer_down", "device": "de-fra-core-01", "rationale": "manual escalation" }
```

For ad-hoc proposals not tied to a drift row.

### `POST /api/mv/remediation/approve/<proposal_id>`

```json
{ "actor": "alice", "timeout_s": 30 }
```

Flips `pending → approved → executing` and kicks the Health Gate job.
Returns the updated proposal. The Health Gate runs in the background; poll
`/get/<id>` to see the final verdict.

### `POST /api/mv/remediation/reject/<proposal_id>`

```json
{ "actor": "bob", "reason": "known false positive" }
```

### `GET /api/mv/remediation/get/<proposal_id>`
### `GET /api/mv/remediation/recent?limit=20`

## Python contract

```python
import remediation as rem

# Propose from a drift row (auto-picks runbook, or auto-rejects)
p = rem.propose_for_drift({
    "hostname": "de-fra-core-01", "field": "ip",
    "sot": "10.200.0.99", "observed": "10.200.0.11", "severity": "high",
})
print(p.state)             # pending
print(p.runbook_id)        # bgp_peer_down
print(p.rationale)         # AI explanation

# Approve — kicks Health Gate
p = rem.approve(p.proposal_id, actor="operator")
print(p.health_gate_job_id)  # hg-...

# Poll for verdict
while p.state not in ("done", "rejected", "error"):
    time.sleep(1)
    p = rem.get(p.proposal_id)
print(p.verdict)  # "confirmed" or "abandoned"
```

## UI panel

Tab: **Auto-Remediate** (under Change Control nav). Shows:

- **4 summary tiles** — pending / executing / confirmed / rejected-or-abandoned
- **Propose for all current drift** button — pulls live drift from NetBox SoT
  and creates one proposal per row (auto-rejecting where no runbook fits)
- **Per-row Approve / Reject buttons** on each pending proposal
- **Verdict badges** painted onto each row once the Health Gate returns
- **GAIT audit trail line** — `hg=<job_id> · approved by <actor>` so the
  full lineage stays visible after the verdict

The panel re-renders the entire queue on every state change (no flicker —
HTML diffing handled by setting `innerHTML` of the scroll area).

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
pytest test_remediation.py -v
```

25 tests across `TestDriftLookup`, `TestPropose`, `TestProposeForDrift`,
`TestApprove`, `TestReject`, `TestClosedLoopE2E`, `TestRegistry`.

Runs in ~0.1s because tests inject a stub Health Gate submitter (`approve(...,
health_gate_submit=...)`) instead of spawning real threads. One E2E test
uses the real `health_gate` module in `block=True` mode to verify the
verdict mirrors back into the Proposal.

## Key design decisions

1. **`health_gate_submit` is injectable** — lets tests stub the gate without
   `unittest.mock`. The Flask endpoint uses the default (real) `hg.submit`.
2. **Background watcher mirrors verdict into Proposal** — the UI doesn't have
   to poll *two* APIs (HG status + remediation get); only `remediation/get/<id>`
   is needed. The watcher has a 10-minute hard cap so a stuck HG can't leak
   a thread forever.
3. **Auto-rejected proposals still get stored** — auditors care about
   "what did the system consider and decline", not just "what executed".
4. **GAIT logging is best-effort** — wrapped in `try/except`; an audit-log
   outage must not break the remediation flow.
5. **No LLM in the proposer (yet)** — the drift→runbook mapping is a static
   table for deterministic demos. The shape is ready for an LLM upgrade
   (return `runbook_id` + `confidence` + `rationale` from a model call) without
   changing the public API.

## Related

- `health_gate.py` — Day-1 confirmed-commit gate that the runbook executes
  through. Without it, an auto-approved runbook would have no rollback.
- `netbox_sot.py` — Day-3/4 drift detector that feeds this panel.
- `gait_audit.py` — append-only JSONL audit trail. Every propose / approve /
  reject / verdict transition writes a GAIT row.
- `src/runbooks/*.yaml` — the runbook catalog the proposer picks from.
