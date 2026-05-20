# Auto-Postmortem — Day-8

Correlates GAIT + Health Gate + Remediation events into a structured incident
report. Markdown output is ready to paste into a ticket / Slack / on-call review.

## Why it exists

Every senior NE has lost hours writing postmortems by hand: scroll through
logs, cross-reference timestamps, work out which config change caused which
flap, format it for the ticket. The data needed to *write* the postmortem is
already in the tool — it just needs to be stitched together.

This module reads everything the closed loop already records (GAIT audit
trail, Health Gate jobs, Remediation proposals) and emits a structured
incident report in <1s.

## Lifecycle

```
                  GAIT events ─┐
            Health Gate jobs ──┼──▶  collect_events(start, end)
       Remediation proposals ─┘            │
                                           ▼
                              ┌────────────────────────┐
                              │  chronological merge   │
                              └─────────┬──────────────┘
                                        │
                       ┌────────────────┴───────────────┐
                       ▼                                ▼
              correlate_root_cause()           Incident dataclass
              (priority heuristics)             (id, severity, status,
                       │                         affected, events)
                       ▼                                │
                  ┌─────────────────┐                   │
                  │ root cause str  │ ──────────────────┤
                  └─────────────────┘                   ▼
                                                render_markdown()
                                                        │
                                                        ▼
                                                  paste-ready .md
```

## Root-cause heuristics (priority order)

1. **Chaos test** — any `chaos_monkey:break` in window → root cause flagged plainly
2. **Health Gate abandoned** — quote the first regression message
3. **Remediation rejected/errored** — point to the proposal_id
4. **Multi-device error cluster** — "Fleet-level event — N devices affected"
5. **Single-device error** — "Local event on X — see timeline"
6. **Otherwise** — "Unknown — see raw timeline"

Deterministic, no LLM call. An LLM-augmented narrative layer can come later
without changing the public API.

## Auto-detection

`detect_incidents(window_h=2)` scans the recent window for anchors:

- Any Health Gate `abandoned` verdict → anchor at that timestamp
- Any cluster of ≥3 error/critical events within 60s → anchor at the cluster start

Each anchor expands ±5 min for the timeline. Anchors within 10 min of each
other are merged so one outage doesn't show as three separate incidents.

## Severity tiering

| Severity | Trigger |
|----------|---------|
| **P1** | Any event with `severity=critical` |
| **P2** | Any event with `severity=error` |
| **P3** | Otherwise |

## API

### `GET /api/mv/postmortem/incidents?window_h=N`
Auto-detected incidents in the last N hours.

### `POST /api/mv/postmortem/generate`
```json
{ "minutes_back": 30, "devices": ["de-fra-core-01"] }
```
Or explicit:
```json
{ "start": "2026-05-19T14:30:00Z", "end": "2026-05-19T14:40:00Z" }
```
Returns:
```json
{ "incident": { ... }, "markdown": "# Incident INC-..." }
```

### `GET /api/mv/postmortem/saved`
List previously persisted reports.

### `POST /api/mv/postmortem/save`
Generate + persist to `postmortems/INC-*.md` and `INC-*.json`.

## Python contract

```python
from datetime import datetime, timedelta, timezone
import postmortem as pm

# Auto-detect recent incidents
incs = pm.detect_incidents(window_h=2)
for inc in incs:
    print(inc.incident_id, inc.severity, inc.root_cause)

# Generate over an explicit window
end = datetime.now(timezone.utc)
start = end - timedelta(minutes=30)
inc = pm.generate(start, end, devices=["de-fra-core-01"])

# Render + persist
print(pm.render_markdown(inc))
path = pm.save(inc)
```

## UI panel

Tab: **📋 Postmortem** (under Audit mode).

- **Auto-detect** button — scans the selected window, renders the first incident
- **Generate now** — builds a report from the selected window unconditionally
- **Window selector** — 30 min / 2 h / 6 h / 24 h
- **Copy MD** — copies the markdown to clipboard
- **Save** — persists to `postmortems/` and writes a JSON sidecar for replay
- **Split view**: rendered markdown on the left, raw event table on the right
  (timestamp · severity badge · source · target · message)

## Example output

```markdown
# Incident INC-20260519-143200-abc123 · Severity: P1

- **Duration:** 2026-05-19T14:32:00+00:00 → 2026-05-19T14:35:42+00:00 (222s)
- **Affected:** de-fra-core-01
- **Status:** abandoned
- **Auto-detected:** yes

## Root cause
Health Gate aborted change · regression: BGP peers regressed by 1

## Timeline
- `2026-05-19T14:32:00+00:00` · **INFO** · `gait` · `de-fra-core-01` — operator → chaos_monkey:break
- `2026-05-19T14:32:01+00:00` · **INFO** · `health_gate` · `de-fra-core-01` — Health Gate pending
- `2026-05-19T14:32:15+00:00` · **CRITICAL** · `health_gate` · `de-fra-core-01` — Health Gate abandoned — BGP peers regressed by 1
- `2026-05-19T14:35:42+00:00` · **INFO** · `gait` · `de-fra-core-01` — netconf → auto_revert

## Audit trail
- GAIT entries: **3**
- Health Gate jobs: **2**
- Remediation proposals: **0**
```

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
pytest test_postmortem.py -v
```

22 tests in ~0.2s covering dataclasses, root-cause heuristics, severity
tiering, status detection, affected-devices logic, end-to-end generate +
detect, markdown rendering, and save/list round-trip.

## Key design decisions

1. **No new dependencies** — reuses `gait_audit`, `health_gate`, `remediation`
   modules and stdlib only.
2. **Deterministic root-cause** — heuristics over LLM for the first pass.
   The interface is ready for an LLM narrator (returns same Incident dict
   shape, just richer `root_cause` and per-event prose).
3. **Append-only persistence** — `postmortems/INC-*.md` + JSON sidecar.
   Filenames are sortable. JSON sidecar is for future "replay" tooling.
4. **Best-effort event collection** — each `_from_*` collector swallows
   ImportErrors so a missing upstream module doesn't break the report.
5. **Two trigger paths** — `detect_incidents()` for proactive scan,
   `generate()` for explicit window. Both return the same shape.

## Related

- `health_gate.py` — Day-1 confirmed-commit gate (one of the event sources)
- `netbox_sot.py` — Day-3/4 drift detector (could be added as a 4th source)
- `remediation.py` — Day-5/6 closed-loop approvals (event source)
- `gait_audit.py` — append-only JSONL audit trail (primary event source)
