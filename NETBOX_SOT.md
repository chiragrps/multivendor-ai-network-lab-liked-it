# NetBox SoT — Source-of-Truth drift detector

Day-3/4 panel that answers the audit question every NOC eventually has to ask:
**does what's actually running match what NetBox says should be running?**

## Why it exists

Configuration tools (Ansible, Salt, Nornir) treat the SoT as input. Audit tools
treat it as constraint. Neither runs the comparison the other direction —
"what do I have that NetBox doesn't know about?" — and that's where the worst
incidents come from: ghost devices nobody documented, ASNs that drifted during
a maintenance window, IPs reassigned without a ticket.

This panel runs both directions of the comparison and tiers the result.

## Comparison model

```
        NetBox SoT          Running Lab (inventory.json / live)
            │                                │
            └────── compute_drift() ─────────┘
                              │
                              ▼
                      DriftReport
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        presence       field-level     severity tier
   (extra/missing)    (ip, AS, site,   (critical / high /
                       vendor, model,   medium / low)
                       role, OS)
```

## Drift taxonomy

| Drift type | Field | Severity | Example |
|------------|-------|----------|---------|
| Extra device in lab | `presence` (sot=missing) | **critical** | Lab is running `nl-ams-edge-01` but NetBox has no record |
| Missing device | `presence` (observed=missing) | **high** | NetBox planned `uk-lon-fw-02` but it's not deployed |
| IP mismatch | `ip` | high | NetBox says `10.200.0.99`, lab says `10.200.0.11` |
| ASN mismatch | `as` | high | NetBox says `65103`, lab announces `65003` |
| Site mismatch | `site` | high | NetBox says `DE-FRA`, lab tagged `EU-CDG` |
| Vendor mismatch | `vendor` | medium | NetBox `juniper`, lab `arista` |
| Role mismatch | `role` | medium | NetBox `core`, lab `dist` |
| Model mismatch | `model` | low | NetBox `MX240`, lab `MX480` |
| OS mismatch | `os` | low | NetBox `junos`, lab `frr` |

When the SoT side declares `None` for a field, drift is **suppressed** —
avoids false positives on optional metadata (NetBox doesn't track ASN on
firewalls, for example).

## Modes

`_detect_mode()` chooses one of two paths:

- **real** — `NETBOX_URL` + `NETBOX_TOKEN` env vars set AND `pynetbox`
  importable AND `NETBOX_SOT_FORCE_SIMULATE` unset. Queries NetBox via
  `pynetbox`, filtered by tag (`NETBOX_SOT_TAG`, default `multivendor-lab`)
  to avoid pulling the entire production fleet into the demo panel.
- **simulated** — everything else. Reads `network-lab/demo-devices/netbox_sot.json`
  (a seed file with 5 intentional drift rows baked in). Falls back to this
  path even in real mode if the NetBox query throws — the panel always
  loads.

Force simulated for tests / offline demos:

```bash
export NETBOX_SOT_FORCE_SIMULATE=1
```

## API

### `GET /api/mv/netbox-sot/devices`

```json
{
  "sot": [ { "hostname": "...", "ip": "...", "as": 65001, "vendor": "frr", ... } ],
  "observed": [ ... ],
  "sot_count": 26,
  "observed_count": 26,
  "mode": "simulated"
}
```

### `GET /api/mv/netbox-sot/drift`

```json
{
  "ts": "2026-05-18T21:30:00.123+00:00",
  "mode": "simulated",
  "sot_count": 26,
  "observed_count": 26,
  "matched_count": 25,
  "drift_count": 5,
  "drift_rows": [
    {
      "hostname": "nl-ams-edge-01",
      "field": "presence",
      "sot": "missing",
      "observed": "present",
      "severity": "critical"
    },
    ...
  ]
}
```

### `POST /api/mv/netbox-sot/refresh`

Same shape as `/drift`, but forces a re-read of both files (so a user can
edit `netbox_sot.json` and see the change immediately).

## Python contract

```python
import netbox_sot as nbs

report = nbs.refresh()
print(f"{report.drift_count} drift rows ({report.mode} mode)")
for row in report.drift_rows:
    print(f"  {row['severity']:9} {row['hostname']:20} {row['field']:9} "
          f"sot={row['sot']!r} observed={row['observed']!r}")
```

## UI panel

Tab: **NetBox SoT** (visible in `audit` mode under Inventory & Audit).

- **4 summary tiles** — SoT count · Observed count · Matched · Drift found
  (the Drift tile changes border color: green @ 0, yellow ≤ 3, red ≥ 4)
- **Severity filter** — all / critical only / high+ / medium+
- **Refresh button** — `POST /api/mv/netbox-sot/refresh`, repaints the table
- **Drift table** — severity badge · hostname · field · SoT value · Observed value,
  sorted by severity descending

## Seed file drift (what the demo always shows)

The simulated SoT bakes in 5 drift rows so the panel is interesting on first
load:

1. `de-fra-core-01` — SoT `ip=10.200.0.99`, lab `10.200.0.11` (**high**)
2. `de-fra-core-02` — SoT `model=FRR-MX240`, lab `FRR-MX480` (**low**)
3. `uk-lon-core-01` — SoT `as=65103`, lab `65003` (**high**)
4. `uk-lon-fw-02` — only in SoT (**high** — planned-but-not-deployed)
5. `nl-ams-edge-01` — only in lab (**critical** — extra-in-lab)

## Testing

```bash
cd 04_Scripts_Tools/DCN_Network_Tool
pytest test_netbox_sot.py -v
```

Coverage: 25 tests across `TestModeDetection`, `TestNormalize`, `TestLoaders`,
`TestComputeDrift`, `TestSeedIntegrationDrift`, `TestRefresh`. Runs in ~0.05s
because the tests work entirely off the seed file and ad-hoc fixtures —
no network, no NetBox dependency, no Flask app required.

## Key design decisions

1. **SoT-side `None` suppresses drift** — lets the seed file leave optional
   fields blank without polluting the report with false positives.
2. **Lowercased hostname is the join key** — NetBox sometimes returns
   uppercase names; the lab inventory uses lowercase. Normalize both sides
   in `_normalize()` before joining.
3. **Severity-based ordering** — table sorts by severity DESC so the worst
   drift sits at the top.
4. **Fallback to simulated on NetBox errors** — a 500 from NetBox shouldn't
   take the panel down. The `try/except` in `fetch_sot()` swallows the
   error and reads the seed instead. (Caller can detect this by checking
   `report.mode`.)
5. **Lazy `pynetbox` import** — only loaded when real mode is selected.
   Saves startup time + lets the test env run without pynetbox installed.
6. **Refresh = re-read both files** — not a NetBox-only refresh; the
   observed side also gets re-read so the panel reflects edits to
   `inventory.json` made between calls.

## Related

- `health_gate.py` — the Day-1 *change* gate. NetBox SoT is the
  *audit-time* version of the same question: does observed match intent?
- `gait_audit.record` — the append-only audit trail. NetBox SoT does NOT
  write to GAIT on read — only mutations should be audited.
- Day 4 docker-compose seed — optional NetBox + Postgres + Redis stack
  for users who want to drive real-mode against a local NetBox.
