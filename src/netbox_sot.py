"""
NetBox SoT (Source-of-Truth) — Day-3/4 drift detector.

Answers the audit question: *Does what's actually running match what NetBox
says should be running?*

Modes
-----
- **real**       — `NETBOX_URL` + `NETBOX_TOKEN` env vars set AND `pynetbox`
                   importable. Queries NetBox for devices, primary IPs, AS,
                   BGP peerings.
- **simulated**  — Reads `network-lab/demo-devices/netbox_sot.json` as the
                   pretend SoT. Intentional drift is baked in so the panel
                   has something to flag.

Observed
--------
- Reads `network-lab/demo-devices/inventory.json` as the "live" view (the
  same file the rest of the demo uses as the topology source of truth for
  the running lab).

Drift
-----
Each device pair (sot, observed) is compared field-by-field. Differences
are emitted as structured rows so the UI can render a table:

    {"hostname": "de-fra-core-01", "field": "ip",
     "sot": "10.200.0.11", "observed": "10.200.0.99",
     "severity": "high"}

Missing-on-one-side rows use field=`presence` and severity=`critical`
(extra) or `high` (missing in lab).

Public surface
--------------
    fetch_sot()        → list[dict]
    fetch_observed()   → list[dict]
    compute_drift()    → DriftReport
    refresh()          → DriftReport (force re-read both sides)
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).resolve().parent
_LAB_DIR = _HERE.parent / "network-lab" / "demo-devices"
DEFAULT_OBSERVED_PATH = _LAB_DIR / "inventory.json"
DEFAULT_SOT_PATH = _LAB_DIR / "netbox_sot.json"

# Fields compared device-by-device. Drift on each is reported with the
# severity below — tuned so "wrong AS or IP" outranks "wrong model string".
_COMPARED_FIELDS: dict[str, str] = {
    "ip": "high",
    "as": "high",
    "site": "high",
    "vendor": "medium",
    "model": "low",
    "role": "medium",
    "os": "low",
}


# ──────────────────────────────────────────────────────────────────────────────
# Datamodels
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class DriftRow:
    """One field-level difference between SoT and observed."""
    hostname: str
    field: str
    sot: Any
    observed: Any
    severity: str  # critical | high | medium | low


@dataclass
class DriftReport:
    ts: str
    mode: str  # real | simulated
    sot_count: int
    observed_count: int
    matched_count: int
    drift_rows: list[dict] = field(default_factory=list)

    @property
    def drift_count(self) -> int:
        return len(self.drift_rows)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["drift_count"] = self.drift_count
        return d


# ──────────────────────────────────────────────────────────────────────────────
# Mode detection
# ──────────────────────────────────────────────────────────────────────────────


def _detect_mode() -> str:
    if os.environ.get("NETBOX_SOT_FORCE_SIMULATE") == "1":
        return "simulated"
    has_creds = bool(os.environ.get("NETBOX_URL")) and bool(os.environ.get("NETBOX_TOKEN"))
    if not has_creds:
        return "simulated"
    try:
        import pynetbox  # noqa: F401
    except ImportError:
        return "simulated"
    return "real"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


# ──────────────────────────────────────────────────────────────────────────────
# Loaders
# ──────────────────────────────────────────────────────────────────────────────


def _load_json(path: Path) -> dict:
    """Load JSON file; return empty topology shell if missing.

    Keeps the panel usable in environments where the seed isn't present
    (e.g. user cloned without the lab/ directory).
    """
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return {"devices": [], "bgp_sessions": []}


def fetch_observed(observed_path: Path | None = None) -> list[dict]:
    """The 'live lab' view — devices the running tool actually knows about."""
    data = _load_json(observed_path or DEFAULT_OBSERVED_PATH)
    devices = data.get("devices") or []
    # Normalize: only the fields we compare, plus hostname as primary key.
    return [_normalize(d) for d in devices]


def fetch_sot(sot_path: Path | None = None) -> list[dict]:
    """Source-of-truth view.

    In simulated mode this is `netbox_sot.json`. In real mode this is a live
    NetBox query — kept thin and synchronous because the panel polls on
    demand, not in a hot loop.
    """
    mode = _detect_mode()
    if mode == "real":
        try:
            return _fetch_sot_real()
        except Exception:
            # Fall back to simulated if NetBox is unreachable — the panel
            # should still load even when the SoT is down.
            pass
    return [_normalize(d) for d in _load_json(sot_path or DEFAULT_SOT_PATH).get("devices") or []]


def _fetch_sot_real() -> list[dict]:
    """Query a live NetBox instance for the lab devices.

    Filter by tag `multivendor-lab` when present so we don't pull all 7,000+
    production devices into the demo panel.
    """
    import pynetbox  # local import — only loaded in real mode

    nb = pynetbox.api(
        os.environ["NETBOX_URL"],
        token=os.environ["NETBOX_TOKEN"],
        threading=True,
    )
    tag = os.environ.get("NETBOX_SOT_TAG", "multivendor-lab")
    try:
        raw = list(nb.dcim.devices.filter(tag=tag))
    except Exception:
        raw = list(nb.dcim.devices.all())
    out: list[dict] = []
    for d in raw:
        primary_ip = str(d.primary_ip).split("/")[0] if d.primary_ip else None
        out.append(_normalize({
            "hostname": (d.name or "").lower(),
            "ip": primary_ip,
            "vendor": (d.device_type.manufacturer.slug if d.device_type else None),
            "model": (d.device_type.model if d.device_type else None),
            "role": (d.role.slug if d.role else None),
            "site": (d.site.slug.upper() if d.site else None),
            "os": (getattr(d, "platform", None).slug if getattr(d, "platform", None) else None),
            "as": getattr(d, "custom_fields", {}).get("asn") if hasattr(d, "custom_fields") else None,
        }))
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Normalization & comparison
# ──────────────────────────────────────────────────────────────────────────────


def _normalize(d: dict) -> dict:
    """Strip to the comparable shape — lowercased hostname is the join key."""
    return {
        "hostname": (d.get("hostname") or "").strip().lower(),
        "ip": d.get("ip"),
        "as": d.get("as"),
        "vendor": d.get("vendor"),
        "model": d.get("model"),
        "role": d.get("role"),
        "site": d.get("site"),
        "os": d.get("os"),
    }


def _index_by_hostname(rows: Iterable[dict]) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for r in rows:
        h = r.get("hostname")
        if h:
            out[h] = r
    return out


def compute_drift(
    sot: list[dict] | None = None,
    observed: list[dict] | None = None,
    *,
    mode: str | None = None,
) -> DriftReport:
    """Produce a structured drift report.

    Compares every field in `_COMPARED_FIELDS` device-by-device. Adds
    presence rows for devices that exist on only one side.
    """
    sot_rows = sot if sot is not None else fetch_sot()
    obs_rows = observed if observed is not None else fetch_observed()
    sot_idx = _index_by_hostname(sot_rows)
    obs_idx = _index_by_hostname(obs_rows)
    matched = 0
    drift: list[DriftRow] = []

    # Devices that exist in SoT but not in the lab → "missing in lab"
    for host, s in sot_idx.items():
        if host not in obs_idx:
            drift.append(DriftRow(
                hostname=host, field="presence",
                sot="present", observed="missing",
                severity="high",
            ))
            continue
        matched += 1
        o = obs_idx[host]
        for fld, sev in _COMPARED_FIELDS.items():
            sv, ov = s.get(fld), o.get(fld)
            # Skip when SoT doesn't declare the field — avoid spurious drift
            # on optional metadata (e.g. SoT doesn't track AS for firewalls).
            if sv is None:
                continue
            if sv != ov:
                drift.append(DriftRow(
                    hostname=host, field=fld,
                    sot=sv, observed=ov,
                    severity=sev,
                ))

    # Devices in the lab that SoT doesn't know about → "extra / not in SoT"
    for host in obs_idx:
        if host not in sot_idx:
            drift.append(DriftRow(
                hostname=host, field="presence",
                sot="missing", observed="present",
                severity="critical",
            ))

    return DriftReport(
        ts=_now_iso(),
        mode=mode or _detect_mode(),
        sot_count=len(sot_idx),
        observed_count=len(obs_idx),
        matched_count=matched,
        drift_rows=[asdict(r) for r in drift],
    )


def refresh(
    sot_path: Path | None = None,
    observed_path: Path | None = None,
) -> DriftReport:
    """Force a fresh read of both sides + recompute drift."""
    sot = fetch_sot(sot_path)
    obs = fetch_observed(observed_path)
    return compute_drift(sot=sot, observed=obs)


__all__ = [
    "DriftRow",
    "DriftReport",
    "fetch_sot",
    "fetch_observed",
    "compute_drift",
    "refresh",
]
