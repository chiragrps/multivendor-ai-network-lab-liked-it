"""
Auto-Postmortem — Day-8.

Correlates GAIT + Health Gate + Remediation events into a structured incident
report. Outputs Markdown ready to paste into a ticket / Slack / on-call review.

Design constraints:
  - No new dependencies. Reuses gait_audit, health_gate, remediation.
  - Heuristic root-cause (deterministic). LLM augmentation can come later.
  - Single source of truth: the events themselves. The report is a view.

Public surface:
    detect_incidents(window_h=2)       → list[Incident]
    generate(start, end, devices=None) → Incident
    render_markdown(incident)          → str
    save(incident, path)               → str (path written)
    list_saved()                       → list[dict]
"""
from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


# ──────────────────────────────────────────────────────────────────────────────
# Datamodel
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Event:
    """One row in the correlated timeline."""
    ts: str           # ISO timestamp
    source: str       # gait | health_gate | remediation
    severity: str     # info | warn | error | critical
    target: str       # hostname or "fleet"
    message: str
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Incident:
    incident_id: str
    started_at: str
    ended_at: str
    severity: str               # P1 | P2 | P3
    affected_devices: list[str]
    root_cause: str
    status: str                 # resolved | active | abandoned
    auto_detected: bool
    events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ──────────────────────────────────────────────────────────────────────────────
# Paths
# ──────────────────────────────────────────────────────────────────────────────


_HERE = Path(__file__).resolve().parent
_SAVE_DIR = _HERE.parent / "postmortems"
_SAVE_DIR.mkdir(exist_ok=True)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse_iso(s: str) -> datetime:
    """Best-effort ISO parse — events use seconds, jobs use ms."""
    if not s:
        return _now()
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        # strip sub-second if needed
        s2 = re.sub(r"\.\d+", "", s)
        try:
            return datetime.fromisoformat(s2.replace("Z", "+00:00"))
        except ValueError:
            return _now()


# ──────────────────────────────────────────────────────────────────────────────
# Event collectors — each returns Events in the requested window
# ──────────────────────────────────────────────────────────────────────────────


def _from_gait(start: datetime, end: datetime, devices: set[str] | None) -> list[Event]:
    try:
        import gait_audit as g
    except ImportError:
        return []
    raw = g.recent(limit=5000)  # enough to cover any sensible window
    out: list[Event] = []
    for evt in raw:
        ts = _parse_iso(evt.get("ts", ""))
        if ts < start or ts > end:
            continue
        target = (evt.get("target") or "fleet")
        if devices and target not in devices and target != "fleet":
            continue
        status = evt.get("status") or "ok"
        sev = "error" if status == "error" else "warn" if status == "blocked" else "info"
        out.append(Event(
            ts=evt.get("ts") or "",
            source="gait",
            severity=sev,
            target=target,
            message=f"{evt.get('actor', '?')} → {evt.get('action', '?')}",
            extra={"status": status, "prompt": evt.get("prompt", "")[:200]},
        ))
    return out


def _from_health_gate(start: datetime, end: datetime, devices: set[str] | None) -> list[Event]:
    try:
        import health_gate as hg
    except ImportError:
        return []
    jobs = hg.list_recent_jobs(limit=200)
    out: list[Event] = []
    for j in jobs:
        ts = _parse_iso(j.get("started_at") or j.get("finished_at") or "")
        if ts < start or ts > end:
            continue
        host = j.get("hostname") or "fleet"
        if devices and host not in devices:
            continue
        verdict = j.get("final_verdict") or "pending"
        sev = "critical" if verdict == "abandoned" else "error" if verdict == "error" else "info"
        msg = f"Health Gate {verdict}"
        if j.get("regressions"):
            msg += f" — {j['regressions'][0]}"
        out.append(Event(
            ts=j.get("started_at") or j.get("finished_at") or "",
            source="health_gate",
            severity=sev,
            target=host,
            message=msg,
            extra={"job_id": j.get("job_id"), "regressions": j.get("regressions", [])},
        ))
    return out


def _from_remediation(start: datetime, end: datetime, devices: set[str] | None) -> list[Event]:
    try:
        import remediation as rem
    except ImportError:
        return []
    props = rem.list_recent(limit=200)
    out: list[Event] = []
    for p in props:
        ts = _parse_iso(p.get("proposed_at") or "")
        if ts < start or ts > end:
            continue
        host = p.get("device") or "fleet"
        if devices and host not in devices:
            continue
        state = p.get("state") or "pending"
        verdict = p.get("verdict")
        sev = ("critical" if verdict == "abandoned"
               else "warn" if state in ("rejected", "error")
               else "info")
        msg = f"Remediation proposal {state}"
        if verdict:
            msg += f" → {verdict}"
        if p.get("runbook_id"):
            msg += f" (runbook: {p['runbook_id']})"
        out.append(Event(
            ts=p.get("proposed_at") or "",
            source="remediation",
            severity=sev,
            target=host,
            message=msg,
            extra={"proposal_id": p.get("proposal_id"), "rationale": (p.get("rationale") or "")[:160]},
        ))
    return out


def collect_events(
    start: datetime,
    end: datetime,
    devices: list[str] | None = None,
) -> list[Event]:
    """Merge events from every source, sorted by timestamp ascending."""
    dev_set = set(devices) if devices else None
    events: list[Event] = []
    events += _from_gait(start, end, dev_set)
    events += _from_health_gate(start, end, dev_set)
    events += _from_remediation(start, end, dev_set)
    # chronological for a readable timeline
    events.sort(key=lambda e: e.ts or "")
    return events


# ──────────────────────────────────────────────────────────────────────────────
# Root-cause heuristics (deterministic — no LLM)
# ──────────────────────────────────────────────────────────────────────────────


def correlate_root_cause(events: list[Event]) -> str:
    """Best-guess root cause from event correlation.

    Heuristics, in priority order:
      1. Chaos test → say so plainly.
      2. Health Gate abandoned → quote the first regression.
      3. Remediation rejected/error → that's the cause.
      4. Critical / error events on multiple devices in <60s → fleet event.
      5. Otherwise: unknown — see timeline.
    """
    msgs = [e.message.lower() for e in events]
    if any("chaos" in m for m in msgs):
        return "Chaos test triggered (controlled break)."
    for e in events:
        if e.source == "health_gate" and "abandoned" in e.message.lower():
            regs = e.extra.get("regressions") or []
            if regs:
                return f"Health Gate aborted change · regression: {regs[0]}"
            return "Health Gate aborted change · regression detected during watch window."
    for e in events:
        if e.source == "remediation" and e.severity in ("warn", "critical"):
            return f"Remediation {e.message.lower()} · see proposal {e.extra.get('proposal_id', '?')}"
    # multi-device correlation
    devs_with_critical = {e.target for e in events if e.severity in ("error", "critical") and e.target != "fleet"}
    if len(devs_with_critical) >= 2:
        return f"Fleet-level event — {len(devs_with_critical)} devices affected"
    if devs_with_critical:
        return f"Local event on {next(iter(devs_with_critical))} — see timeline for details"
    return "Unknown — see raw timeline."


def _severity(events: list[Event]) -> str:
    if any(e.severity == "critical" for e in events):
        return "P1"
    if any(e.severity == "error" for e in events):
        return "P2"
    return "P3"


def _status(events: list[Event]) -> str:
    # Reverse-scan: if the last decisive event is "confirmed" or "fix confirmed" → resolved
    for e in reversed(events):
        m = e.message.lower()
        if "confirmed" in m:
            return "resolved"
        if "abandoned" in m:
            return "abandoned"
    return "active"


def _affected(events: list[Event]) -> list[str]:
    devs = {e.target for e in events if e.target and e.target != "fleet"}
    return sorted(devs)


# ──────────────────────────────────────────────────────────────────────────────
# Public API: detect, generate, render, save
# ──────────────────────────────────────────────────────────────────────────────


def generate(
    start: datetime,
    end: datetime,
    devices: list[str] | None = None,
    *,
    incident_id: str | None = None,
    auto_detected: bool = False,
) -> Incident:
    events = collect_events(start, end, devices)
    inc = Incident(
        incident_id=incident_id or f"INC-{_now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}",
        started_at=events[0].ts if events else _iso(start),
        ended_at=events[-1].ts if events else _iso(end),
        severity=_severity(events),
        affected_devices=_affected(events),
        root_cause=correlate_root_cause(events),
        status=_status(events),
        auto_detected=auto_detected,
        events=[asdict(e) for e in events],
    )
    return inc


def detect_incidents(window_h: int = 2) -> list[Incident]:
    """Scan the last `window_h` hours for distinct trouble windows.

    A trouble window is anchored on any Health Gate `abandoned` verdict OR
    any cluster of >= 3 error/critical events within 60 seconds. Each anchor
    is expanded ±5min to capture lead-up and recovery, then deduplicated.
    """
    end = _now()
    start = end - timedelta(hours=window_h)
    events = collect_events(start, end)
    anchors: list[datetime] = []
    # explicit anchors: Health Gate abandons
    for e in events:
        if e.source == "health_gate" and "abandoned" in e.message.lower():
            anchors.append(_parse_iso(e.ts))
    # clustering anchors
    err_times = [_parse_iso(e.ts) for e in events if e.severity in ("error", "critical")]
    err_times.sort()
    for i, t in enumerate(err_times):
        cluster = [u for u in err_times if 0 <= (u - t).total_seconds() <= 60]
        if len(cluster) >= 3:
            anchors.append(t)
    if not anchors:
        return []
    # dedupe: merge anchors within 10min
    anchors.sort()
    merged: list[datetime] = []
    for a in anchors:
        if merged and (a - merged[-1]).total_seconds() <= 600:
            continue
        merged.append(a)
    out: list[Incident] = []
    for a in merged:
        out.append(generate(a - timedelta(minutes=5), a + timedelta(minutes=5), auto_detected=True))
    return out


def render_markdown(incident: Incident) -> str:
    """Pretty Markdown — ready to paste into a ticket."""
    lines: list[str] = []
    lines.append(f"# Incident {incident.incident_id} · Severity: {incident.severity}")
    lines.append("")
    started = _parse_iso(incident.started_at)
    ended = _parse_iso(incident.ended_at)
    dur = ended - started
    lines.append(f"- **Duration:** {incident.started_at} → {incident.ended_at} ({int(dur.total_seconds())}s)")
    affected = ", ".join(incident.affected_devices) or "fleet"
    lines.append(f"- **Affected:** {affected}")
    lines.append(f"- **Status:** {incident.status}")
    lines.append(f"- **Auto-detected:** {'yes' if incident.auto_detected else 'no'}")
    lines.append("")
    lines.append("## Root cause")
    lines.append(incident.root_cause)
    lines.append("")
    lines.append("## Timeline")
    if not incident.events:
        lines.append("_No events in window._")
    else:
        for e in incident.events:
            sev = e.get("severity", "info").upper()
            tgt = e.get("target") or "fleet"
            src = e.get("source", "?")
            lines.append(f"- `{e.get('ts','')}` · **{sev}** · `{src}` · `{tgt}` — {e.get('message','')}")
    lines.append("")
    lines.append("## Audit trail")
    gait_n = sum(1 for e in incident.events if e.get("source") == "gait")
    hg_n = sum(1 for e in incident.events if e.get("source") == "health_gate")
    rem_n = sum(1 for e in incident.events if e.get("source") == "remediation")
    lines.append(f"- GAIT entries: **{gait_n}**")
    lines.append(f"- Health Gate jobs: **{hg_n}**")
    lines.append(f"- Remediation proposals: **{rem_n}**")
    return "\n".join(lines)


def save(incident: Incident) -> str:
    """Persist as `postmortems/<id>.md` and return the path."""
    path = _SAVE_DIR / f"{incident.incident_id}.md"
    path.write_text(render_markdown(incident), encoding="utf-8")
    # also keep a JSON sidecar for replay
    json_path = _SAVE_DIR / f"{incident.incident_id}.json"
    json_path.write_text(json.dumps(incident.to_dict(), indent=2), encoding="utf-8")
    return str(path)


def list_saved() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in sorted(_SAVE_DIR.glob("INC-*.json"), reverse=True):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            out.append({
                "incident_id": data.get("incident_id"),
                "severity": data.get("severity"),
                "started_at": data.get("started_at"),
                "affected_devices": data.get("affected_devices"),
                "status": data.get("status"),
            })
        except (OSError, json.JSONDecodeError):
            continue
    return out


__all__ = [
    "Event", "Incident",
    "collect_events", "correlate_root_cause",
    "generate", "detect_incidents",
    "render_markdown", "save", "list_saved",
]
