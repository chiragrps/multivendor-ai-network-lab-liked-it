"""
health_gate.py — Day-1 of the Observe → Decide → Act → Verify orchestrator.

Inspired by NetClaw + rustnetconf's confirmed-commit semantics (RFC 6241 §8.4).

Flow:
    1. snapshot_pre(device)          — capture baseline (BGP peers up, ifaces up, alerts)
    2. apply_confirmed(device, xml)  — push edit with <commit><confirmed/>...</commit>
    3. watch_window(device, base)    — poll every 5s for `timeout_s`
    4. decide()                       — if all signals clean → confirm; else abandon
    5. on session-drop OR abandon    — Junos auto-rolls back at the timeout

Design choices:
  - Real Junos path: junos-eznc (PyEZ) confirmed-commit + watcher.
  - FRR-lab path:    SIMULATED confirmed-commit (FRR vtysh has no native
                     <commit confirmed/> RPC). The simulation is honest —
                     the GAIT trail flags `mode=simulated` so demo viewers
                     understand the seam between "real NETCONF" and "lab".
  - Jobs are in-memory (single-worker assumption matches the rest of app.py).
  - State is exposed via /api/mv/health-gate/status/<job_id> so the UI can
    poll without blocking the request thread.

This module owns NO Flask routes — those live in multivendor_extensions.py.
"""
from __future__ import annotations

import os
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable

# ─── Constants ─────────────────────────────────────────────────────────────
DEFAULT_TIMEOUT_S = 60
DEFAULT_POLL_INTERVAL_S = 5
DEFAULT_TOLERANCE = {
    "bgp_peers_lost":     0,   # any BGP peer drop = abandon
    "interfaces_lost":    0,   # any interface flap down = abandon
    "alerts_added":       0,   # any new critical alert = abandon
}

# Job lifecycle states
PHASES = ("idle", "snapshot_pre", "applying", "watching", "deciding", "done")


# ─── Snapshot model ────────────────────────────────────────────────────────
@dataclass
class Snapshot:
    """A point-in-time health snapshot of a single device."""
    hostname: str
    ts: str
    bgp_peers_up: int = 0
    interfaces_up: int = 0
    alerts_count: int = 0
    raw: dict[str, Any] = field(default_factory=dict)

    def diff(self, baseline: "Snapshot") -> dict[str, int]:
        """Return signed deltas against a baseline (negative = regression)."""
        return {
            "bgp_peers_delta":  self.bgp_peers_up   - baseline.bgp_peers_up,
            "interfaces_delta": self.interfaces_up  - baseline.interfaces_up,
            "alerts_delta":     self.alerts_count   - baseline.alerts_count,
        }

    def regression_against(self, baseline: "Snapshot", tolerance: dict[str, int]) -> list[str]:
        """List human-readable regressions (empty = healthy)."""
        d = self.diff(baseline)
        regressions: list[str] = []
        if -d["bgp_peers_delta"]  > tolerance["bgp_peers_lost"]:
            regressions.append(f"BGP peers regressed by {-d['bgp_peers_delta']}")
        if -d["interfaces_delta"] > tolerance["interfaces_lost"]:
            regressions.append(f"Interfaces regressed by {-d['interfaces_delta']}")
        if  d["alerts_delta"]     > tolerance["alerts_added"]:
            regressions.append(f"Alerts increased by {d['alerts_delta']}")
        return regressions


# ─── Job state ─────────────────────────────────────────────────────────────
@dataclass
class HealthGateJob:
    """In-memory state for one Health Gate run."""
    job_id: str
    hostname: str
    edit_payload: str
    timeout_s: int
    tolerance: dict[str, int]
    mode: str = "simulated"          # "real" (PyEZ) | "simulated" (FRR lab)
    phase: str = "idle"
    progress_pct: int = 0
    pre_snapshot: dict | None = None
    last_snapshot: dict | None = None
    regressions: list[str] = field(default_factory=list)
    final_verdict: str = ""           # "confirmed" | "abandoned" | "error"
    error: str = ""
    started_at: str = ""
    finished_at: str = ""
    watch_samples: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─── In-memory job registry ────────────────────────────────────────────────
_JOBS: dict[str, HealthGateJob] = {}
_JOBS_LOCK = threading.Lock()


def _store_job(job: HealthGateJob) -> None:
    with _JOBS_LOCK:
        _JOBS[job.job_id] = job


def get_job(job_id: str) -> HealthGateJob | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def list_recent_jobs(limit: int = 20) -> list[dict[str, Any]]:
    """Return up to `limit` recent jobs, newest first."""
    with _JOBS_LOCK:
        snap = list(_JOBS.values())
    snap.sort(key=lambda j: j.started_at, reverse=True)
    return [j.to_dict() for j in snap[:limit]]


# ─── Snapshot capture ──────────────────────────────────────────────────────
def _now_iso() -> str:
    """ISO timestamp with millisecond resolution so list_recent ordering is stable."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def capture_snapshot(hostname: str, snapshot_fn: Callable | None = None) -> Snapshot:
    """
    Build a Snapshot for `hostname`. Pluggable for tests — pass `snapshot_fn`
    returning a dict to inject mock state.

    In production this would shell out to /api/cli-fleet or vtysh; for the
    lab we use a heuristic that matches the demo's inventory.
    """
    if snapshot_fn is not None:
        raw = snapshot_fn(hostname) or {}
    else:
        raw = _default_lab_snapshot(hostname)

    return Snapshot(
        hostname=hostname,
        ts=_now_iso(),
        bgp_peers_up=int(raw.get("bgp_peers_up", 0)),
        interfaces_up=int(raw.get("interfaces_up", 0)),
        alerts_count=int(raw.get("alerts_count", 0)),
        raw=raw,
    )


def _default_lab_snapshot(hostname: str) -> dict[str, Any]:
    """
    Default snapshot for the FRR lab — uses deterministic baselines that
    match the inventory's BGP topology. Real deployments would replace
    this with live polling via /api/cli-fleet or PyEZ get_bgp_summary.
    """
    # Inventory-aware baselines (FRR cores have 3-4 peers, edges 1-2)
    profiles = {
        "de-fra-core-01": {"bgp_peers_up": 4, "interfaces_up": 12, "alerts_count": 0},
        "de-fra-core-02": {"bgp_peers_up": 2, "interfaces_up": 8,  "alerts_count": 0},
        "uk-lon-core-01": {"bgp_peers_up": 2, "interfaces_up": 6,  "alerts_count": 0},
        "nl-ams-core-01": {"bgp_peers_up": 2, "interfaces_up": 6,  "alerts_count": 0},
        "us-nyc-core-01": {"bgp_peers_up": 1, "interfaces_up": 4,  "alerts_count": 0},
        "de-fra-edge-01": {"bgp_peers_up": 2, "interfaces_up": 4,  "alerts_count": 0},
        "uk-lon-edge-01": {"bgp_peers_up": 1, "interfaces_up": 3,  "alerts_count": 0},
        "nl-ams-edge-01": {"bgp_peers_up": 1, "interfaces_up": 3,  "alerts_count": 0},
        "de-fra-dist-01": {"bgp_peers_up": 1, "interfaces_up": 3,  "alerts_count": 0},
        "uk-lon-dist-01": {"bgp_peers_up": 1, "interfaces_up": 3,  "alerts_count": 0},
    }
    return profiles.get(hostname, {"bgp_peers_up": 0, "interfaces_up": 0, "alerts_count": 0})


# ─── Apply (commit-confirmed orchestration) ────────────────────────────────
def _detect_mode(hostname: str) -> str:
    """
    Decide whether to use real PyEZ or simulated path.

    Real path requires:
      - PyEZ installed
      - hostname is a Juniper device (vendor=juniper in inventory)
      - SSH key reachable
    """
    if os.environ.get("HEALTH_GATE_FORCE_SIMULATE", "").lower() in ("1", "true", "yes"):
        return "simulated"
    try:
        import jnpr.junos  # noqa: F401
    except Exception:
        return "simulated"
    return "real" if hostname.startswith(("de-fra", "uk-lon", "nl-ams", "us-nyc", "eu-cdg")) and "-fw-" in hostname else "simulated"


def _record_gait(job: HealthGateJob, action: str, status: str, response: str) -> None:
    """Append a GAIT event for this job. Best-effort — failures don't block."""
    try:
        from . import gait_audit  # type: ignore
    except Exception:
        try:
            import gait_audit  # type: ignore
        except Exception:
            return
    try:
        gait_audit.record(
            actor="health_gate",
            action=action,
            target=job.hostname,
            response=response,
            status=status,
            extra={
                "job_id": job.job_id,
                "mode": job.mode,
                "timeout_s": job.timeout_s,
            },
        )
    except Exception:
        pass


def _run_job(
    job: HealthGateJob,
    snapshot_fn: Callable | None = None,
    fail_at_phase: str | None = None,        # for tests / demo
    induce_regression_after_s: int | None = None,  # for tests / demo
    induce_alert_spike_after_s: int | None = None,  # for tests / demo
) -> None:
    """Background worker — drives the gate through its phases."""
    job.started_at = _now_iso()
    job.phase = "snapshot_pre"
    job.progress_pct = 5

    try:
        # ── 1. Capture pre-snapshot ──
        pre = capture_snapshot(job.hostname, snapshot_fn=snapshot_fn)
        job.pre_snapshot = asdict(pre)
        _record_gait(job, action="snapshot_pre", status="ok",
                     response=f"baseline bgp={pre.bgp_peers_up} if={pre.interfaces_up} alerts={pre.alerts_count}")

        if fail_at_phase == "snapshot_pre":
            raise RuntimeError("forced test failure at snapshot_pre")

        # ── 2. Apply config with <commit confirmed/> ──
        job.phase = "applying"
        job.progress_pct = 15
        if job.mode == "real":
            _apply_real_netconf(job)
        else:
            _apply_simulated(job)
        _record_gait(job, action="apply", status="ok",
                     response=f"commit-confirmed timeout={job.timeout_s}s mode={job.mode}")

        if fail_at_phase == "applying":
            raise RuntimeError("forced test failure at applying")

        # ── 3. Watch window ──
        # Use wall-clock + max-iteration guard so tests with poll=0 don't loop forever.
        job.phase = "watching"
        poll = max(DEFAULT_POLL_INTERVAL_S, 0.0)
        max_iters = max(1, int(job.timeout_s / max(poll, 1)) + 2)
        start_t = time.monotonic()
        iters = 0
        while iters < max_iters:
            iters += 1
            elapsed = time.monotonic() - start_t
            if elapsed >= job.timeout_s:
                break
            now = capture_snapshot(job.hostname, snapshot_fn=snapshot_fn)
            # Test hook: artificially degrade after N seconds (or immediately if 0)
            if induce_regression_after_s is not None and elapsed >= induce_regression_after_s:
                now.bgp_peers_up = max(0, now.bgp_peers_up - 1)
            if induce_alert_spike_after_s is not None and elapsed >= induce_alert_spike_after_s:
                now.alerts_count = now.alerts_count + 3
            sample = {
                "ts": now.ts,
                "elapsed_s": round(elapsed, 2),
                "bgp_peers_up": now.bgp_peers_up,
                "interfaces_up": now.interfaces_up,
                "alerts_count": now.alerts_count,
            }
            job.watch_samples.append(sample)
            job.last_snapshot = asdict(now)

            # Check regression against baseline
            regressions = now.regression_against(pre, job.tolerance)
            if regressions:
                job.regressions = regressions
                job.phase = "deciding"
                job.progress_pct = 90
                job.final_verdict = "abandoned"
                _record_gait(
                    job, action="abandon", status="blocked",
                    response="regressions: " + " | ".join(regressions) + " — device will auto-revert at timeout",
                )
                break

            job.progress_pct = min(85, 15 + int(70 * (elapsed / max(job.timeout_s, 1))))
            if poll > 0:
                time.sleep(poll)

        # ── 4. Decide ──
        if not job.regressions:
            job.phase = "deciding"
            job.progress_pct = 95
            if job.mode == "real":
                _confirm_real_netconf(job)
            else:
                pass  # simulated path: just mark confirmed
            job.final_verdict = "confirmed"
            _record_gait(job, action="confirm", status="ok",
                         response=f"all signals clean across {len(job.watch_samples)} samples")

    except Exception as exc:
        job.final_verdict = "error"
        job.error = str(exc)
        _record_gait(job, action="error", status="error", response=str(exc))
    finally:
        job.phase = "done"
        job.progress_pct = 100
        job.finished_at = _now_iso()


def _apply_real_netconf(job: HealthGateJob) -> None:
    """Real Junos path: PyEZ NETCONF <edit-config> + <commit confirmed/>."""
    try:
        from jnpr.junos import Device as _JunosDevice  # type: ignore
    except ImportError:
        # Shouldn't happen — _detect_mode would have returned 'simulated'.
        # Defensive: degrade to simulated.
        job.mode = "simulated"
        return _apply_simulated(job)

    # Resolve IP via env-driven lookup. Demo doesn't actually have a Junos box
    # so we'd 501 here in production; for now this branch is dead code in the lab.
    ssh_key  = os.environ.get("DCN_SSH_KEY", os.path.expanduser("~/.ssh/netlab_admin"))
    ssh_user = os.environ.get("DCN_SSH_USER", "netadmin2")

    dev = _JunosDevice(host=job.hostname, user=ssh_user,
                       ssh_private_key_file=ssh_key, gather_facts=False)
    dev.open()
    try:
        from jnpr.junos.utils.config import Config  # type: ignore
        with Config(dev, mode='exclusive') as cu:
            cu.load(job.edit_payload, format='xml', merge=True)
            cu.commit(confirm=job.timeout_s // 60 or 1)  # PyEZ takes minutes
    finally:
        dev.close()


def _apply_simulated(job: HealthGateJob) -> None:
    """Lab/FRR path: simulate the commit-confirmed semantics."""
    del job  # parameter kept for symmetry with _apply_real_netconf
    # Tiny delay so the UI shows the 'applying' phase
    time.sleep(0.05)


def _confirm_real_netconf(job: HealthGateJob) -> None:
    """Send the final <commit/> on the real Junos device."""
    try:
        from jnpr.junos import Device as _JunosDevice  # type: ignore
        from jnpr.junos.utils.config import Config  # type: ignore
    except ImportError:
        return

    ssh_key  = os.environ.get("DCN_SSH_KEY", os.path.expanduser("~/.ssh/netlab_admin"))
    ssh_user = os.environ.get("DCN_SSH_USER", "netadmin2")

    dev = _JunosDevice(host=job.hostname, user=ssh_user,
                       ssh_private_key_file=ssh_key, gather_facts=False)
    dev.open()
    try:
        with Config(dev, mode='exclusive') as cu:
            cu.commit_check()
            cu.commit()  # no confirm = makes the candidate permanent
    finally:
        dev.close()


# ─── Public API (used by the Flask blueprint) ──────────────────────────────
def submit(
    hostname: str,
    edit_payload: str = "",
    timeout_s: int = DEFAULT_TIMEOUT_S,
    tolerance: dict[str, int] | None = None,
    *,
    snapshot_fn: Callable | None = None,
    block: bool = False,
    **test_hooks: Any,
) -> HealthGateJob:
    """
    Submit a Health Gate run. Returns the job immediately; the worker
    runs in a daemon thread unless `block=True` (test-only).
    """
    if not hostname:
        raise ValueError("hostname required")

    job = HealthGateJob(
        job_id=f"hg-{uuid.uuid4().hex[:12]}",
        hostname=hostname,
        edit_payload=edit_payload or "<configuration/>",
        timeout_s=int(timeout_s),
        tolerance={**DEFAULT_TOLERANCE, **(tolerance or {})},
        mode=_detect_mode(hostname),
    )
    _store_job(job)

    runner_args = dict(snapshot_fn=snapshot_fn, **test_hooks)
    if block:
        _run_job(job, **runner_args)
        return job

    t = threading.Thread(target=_run_job, args=(job,), kwargs=runner_args, daemon=True)
    t.start()
    return job


# Re-exports for test/import convenience
__all__ = [
    "Snapshot",
    "HealthGateJob",
    "DEFAULT_TIMEOUT_S",
    "DEFAULT_TOLERANCE",
    "PHASES",
    "submit",
    "capture_snapshot",
    "get_job",
    "list_recent_jobs",
]
