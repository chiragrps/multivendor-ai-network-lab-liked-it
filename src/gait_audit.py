"""
gait_audit.py — GAIT (Git AI Trail) immutable audit log.

Inspired by NetClaw. Every AI-driven action appends a JSONL record so we can
later answer "what did the agent do, when, why, and what was the outcome".

Records are append-only; rotation by date.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_AUDIT_DIR = os.path.normpath(os.path.join(_HERE, "../../audit"))
_LOCK = threading.Lock()


def _audit_path(when: datetime | None = None) -> str:
    when = when or datetime.now(timezone.utc)
    os.makedirs(_AUDIT_DIR, exist_ok=True)
    return os.path.join(_AUDIT_DIR, f"gait_{when:%Y-%m-%d}.jsonl")


def record(
    *,
    actor: str,
    action: str,
    target: str | None = None,
    prompt: str | None = None,
    response: str | None = None,
    tools_called: list[str] | None = None,
    tokens: dict[str, int] | None = None,
    status: str = "ok",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Append a single GAIT event.

    Args:
        actor:        who did it (e.g. "ai_command", "orchestrator", "eval_harness")
        action:       what action (e.g. "diagnose_bgp", "verify_intent")
        target:       device or scope (e.g. "fra-core-01", "fleet")
        prompt:       NL prompt or canonical task
        response:     summary of the result (truncate large blobs)
        tools_called: list of tool names invoked
        tokens:       {"input": n, "output": m}
        status:       "ok" | "error" | "blocked"
        extra:        any free-form metadata

    Returns:
        the written event dict (with id + ts).
    """
    event: dict[str, Any] = {
        "id": f"gait-{int(time.time() * 1000)}",
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "actor": actor,
        "action": action,
        "target": target,
        "prompt": (prompt or "")[:2000],
        "response": (response or "")[:2000],
        "tools_called": tools_called or [],
        "tokens": tokens or {},
        "status": status,
    }
    if extra:
        event["extra"] = extra

    path = _audit_path()
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with _LOCK:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line)
    return event


def recent(limit: int = 50, actor: str | None = None) -> list[dict[str, Any]]:
    """Return the last N events (today's file, then yesterday's if needed)."""
    files: list[str] = []
    today = datetime.now(timezone.utc)
    files.append(_audit_path(today))
    # also include yesterday so a fresh-day query isn't empty
    yesterday = datetime.fromtimestamp(today.timestamp() - 86400, timezone.utc)
    files.append(_audit_path(yesterday))

    events: list[dict[str, Any]] = []
    for path in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if actor and evt.get("actor") != actor:
                        continue
                    events.append(evt)
        except OSError:
            continue

    # newest first
    events.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return events[:limit]


def stats() -> dict[str, Any]:
    """Aggregate statistics on the audit log (today)."""
    events = recent(limit=10_000)
    by_actor: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total_tokens = {"input": 0, "output": 0}
    for e in events:
        by_actor[e.get("actor", "?")] = by_actor.get(e.get("actor", "?"), 0) + 1
        by_status[e.get("status", "?")] = by_status.get(e.get("status", "?"), 0) + 1
        toks = e.get("tokens") or {}
        total_tokens["input"] += int(toks.get("input", 0) or 0)
        total_tokens["output"] += int(toks.get("output", 0) or 0)
    return {
        "total_events": len(events),
        "by_actor": by_actor,
        "by_status": by_status,
        "tokens": total_tokens,
    }
