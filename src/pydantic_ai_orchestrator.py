"""
pydantic_ai_orchestrator.py — Multi-agent orchestrator with Pydantic-validated outputs.

Inspired by Hugo Tinoco's pydantic-ai network-automation post. Uses the
native Anthropic SDK + Pydantic BaseModel for structured output validation,
so we get the pattern without pulling in the pydantic-ai dependency.

Architecture:

    OrchestratorAgent
       ├── classify(prompt) -> "routing" | "acl" | "incident" | "general"
       ├── delegate -> RoutingAgent / ACLAgent / IncidentAgent
       └── finalize(result) -> structured envelope

Each child agent returns a Pydantic BaseModel result; the orchestrator
serializes it into a single response.

Falls back to a deterministic stub when ANTHROPIC_API_KEY is missing —
so the demo still functions offline.
"""
from __future__ import annotations

import json
import os
import logging
import re
import time
from typing import Any, Literal

logger = logging.getLogger(__name__)

try:
    from pydantic import BaseModel, Field  # type: ignore
    _HAS_PYDANTIC = True
except ImportError:
    _HAS_PYDANTIC = False

    class BaseModel:  # type: ignore[no-redef]
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self) -> dict[str, Any]:
            return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

    def Field(*args: Any, **kwargs: Any) -> Any:  # type: ignore[no-redef]
        return kwargs.get("default")


# ─── Structured output models ────────────────────────────────────────────────


class RoutingDiagnosis(BaseModel):
    """BGP/OSPF routing problem diagnosis."""
    protocol: Literal["bgp", "ospf", "isis", "unknown"] = "unknown"  # type: ignore[assignment]
    affected_device: str = ""
    affected_peer: str | None = None
    state: str = ""
    root_cause: str = ""
    evidence: list[str] = Field(default_factory=list)
    remediation: list[str] = Field(default_factory=list)
    confidence: float = 0.0


class ACLDiagnosis(BaseModel):
    """Firewall / ACL policy diagnosis."""
    device: str = ""
    policy_name: str | None = None
    flow: dict[str, Any] = Field(default_factory=dict)  # src, dst, port, proto
    decision: Literal["deny", "permit", "drop", "unknown"] = "unknown"  # type: ignore[assignment]
    matching_line: str | None = None
    root_cause: str = ""
    proposed_change: str | None = None
    confidence: float = 0.0


class IncidentTicket(BaseModel):
    """Structured incident ticket — like a JIRA / ServiceNow record."""
    ticket_id: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "low"  # type: ignore[assignment]
    title: str = ""
    summary: str = ""
    affected_devices: list[str] = Field(default_factory=list)
    root_cause: str = ""
    remediation_steps: list[str] = Field(default_factory=list)
    requires_change_window: bool = False


# ─── Orchestrator ────────────────────────────────────────────────────────────


def _has_anthropic() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY", ""))


def _classify(prompt: str) -> str:
    """Cheap heuristic classifier. Routing & ACL keywords win first."""
    p = prompt.lower()
    if any(k in p for k in ("bgp", "ospf", "isis", "neighbor", "peer", "as ", "as-mismatch", "route ")):
        return "routing"
    if any(k in p for k in ("acl", "policy", "firewall", "deny", "permit", "drop", "blocked")):
        return "acl"
    if any(k in p for k in ("ticket", "incident", "outage", "user reports", "p1", "p2")):
        return "incident"
    return "routing"  # default — most network NL prompts are routing


# Module-scoped buffer for the most recent token usage from _call_claude.
# Read once per public-facing call and reset; not thread-safe across concurrent agents
# (acceptable here — orchestrator is invoked sequentially per request).
_LAST_USAGE: dict[str, int] = {"input": 0, "output": 0}


def _pop_last_usage() -> dict[str, int]:
    """Return and reset the most recent token usage."""
    u = dict(_LAST_USAGE)
    _LAST_USAGE["input"] = 0
    _LAST_USAGE["output"] = 0
    return u


def _call_claude(system: str, user: str, model: str = "claude-haiku-4-5", max_tokens: int = 600) -> str:
    if not _has_anthropic():
        return ""
    try:
        import anthropic  # type: ignore
    except ImportError:
        return ""
    try:
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=model, max_tokens=max_tokens, system=system,
            messages=[{"role": "user", "content": user}],
        )
        # Capture token usage for downstream GAIT recording
        usage = getattr(resp, "usage", None)
        if usage is not None:
            _LAST_USAGE["input"] += int(getattr(usage, "input_tokens", 0) or 0)
            _LAST_USAGE["output"] += int(getattr(usage, "output_tokens", 0) or 0)
        return resp.content[0].text if resp.content else ""
    except (anthropic.APIError, anthropic.APIConnectionError, anthropic.RateLimitError) as e:
        logger.warning("Anthropic API call failed: %s", e)
        return ""
    except KeyError:
        logger.error("ANTHROPIC_API_KEY missing from environment at call time")
        return ""


def _extract_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    m = re.search(r"\{[\s\S]*\}", text)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


# ─── Child agents ────────────────────────────────────────────────────────────


def routing_agent(prompt: str) -> RoutingDiagnosis:
    sys = (
        "You are a routing specialist (BGP/OSPF/IS-IS). Respond with strict JSON matching:\n"
        '{"protocol": "bgp|ospf|isis|unknown", "affected_device": "", "affected_peer": "",'
        '"state": "", "root_cause": "", "evidence": [], "remediation": [], "confidence": 0.0}\n'
        "No prose. JSON only."
    )
    raw = _call_claude(sys, prompt)
    data = _extract_json(raw) or {}
    if not data:
        data = {
            "protocol": "bgp",
            "affected_device": _guess_device(prompt),
            "state": "Idle",
            "root_cause": "Best-effort offline diagnosis (no LLM available).",
            "evidence": [prompt[:200]],
            "remediation": [
                "Verify L1/L2 — interface up/up",
                "Verify L3 — ping peer IP",
                "Compare local/remote AS, MTU, area, auth",
                "If config matches, soft-reset the neighbor (clear bgp neighbor)",
            ],
            "confidence": 0.4,
        }
    try:
        return RoutingDiagnosis(**data)
    except (TypeError, ValueError) as e:
        logger.warning("RoutingDiagnosis validation failed: %s", e)
        return RoutingDiagnosis(root_cause="parsing failed", evidence=[raw[:300]])


def acl_agent(prompt: str) -> ACLDiagnosis:
    sys = (
        "You are a firewall/ACL specialist. Respond with strict JSON matching:\n"
        '{"device": "", "policy_name": "", "flow": {"src":"","dst":"","port":0,"proto":""},'
        '"decision": "deny|permit|drop|unknown", "matching_line": "", "root_cause": "",'
        '"proposed_change": "", "confidence": 0.0}\n'
        "No prose. JSON only."
    )
    raw = _call_claude(sys, prompt)
    data = _extract_json(raw) or {}
    if not data:
        data = {
            "device": _guess_device(prompt),
            "policy_name": None,
            "flow": {},
            "decision": "deny",
            "root_cause": "Best-effort offline diagnosis (no LLM available).",
            "proposed_change": "Add specific permit rule (avoid any/any) for the legitimate flow.",
            "confidence": 0.4,
        }
    try:
        return ACLDiagnosis(**data)
    except (TypeError, ValueError) as e:
        logger.warning("ACLDiagnosis validation failed: %s", e)
        return ACLDiagnosis(root_cause="parsing failed")


def incident_agent(prompt: str, severity_hint: str = "medium") -> IncidentTicket:
    sys = (
        "You are an NOC analyst creating an incident ticket. Respond with strict JSON matching:\n"
        '{"ticket_id":"","severity":"low|medium|high|critical","title":"","summary":"",'
        '"affected_devices":[], "root_cause":"", "remediation_steps":[], "requires_change_window": false}\n'
        "No prose. JSON only."
    )
    raw = _call_claude(sys, prompt)
    data = _extract_json(raw) or {}
    if not data.get("ticket_id"):
        data.setdefault("ticket_id", f"INC-{int(time.time())}")
        data.setdefault("severity", severity_hint)
        data.setdefault("title", prompt[:80])
        data.setdefault("summary", prompt[:300])
        data.setdefault("affected_devices", [_guess_device(prompt)])
        data.setdefault("root_cause", "Pending investigation.")
        data.setdefault("remediation_steps", ["Triage and assign to network on-call."])
        data.setdefault("requires_change_window", False)
    try:
        return IncidentTicket(**data)
    except (TypeError, ValueError) as e:
        logger.warning("IncidentTicket validation failed: %s", e)
        return IncidentTicket(ticket_id=f"INC-{int(time.time())}", title=prompt[:80])


def _guess_device(prompt: str) -> str:
    m = re.search(r"\b([a-z]{2,4}-[a-z0-9]+-\d{2}[a-z]?)\b", prompt)
    return m.group(1) if m else ""


# ─── Orchestrator entrypoint ─────────────────────────────────────────────────


def run_orchestrator(prompt: str) -> str:
    """
    Top-level entrypoint used by eval_harness and the UI.
    Returns a human-readable string (so it slots into the existing ai_command UI).
    """
    decision = _classify(prompt)
    if decision == "routing":
        result: BaseModel = routing_agent(prompt)
    elif decision == "acl":
        result = acl_agent(prompt)
    elif decision == "incident":
        result = incident_agent(prompt)
    else:
        result = routing_agent(prompt)

    payload = result.model_dump()
    return _format_for_human(decision, payload)


def run_orchestrator_structured(prompt: str) -> dict[str, Any]:
    """Same as run_orchestrator but returns the dict envelope for API/UI."""
    decision = _classify(prompt)
    _pop_last_usage()  # reset before invocation
    if decision == "routing":
        result: BaseModel = routing_agent(prompt)
    elif decision == "acl":
        result = acl_agent(prompt)
    elif decision == "incident":
        result = incident_agent(prompt)
    else:
        result = routing_agent(prompt)
    usage = _pop_last_usage()

    return {
        "agent": decision,
        "result": result.model_dump(),
        "rendered": _format_for_human(decision, result.model_dump()),
        "online": _has_anthropic(),
        "usage": usage,
    }


def _format_for_human(agent: str, data: dict[str, Any]) -> str:
    lines: list[str] = [f"[{agent.upper()} AGENT]"]
    if agent == "routing":
        lines.append(f"Protocol: {data.get('protocol')}")
        lines.append(f"Device:   {data.get('affected_device')}")
        if data.get("affected_peer"):
            lines.append(f"Peer:     {data.get('affected_peer')}")
        lines.append(f"State:    {data.get('state')}")
        lines.append(f"Root cause: {data.get('root_cause')}")
        if data.get("evidence"):
            lines.append("Evidence:")
            for e in data["evidence"]:
                lines.append(f"  - {e}")
        if data.get("remediation"):
            lines.append("Remediation:")
            for r in data["remediation"]:
                lines.append(f"  - {r}")
        lines.append(f"Confidence: {data.get('confidence')}")
    elif agent == "acl":
        lines.append(f"Device:   {data.get('device')}")
        lines.append(f"Policy:   {data.get('policy_name')}")
        lines.append(f"Decision: {data.get('decision')}")
        if data.get("matching_line"):
            lines.append(f"Matching line: {data['matching_line']}")
        lines.append(f"Root cause: {data.get('root_cause')}")
        if data.get("proposed_change"):
            lines.append(f"Proposed change: {data['proposed_change']}")
    elif agent == "incident":
        lines.append(f"Ticket: {data.get('ticket_id')} [{data.get('severity')}]")
        lines.append(f"Title:  {data.get('title')}")
        lines.append(f"Summary: {data.get('summary')}")
        if data.get("affected_devices"):
            lines.append(f"Affected: {', '.join(data['affected_devices'])}")
        lines.append(f"Root cause: {data.get('root_cause')}")
        if data.get("remediation_steps"):
            lines.append("Remediation steps:")
            for s in data["remediation_steps"]:
                lines.append(f"  - {s}")
        lines.append(f"Change window required: {data.get('requires_change_window')}")
    return "\n".join(lines)
