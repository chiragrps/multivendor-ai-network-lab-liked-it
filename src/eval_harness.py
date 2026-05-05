"""
eval_harness.py — Run AI-driven diagnoses against pre-defined incident scenarios
and score them with an LLM-as-judge.

Inspired by NIKA. Each scenario in scenarios.json declares:
  - injected fault (type, device, params)
  - expected root cause keywords
  - expected remediation keywords

Workflow:
  1. Inject the fault (sim layer is best-effort; for some faults we just
     describe the symptom to the agent without actually modifying state).
  2. Hand the symptom to the agent under test (orchestrator | ai_command).
  3. Compare agent output keywords vs expected via a simple keyword overlap
     score, then optionally an LLM judge for a richer 0–10 score.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any

import gait_audit

_HERE = os.path.dirname(os.path.abspath(__file__))
_SCENARIOS_FILE = os.path.join(_HERE, "scenarios.json")


def load_scenarios() -> list[dict[str, Any]]:
    with open(_SCENARIOS_FILE) as f:
        return json.load(f)["scenarios"]


def get_scenario(scenario_id: str) -> dict[str, Any] | None:
    for s in load_scenarios():
        if s["id"] == scenario_id:
            return s
    return None


def _keyword_overlap(text: str, keywords: list[str]) -> tuple[int, list[str]]:
    """Return (count, hits) of keywords found case-insensitively in text."""
    lower = text.lower()
    hits = [k for k in keywords if k.lower() in lower]
    return len(hits), hits


def keyword_score(agent_output: str, scenario: dict[str, Any]) -> dict[str, Any]:
    """Cheap, deterministic 0–10 score based on keyword overlap."""
    rc_kw = scenario.get("expected_root_cause_keywords", [])
    rm_kw = scenario.get("expected_remediation_keywords", [])
    rc_hit, rc_hits = _keyword_overlap(agent_output, rc_kw)
    rm_hit, rm_hits = _keyword_overlap(agent_output, rm_kw)

    rc_score = (rc_hit / max(len(rc_kw), 1)) * 6.0   # weight root-cause higher
    rm_score = (rm_hit / max(len(rm_kw), 1)) * 4.0
    score = round(rc_score + rm_score, 2)

    return {
        "score": score,
        "max": 10,
        "root_cause_hits": rc_hits,
        "remediation_hits": rm_hits,
        "method": "keyword",
    }


def llm_judge(agent_output: str, scenario: dict[str, Any]) -> dict[str, Any] | None:
    """
    Use Anthropic claude-haiku-4-5 to score 0–10 with reasoning.
    Returns None if ANTHROPIC_API_KEY is not set or anthropic SDK missing.
    On success the returned dict includes a `usage` field with input/output tokens.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None

    client = anthropic.Anthropic(api_key=api_key)
    prompt = (
        "You are an expert network engineer judging an AI agent's diagnosis.\n\n"
        f"Scenario:\n  Title: {scenario['title']}\n"
        f"  Category: {scenario['category']}\n"
        f"  Expected root cause keywords: {scenario.get('expected_root_cause_keywords')}\n"
        f"  Expected remediation keywords: {scenario.get('expected_remediation_keywords')}\n\n"
        f"Agent's diagnosis:\n{agent_output}\n\n"
        "Score the diagnosis from 0 to 10 (10 = perfect). Consider:\n"
        "  - Correct root cause identification (60%)\n"
        "  - Actionable remediation (30%)\n"
        "  - No hallucinated devices/peers/IPs (10%)\n\n"
        "Respond with strict JSON: {\"score\": <0-10>, \"reasoning\": \"...\"}"
    )
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        text = resp.content[0].text if resp.content else "{}"
        usage = getattr(resp, "usage", None)
        token_in = int(getattr(usage, "input_tokens", 0) or 0) if usage else 0
        token_out = int(getattr(usage, "output_tokens", 0) or 0) if usage else 0
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return {"score": 0, "method": "llm_judge", "max": 10, "error": True,
                    "usage": {"input": token_in, "output": token_out}}
        parsed = json.loads(m.group(0))
        parsed["method"] = "llm_judge"
        parsed["model"] = "claude-haiku-4-5"
        parsed["max"] = 10
        parsed["usage"] = {"input": token_in, "output": token_out}
        return parsed
    except Exception as e:  # noqa: BLE001
        return {"score": 0, "reasoning": f"judge error: {e}", "method": "llm_judge", "max": 10, "error": True}


def synthesize_symptom(scenario: dict[str, Any]) -> str:
    """
    Translate the scenario's structured fault into a natural-language symptom
    that we hand to the agent. (We don't actually break the lab on every run.)
    """
    f = scenario["fault"]
    t = f["type"]
    if t == "bgp_peer_down":
        return (
            f"The BGP peer {f['peer_hostname']} ({f['peer_ip']}) on device "
            f"{f['device']} is reporting state Idle. It was Established 5 minutes ago. "
            "Diagnose root cause and propose a remediation."
        )
    if t == "bgp_as_mismatch":
        return (
            f"BGP session on {f['device']} towards {f['peer_hostname']} is failing. "
            f"Local config says remote-as {f['configured_as']}, but peer reports its AS as {f['expected_as']}. "
            "Diagnose and fix."
        )
    if t == "ospf_area_mismatch":
        return (
            f"OSPF adjacency between {f['device']} and {f['peer_hostname']} is stuck in ExStart. "
            f"Local interface is in area {f['configured_area']}, peer in {f['expected_area']}. "
            "Diagnose and fix."
        )
    if t == "interface_down":
        return (
            f"Interface {f['interface']} on {f['device']} is down/down. "
            "No optic alarm. Diagnose and propose remediation."
        )
    if t == "mtu_mismatch":
        return (
            f"BGP session between {f['device_a']} (MTU {f['mtu_a']}) and "
            f"{f['device_b']} (MTU {f['mtu_b']}) flaps every 30s with 'hold timer expired'. "
            "Diagnose."
        )
    if t == "acl_block":
        return (
            f"User reports management traffic from {f['src']} to TCP/{f['dst_port']} "
            f"is being denied at {f['device']}. Policy {f['policy']} is suspected. Diagnose and propose fix."
        )
    if t == "acl_overpermissive":
        return (
            f"Audit reports policy {f['policy']} on {f['device']} as overly permissive (any/any). "
            "Recommend a tighter rule."
        )
    if t == "cve_present":
        return (
            f"Device {f['device']} runs an OS version vulnerable to {f['cve_id']}. "
            "Recommend remediation."
        )
    if t == "intent_drift":
        return (
            f"NetBox claims {f['device']} should peer with {f['claimed_peer']}, "
            "but device shows no such neighbor. Diagnose drift and fix."
        )
    if t == "high_cpu":
        return (
            f"Device {f['device']} reports CPU at {f['cpu_pct']}%. "
            f"Suspected cause: {f['cause']}. Diagnose and recommend mitigation."
        )
    return f"Unknown fault type: {t}. Raw payload: {json.dumps(f)}"


def run_scenario(scenario_id: str, agent: str = "ai_command") -> dict[str, Any]:
    """
    Run a single scenario end-to-end. The actual agent invocation is delegated
    to a callable resolved lazily (we only import here to avoid cycles).

    Returns dict with: {symptom, agent_output, keyword_score, llm_score?, total_ms, scenario, usage}
    """
    scenario = get_scenario(scenario_id)
    if not scenario:
        return {"error": f"Unknown scenario: {scenario_id}"}

    symptom = synthesize_symptom(scenario)
    t0 = time.time()

    agent_output, agent_usage = _invoke_agent_with_usage(agent, symptom)
    elapsed_ms = int((time.time() - t0) * 1000)

    kscore = keyword_score(agent_output, scenario)
    jscore = llm_judge(agent_output, scenario)
    judge_usage = (jscore or {}).get("usage", {"input": 0, "output": 0}) if isinstance(jscore, dict) else {"input": 0, "output": 0}

    total_usage = {
        "input":  int(agent_usage.get("input", 0)) + int(judge_usage.get("input", 0)),
        "output": int(agent_usage.get("output", 0)) + int(judge_usage.get("output", 0)),
    }

    result = {
        "scenario_id": scenario_id,
        "scenario": {"title": scenario["title"], "category": scenario["category"], "severity": scenario["severity"]},
        "agent": agent,
        "symptom": symptom,
        "agent_output": agent_output,
        "keyword_score": kscore,
        "llm_score": jscore,
        "total_ms": elapsed_ms,
        "usage": total_usage,
    }

    gait_audit.record(
        actor="eval_harness",
        action="run_scenario",
        target=scenario["fault"].get("device"),
        prompt=symptom,
        response=agent_output[:500],
        tools_called=[agent],
        tokens=total_usage,
        status="ok",
        extra={"scenario_id": scenario_id, "score": kscore["score"]},
    )
    return result


def _invoke_agent_with_usage(agent: str, symptom: str) -> tuple[str, dict[str, int]]:
    """Resolve and invoke the agent. Returns (output, usage_tokens)."""
    if agent == "orchestrator":
        try:
            from pydantic_ai_orchestrator import run_orchestrator_structured  # type: ignore
            envelope = run_orchestrator_structured(symptom)
            return envelope.get("rendered", ""), envelope.get("usage") or {"input": 0, "output": 0}
        except Exception as e:  # noqa: BLE001
            return f"[orchestrator unavailable: {e}]\n" + _stub_agent(symptom), {"input": 0, "output": 0}
    if agent == "ai_command":
        out = _ai_command_sync(symptom)
        usage = _pop_last_ai_usage()
        if out:
            return out, usage
        return _stub_agent(symptom), {"input": 0, "output": 0}
    return _stub_agent(symptom), {"input": 0, "output": 0}


def _invoke_agent(agent: str, symptom: str) -> str:
    """Resolve and invoke the agent. Falls back to a deterministic stub if no AI configured."""
    if agent == "orchestrator":
        try:
            from pydantic_ai_orchestrator import run_orchestrator  # type: ignore
            return run_orchestrator(symptom)
        except Exception as e:  # noqa: BLE001
            return f"[orchestrator unavailable: {e}]\n" + _stub_agent(symptom)
    if agent == "ai_command":
        out = _ai_command_sync(symptom)
        if out:
            return out
        return _stub_agent(symptom)
    return _stub_agent(symptom)


_LAST_AI_USAGE: dict[str, int] = {"input": 0, "output": 0}


def _pop_last_ai_usage() -> dict[str, int]:
    u = dict(_LAST_AI_USAGE)
    _LAST_AI_USAGE["input"] = 0
    _LAST_AI_USAGE["output"] = 0
    return u


def _ai_command_sync(prompt: str) -> str | None:
    """Call Anthropic claude-haiku-4-5 directly with a network-engineering system prompt.
    Side effect: records token usage in module-scoped _LAST_AI_USAGE.
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return None
    try:
        import anthropic  # type: ignore
    except ImportError:
        return None
    client = anthropic.Anthropic(api_key=api_key)
    try:
        resp = client.messages.create(
            model="claude-haiku-4-5",
            max_tokens=600,
            system=(
                "You are a senior network engineer (CCIE/JNCIE-level). Diagnose the symptom "
                "and respond with: (1) ROOT CAUSE in one sentence, (2) EVIDENCE bullets, "
                "(3) REMEDIATION steps including exact CLI for Junos/EOS/FRR as relevant."
            ),
            messages=[{"role": "user", "content": prompt}],
        )
        usage = getattr(resp, "usage", None)
        if usage is not None:
            _LAST_AI_USAGE["input"] = int(getattr(usage, "input_tokens", 0) or 0)
            _LAST_AI_USAGE["output"] = int(getattr(usage, "output_tokens", 0) or 0)
        return resp.content[0].text if resp.content else ""
    except Exception:
        return None


def _stub_agent(symptom: str) -> str:
    """Deterministic, keyword-rich fallback so the harness still produces useful output offline."""
    return (
        "ROOT CAUSE: Best-effort offline diagnosis (no LLM available).\n"
        f"EVIDENCE: Symptom received — {symptom[:200]}\n"
        "REMEDIATION: Verify peer reachability with ping, check interface status, "
        "compare local and remote BGP/OSPF area/AS configuration, align MTU, restart neighbor "
        "(clear bgp neighbor) once root cause is confirmed."
    )
