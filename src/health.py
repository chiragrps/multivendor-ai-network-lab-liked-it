"""Per-device health collector — single-device operational snapshot over SSH.

Inspired by scottpeterman/what_a_NOS_could_be: instead of polling SNMP, just run a
focused set of `show` commands in parallel and return one structured JSON document
with everything an engineer wants to see on a device dashboard.

Schema (every key is always present; missing data → None / [] / {}):

    {
      "meta": {
        "hostname": str,
        "ip": str,
        "dtype": str,             # frr | eos | junos | arista-eos | nokia-srl
        "collected_at": float,    # unix epoch
        "collect_time": float,    # seconds total
        "via": str,               # ssh | docker-exec
        "errors": [str],          # non-fatal per-command errors
      },
      "version": {"raw": str, "version": str | None, "uptime": str | None},
      "bgp":     {"peers": [{"neighbor", "asn", "state", "uptime", "prefixes"}],
                  "established": int, "down": int},
      "ospf":    {"neighbors": [{"neighbor", "state", "interface", "dead_time"}],
                  "full": int},
      "interfaces": {"list": [{"name", "status", "addresses"}], "up": int, "down": int},
      "routes":  {"total": int | None, "by_protocol": {protocol: count}},
      "memory":  {"used_mb": float | None, "total_mb": float | None, "pct": float | None},
      "cpu":     {"pct_1min": float | None},
    }

Design choices:

* **Stateless.** Re-run on every request — the caller (Flask route or MCP tool) owns
  caching. Keeps the module easy to test and reason about.
* **Parallel.** Commands fan out via ThreadPoolExecutor — 8+ vtysh calls in <2s on the lab.
* **Soft failures.** A failed command goes into `meta.errors` as a string; never raises.
  The dashboard can render partial data.
* **Vendor-aware command sets.** FRR/Arista/Junos all have different "show" verbs;
  the map below is the only thing that needs editing to add a new platform.

This module imports nothing from `app.py` directly — it takes a `runner` callable to
avoid the 15K-line app.py import surface in tests.
"""
from __future__ import annotations

import json
import logging
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Type alias: runner(ip, dtype, command, port=22) -> {"success", "output", ...}
RunnerCallable = Callable[..., dict]


# ---------------------------------------------------------------------------
# Vendor command tables. Order matters within a section — first command that
# returns useful output wins. JSON variants come before text fallbacks.
# ---------------------------------------------------------------------------

FRR_COMMANDS: dict[str, list[str]] = {
    "version":    ["show version"],
    "bgp":        ["show ip bgp summary json", "show ip bgp summary"],
    "ospf":       ["show ip ospf neighbor json", "show ip ospf neighbor"],
    "interfaces": ["show interface brief json", "show interface brief"],
    "routes":     ["show ip route summary json", "show ip route summary"],
    "memory":     ["show memory summary"],
    "cpu":        ["show thread cpu"],  # FRR exposes thread CPU; vtysh has no proc CPU
}

EOS_COMMANDS: dict[str, list[str]] = {
    "version":    ["show version | json", "show version"],
    "bgp":        ["show ip bgp summary | json", "show ip bgp summary"],
    "ospf":       ["show ip ospf neighbor | json", "show ip ospf neighbor"],
    "interfaces": ["show interfaces status | json", "show interfaces status"],
    "routes":     ["show ip route summary | json", "show ip route summary"],
    "memory":     ["show processes top once | json", "show version"],
    "cpu":        ["show processes top once | json"],
}

JUNOS_COMMANDS: dict[str, list[str]] = {
    "version":    ["show version | display json", "show version"],
    "bgp":        ["show bgp summary | display json", "show bgp summary"],
    "ospf":       ["show ospf neighbor | display json", "show ospf neighbor"],
    "interfaces": ["show interfaces terse | display json", "show interfaces terse"],
    "routes":     ["show route summary | display json", "show route summary"],
    "memory":     ["show system memory | display json", "show system memory"],
    "cpu":        ["show system processes extensive"],
}

COMMAND_MAP: dict[str, dict[str, list[str]]] = {
    "frr":        FRR_COMMANDS,
    "eos":        EOS_COMMANDS,
    "arista-eos": EOS_COMMANDS,
    "arista":     EOS_COMMANDS,
    "junos":      JUNOS_COMMANDS,
}

# Per-command timeout — vtysh is fast, but if a remote routing daemon is wedged
# we don't want one bad command to gate the whole snapshot.
COMMAND_TIMEOUT_S = 15
SNAPSHOT_TIMEOUT_S = 30


def collect_health(
    hostname: str,
    ip: str,
    dtype: str,
    port: int = 22,
    runner: Optional[RunnerCallable] = None,
    commands: Optional[dict[str, list[str]]] = None,
) -> dict:
    """Collect a full health snapshot for one device.

    Args:
        hostname/ip/dtype/port: device identity (typically from inventory).
        runner: callable that executes a single command on a device. Defaults to the
            production `run_command_on_device` from `app`. Pass a fake for testing.
        commands: vendor command table override — defaults to COMMAND_MAP[dtype].

    Returns the JSON-shaped dict described in the module docstring. Never raises;
    individual command failures land in `meta.errors`.
    """
    t0 = time.time()
    errors: list[str] = []

    if runner is None:
        # Lazy import — keeps the module importable in tests without paramiko.
        from app import run_command_on_device  # type: ignore[import-not-found]
        runner = run_command_on_device

    cmd_table = commands or COMMAND_MAP.get(dtype.lower())
    if cmd_table is None:
        errors.append(f"unsupported dtype: {dtype!r}")
        return _empty_snapshot(hostname, ip, dtype, t0, errors)

    # Fan out commands in parallel — fail-fast per command, never block the whole snapshot.
    raw: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(cmd_table)) as pool:
        future_to_section = {
            pool.submit(_run_with_fallback, runner, ip, dtype, cmds, port): section
            for section, cmds in cmd_table.items()
        }
        deadline = time.time() + SNAPSHOT_TIMEOUT_S
        for fut in as_completed(future_to_section, timeout=SNAPSHOT_TIMEOUT_S):
            section = future_to_section[fut]
            try:
                raw[section] = fut.result(timeout=max(1.0, deadline - time.time()))
            except Exception as exc:  # noqa: BLE001 — surface any error, never raise
                errors.append(f"{section}: {exc}")
                raw[section] = {"success": False, "output": "", "command": ""}

    snapshot = _empty_snapshot(hostname, ip, dtype, t0, errors)
    snapshot["meta"]["via"] = raw.get("version", {}).get("via", "ssh")

    snapshot["version"]    = _parse_version(raw.get("version", {}), dtype)
    snapshot["bgp"]        = _parse_bgp(raw.get("bgp", {}), dtype)
    snapshot["ospf"]       = _parse_ospf(raw.get("ospf", {}), dtype)
    snapshot["interfaces"] = _parse_interfaces(raw.get("interfaces", {}), dtype)
    snapshot["routes"]     = _parse_routes(raw.get("routes", {}), dtype)
    snapshot["memory"]     = _parse_memory(raw.get("memory", {}), dtype)
    snapshot["cpu"]        = _parse_cpu(raw.get("cpu", {}), dtype)

    snapshot["meta"]["collect_time"] = round(time.time() - t0, 3)
    # Append any per-command errors discovered during parsing
    for section, result in raw.items():
        if not result.get("success") and result.get("error"):
            errors.append(f"{section}: {result['error']}")
    return snapshot


def _run_with_fallback(
    runner: RunnerCallable, ip: str, dtype: str, commands: list[str], port: int,
) -> dict:
    """Try each command in order; return the first one that succeeds with non-empty output."""
    last_result: dict = {"success": False, "output": "", "command": ""}
    for cmd in commands:
        try:
            result = runner(ip, dtype, cmd, port=port)
        except TypeError:
            # Some runners don't accept the port kwarg — retry without
            result = runner(ip, dtype, cmd)
        last_result = result or last_result
        if result and result.get("success") and (result.get("output") or "").strip():
            return result
    return last_result


def _empty_snapshot(hostname: str, ip: str, dtype: str, t0: float, errors: list[str]) -> dict:
    """Return the default schema with empty values. Mutated in-place by collect_health."""
    return {
        "meta": {
            "hostname": hostname,
            "ip": ip,
            "dtype": dtype,
            "collected_at": t0,
            "collect_time": 0.0,
            "via": "ssh",
            "errors": errors,
        },
        "version":    {"raw": "", "version": None, "uptime": None},
        "bgp":        {"peers": [], "established": 0, "down": 0},
        "ospf":       {"neighbors": [], "full": 0},
        "interfaces": {"list": [], "up": 0, "down": 0},
        "routes":     {"total": None, "by_protocol": {}},
        "memory":     {"used_mb": None, "total_mb": None, "pct": None},
        "cpu":        {"pct_1min": None},
    }


# ---------------------------------------------------------------------------
# Parsers. Each one takes the raw runner result + dtype, returns the schema
# slice. Soft-failing — bad input → empty/None values, never an exception.
# ---------------------------------------------------------------------------

def _try_json(output: str) -> Optional[dict]:
    """Best-effort JSON parse — returns None if the output isn't JSON."""
    if not output:
        return None
    try:
        return json.loads(output)
    except (ValueError, TypeError):
        return None


def _parse_version(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"raw": output[:500], "version": None, "uptime": None}
    if not output:
        return out

    if dtype == "frr":
        # "FRRouting 9.1.0 (de-fra-core-01) compiled on 2024-01-15."
        m = re.search(r"FRRouting\s+(\S+)", output)
        if m:
            out["version"] = m.group(1)
        m = re.search(r"uptime\s+is\s+(.+?)$", output, re.MULTILINE | re.IGNORECASE)
        if m:
            out["uptime"] = m.group(1).strip()
        return out

    data = _try_json(output)
    if data:
        # EOS json shape: {"version": "...", "uptime": float-seconds, ...}
        if isinstance(data, dict):
            out["version"] = data.get("version") or data.get("softwareImageVersion")
            uptime = data.get("uptime") or data.get("bootupTimestamp")
            if isinstance(uptime, (int, float)):
                out["uptime"] = f"{int(uptime)}s"
            elif isinstance(uptime, str):
                out["uptime"] = uptime
        return out

    # Generic free-form fallback
    m = re.search(r"(?:version|software)\D*([\d.]+\S*)", output, re.IGNORECASE)
    if m:
        out["version"] = m.group(1)
    m = re.search(r"uptime\s+is\s+(.+?)$", output, re.MULTILINE | re.IGNORECASE)
    if m:
        out["uptime"] = m.group(1).strip()
    return out


def _parse_bgp(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"peers": [], "established": 0, "down": 0}
    if not output:
        return out

    data = _try_json(output)
    if data and isinstance(data, dict):
        # FRR JSON shape: {"ipv4Unicast": {"peers": {"10.x.x.x": {...}}}}
        peers_block = None
        if "ipv4Unicast" in data:
            peers_block = data["ipv4Unicast"].get("peers", {})
        elif "peers" in data:
            peers_block = data["peers"]
        elif "vrfs" in data:
            # Arista EOS json: {"vrfs": {"default": {"peers": {...}}}}
            default_vrf = data["vrfs"].get("default", {})
            peers_block = default_vrf.get("peers", {})

        if isinstance(peers_block, dict):
            for neighbor, info in peers_block.items():
                state = (info.get("state") or info.get("peerState") or "").lower()
                established = state in ("established", "estab")
                peer = {
                    "neighbor": neighbor,
                    "asn": info.get("remoteAs") or info.get("asn"),
                    "state": "Established" if established else (state.title() or "Down"),
                    "uptime": _fmt_uptime(info.get("peerUptime")
                                          or info.get("uptime")
                                          or info.get("upDownTime")),
                    "prefixes": info.get("pfxRcd") or info.get("prefixReceived") or 0,
                }
                out["peers"].append(peer)
                if established:
                    out["established"] += 1
                else:
                    out["down"] += 1
            return out

    # Text fallback — Cisco-style 11-column summary (FRR / EOS / IOS all look similar)
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        # Heuristic: first column looks like an IP, second is BGP version number
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            continue
        state_or_prefixes = parts[-1]
        established = state_or_prefixes.isdigit()
        peer = {
            "neighbor": parts[0],
            "asn": parts[2] if parts[2].isdigit() else None,
            "state": "Established" if established else state_or_prefixes,
            "uptime": parts[-2],
            "prefixes": int(state_or_prefixes) if established else 0,
        }
        out["peers"].append(peer)
        if established:
            out["established"] += 1
        else:
            out["down"] += 1
    return out


def _parse_ospf(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"neighbors": [], "full": 0}
    if not output:
        return out

    data = _try_json(output)
    if data and isinstance(data, dict):
        # FRR json shape: {"neighbors": {"<router-id>": [{...}, ...]}}
        if "neighbors" in data and isinstance(data["neighbors"], dict):
            for router_id, entries in data["neighbors"].items():
                if not isinstance(entries, list):
                    entries = [entries]
                for entry in entries:
                    state = (entry.get("converged") or entry.get("nbrState") or "").lower()
                    is_full = "full" in state
                    out["neighbors"].append({
                        "neighbor": router_id,
                        "state": "Full" if is_full else state.title() or "Init",
                        "interface": entry.get("ifaceName") or entry.get("interface"),
                        "dead_time": entry.get("upTimeInMsec") or entry.get("deadTimeMsecs"),
                    })
                    if is_full:
                        out["full"] += 1
            return out

    # Text fallback — Cisco-style table
    for line in output.splitlines():
        m = re.match(
            r"^\s*(\S+)\s+\d+\s+(\S+)/\S+\s+([\d:hms]+)\s+(\S+)\s+(\S+)",
            line,
        )
        if m:
            state = m.group(2).lower()
            is_full = "full" in state
            out["neighbors"].append({
                "neighbor": m.group(1),
                "state": "Full" if is_full else m.group(2),
                "interface": m.group(5),
                "dead_time": m.group(3),
            })
            if is_full:
                out["full"] += 1
    return out


def _parse_interfaces(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"list": [], "up": 0, "down": 0}
    if not output:
        return out

    data = _try_json(output)
    if data and isinstance(data, dict):
        # FRR: {"<name>": {"administrativeStatus": "up", "operationalStatus": "up", ...}}
        # EOS: {"interfaceStatuses": {"Ethernet1": {"linkStatus": "connected", ...}}}
        items = data.get("interfaceStatuses", data)
        if isinstance(items, dict):
            for name, info in items.items():
                if not isinstance(info, dict):
                    continue
                status = (
                    info.get("operationalStatus")
                    or info.get("linkStatus")
                    or info.get("lineProtocolStatus")
                    or ""
                ).lower()
                is_up = status in ("up", "connected")
                addresses = []
                for addr in info.get("ipAddresses", info.get("addresses", [])) or []:
                    if isinstance(addr, dict):
                        addresses.append(addr.get("address") or addr.get("ipAddr") or "")
                    elif isinstance(addr, str):
                        addresses.append(addr)
                out["list"].append({
                    "name": name,
                    "status": "up" if is_up else (status or "down"),
                    "addresses": [a for a in addresses if a],
                })
                if is_up:
                    out["up"] += 1
                else:
                    out["down"] += 1
            return out

    # Text fallback — "Interface  Status  VRF  Addresses"
    in_table = False
    for line in output.splitlines():
        if re.match(r"^\s*Interface\s+", line):
            in_table = True
            continue
        if not in_table or not line.strip():
            continue
        parts = line.split(None, 3)
        if len(parts) < 2:
            continue
        name, status = parts[0], parts[1].lower()
        is_up = status in ("up", "connected")
        addresses = [parts[3]] if len(parts) > 3 and "/" in parts[3] else []
        out["list"].append({"name": name, "status": "up" if is_up else status,
                            "addresses": addresses})
        if is_up:
            out["up"] += 1
        else:
            out["down"] += 1
    return out


def _parse_routes(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"total": None, "by_protocol": {}}
    if not output:
        return out

    data = _try_json(output)
    if data and isinstance(data, dict):
        # FRR: {"routesTotal": 42, "routesTotalFib": 40, "routes": {...}}
        out["total"] = data.get("routesTotal") or data.get("totalRoutes")
        # Best-effort: try to pull protocol breakdown
        proto_block = data.get("routes") or data.get("byProtocol") or {}
        if isinstance(proto_block, dict):
            for proto, count in proto_block.items():
                if isinstance(count, int):
                    out["by_protocol"][proto] = count
        return out

    # Text fallback: "Route Source   Routes  FIB"
    total = 0
    for line in output.splitlines():
        m = re.match(r"^\s*(connected|static|kernel|bgp|ospf|isis|rip)\s+(\d+)", line, re.I)
        if m:
            proto, count = m.group(1).lower(), int(m.group(2))
            out["by_protocol"][proto] = count
            total += count
    if total:
        out["total"] = total
    return out


def _parse_memory(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"used_mb": None, "total_mb": None, "pct": None}
    if not output:
        return out

    # FRR `show memory summary` example:
    #   System allocator statistics:
    #     Total heap allocated:  16 MiB
    #     Holding block headers: ...
    m_total = re.search(r"Total heap allocated:\s+(\d+(?:\.\d+)?)\s*(KiB|MiB|GiB)", output)
    if m_total:
        val = float(m_total.group(1))
        unit = m_total.group(2)
        scale = {"KiB": 1 / 1024, "MiB": 1.0, "GiB": 1024.0}.get(unit, 1.0)
        out["used_mb"] = round(val * scale, 1)

    # /proc/meminfo style: "MemTotal: 16384 kB" / "MemFree: 8192 kB"
    m_t = re.search(r"MemTotal:?\s+(\d+)\s*(?:kB|KB)?", output, re.IGNORECASE)
    m_f = re.search(r"MemFree:?\s+(\d+)\s*(?:kB|KB)?", output, re.IGNORECASE)
    if m_t:
        out["total_mb"] = round(int(m_t.group(1)) / 1024, 1)
        if m_f:
            out["used_mb"] = round(out["total_mb"] - int(m_f.group(1)) / 1024, 1)
            out["pct"] = round(out["used_mb"] / out["total_mb"] * 100, 1)
    return out


def _parse_cpu(result: dict, dtype: str) -> dict:
    output = (result.get("output") or "").strip()
    out = {"pct_1min": None}
    if not output:
        return out

    # FRR `show thread cpu` per-thread breakdown — pick the worst offender
    # Format: "CPU usage averaged over 1m: <usr>%/<sys>% ..."  (varies by version)
    m = re.search(r"(?:CPU|Total).*?(\d+(?:\.\d+)?)\s*%", output)
    if m:
        try:
            out["pct_1min"] = float(m.group(1))
        except ValueError:
            pass

    data = _try_json(output)
    if data and isinstance(data, dict):
        # EOS show processes top once | json
        if "processes" in data:
            total = 0.0
            for proc in (data["processes"] or {}).values():
                if isinstance(proc, dict):
                    total += float(proc.get("cpuPctShared") or proc.get("cpuPct") or 0)
            out["pct_1min"] = round(total, 1)
    return out


def _fmt_uptime(val) -> str:
    """Normalize uptime values from various JSON shapes into a string."""
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        # FRR returns peerUptimeMsec (milliseconds since epoch start)
        seconds = int(val / 1000) if val > 10**9 else int(val)
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m{seconds % 60}s"
        if seconds < 86400:
            return f"{seconds // 3600}h{(seconds % 3600) // 60}m"
        return f"{seconds // 86400}d{(seconds % 86400) // 3600}h"
    return str(val)
