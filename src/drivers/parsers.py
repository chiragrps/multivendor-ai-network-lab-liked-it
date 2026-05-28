"""Standalone, vendor-tagged parsers for the driver layer.

Ported from ``src/health.py`` (BGP / OSPF / interfaces / routes / version) and
``network-lab/telemetry/clab_collector.py`` (interface counters). Differences
vs. health.py:

* Functions take ``(vendor, raw)`` — a vendor string and the *raw* output text —
  instead of a runner-result dict + dtype. This makes them trivially testable.
* Every function SOFT-FAILS: bad / empty / unexpected input returns the fixed
  empty shape for that section. They never raise.
* Normalized shapes follow the spec:
    - bgp:                {"peers": [...], "established": int, "total": int}
    - ospf:               {"neighbors": [...], "full": int, "total": int}
    - interfaces:         {"list": [...], "up": int, "total": int}
    - interface_counters: {"interfaces": [{interface, in_octets, ...}]}
    - routes:             {"total": int|None, "by_protocol": {proto: count}}
    - version:            {"version": str|None, "uptime": str|None, "raw": str}
"""
from __future__ import annotations

import json
import re

from .commands import canonical_vendor

_SRL_VENDORS = ("nokia-srl", "srl", "nokia")


# ───────────────────────────── helpers ────────────────────────────────────────

def _try_json(output: str) -> dict | list | None:
    """Best-effort JSON parse — tolerates leading banner text before the body."""
    if not output:
        return None
    text = output.strip()
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    # cEOS / sr_cli sometimes print a banner line before the JSON body.
    start = text.find("{")
    if start == -1:
        start = text.find("[")
    if start == -1:
        return None
    try:
        return json.loads(text[start:])
    except (ValueError, TypeError):
        return None


def _fmt_uptime(val: object) -> str:
    """Normalize uptime values from various JSON shapes into a string."""
    if val is None:
        return ""
    if isinstance(val, (int, float)):
        seconds = int(val / 1000) if val > 10**9 else int(val)
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m{seconds % 60}s"
        if seconds < 86400:
            return f"{seconds // 3600}h{(seconds % 3600) // 60}m"
        return f"{seconds // 86400}d{(seconds % 86400) // 3600}h"
    return str(val)


def _is_srl(vendor: str) -> bool:
    return (vendor or "").strip().lower() in _SRL_VENDORS


def _is_frr(vendor: str) -> bool:
    return canonical_vendor(vendor) == "frr"


def _to_int(token: str) -> int:
    try:
        return int(token)
    except (ValueError, TypeError):
        return 0


# ───────────────────────────── version ────────────────────────────────────────

def parse_version(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"raw": output[:500], "version": None, "uptime": None}
    if not output:
        return out

    if _is_frr(vendor):
        m = re.search(r"FRRouting\s+(\S+)", output)
        if m:
            out["version"] = m.group(1)
        m = re.search(r"uptime\s+is\s+(.+?)$", output, re.MULTILINE | re.IGNORECASE)
        if m:
            out["uptime"] = m.group(1).strip()
        return out

    data = _try_json(output)
    if isinstance(data, dict):
        out["version"] = data.get("version") or data.get("softwareImageVersion")
        uptime = data.get("uptime") or data.get("bootupTimestamp")
        if isinstance(uptime, (int, float)):
            out["uptime"] = f"{int(uptime)}s"
        elif isinstance(uptime, str):
            out["uptime"] = uptime
        return out

    m = re.search(r"(?:version|software)\D*([\d.]+\S*)", output, re.IGNORECASE)
    if m:
        out["version"] = m.group(1)
    m = re.search(r"uptime\s+is\s+(.+?)$", output, re.MULTILINE | re.IGNORECASE)
    if m:
        out["uptime"] = m.group(1).strip()
    return out


# ───────────────────────────── bgp ────────────────────────────────────────────

def parse_bgp(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"peers": [], "established": 0, "total": 0}
    if not output:
        return out

    # ── Nokia SR Linux text table ────────────────────────────────────────────
    if _is_srl(vendor):
        for line in output.splitlines():
            m = re.search(
                r"^\s*\|\s*\S+\s*\|\s*(\d+\.\d+\.\d+\.\d+)\s*\|\s*\S+\s*\|\s*\S+\s*\|\s*(\d+)\s*\|\s*"
                r"(established|active|connect|idle|opensent|openconfirm)\s",
                line, re.I,
            )
            if m:
                neighbor, asn, state = m.group(1), int(m.group(2)), m.group(3).lower()
                established = state == "established"
                out["peers"].append({
                    "neighbor": neighbor, "asn": asn,
                    "state": "Established" if established else state.title(),
                    "uptime": None, "prefixes": 0,
                })
                if established:
                    out["established"] += 1
        out["total"] = len(out["peers"])
        return out

    data = _try_json(output)
    if isinstance(data, dict):
        peers_block = None
        if "ipv4Unicast" in data:
            peers_block = data["ipv4Unicast"].get("peers", {})
        elif "l2VpnEvpn" in data and isinstance(data["l2VpnEvpn"], dict):
            peers_block = data["l2VpnEvpn"].get("peers", {})
        elif "peers" in data:
            peers_block = data["peers"]
        elif "vrfs" in data:
            default_vrf = data["vrfs"].get("default", {})
            peers_block = default_vrf.get("peers", {})

        if isinstance(peers_block, dict):
            for neighbor, info in peers_block.items():
                if not isinstance(info, dict):
                    continue
                state = (info.get("state") or info.get("peerState") or "").lower()
                established = state in ("established", "estab")
                out["peers"].append({
                    "neighbor": neighbor,
                    "asn": info.get("remoteAs") or info.get("asn"),
                    "state": "Established" if established else (state.title() or "Down"),
                    "uptime": _fmt_uptime(info.get("peerUptime")
                                          or info.get("uptime")
                                          or info.get("upDownTime")),
                    "prefixes": info.get("pfxRcd") or info.get("prefixReceived") or 0,
                })
                if established:
                    out["established"] += 1
            out["total"] = len(out["peers"])
            return out

    # Text fallback — Cisco-style 11-column summary.
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 10:
            continue
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            continue
        state_or_prefixes = parts[-1]
        established = state_or_prefixes.isdigit()
        out["peers"].append({
            "neighbor": parts[0],
            "asn": parts[2] if parts[2].isdigit() else None,
            "state": "Established" if established else state_or_prefixes,
            "uptime": parts[-2],
            "prefixes": int(state_or_prefixes) if established else 0,
        })
        if established:
            out["established"] += 1
    out["total"] = len(out["peers"])
    return out


# ───────────────────────────── ospf ───────────────────────────────────────────

def parse_ospf(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"neighbors": [], "full": 0, "total": 0}
    if not output:
        return out

    data = _try_json(output)
    if isinstance(data, dict):
        # FRR: {"neighbors": {"<router-id>": [{...}]}}
        if "neighbors" in data and isinstance(data["neighbors"], dict):
            for router_id, entries in data["neighbors"].items():
                items = entries if isinstance(entries, list) else [entries]
                for entry in items:
                    if not isinstance(entry, dict):
                        continue
                    state = (entry.get("converged") or entry.get("nbrState") or "").lower()
                    is_full = "full" in state
                    out["neighbors"].append({
                        "neighbor": router_id,
                        "state": "Full" if is_full else (state.title() or "Init"),
                        "interface": entry.get("ifaceName") or entry.get("interface"),
                        "dead_time": entry.get("upTimeInMsec") or entry.get("deadTimeMsecs"),
                    })
                    if is_full:
                        out["full"] += 1
            out["total"] = len(out["neighbors"])
            return out

        # Arista EOS: {"vrfs": {"default": {"instList": {...: {"ospfNeighborEntries": [...]}}}}}
        if "vrfs" in data and isinstance(data["vrfs"], dict):
            for vrf in data["vrfs"].values():
                if not isinstance(vrf, dict):
                    continue
                for ins in (vrf.get("instList") or {}).values():
                    if not isinstance(ins, dict):
                        continue
                    for entry in ins.get("ospfNeighborEntries", []):
                        if not isinstance(entry, dict):
                            continue
                        state = str(entry.get("adjacencyState", "")).lower()
                        is_full = "full" in state
                        out["neighbors"].append({
                            "neighbor": entry.get("routerId") or entry.get("interfaceAddress"),
                            "state": "Full" if is_full else (state.title() or "Init"),
                            "interface": entry.get("interfaceName"),
                            "dead_time": entry.get("inactivity"),
                        })
                        if is_full:
                            out["full"] += 1
            out["total"] = len(out["neighbors"])
            return out

    # Text fallback — Cisco-style table.
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
    out["total"] = len(out["neighbors"])
    return out


# ───────────────────────────── interfaces ─────────────────────────────────────

def parse_interfaces(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"list": [], "up": 0, "total": 0}
    if not output:
        return out

    # ── Nokia SR Linux ───────────────────────────────────────────────────────
    if _is_srl(vendor):
        current = None
        for line in output.splitlines():
            m = re.match(r"^(ethernet-\S+|mgmt\d+|system\d+|lo\d+|lag\d+)\s+is\s+(up|down)",
                         line, re.I)
            if m:
                current = {"name": m.group(1), "status": m.group(2).lower(), "addresses": []}
                out["list"].append(current)
                if current["status"] == "up":
                    out["up"] += 1
                continue
            if current is None:
                continue
            m2 = re.search(r"IPv4\s+addr\s*:\s*(\d+\.\d+\.\d+\.\d+/\d+)", line)
            if m2:
                current["addresses"].append(m2.group(1))
        out["total"] = len(out["list"])
        return out

    data = _try_json(output)
    if isinstance(data, dict):
        items = data.get("interfaceStatuses", data)
        if isinstance(items, dict):
            for name, info in items.items():
                if not isinstance(info, dict):
                    continue
                status = (
                    info.get("status")
                    or info.get("operationalStatus")
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
            out["total"] = len(out["list"])
            return out

    # Text fallback — "Interface  Status  VRF  Addresses".
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
    out["total"] = len(out["list"])
    return out


# ───────────────────────── interface counters ─────────────────────────────────
# Ported from clab_collector.py probe_intf_counters_{frr,arista,srl}. Output
# shape: {"interfaces": [{interface, in_octets, out_octets, in_packets,
# out_packets, in_errors, out_errors}]}.

def _counter_row(name: str, in_oct: int, out_oct: int, in_pkt: int,
                 out_pkt: int, in_err: int, out_err: int) -> dict:
    return {
        "interface": name,
        "in_octets": in_oct, "out_octets": out_oct,
        "in_packets": in_pkt, "out_packets": out_pkt,
        "in_errors": in_err, "out_errors": out_err,
    }


def _counters_frr(data: dict) -> list[dict]:
    results = []
    for name, info in (data if isinstance(data, dict) else {}).items():
        if not isinstance(info, dict) or name in ("lo", "lo0", "lo1", "eth0"):
            continue
        results.append(_counter_row(
            name,
            info.get("inputBytes", 0), info.get("outputBytes", 0),
            info.get("inputPackets", 0), info.get("outputPackets", 0),
            info.get("inputErrors", 0), info.get("outputErrors", 0),
        ))
    return results


def _counters_arista(data: dict) -> list[dict]:
    results = []
    intfs = data.get("interfaces", {}) if isinstance(data, dict) else {}
    for name, info in (intfs if isinstance(intfs, dict) else {}).items():
        if not isinstance(info, dict) or name.startswith(("Ma", "Lo")):
            continue
        results.append(_counter_row(
            name,
            info.get("inOctets", 0), info.get("outOctets", 0),
            info.get("inUcastPkts", 0) + info.get("inMulticastPkts", 0) + info.get("inBroadcastPkts", 0),
            info.get("outUcastPkts", 0) + info.get("outMulticastPkts", 0) + info.get("outBroadcastPkts", 0),
            info.get("inErrors", 0), info.get("outErrors", 0),
        ))
    return results


def _counters_srl(raw: str) -> list[dict]:
    """Parse SRL ``show interface detail`` two-column (Rx Tx) statistics.

    Format per interface:
        Interface: ethernet-1/1
        ...
        Traffic statistics for ethernet-1/1
          Octets              161660   73279     <- Rx Tx
          Unicast packets     1988     862
          Errored packets     3        0
    """
    results: list[dict] = []
    current_intf = None
    in_oct = out_oct = in_pkt = out_pkt = in_err = out_err = 0
    have_stats = False

    def flush() -> None:
        if current_intf and have_stats:
            results.append(_counter_row(current_intf, in_oct, out_oct,
                                        in_pkt, out_pkt, in_err, out_err))

    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith("Interface:"):
            flush()
            parts = stripped.split()
            current_intf = parts[1] if len(parts) > 1 else None
            in_oct = out_oct = in_pkt = out_pkt = in_err = out_err = 0
            have_stats = False
            continue
        if stripped.startswith("Octets"):
            cols = stripped.split()
            if len(cols) >= 3:
                in_oct, out_oct = _to_int(cols[-2]), _to_int(cols[-1])
                have_stats = True
        elif stripped.startswith("Unicast packets"):
            cols = stripped.split()
            if len(cols) >= 4:
                in_pkt, out_pkt = _to_int(cols[-2]), _to_int(cols[-1])
                have_stats = True
        elif stripped.startswith("Errored packets"):
            cols = stripped.split()
            if len(cols) >= 4:
                in_err = _to_int(cols[-2])
                out_err = _to_int(cols[-1]) if cols[-1] != "N/A" else 0
                have_stats = True
    flush()
    return results


def parse_interface_counters(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"interfaces": []}
    if not output:
        return out

    if _is_srl(vendor):
        out["interfaces"] = _counters_srl(output)
        return out

    data = _try_json(output)
    if _is_frr(vendor):
        if isinstance(data, dict):
            out["interfaces"] = _counters_frr(data)
        return out

    # Arista / other JSON vendors.
    if isinstance(data, dict):
        out["interfaces"] = _counters_arista(data)
    return out


# ───────────────────────────── routes ─────────────────────────────────────────

def parse_routes(vendor: str, raw: str) -> dict:
    output = (raw or "").strip()
    out: dict = {"total": None, "by_protocol": {}}
    if not output:
        return out

    data = _try_json(output)
    if isinstance(data, dict):
        out["total"] = data.get("routesTotal") or data.get("totalRoutes")
        proto_block = data.get("routes") or data.get("byProtocol") or {}
        if isinstance(proto_block, dict):
            for proto, count in proto_block.items():
                if isinstance(count, int):
                    out["by_protocol"][proto] = count
        return out

    # Text fallback: "Route Source   Routes  FIB".
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
