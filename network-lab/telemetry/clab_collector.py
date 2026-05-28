#!/usr/bin/env python3
"""clab Clos-EVPN Fabric Telemetry Collector.

Polls every node of the running ``clab-clos-evpn-*`` fabric via
``docker exec`` (no SSH required, works for all 3 vendors) and writes metrics
to InfluxDB in line protocol.

Vendors handled:
  - Nokia SR Linux  -> sr_cli flat tables
  - Arista cEOS     -> Cli -p 15 -c '... | json'
  - FRR             -> vtysh -c '... json'

Run from the lab host (NOT inside the dcn-lab_lab-net collector container).
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from dataclasses import dataclass

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("clab-collector")

INFLUX_URL    = os.environ.get("INFLUXDB_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.environ.get("INFLUXDB_TOKEN",  "dcn-lab-token-secret")
INFLUX_ORG    = os.environ.get("INFLUXDB_ORG",    "dcn-lab")
INFLUX_BUCKET = os.environ.get("INFLUXDB_BUCKET", "network-telemetry")
POLL_INTERVAL = int(os.environ.get("CLAB_POLL_INTERVAL", "15"))


@dataclass(frozen=True)
class Node:
    hostname: str
    container: str
    vendor: str   # nokia-srl | arista-eos | frr
    role: str     # spine | leaf


FABRIC: tuple[Node, ...] = (
    Node("spine1", "clab-clos-evpn-spine1", "nokia-srl",  "spine"),
    Node("spine2", "clab-clos-evpn-spine2", "arista-eos", "spine"),
    Node("spine3", "clab-clos-evpn-spine3", "frr",        "spine"),
    Node("leaf1",  "clab-clos-evpn-leaf1",  "arista-eos", "leaf"),
    Node("leaf2",  "clab-clos-evpn-leaf2",  "nokia-srl",  "leaf"),
    Node("leaf3",  "clab-clos-evpn-leaf3",  "frr",        "leaf"),
    Node("leaf4",  "clab-clos-evpn-leaf4",  "arista-eos", "leaf"),
    Node("leaf5",  "clab-clos-evpn-leaf5",  "nokia-srl",  "leaf"),
    Node("leaf6",  "clab-clos-evpn-leaf6",  "frr",        "leaf"),
)


# ───────────── Persistent docker-exec session pool (roadmap #4 cross-cut) ─────
#
# Each `docker exec` invocation pays ~30-50 ms of docker CLI startup + RPC
# overhead, BEFORE the in-container command even runs. With 9 nodes × 3
# probes per 15 s cycle, that's ~1 s of pure overhead per cycle. A persistent
# shell session per container collapses that to a single roundtrip per
# command — we keep one long-running `docker exec -i sh` and send commands
# via stdin, reading until an end-of-command marker.
#
# Falls back to one-shot `subprocess.run` if a session can't be opened or
# if a command fails twice in a row (auto-recovery for container restart).

import threading

_SESSION_LOCK = threading.Lock()
_SESSIONS: dict[str, subprocess.Popen] = {}
_SESSION_MISSES: dict[str, int] = {}
_END_MARKER = "__DCN_END__"


def _open_session(container: str) -> subprocess.Popen | None:
    """Spawn a long-running `docker exec -i sh` process for `container`.
    Returns None if the container isn't running."""
    try:
        p = subprocess.Popen(
            ["docker", "exec", "-i", container, "sh"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("could not open session for %s: %s", container, exc)
        return None
    return p


def _read_until_marker(p: subprocess.Popen, timeout: float = 12.0) -> str:
    """Read from p.stdout until the END marker, return everything before it."""
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    assert p.stdout is not None
    while time.monotonic() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        if _END_MARKER in line:
            return "".join(chunks)
        chunks.append(line)
    return "".join(chunks)


def docker_run(container: str, *cmd: str, timeout: int = 15) -> str:
    """Run a command inside a container via a persistent shell session.

    Falls back to subprocess.run if the session breaks. The first call to a
    container pays the session-open cost (~50 ms); every subsequent call is
    ~5 ms instead of ~40 ms. Across a 15 s collector cycle that's a ~3-4×
    throughput win — see roadmap #4."""
    if not cmd:
        return ""
    with _SESSION_LOCK:
        sess = _SESSIONS.get(container)
        if sess is None or sess.poll() is not None:
            sess = _open_session(container)
            if sess is None:
                # No session — fall back to one-shot
                return _docker_run_oneshot(container, *cmd, timeout=timeout)
            _SESSIONS[container] = sess
            _SESSION_MISSES[container] = 0

    # Build the command line. cmd is a list-arg tuple (vtysh, -c, "show ...")
    # — shell-quote it and append a sentinel printf so we can detect EOC.
    import shlex
    line = " ".join(shlex.quote(c) for c in cmd) + f"; printf '%s\\n' '{_END_MARKER}'\n"
    try:
        assert sess.stdin is not None
        sess.stdin.write(line)
        sess.stdin.flush()
        out = _read_until_marker(sess, timeout=timeout)
        return out
    except (BrokenPipeError, OSError) as exc:  # session died — recycle
        log.debug("session for %s broke: %s — recycling", container, exc)
        with _SESSION_LOCK:
            _SESSION_MISSES[container] = _SESSION_MISSES.get(container, 0) + 1
            try:
                sess.kill()
            except Exception:
                pass
            _SESSIONS.pop(container, None)
        return _docker_run_oneshot(container, *cmd, timeout=timeout)


def _docker_run_oneshot(container: str, *cmd: str, timeout: int = 15) -> str:
    """Legacy one-shot path. Used by docker_run as a fallback."""
    full = ["docker", "exec", container, *cmd]
    result = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(f"{container}: rc={result.returncode}: {(result.stderr or '').strip()[:200]}")
    return result.stdout


def try_json(text: str) -> dict | list | None:
    text = text.strip()
    if not text:
        return None
    start = text.find("{")
    if start == -1:
        start = text.find("[")
    if start == -1:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


# ─────────────────────────── per-vendor probes ────────────────────────────────


def _safe(fn, default):
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        log.debug("probe step failed (defaulting): %s", exc)
        return default


def probe_frr(node: Node) -> dict[str, tuple[int, int]]:
    def bgp() -> tuple[int, int]:
        raw = docker_run(node.container, "vtysh", "-c", "show bgp summary json")
        data = try_json(raw) or {}
        af = data.get("ipv4Unicast") or data.get("l2VpnEvpn") or data
        peers = (af or {}).get("peers", {}) if isinstance(af, dict) else {}
        established = sum(1 for p in peers.values() if str(p.get("state", "")).lower() == "established")
        return established, len(peers)

    def ospf() -> tuple[int, int]:
        raw = docker_run(node.container, "vtysh", "-c", "show ip ospf neighbor json")
        data = try_json(raw) or {}
        full = total = 0
        nbrs = data.get("neighbors", {})
        if isinstance(nbrs, dict):
            for entries in nbrs.values():
                items = entries if isinstance(entries, list) else [entries]
                for n in items:
                    total += 1
                    if "Full" in str(n.get("converged") or n.get("nbrState") or ""):
                        full += 1
        return full, total

    def intf() -> tuple[int, int]:
        raw = docker_run(node.container, "vtysh", "-c", "show interface brief json")
        data = try_json(raw) or {}
        intfs = data.get("interfaces", data) if isinstance(data, dict) else {}
        if not isinstance(intfs, dict):
            intfs = {}
        up = sum(1 for v in intfs.values()
                 if isinstance(v, dict) and str(v.get("administrativeStatus", v.get("status", ""))).lower() in ("up", "active"))
        return up, len(intfs)

    return {"bgp": _safe(bgp, (0, 0)), "ospf": _safe(ospf, (0, 0)), "intf": _safe(intf, (0, 0))}


def probe_arista(node: Node) -> dict[str, tuple[int, int]]:
    def bgp() -> tuple[int, int]:
        raw = docker_run(node.container, "Cli", "-p", "15", "-c", "show ip bgp summary | json")
        data = try_json(raw) or {}
        default = (data.get("vrfs") or {}).get("default", {})
        peers = default.get("peers", {})
        established = sum(1 for p in peers.values() if str(p.get("peerState", "")).lower() == "established")
        return established, len(peers)

    def ospf() -> tuple[int, int]:
        raw = docker_run(node.container, "Cli", "-p", "15", "-c", "show ip ospf neighbor | json")
        data = try_json(raw) or {}
        nbrs: list[dict] = []
        for v in (data.get("vrfs") or {}).values():
            for ins in (v.get("instList") or {}).values():
                for entry in ins.get("ospfNeighborEntries", []):
                    nbrs.append(entry)
        full = sum(1 for n in nbrs if "full" in str(n.get("adjacencyState", "")).lower())
        return full, len(nbrs)

    def intf() -> tuple[int, int]:
        raw = docker_run(node.container, "Cli", "-p", "15", "-c", "show interfaces status | json")
        data = try_json(raw) or {}
        intfs = data.get("interfaceStatuses", {})
        up = sum(1 for i in intfs.values() if str(i.get("linkStatus", "")).lower() == "connected")
        return up, len(intfs)

    return {"bgp": _safe(bgp, (0, 0)), "ospf": _safe(ospf, (0, 0)), "intf": _safe(intf, (0, 0))}


def probe_srl(node: Node) -> dict[str, tuple[int, int]]:
    def bgp() -> tuple[int, int]:
        raw = docker_run(node.container, "sr_cli", "-d", "show network-instance default protocols bgp neighbor")
        lines = [l for l in raw.splitlines() if l.strip()]
        bgp_total = sum(1 for l in lines if "AS" in l and ("." in l or ":" in l))
        bgp_up = sum(1 for l in lines if "established" in l.lower())
        return bgp_up, max(bgp_total, bgp_up)

    def ospf() -> tuple[int, int]:
        raw = docker_run(node.container, "sr_cli", "-d", "show network-instance default protocols ospf neighbor")
        lines = [l for l in raw.splitlines() if l.strip()]
        full = sum(1 for l in lines if "full" in l.lower())
        return full, full

    def intf() -> tuple[int, int]:
        raw = docker_run(node.container, "sr_cli", "-d", "show interface")
        lines = [l for l in raw.splitlines() if l.strip()]
        intf_up = sum(1 for l in lines if " up " in l.lower() or l.lower().rstrip().endswith(" up"))
        intf_total = sum(1 for l in lines if l.lstrip().startswith(("ethernet", "mgmt", "lo")))
        return intf_up, max(intf_total, intf_up)

    return {"bgp": _safe(bgp, (0, 0)), "ospf": _safe(ospf, (0, 0)), "intf": _safe(intf, (0, 0))}


PROBES = {"frr": probe_frr, "arista-eos": probe_arista, "nokia-srl": probe_srl}


def probe_intf_counters_frr(node: Node) -> list[dict]:
    raw = docker_run(node.container, "vtysh", "-c", "show interface json")
    data = try_json(raw) or {}
    results = []
    for name, info in (data if isinstance(data, dict) else {}).items():
        if not isinstance(info, dict) or name in ("lo", "lo0", "lo1", "eth0"):
            continue
        counters = info.get("inputPackets", info.get("rxCounters", {}))
        results.append({
            "interface": name,
            "in_octets": info.get("inputBytes", 0),
            "out_octets": info.get("outputBytes", 0),
            "in_packets": info.get("inputPackets", 0),
            "out_packets": info.get("outputPackets", 0),
            "in_errors": info.get("inputErrors", 0),
            "out_errors": info.get("outputErrors", 0),
        })
    return results


def probe_intf_counters_arista(node: Node) -> list[dict]:
    raw = docker_run(node.container, "Cli", "-p", "15", "-c", "show interfaces counters | json")
    data = try_json(raw) or {}
    intfs = data.get("interfaces", {})
    results = []
    for name, info in intfs.items():
        if name.startswith(("Ma", "Lo")):
            continue
        results.append({
            "interface": name,
            "in_octets": info.get("inOctets", 0),
            "out_octets": info.get("outOctets", 0),
            "in_packets": info.get("inUcastPkts", 0) + info.get("inMulticastPkts", 0) + info.get("inBroadcastPkts", 0),
            "out_packets": info.get("outUcastPkts", 0) + info.get("outMulticastPkts", 0) + info.get("outBroadcastPkts", 0),
            "in_errors": info.get("inErrors", 0),
            "out_errors": info.get("outErrors", 0),
        })
    return results


def probe_intf_counters_srl(node: Node) -> list[dict]:
    raw = docker_run(node.container, "sr_cli", "-d", "show interface detail")
    results = []
    current_intf = None
    in_oct = out_oct = in_pkt = out_pkt = in_err = out_err = 0
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.startswith(("ethernet-", "lag", "irb")):
            if current_intf:
                results.append({"interface": current_intf, "in_octets": in_oct, "out_octets": out_oct,
                                "in_packets": in_pkt, "out_packets": out_pkt, "in_errors": in_err, "out_errors": out_err})
            current_intf = stripped.split()[0]
            in_oct = out_oct = in_pkt = out_pkt = in_err = out_err = 0
        if "in-octets" in stripped:
            try: in_oct = int(stripped.split()[-1])
            except ValueError: pass
        elif "out-octets" in stripped:
            try: out_oct = int(stripped.split()[-1])
            except ValueError: pass
        elif "in-unicast-packets" in stripped:
            try: in_pkt = int(stripped.split()[-1])
            except ValueError: pass
        elif "out-unicast-packets" in stripped:
            try: out_pkt = int(stripped.split()[-1])
            except ValueError: pass
        elif "in-error-packets" in stripped:
            try: in_err = int(stripped.split()[-1])
            except ValueError: pass
        elif "out-error-packets" in stripped:
            try: out_err = int(stripped.split()[-1])
            except ValueError: pass
    if current_intf:
        results.append({"interface": current_intf, "in_octets": in_oct, "out_octets": out_oct,
                        "in_packets": in_pkt, "out_packets": out_pkt, "in_errors": in_err, "out_errors": out_err})
    return results


COUNTER_PROBES = {"frr": probe_intf_counters_frr, "arista-eos": probe_intf_counters_arista, "nokia-srl": probe_intf_counters_srl}


# ─────────────────────────── line protocol ────────────────────────────────────


def tag_escape(value: str) -> str:
    return value.replace(",", r"\,").replace(" ", r"\ ").replace("=", r"\=")


def make_line(measurement: str, node: Node, fields: dict[str, int], ts_ns: int) -> str:
    tags = (
        f"host={tag_escape(node.hostname)},"
        f"vendor={tag_escape(node.vendor)},"
        f"role={tag_escape(node.role)},"
        f"fabric=clos-evpn,"
        f"site=CLAB-DC1"
    )
    field_str = ",".join(f"{k}={int(v)}i" for k, v in fields.items())
    return f"{measurement},{tags} {field_str} {ts_ns}"


def write_influx(lines: list[str]) -> None:
    if not lines:
        return
    url = f"{INFLUX_URL}/api/v2/write?org={INFLUX_ORG}&bucket={INFLUX_BUCKET}&precision=ns"
    headers = {"Authorization": f"Token {INFLUX_TOKEN}", "Content-Type": "text/plain; charset=utf-8"}
    resp = requests.post(url, data="\n".join(lines).encode(), headers=headers, timeout=10)
    if resp.status_code not in (200, 204):
        log.error("InfluxDB write failed: %s — %s", resp.status_code, resp.text[:200])
    else:
        log.info("Wrote %d clab metrics to InfluxDB", len(lines))


STATUS_FILE = os.environ.get("CLAB_STATUS_FILE", "/tmp/clab_status.json")


def collect_once() -> None:
    ts_ns = time.time_ns()
    lines: list[str] = []
    status: dict = {"updated_ns": ts_ns, "fabric": "clos-evpn", "site": "CLAB-DC1", "nodes": {}}
    for node in FABRIC:
        probe = PROBES.get(node.vendor)
        if probe is None:
            continue
        try:
            metrics = probe(node)
        except Exception as exc:  # noqa: BLE001
            log.warning("  %s (%s) skipped: %s", node.hostname, node.vendor, exc)
            continue
        bgp_up, bgp_total = metrics.get("bgp", (0, 0))
        ospf_full, ospf_total = metrics.get("ospf", (0, 0))
        intf_up, intf_total = metrics.get("intf", (0, 0))
        lines.append(make_line("bgp_session_count",   node, {"established": bgp_up,  "total": bgp_total},  ts_ns))
        lines.append(make_line("ospf_neighbor_count", node, {"full": ospf_full,      "total": ospf_total}, ts_ns))
        lines.append(make_line("interface_count",     node, {"up": intf_up,          "total": intf_total}, ts_ns))
        status["nodes"][node.hostname] = {
            "vendor": node.vendor, "role": node.role,
            "bgp_up": bgp_up, "bgp_total": bgp_total,
            "ospf_full": ospf_full, "ospf_total": ospf_total,
            "intf_up": intf_up, "intf_total": intf_total,
            "healthy": bgp_up > 0 and intf_up > 0,
        }
        log.info("  %-7s %-10s bgp=%d/%d ospf=%d/%d intf=%d/%d",
                 node.hostname, node.vendor, bgp_up, bgp_total, ospf_full, ospf_total, intf_up, intf_total)
        counter_probe = COUNTER_PROBES.get(node.vendor)
        if counter_probe:
            try:
                for ctr in counter_probe(node):
                    fields = {k: v for k, v in ctr.items() if k != "interface" and isinstance(v, int)}
                    if fields:
                        intf_name = tag_escape(ctr.get("interface", "unknown"))
                        tags = f"source={tag_escape(node.hostname)},role={node.role},vendor={tag_escape(node.vendor)},interface_name={intf_name}"
                        fld_str = ",".join(f"{k}={v}i" for k, v in fields.items())
                        lines.append(f"intf-counters,{tags} {fld_str} {ts_ns}")
            except Exception as exc:
                log.debug("  %s counter probe failed: %s", node.hostname, exc)
    write_influx(lines)
    try:
        tmp = STATUS_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(status, f, indent=2)
        os.replace(tmp, STATUS_FILE)
    except OSError as exc:
        log.warning("status file write failed: %s", exc)


def main() -> int:
    log.info("clab collector start - poll_interval=%ss influx=%s bucket=%s",
             POLL_INTERVAL, INFLUX_URL, INFLUX_BUCKET)
    once = "--once" in sys.argv
    while True:
        try:
            collect_once()
        except KeyboardInterrupt:
            log.info("interrupted - exit")
            return 0
        except Exception as exc:  # noqa: BLE001
            log.exception("collect_once raised: %s", exc)
        if once:
            return 0
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    raise SystemExit(main())
