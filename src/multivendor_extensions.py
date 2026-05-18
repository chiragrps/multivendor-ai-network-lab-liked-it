#!/usr/bin/env python3
"""
Multivendor AI Network Platform — Extension Endpoints
======================================================
Adds Tier 1 & 2 capabilities to the DCN Network Tool:

Tier 1:
  POST /api/mv/batfish/fleet      — Batfish-style analysis of all 16 sanitized configs
  GET  /api/mv/suzieq/analyze     — SuzieQ-style fleet observability (offline config parse)
  GET  /api/mv/gnmi/query         — gNMI-style telemetry query (FRR containers via vtysh)

Tier 2:
  GET  /api/mv/syslog/recent      — Live syslog ring-buffer (populated by background thread)
  GET  /api/mv/snmp/traps         — SNMP trap ring-buffer
  POST /api/mv/junos/netconf      — Juniper PyEZ/NETCONF query (real devices)
  GET  /api/mv/topology           — Full 26-device topology JSON for diagram rendering
  GET  /api/mv/devices            — Multivendor inventory (16 static + 10 FRR live)

Register in app.py with:
    from multivendor_extensions import mv_bp
    app.register_blueprint(mv_bp)
"""

import os, sys, json, re, time, threading, socket, struct, logging
from datetime import datetime, timezone
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Blueprint, request, jsonify

log = logging.getLogger(__name__)

mv_bp = Blueprint("mv", __name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
_HERE       = os.path.dirname(os.path.abspath(__file__))


def _resolve_lab_dir() -> str:
    """Locate the network-lab/ directory, supporting both repo layouts:
    - new (multivendor-ai-network-lab):  src/<this>  →  ../network-lab/
    - legacy (DCN_Network_Tool flat):    <this>      →  ../../network-lab/
    """
    for rel in ("../network-lab", "../../network-lab"):
        candidate = os.path.normpath(os.path.join(_HERE, rel))
        if os.path.isdir(os.path.join(candidate, "demo-devices")):
            return candidate
    return os.path.normpath(os.path.join(_HERE, "../../network-lab"))


_LAB_DIR    = _resolve_lab_dir()
_DEMO_DIR   = os.path.join(_LAB_DIR, "demo-devices")
_INV_FILE   = os.path.join(_DEMO_DIR, "inventory.json")

# ── Load inventory ────────────────────────────────────────────────────────────
def _load_inventory() -> dict:
    try:
        with open(_INV_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log.warning("inventory.json not loadable: %s", e)
        return {"devices": [], "bgp_sessions": []}

_INVENTORY = _load_inventory()
_ALL_DEVICES: list[dict] = _INVENTORY.get("devices", [])
_BGP_SESSIONS: list[dict] = _INVENTORY.get("bgp_sessions", [])

# ── Ring buffers ──────────────────────────────────────────────────────────────
_SYSLOG_BUFFER: deque = deque(maxlen=500)
_TRAP_BUFFER:   deque = deque(maxlen=200)

# ══════════════════════════════════════════════════════════════════════════════
# ── GET /api/mv/devices ───────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@mv_bp.route("/api/mv/devices", methods=["GET"])
def mv_devices():
    """Return full multivendor inventory (static configs + live FRR containers)."""
    vendor_filter = request.args.get("vendor", "").lower()
    site_filter   = request.args.get("site", "").lower()
    live_filter   = request.args.get("live", "")

    devs = list(_ALL_DEVICES)
    if vendor_filter:
        devs = [d for d in devs if d.get("vendor","").lower() == vendor_filter]
    if site_filter:
        devs = [d for d in devs if d.get("site","").lower() == site_filter]
    if live_filter.lower() in ("true","1"):
        devs = [d for d in devs if d.get("live")]
    elif live_filter.lower() in ("false","0"):
        devs = [d for d in devs if not d.get("live")]

    vendors  = sorted(set(d["vendor"] for d in _ALL_DEVICES))
    sites    = sorted(set(d["site"]   for d in _ALL_DEVICES))
    roles    = sorted(set(d["role"]   for d in _ALL_DEVICES))
    live_cnt = sum(1 for d in _ALL_DEVICES if d.get("live"))

    return jsonify({
        "total": len(_ALL_DEVICES),
        "filtered": len(devs),
        "live_containers": live_cnt,
        "static_configs": len(_ALL_DEVICES) - live_cnt,
        "vendors": vendors,
        "sites": sites,
        "roles": roles,
        "devices": devs,
    })

# ══════════════════════════════════════════════════════════════════════════════
# ── GET /api/mv/topology ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

@mv_bp.route("/api/mv/topology", methods=["GET"])
def mv_topology():
    """Return full topology for SVG diagram rendering."""
    return jsonify({
        "devices": _ALL_DEVICES,
        "bgp_sessions": _BGP_SESSIONS,
        "sites": [
            {"name": "DE-FRA", "label": "Frankfurt",  "x": 400, "y": 200},
            {"name": "UK-LON", "label": "London",     "x": 200, "y": 120},
            {"name": "NL-AMS", "label": "Amsterdam",  "x": 350, "y": 120},
            {"name": "EU-CDG", "label": "Paris",      "x": 200, "y": 270},
            {"name": "US-NYC", "label": "New York",   "x": 650, "y": 180},
        ],
    })

# ══════════════════════════════════════════════════════════════════════════════
# ── POST /api/mv/batfish/fleet — Batfish-style fleet config analysis ──────────
# ══════════════════════════════════════════════════════════════════════════════

_BATFISH_RULES = [
    # (pattern, severity, message, category)
    (r'authentication-key\s+"[^$]',         "error",   "BGP auth key in plaintext — use encrypted format ($9$...)",       "security"),
    (r'authentication\s+md5',               "pass",    "BGP MD5 authentication present",                                   "security"),
    (r'authentication\s+sha',               "pass",    "BGP SHA authentication present",                                   "security"),
    (r'no\s+export',                        "warn",    "BGP no-export community — verify intentional",                     "routing"),
    (r'prefix-limit',                       "pass",    "BGP prefix-limit configured",                                      "routing"),
    (r'bfd',                                "pass",    "BFD sub-second failure detection configured",                      "reliability"),
    (r'log-updown',                         "pass",    "BGP log-updown enabled",                                          "observability"),
    (r'area\s+0\.0\.0\.0',                  "pass",    "OSPF area 0.0.0.0 present",                                       "routing"),
    (r'graceful-restart',                   "pass",    "BGP graceful-restart configured",                                  "reliability"),
    (r'route-reflector-client',             "pass",    "BGP route-reflector configured",                                   "routing"),
    (r'multihop',                           "warn",    "BGP multihop — verify TTL security",                              "security"),
    (r'syslog|logging',                     "pass",    "Remote syslog/logging configured",                                 "observability"),
    (r'snmp',                               "pass",    "SNMP monitoring configured",                                       "observability"),
    (r'ntp',                                "pass",    "NTP time sync configured",                                         "reliability"),
    (r'screen\s+ids|zone-policy|security-zone', "pass","Firewall security zones/policies present",                         "security"),
    (r'idle-timeout|idle_timeout',          "pass",    "SSH idle timeout configured",                                      "security"),
    (r'deny-commands|deny-configuration',   "pass",    "Read-only user class with deny-commands",                          "security"),
    (r'hold.?time\s+(\d+)',                 "info",    "BGP hold-time detected",                                           "routing"),
    (r'gnmi|grpc',                          "pass",    "gNMI/gRPC telemetry enabled",                                     "observability"),
    (r'management\s+api\s+http|http.*management', "warn", "HTTP management API enabled — prefer HTTPS",                  "security"),
    (r'no\s+lldp|lldp\s+disable',          "warn",    "LLDP disabled — may affect topology discovery",                   "observability"),
    (r'rpki|route-origin-validation',       "pass",    "RPKI route origin validation configured",                          "security"),
]

def _analyze_one_config(dev: dict) -> dict:
    """Analyze a single device config file and return findings."""
    cfg_path = dev.get("config")
    if not cfg_path:
        return {"hostname": dev["hostname"], "vendor": dev["vendor"], "role": dev["role"],
                "site": dev["site"], "findings": [], "score": 100, "error": "no config file (live FRR device)"}

    full_path = os.path.join(_DEMO_DIR, cfg_path)
    if not os.path.exists(full_path):
        return {"hostname": dev["hostname"], "vendor": dev["vendor"], "role": dev["role"],
                "site": dev["site"], "findings": [], "score": 0, "error": f"config not found: {full_path}"}

    with open(full_path, errors="replace") as f:
        text = f.read()

    findings = []
    score = 100  # start at 100, deduct for errors/warns

    for pattern, severity, message, category in _BATFISH_RULES:
        m = re.search(pattern, text, re.IGNORECASE)
        if severity == "pass" and m:
            findings.append({"severity": "pass",  "message": message, "category": category})
        elif severity in ("error", "warn", "info") and m:
            findings.append({"severity": severity, "message": message, "category": category})
            if severity == "error":
                score -= 20
            elif severity == "warn":
                score -= 5

    # Extra: check hold-time value
    ht = re.search(r'hold.?time\s+(\d+)', text, re.I)
    if ht and int(ht.group(1)) > 30:
        findings.append({"severity": "warn",
                         "message": f"BGP hold-time {ht.group(1)}s — recommend ≤30s for fast failover",
                         "category": "routing"})
        score -= 5

    # Check external BGP without export policy
    if re.search(r'type\s+external|peer-type external', text, re.I) and not re.search(r'export\s+["\w]', text, re.I):
        findings.append({"severity": "error",
                         "message": "External BGP peer without export policy — may leak internal prefixes",
                         "category": "security"})
        score -= 20

    # Check for gNMI on correct port (Juniper 32767, Arista 32767)
    if re.search(r'gnmi|grpc', text, re.I):
        port_match = re.search(r'port\s+(\d+)', text[max(0, text.lower().find('gnmi')-200):
                                                       text.lower().find('gnmi')+200], re.I)
        if port_match and port_match.group(1) not in ("32767", "6030", "57400"):
            findings.append({"severity": "warn",
                             "message": f"gNMI on non-standard port {port_match.group(1)} — check vendor defaults",
                             "category": "observability"})

    errors   = [f for f in findings if f["severity"] == "error"]
    warnings = [f for f in findings if f["severity"] == "warn"]
    passes   = [f for f in findings if f["severity"] == "pass"]

    return {
        "hostname":  dev["hostname"],
        "vendor":    dev["vendor"],
        "model":     dev.get("model", ""),
        "role":      dev["role"],
        "site":      dev["site"],
        "os":        dev.get("os", ""),
        "findings":  findings,
        "errors":    len(errors),
        "warnings":  len(warnings),
        "passes":    len(passes),
        "score":     max(0, score),
        "config_lines": len(text.splitlines()),
    }


@mv_bp.route("/api/mv/batfish/fleet", methods=["POST"])
def mv_batfish_fleet():
    """Analyze all 16 sanitized device configs in parallel (Batfish-style)."""
    data         = request.get_json(force=True) or {}
    site_filter  = (data.get("site") or "").strip().lower()
    role_filter  = (data.get("role") or "").strip().lower()
    vendor_filter= (data.get("vendor") or "").strip().lower()

    targets = [d for d in _ALL_DEVICES if d.get("config")]  # only static-config devices
    if site_filter:
        targets = [d for d in targets if d["site"].lower() == site_filter]
    if role_filter:
        targets = [d for d in targets if d["role"].lower() == role_filter]
    if vendor_filter:
        targets = [d for d in targets if d["vendor"].lower() == vendor_filter]

    if not targets:
        return jsonify({"error": "No matching config devices found"}), 404

    t_start = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_analyze_one_config, dev): dev for dev in targets}
        for fut in as_completed(futs):
            results.append(fut.result())

    elapsed   = round(time.monotonic() - t_start, 2)
    total_err = sum(r.get("errors",0)   for r in results)
    total_wrn = sum(r.get("warnings",0) for r in results)
    total_pas = sum(r.get("passes",0)   for r in results)
    avg_score = round(sum(r.get("score",0) for r in results) / len(results), 1) if results else 0

    # Sort by score ascending (worst first)
    results.sort(key=lambda r: r.get("score", 100))

    return jsonify({
        "analyzed": len(results),
        "elapsed":  elapsed,
        "total_errors":   total_err,
        "total_warnings": total_wrn,
        "total_passes":   total_pas,
        "fleet_score":    avg_score,
        "results": results,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── GET /api/mv/suzieq/analyze — SuzieQ-style fleet observability ─────────────
# ══════════════════════════════════════════════════════════════════════════════

def _suzieq_parse_device(dev: dict) -> dict:
    """Parse BGP/OSPF/interface state from static configs — SuzieQ offline mode."""
    cfg_path = dev.get("config")
    result = {
        "hostname": dev["hostname"],
        "vendor":   dev["vendor"],
        "site":     dev["site"],
        "role":     dev["role"],
        "bgp_peers": [],
        "ospf_areas": [],
        "interfaces": [],
        "gnmi_enabled": False,
        "snmp_enabled": False,
        "ntp_servers": [],
        "assert": {"bgp": "pass", "ospf": "pass", "security": "pass"},
        "issues": [],
    }

    if not cfg_path:
        result["assert"] = {"bgp": "live-only", "ospf": "live-only", "security": "live-only"}
        return result

    full_path = os.path.join(_DEMO_DIR, cfg_path)
    if not os.path.exists(full_path):
        result["issues"].append("Config file not found")
        return result

    with open(full_path, errors="replace") as f:
        text = f.read()

    # BGP peers
    if dev["vendor"] == "juniper":
        bgp_neighbors = re.findall(r'neighbor\s+(\d+\.\d+\.\d+\.\d+)', text)
        bgp_groups = re.findall(r'group\s+"?([^"{\s]+)"?\s*\{', text)
        peer_as = re.findall(r'peer-as\s+(\d+)', text)
        result["bgp_peers"] = [{"ip": ip, "group": bgp_groups[i] if i < len(bgp_groups) else "unknown",
                                 "peer_as": peer_as[i] if i < len(peer_as) else None}
                                for i, ip in enumerate(bgp_neighbors[:20])]
        # OSPF areas
        result["ospf_areas"] = list(set(re.findall(r'area\s+(\d+\.\d+\.\d+\.\d+)', text)))
        # Interfaces
        ifaces = re.findall(r'interface\s+([a-z][a-z0-9/.-]+)\s*\{', text, re.I)
        result["interfaces"] = list(set(ifaces[:30]))
        # NTP
        result["ntp_servers"] = re.findall(r'server\s+(\d+\.\d+\.\d+\.\d+)', text[:5000])
    else:  # Arista EOS
        bgp_neighbors = re.findall(r'neighbor\s+(\d+\.\d+\.\d+\.\d+)\s+remote-as\s+(\d+)', text)
        result["bgp_peers"] = [{"ip": ip, "peer_as": asn, "group": "eos-bgp"} for ip, asn in bgp_neighbors[:20]]
        result["ospf_areas"] = list(set(re.findall(r'area\s+(\d+)', text)))
        ifaces = re.findall(r'^interface\s+([\w/.\-]+)', text, re.MULTILINE)
        result["interfaces"] = list(set(ifaces[:30]))
        result["ntp_servers"] = re.findall(r'ntp\s+server\s+(\d+\.\d+\.\d+\.\d+)', text)

    # gNMI check
    result["gnmi_enabled"] = bool(re.search(r'gnmi|grpc', text, re.I))
    # SNMP check
    result["snmp_enabled"] = bool(re.search(r'snmp', text, re.I))

    # Assertions
    if not result["bgp_peers"]:
        result["assert"]["bgp"] = "no-bgp"
    elif re.search(r'authentication-key\s+"[^$]', text, re.I):
        result["assert"]["bgp"] = "fail"
        result["issues"].append("BGP plaintext auth key")

    if not result["ospf_areas"]:
        result["assert"]["ospf"] = "no-ospf"

    if not result["snmp_enabled"]:
        result["issues"].append("SNMP not configured")
    if not result["gnmi_enabled"]:
        result["issues"].append("gNMI not configured")

    return result


@mv_bp.route("/api/mv/suzieq/analyze", methods=["GET"])
def mv_suzieq_analyze():
    """SuzieQ-style offline config analysis across the full fleet."""
    verb    = request.args.get("verb", "show")       # show | assert | unique | summarize
    table   = request.args.get("table", "bgp")       # bgp | ospf | interfaces | inventory
    site    = request.args.get("site", "").lower()
    vendor  = request.args.get("vendor", "").lower()

    targets = [d for d in _ALL_DEVICES if d.get("config")]
    if site:
        targets = [d for d in targets if d["site"].lower() == site]
    if vendor:
        targets = [d for d in targets if d["vendor"].lower() == vendor]

    t_start = time.monotonic()
    parsed  = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_suzieq_parse_device, dev): dev for dev in targets}
        for fut in as_completed(futs):
            parsed.append(fut.result())

    elapsed = round(time.monotonic() - t_start, 2)

    if verb == "assert":
        # Return pass/fail per device for the requested table
        assert_results = []
        for p in parsed:
            status = p["assert"].get(table, "unknown")
            assert_results.append({
                "hostname": p["hostname"], "vendor": p["vendor"], "site": p["site"],
                "assert": status, "issues": p["issues"],
            })
        fail_cnt = sum(1 for a in assert_results if a["assert"] == "fail")
        return jsonify({
            "table": table, "verb": verb, "devices": len(assert_results),
            "pass": len(assert_results) - fail_cnt, "fail": fail_cnt,
            "elapsed": elapsed, "results": assert_results,
        })

    elif verb == "summarize":
        total_bgp    = sum(len(p["bgp_peers"]) for p in parsed)
        total_ospf   = sum(len(p["ospf_areas"]) for p in parsed)
        total_iface  = sum(len(p["interfaces"]) for p in parsed)
        unique_areas = sorted({a for p in parsed for a in p["ospf_areas"]})
        with_gnmi    = sum(1 for p in parsed if p["gnmi_enabled"])
        with_snmp    = sum(1 for p in parsed if p["snmp_enabled"])
        vendor_dist: dict[str, int] = {}
        for p in parsed:
            vendor_dist[p["vendor"]] = vendor_dist.get(p["vendor"], 0) + 1
        return jsonify({
            "table": table, "verb": verb, "elapsed": elapsed,
            "devices_analyzed": len(parsed),
            "total_bgp_peers":   total_bgp,
            "total_ospf_areas":  total_ospf,
            "unique_ospf_areas": unique_areas,
            "total_interfaces":  total_iface,
            "gnmi_enabled":      with_gnmi,
            "snmp_enabled":      with_snmp,
            "vendor_distribution": vendor_dist,
            "common_issues":     list({i for p in parsed for i in p["issues"]})[:10],
        })

    elif verb == "unique":
        if table == "bgp":
            all_asns = sorted(set(
                str(peer.get("peer_as")) for p in parsed for peer in p["bgp_peers"] if peer.get("peer_as")
            ))
            return jsonify({"table": table, "verb": verb, "elapsed": elapsed,
                            "column": "peer_as", "unique_values": all_asns})
        elif table == "interfaces":
            all_types = sorted(set(
                re.match(r'^([a-z]+)', iface, re.I).group(1).lower()
                for p in parsed for iface in p["interfaces"]
                if re.match(r'^[a-z]', iface, re.I)
            ))
            return jsonify({"table": table, "verb": verb, "elapsed": elapsed,
                            "column": "type", "unique_values": all_types})

    # Default: show
    rows = []
    for p in parsed:
        if table == "bgp":
            for peer in p["bgp_peers"][:5]:
                rows.append({"hostname": p["hostname"], "vendor": p["vendor"], "site": p["site"],
                             "peer": peer["ip"], "peer_as": peer.get("peer_as"),
                             "state": "ESTABLISHED" if not p["issues"] else "UNKNOWN"})
        elif table == "ospf":
            for area in p["ospf_areas"]:
                rows.append({"hostname": p["hostname"], "vendor": p["vendor"], "site": p["site"], "area": area})
        elif table == "interfaces":
            for iface in p["interfaces"][:8]:
                rows.append({"hostname": p["hostname"], "vendor": p["vendor"], "site": p["site"], "interface": iface})
        elif table == "inventory":
            rows.append({"hostname": p["hostname"], "vendor": p["vendor"], "site": p["site"],
                         "gnmi": p["gnmi_enabled"], "snmp": p["snmp_enabled"],
                         "bgp_peers": len(p["bgp_peers"]), "ospf_areas": len(p["ospf_areas"]),
                         "issues": len(p["issues"])})

    return jsonify({"table": table, "verb": verb, "elapsed": elapsed,
                    "devices": len(parsed), "rows": rows})


# ══════════════════════════════════════════════════════════════════════════════
# ── POST /api/mv/gnmi/query — gNMI-style telemetry (live FRR via vtysh) ──────
# ══════════════════════════════════════════════════════════════════════════════

# Map gNMI OpenConfig paths → vtysh commands
_GNMI_PATH_MAP = {
    "/interfaces/interface/state":           "show interface",
    "/network-instances/network-instance/protocols/protocol/bgp/neighbors": "show bgp summary",
    "/network-instances/network-instance/protocols/protocol/ospf/areas":    "show ip ospf neighbor",
    "/components/component/state":           "show version",
    "/routing-policy/":                      "show ip route summary",
    "bgp":                                   "show bgp summary",
    "ospf":                                  "show ip ospf neighbor",
    "interfaces":                            "show interface brief",
    "version":                               "show version",
    "routes":                                "show ip route summary",
    "cpu":                                   "show processes cpu",
    "memory":                                "show memory",
}

def _gnmi_worker(dev: dict, vtysh_cmd: str) -> dict:
    """Execute vtysh command on FRR container via SSH and return structured response."""
    try:
        import paramiko as _pm
        _LAB_KEY = os.path.normpath(os.path.join(_LAB_DIR, "ssh-keys/lab_key"))
        client = _pm.SSHClient()
        client.set_missing_host_key_policy(_pm.AutoAddPolicy())
        client.connect(
            hostname="127.0.0.1",
            port=dev["port"],
            username="root",
            key_filename=_LAB_KEY,
            timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )
        _, stdout, stderr = client.exec_command(f"vtysh -c '{vtysh_cmd}'", timeout=8)
        output = stdout.read().decode(errors="replace").strip()
        err    = stderr.read().decode(errors="replace").strip()
        client.close()
        return {
            "hostname":  dev["hostname"],
            "site":      dev["site"],
            "vendor":    dev["vendor"],
            "ip":        dev["ip"],
            "port":      dev["port"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output":    output or err,
            "success":   bool(output),
        }
    # ImportError: paramiko absent. SSHException/socket.error: connection issues.
    # OSError: missing key file. Anything else surfaces in the structured error envelope.
    except (ImportError, OSError) as exc:
        log.warning("gnmi_worker connection error on %s: %s", dev.get("hostname"), exc)
        return _gnmi_error_envelope(dev, exc)
    except Exception as exc:  # noqa: BLE001 — paramiko exceptions are subclasses of various stdlib errors
        log.exception("gnmi_worker unexpected failure on %s", dev.get("hostname"))
        return _gnmi_error_envelope(dev, exc)


def _gnmi_error_envelope(dev: dict, exc: BaseException) -> dict:
    """Structured error envelope shared by both gnmi_worker exception arms."""
    return {
        "hostname":  dev["hostname"],
        "site":      dev["site"],
        "vendor":    dev["vendor"],
        "ip":        dev["ip"],
        "port":      dev.get("port"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "output":    str(exc),
        "success":   False,
    }


@mv_bp.route("/api/mv/gnmi/query", methods=["POST"])
def mv_gnmi_query():
    """gNMI-style query — maps OpenConfig paths to vtysh commands on FRR containers."""
    data      = request.get_json(force=True) or {}
    path      = (data.get("path") or "bgp").strip()
    hostname  = (data.get("hostname") or "").strip()
    site      = (data.get("site") or "").strip().lower()
    workers   = min(int(data.get("workers") or 10), 50)

    # Resolve vtysh command
    cmd = None
    for key, vtysh in _GNMI_PATH_MAP.items():
        if key in path:
            cmd = vtysh
            break
    if not cmd:
        cmd = "show version"

    # Select FRR targets
    live_devs = [d for d in _ALL_DEVICES if d.get("live")]
    if hostname:
        live_devs = [d for d in live_devs if d["hostname"] == hostname]
    elif site:
        live_devs = [d for d in live_devs if d["site"].lower() == site]

    if not live_devs:
        return jsonify({"error": "No live FRR containers matched — start docker lab first"}), 503

    t_start = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, len(live_devs))) as pool:
        futs = {pool.submit(_gnmi_worker, dev, cmd): dev for dev in live_devs}
        for fut in as_completed(futs):
            results.append(fut.result())

    elapsed = round(time.monotonic() - t_start, 2)
    ok_cnt  = sum(1 for r in results if r["success"])

    return jsonify({
        "path":    path,
        "command": cmd,
        "targets": len(live_devs),
        "ok":      ok_cnt,
        "elapsed": elapsed,
        "results": results,
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── Syslog receiver (background UDP thread → ring buffer) ──────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_SYSLOG_PORT    = int(os.environ.get("SYSLOG_MCP_PORT", "5140"))  # unprivileged
_SYSLOG_THREAD  = None
_SYSLOG_RUNNING = False

_SEV_NAMES = ["emerg","alert","crit","error","warning","notice","info","debug"]
_FAC_NAMES = ["kern","user","mail","daemon","auth","syslog","lpr","news",
              "uucp","cron","authpriv","ftp","","","","","","","","","local0",
              "local1","local2","local3","local4","local5","local6","local7"]

def _parse_syslog(data: bytes, src_ip: str) -> dict:
    """Parse RFC 3164 / RFC 5424 syslog message into structured dict."""
    try:
        msg = data.decode(errors="replace").strip()
        pri_match = re.match(r'^<(\d+)>(.*)', msg)
        severity = "info"; facility = "user"; content = msg
        if pri_match:
            pri_val  = int(pri_match.group(1))
            severity = _SEV_NAMES[pri_val & 0x07]
            fac_idx  = pri_val >> 3
            facility = _FAC_NAMES[fac_idx] if fac_idx < len(_FAC_NAMES) else str(fac_idx)
            content  = pri_match.group(2)
    except (UnicodeDecodeError, ValueError, IndexError) as e:
        log.debug("syslog parse fallback: %s", e)
        content = data.decode(errors="replace")[:200]; severity = "info"; facility = "user"

    return {
        "ts":       datetime.now(timezone.utc).isoformat(),
        "src":      src_ip,
        "severity": severity,
        "facility": facility,
        "message":  content[:300],
    }

def _syslog_listener():
    """Background UDP syslog listener on SYSLOG_MCP_PORT."""
    global _SYSLOG_RUNNING
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", _SYSLOG_PORT))
        sock.settimeout(1.0)
        log.info(f"Syslog receiver listening on UDP:{_SYSLOG_PORT}")
        while _SYSLOG_RUNNING:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                event = _parse_syslog(data, src_ip)
                _SYSLOG_BUFFER.append(event)
            except socket.timeout:
                continue
            except Exception as e:
                log.debug(f"Syslog recv error: {e}")
        sock.close()
    except Exception as e:
        log.warning(f"Syslog listener failed: {e}")

def start_syslog_receiver():
    """Start background syslog receiver thread."""
    global _SYSLOG_THREAD, _SYSLOG_RUNNING
    if _SYSLOG_THREAD and _SYSLOG_THREAD.is_alive():
        return
    _SYSLOG_RUNNING = True
    _SYSLOG_THREAD = threading.Thread(target=_syslog_listener, daemon=True, name="syslog-receiver")
    _SYSLOG_THREAD.start()

# ── Inject demo syslog events ─────────────────────────────────────────────────
import random as _random

_DEMO_SYSLOG_MESSAGES = [
    ("de-fra-mx-01",    "warning",  "daemon",  "%BGP-5-ADJCHANGE: neighbor 10.200.0.11 Up"),
    ("de-fra-fw-01",    "notice",   "auth",    "%SEC-6-IPACCESSLOGP: list MGMT-IN permitted tcp 192.168.100.1->10.200.1.1:22"),
    ("de-fra-ex-01",    "info",     "daemon",  "%LINEPROTO-5-UPDOWN: Line protocol on GigabitEthernet0/0/0, changed state to up"),
    ("uk-lon-fw-01",    "error",    "kern",    "%PLATFORM-4-ELEMENT_WARNING: Insufficient fan capacity"),
    ("nl-ams-eos-rt-01","warning",  "daemon",  "%BGP-3-NOTIFICATION: sent to neighbor 10.200.3.1 4/0 (hold time expired)"),
    ("de-fra-core-01", "info",    "daemon",  "BGP: rcvd UPDATE about 10.0.0.0/8 -- withdrawn"),
    ("uk-lon-core-01", "error",   "daemon",  "OSPF: router 10.200.0.13 adj change: state -> Full"),
    ("de-fra-eos-rt-01","warning",  "syslog",  "gNMI: subscription restarted for path /interfaces/interface"),
    ("nl-ams-fw-01",    "notice",   "auth",    "SSH: new session from 192.168.100.10 user netadmin1"),
    ("de-fra-dist-01", "info",   "daemon",  "BGP summary: 4 peers, 1245 prefixes received"),
    ("us-nyc-fw-01",    "error",    "kern",    "ifnet: eth0 link down"),
    ("eu-cdg-mx-01",    "warning",  "daemon",  "RPD_BGP_NEIGHBOR_STATE_CHANGED: 203.0.113.1 -> Active"),
    ("nl-ams-eos-sw-01","info",     "daemon",  "MAC address 00:1a:2b:3c:4d:5e learned on Ethernet1"),
    ("uk-lon-ex-01",    "notice",   "daemon",  "RSTP topology change on port ge-0/0/5"),
]

def inject_demo_syslog(n: int = 20):
    """Seed the syslog buffer with realistic demo events."""
    for _ in range(n):
        host, sev, fac, msg = _random.choice(_DEMO_SYSLOG_MESSAGES)
        _SYSLOG_BUFFER.append({
            "ts":       datetime.now(timezone.utc).isoformat(),
            "src":      host,
            "severity": sev,
            "facility": fac,
            "message":  msg,
        })


@mv_bp.route("/api/mv/syslog/recent", methods=["GET"])
def mv_syslog_recent():
    """Return recent syslog events from the ring buffer."""
    limit    = min(int(request.args.get("limit", 100)), 500)
    severity = request.args.get("severity", "").lower()
    host     = request.args.get("host", "").lower()

    events = list(_SYSLOG_BUFFER)[-limit:]
    if severity:
        events = [e for e in events if e.get("severity") == severity]
    if host:
        events = [e for e in events if host in e.get("src", "").lower()]

    sev_counts: dict[str, int] = {}
    for e in events:
        s = e.get("severity", "info")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    return jsonify({
        "total":          len(list(_SYSLOG_BUFFER)),
        "returned":       len(events),
        "receiver_port":  _SYSLOG_PORT,
        "severity_counts": sev_counts,
        "events":         list(reversed(events)),  # newest first
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── SNMP Trap receiver (background UDP:162 → ring buffer) ─────────────────────
# ══════════════════════════════════════════════════════════════════════════════

_TRAP_PORT    = int(os.environ.get("SNMP_TRAP_PORT", "1162"))  # unprivileged
_TRAP_THREAD  = None
_TRAP_RUNNING = False

# OID suffix → human name (common traps)
_TRAP_OIDS = {
    "1.3.6.1.6.3.1.1.5.1": "coldStart",
    "1.3.6.1.6.3.1.1.5.2": "warmStart",
    "1.3.6.1.6.3.1.1.5.3": "linkDown",
    "1.3.6.1.6.3.1.1.5.4": "linkUp",
    "1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
    "1.3.6.1.6.3.1.1.5.6": "egpNeighborLoss",
    "1.3.6.1.4.1.9.9.187.1.2.0.1": "bgpEstablished",
    "1.3.6.1.4.1.9.9.187.1.2.0.2": "bgpBackwardTransition",
}

def _parse_snmp_trap(data: bytes, src_ip: str) -> dict:
    """Minimal SNMP v1/v2c trap parser (enough for demo display)."""
    trap_type = "unknown"
    try:
        # Very basic: detect v2c community + generic-trap OID suffix
        text = data.hex()
        for oid, name in _TRAP_OIDS.items():
            oid_hex = "".join(f"{int(p):02x}" for p in oid.split(".") if p)
            if oid_hex in text:
                trap_type = name
                break
        if trap_type == "unknown" and len(data) > 4:
            # Guess from version byte: 0x30=sequence, then length, then version
            trap_type = "v2cTrap" if data[0] == 0x30 else "genericTrap"
    except (ValueError, IndexError) as e:
        log.debug("snmp trap parse fallback (%s): %s", src_ip, e)
    return {
        "ts":        datetime.now(timezone.utc).isoformat(),
        "src":       src_ip,
        "trap_type": trap_type,
        "raw_len":   len(data),
    }

def _trap_listener():
    global _TRAP_RUNNING
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", _TRAP_PORT))
        sock.settimeout(1.0)
        log.info(f"SNMP trap receiver listening on UDP:{_TRAP_PORT}")
        while _TRAP_RUNNING:
            try:
                data, (src_ip, _) = sock.recvfrom(65535)
                trap = _parse_snmp_trap(data, src_ip)
                _TRAP_BUFFER.append(trap)
            except socket.timeout:
                continue
            except Exception as e:
                log.debug(f"Trap recv error: {e}")
        sock.close()
    except Exception as e:
        log.warning(f"SNMP trap listener failed: {e}")

def start_trap_receiver():
    global _TRAP_THREAD, _TRAP_RUNNING
    if _TRAP_THREAD and _TRAP_THREAD.is_alive():
        return
    _TRAP_RUNNING = True
    _TRAP_THREAD = threading.Thread(target=_trap_listener, daemon=True, name="trap-receiver")
    _TRAP_THREAD.start()

# Demo traps seed
_DEMO_TRAPS = [
    ("de-fra-core-01", "linkDown"),
    ("de-fra-fw-01",    "bgpBackwardTransition"),
    ("uk-lon-fw-01",    "linkUp"),
    ("nl-ams-eos-rt-01","bgpEstablished"),
    ("de-fra-ex-01",    "authenticationFailure"),
    ("us-nyc-eos-rt-01","linkDown"),
    ("eu-cdg-mx-01",    "bgpEstablished"),
    ("uk-lon-core-01", "warmStart"),
]

def inject_demo_traps(n: int = 10):
    for _ in range(n):
        host, trap_type = _random.choice(_DEMO_TRAPS)
        _TRAP_BUFFER.append({
            "ts":        datetime.now(timezone.utc).isoformat(),
            "src":       host,
            "trap_type": trap_type,
            "raw_len":   48,
        })


@mv_bp.route("/api/mv/snmp/traps", methods=["GET"])
def mv_snmp_traps():
    limit = min(int(request.args.get("limit", 50)), 200)
    traps = list(_TRAP_BUFFER)[-limit:]
    trap_counts: dict[str, int] = {}
    for t in traps:
        tp = t.get("trap_type", "unknown")
        trap_counts[tp] = trap_counts.get(tp, 0) + 1
    return jsonify({
        "total":         len(list(_TRAP_BUFFER)),
        "returned":      len(traps),
        "receiver_port": _TRAP_PORT,
        "trap_counts":   trap_counts,
        "traps":         list(reversed(traps)),
    })


# ══════════════════════════════════════════════════════════════════════════════
# ── POST /api/mv/junos/netconf — Juniper PyEZ/NETCONF query ──────────────────
# ══════════════════════════════════════════════════════════════════════════════

@mv_bp.route("/api/mv/junos/netconf", methods=["POST"])
def mv_junos_netconf():
    """Execute a NETCONF RPC against a real Juniper device via PyEZ."""
    data     = request.get_json(force=True) or {}
    hostname = (data.get("hostname") or "").strip()
    rpc_name = (data.get("rpc") or "get-software-information").strip()
    ip       = data.get("ip") or ""

    if not hostname and not ip:
        return jsonify({"error": "hostname or ip required"}), 400

    try:
        from jnpr.junos import Device as _JunosDevice
        from jnpr.junos.exception import ConnectError
        dev_ip = ip or ""
        if not dev_ip:
            # Look up in demo inventory (static devices only)
            inv_dev = next((d for d in _ALL_DEVICES if d["hostname"] == hostname and not d.get("live")), None)
            if inv_dev:
                dev_ip = inv_dev["ip"]
        if not dev_ip:
            return jsonify({"error": f"Device '{hostname}' not in inventory — provide ip explicitly"}), 404

        ssh_key  = os.environ.get("DCN_SSH_KEY", os.path.expanduser("~/.ssh/netlab_admin"))
        ssh_user = os.environ.get("DCN_SSH_USER", "netadmin2")
        dev = _JunosDevice(host=dev_ip, user=ssh_user, ssh_private_key_file=ssh_key, gather_facts=False)
        dev.open()
        rpc_result = getattr(dev.rpc, rpc_name.replace("-", "_"))()
        from lxml import etree as _et
        xml_str = _et.tostring(rpc_result, pretty_print=True).decode()
        dev.close()
        return jsonify({"hostname": hostname, "ip": dev_ip, "rpc": rpc_name, "result": xml_str})
    except ImportError:
        return jsonify({"error": "PyEZ not installed — pip install junos-eznc"}), 501
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ══════════════════════════════════════════════════════════════════════════════
# ── Phase 3: Intent / Path-trace / Eval / Orchestrator / GAIT / Runbooks / CVE
# ══════════════════════════════════════════════════════════════════════════════

# Lazy imports — these helpers live in this folder
def _import_helper(name: str):
    import importlib, sys
    if name in sys.modules:
        return sys.modules[name]
    sys.path.insert(0, _HERE)
    return importlib.import_module(name)


# ── GET /api/mv/intent/verify ──────────────────────────────────────────────────

@mv_bp.route("/api/mv/intent/verify", methods=["GET"])
def mv_intent_verify():
    """
    Cross-reference what configs CLAIM (BGP peers, OSPF areas) vs what SuzieQ
    OBSERVES from parsing the same configs. In a real deployment the
    "observed" side would come from live SuzieQ; here we contrast claims from
    inventory.json bgp_sessions against parsed configs to find drift.
    """
    drift: list[dict] = []
    by_host = {d["hostname"]: d for d in _ALL_DEVICES}

    # 1. inventory.json claims a BGP topology — verify each session has a
    #    corresponding peer entry in at least one side's parsed config
    for sess in _BGP_SESSIONS:
        a, b = sess.get("a"), sess.get("b")
        dev_a, dev_b = by_host.get(a), by_host.get(b)
        if not dev_a or not dev_b:
            drift.append({"type": "unknown_device", "session": sess})
            continue
        # if either side has a static config, parse and check peer presence
        for src, dst in ((dev_a, dev_b), (dev_b, dev_a)):
            if not src.get("config"):
                continue
            parsed = _suzieq_parse_device(src)
            peer_ips = {p["ip"] for p in parsed.get("bgp_peers", [])}
            if dst.get("ip") not in peer_ips:
                drift.append({
                    "type": "claimed_peer_missing",
                    "device": src["hostname"],
                    "claimed_peer": dst["hostname"],
                    "claimed_peer_ip": dst.get("ip"),
                })

    # 2. parsed config has peers NOT declared in inventory.json
    declared_pairs: set[tuple[str, str]] = set()
    for s in _BGP_SESSIONS:
        declared_pairs.add(tuple(sorted([s["a"], s["b"]])))

    ip_to_host = {d["ip"]: d["hostname"] for d in _ALL_DEVICES if d.get("ip")}
    for dev in _ALL_DEVICES:
        if not dev.get("config"):
            continue
        parsed = _suzieq_parse_device(dev)
        for peer in parsed.get("bgp_peers", []):
            pip = peer.get("ip")
            phost = ip_to_host.get(pip)
            if phost and tuple(sorted([dev["hostname"], phost])) not in declared_pairs:
                drift.append({
                    "type": "undeclared_peer",
                    "device": dev["hostname"],
                    "observed_peer": phost,
                    "observed_peer_ip": pip,
                })

    # Deduplicate drift events
    seen: set[str] = set()
    unique: list[dict] = []
    for d in drift:
        key = json.dumps(d, sort_keys=True)
        if key not in seen:
            seen.add(key)
            unique.append(d)

    total = len(_BGP_SESSIONS) * 2
    score = round(max(0.0, 1.0 - (len(unique) / max(total, 1))) * 100, 1)

    return jsonify({
        "drift_count": len(unique),
        "drift": unique,
        "intent_score": score,
        "total_sessions_checked": len(_BGP_SESSIONS),
        "method": "config-claim vs config-parse cross-check",
    })


# ── GET /api/mv/path/trace ─────────────────────────────────────────────────────

@mv_bp.route("/api/mv/path/trace", methods=["GET"])
def mv_path_trace():
    """
    Compute hop-by-hop path between src and dst hostnames using bgp_sessions
    as the graph. Returns nodes (with health colors) + edges for SVG render.
    """
    src = request.args.get("src", "")
    dst = request.args.get("dst", "")
    if not src or not dst:
        return jsonify({"error": "src and dst hostnames required"}), 400
    if src == dst:
        return jsonify({"error": "src and dst must differ", "src": src, "dst": dst}), 400

    # Build a richer adjacency graph that covers all 26 devices, not just the
    # FRR BGP mesh. inventory.json bgp_sessions only enumerate FRR-FRR peerings;
    # static-config devices (Juniper SRX/MX/EX, Arista) need site-level edges
    # so any-to-any path trace works and produces multi-vendor visualizations.
    adj: dict[str, list[str]] = {}
    edge_types: dict[tuple[str, str], str] = {}

    def _add_edge(a: str, b: str, etype: str) -> None:
        if a == b:
            return
        key = tuple(sorted([a, b]))
        if key in edge_types:
            return
        edge_types[key] = etype
        adj.setdefault(a, []).append(b)
        adj.setdefault(b, []).append(a)

    # 1. eBGP/iBGP sessions from inventory.json
    for s in _BGP_SESSIONS:
        _add_edge(s["a"], s["b"], s.get("type", "BGP"))

    # 2. Site-level adjacency: pick the FRR core in each site as the anchor
    #    and connect every other device in that site to it. Falls back to the
    #    first device in the site if no FRR core exists.
    by_site: dict[str, list[dict]] = {}
    for d in _ALL_DEVICES:
        by_site.setdefault(d.get("site", "?"), []).append(d)

    for site, devs in by_site.items():
        cores = [d for d in devs if d.get("vendor") == "frr" and d.get("role") == "core"]
        anchor = cores[0]["hostname"] if cores else devs[0]["hostname"]
        for d in devs:
            _add_edge(anchor, d["hostname"], "site-LAN")

    # BFS
    if src not in adj:
        return jsonify({"error": f"src {src!r} has no edges in topology", "src": src, "dst": dst}), 404
    if dst not in adj:
        return jsonify({"error": f"dst {dst!r} has no edges in topology", "src": src, "dst": dst}), 404

    queue: list[tuple[str, list[str]]] = [(src, [src])]
    seen: set[str] = {src}
    path: list[str] = []
    while queue:
        node, p = queue.pop(0)
        if node == dst:
            path = p
            break
        for n in adj.get(node, []):
            if n not in seen:
                seen.add(n)
                queue.append((n, p + [n]))

    if not path:
        return jsonify({"error": "no path", "src": src, "dst": dst}), 404

    by_host = {d["hostname"]: d for d in _ALL_DEVICES}
    nodes = []
    for hop, h in enumerate(path):
        d = by_host.get(h, {})
        nodes.append({
            "hostname": h,
            "vendor": d.get("vendor", "unknown"),
            "site": d.get("site", "?"),
            "role": d.get("role", "?"),
            "ip": d.get("ip"),
            "hop": hop,
            "color": {"juniper": "#22c55e", "arista": "#3b82f6", "frr": "#a855f7"}.get(d.get("vendor"), "#888"),
            "health": "ok",  # placeholder — could be wired to live BGP state
        })
    edges = []
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        key = tuple(sorted([a, b]))
        edges.append({"from": a, "to": b, "type": edge_types.get(key, "unknown")})

    vendors = sorted({n["vendor"] for n in nodes if n.get("vendor") and n["vendor"] != "unknown"})
    sites = sorted({n["site"] for n in nodes if n.get("site") and n["site"] != "?"})

    return jsonify({
        "src": src,
        "dst": dst,
        "hops": len(path) - 1,
        "path": path,
        "nodes": nodes,
        "edges": edges,
        "vendors": vendors,
        "sites": sites,
    })


# ── Eval harness endpoints ─────────────────────────────────────────────────────

@mv_bp.route("/api/mv/eval/scenarios", methods=["GET"])
def mv_eval_scenarios():
    eh = _import_helper("eval_harness")
    scenarios = eh.load_scenarios()
    return jsonify({"count": len(scenarios), "scenarios": scenarios})


@mv_bp.route("/api/mv/eval/run", methods=["POST"])
def mv_eval_run():
    body = request.get_json(silent=True) or {}
    scenario_id = body.get("scenario_id") or request.args.get("scenario_id", "")
    agent = body.get("agent") or "ai_command"
    if not scenario_id:
        return jsonify({"error": "scenario_id required"}), 400
    eh = _import_helper("eval_harness")
    result = eh.run_scenario(scenario_id, agent=agent)
    return jsonify(result)


# ── Pydantic-AI orchestrator ───────────────────────────────────────────────────

def _find_devices_in_prompt(prompt: str) -> list[dict]:
    """Match any inventory hostname appearing in the prompt (longest first)."""
    p = prompt.lower()
    hits: list[dict] = []
    seen: set[str] = set()
    for d in sorted(_ALL_DEVICES, key=lambda x: -len(x.get("hostname", ""))):
        h = d.get("hostname", "").lower()
        if h and h in p and h not in seen:
            hits.append(d)
            seen.add(h)
    return hits[:3]  # cap at 3 to keep context compact


_BGP_HEADERS = ("router bgp", "protocols bgp", "policy-options", "routing-options")
_OSPF_HEADERS = ("router ospf", "protocols ospf", "interface ", "area ")
_FW_HEADERS = ("security policies", "firewall", "ip access-list", "policy-statement")


def _extract_section(cfg: str, agent: str, max_lines: int = 80) -> str:
    """Pull the BGP / OSPF / firewall section from a config blob, capped to max_lines."""
    if agent == "acl":
        keys = _FW_HEADERS
    elif agent == "incident":
        keys = _BGP_HEADERS + _OSPF_HEADERS + _FW_HEADERS
    else:
        keys = _BGP_HEADERS + _OSPF_HEADERS
    lines = cfg.splitlines()
    keep: list[str] = []
    in_block = False
    block_indent = -1
    for ln in lines:
        low = ln.lower().lstrip()
        if any(low.startswith(k) for k in keys):
            in_block = True
            block_indent = len(ln) - len(ln.lstrip())
            keep.append(ln)
            continue
        if in_block:
            cur_indent = len(ln) - len(ln.lstrip())
            if ln.strip() == "" or cur_indent > block_indent:
                keep.append(ln)
            else:
                in_block = False
        if len(keep) >= max_lines:
            break
    return "\n".join(keep[:max_lines])


def _collect_live_frr(dev: dict, agent: str) -> str:
    """Fetch live state from an FRR container via vtysh."""
    try:
        sys.path.insert(0, _HERE)
        import app as flask_app  # type: ignore
    except ImportError as e:
        return f"# live fetch unavailable: {e}"
    cmds = (
        ("show ip bgp summary", "show running-config bgp")
        if agent != "acl" else
        ("show running-config", "show ip route")
    )
    out: list[str] = []
    for cmd in cmds:
        try:
            r = flask_app.run_command_on_device(
                dev.get("ip", "127.0.0.1"), "frr", cmd, port=int(dev.get("port", 22))
            )
            text = (r or {}).get("output", "")
            if text:
                out.append(f"$ {cmd}\n{text[:1500]}")
        except (OSError, RuntimeError, ValueError) as e:
            out.append(f"# {cmd} failed: {e}")
    return "\n\n".join(out)


def _build_orchestrator_context(prompt: str, agent: str) -> str:
    devs = _find_devices_in_prompt(prompt)
    if not devs:
        return ""
    chunks: list[str] = []
    for d in devs:
        host = d.get("hostname", "?")
        head = f"### Device: {host}  vendor={d.get('vendor','?')} os={d.get('os','?')} site={d.get('site','?')} live={bool(d.get('live'))}"
        chunks.append(head)
        cfg_path = d.get("config")
        if cfg_path:
            full = os.path.join(_DEMO_DIR, cfg_path)
            try:
                with open(full, errors="replace") as f:
                    cfg = f.read()
                section = _extract_section(cfg, agent)
                if section.strip():
                    chunks.append(f"# config snippet ({cfg_path})\n{section}")
                else:
                    chunks.append(f"# config snippet ({cfg_path}) — first 60 lines\n" + "\n".join(cfg.splitlines()[:60]))
            except OSError as e:
                chunks.append(f"# config read failed: {e}")
        if d.get("live"):
            chunks.append(f"# live state\n{_collect_live_frr(d, agent)}")
    return "\n\n".join(chunks)[:8000]  # hard cap to protect token budget


@mv_bp.route("/api/mv/orchestrator", methods=["POST"])
def mv_orchestrator():
    body = request.get_json(silent=True) or {}
    prompt = body.get("prompt") or body.get("query") or ""
    if not prompt:
        return jsonify({"error": "prompt required"}), 400
    orch = _import_helper("pydantic_ai_orchestrator")
    decision = orch._classify(prompt)
    context = _build_orchestrator_context(prompt, decision)
    result = orch.run_orchestrator_structured(prompt, context=context or None)
    result["devices_resolved"] = [d.get("hostname") for d in _find_devices_in_prompt(prompt)]
    g = _import_helper("gait_audit")
    g.record(actor="orchestrator", action="diagnose", target=",".join(result["devices_resolved"]) or None,
             prompt=prompt, response=result.get("rendered", "")[:500],
             tools_called=[result.get("agent", "?")],
             tokens=result.get("usage") or {},
             status="ok",
             extra={"context_chars": result.get("context_chars", 0)})
    return jsonify(result)


# ── GAIT audit endpoints ───────────────────────────────────────────────────────

@mv_bp.route("/api/mv/gait/recent", methods=["GET"])
def mv_gait_recent():
    g = _import_helper("gait_audit")
    limit = int(request.args.get("limit", 50))
    actor = request.args.get("actor") or None
    return jsonify({"events": g.recent(limit=limit, actor=actor), "limit": limit})


# ── Health Gate (Day-1 Observe→Decide→Act→Verify orchestrator) ──────────────
#
# POST /api/mv/health-gate/apply
#   { hostname, edit_payload?, timeout_s?, tolerance? }
#   → { job_id, hostname, mode, phase }
#
# GET  /api/mv/health-gate/status/<job_id>
#   → full job dict (phase, progress_pct, snapshots, verdict, ...)
#
# GET  /api/mv/health-gate/recent?limit=20
#   → newest jobs first
#
@mv_bp.route("/api/mv/health-gate/apply", methods=["POST"])
def mv_health_gate_apply():
    hg = _import_helper("health_gate")
    data = request.get_json(force=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname required"}), 400
    # Whitelist of demo / test hooks the UI is allowed to pass through.
    # These are explicit no-ops in production — see health_gate._run_job.
    _ALLOWED_HOOKS = {
        "induce_regression_after_s",
        "induce_alert_spike_after_s",
        "fail_at_phase",
    }
    hooks = {k: data[k] for k in _ALLOWED_HOOKS if k in data and data[k] is not None}
    try:
        job = hg.submit(
            hostname=hostname,
            edit_payload=data.get("edit_payload") or "",
            timeout_s=int(data.get("timeout_s") or hg.DEFAULT_TIMEOUT_S),
            tolerance=data.get("tolerance") or None,
            **hooks,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except TypeError as e:
        return jsonify({"error": f"bad arguments: {e}"}), 400
    return jsonify({
        "job_id": job.job_id,
        "hostname": job.hostname,
        "mode": job.mode,
        "phase": job.phase,
        "timeout_s": job.timeout_s,
    })


@mv_bp.route("/api/mv/health-gate/status/<job_id>", methods=["GET"])
def mv_health_gate_status(job_id: str):
    hg = _import_helper("health_gate")
    job = hg.get_job(job_id)
    if not job:
        return jsonify({"error": "job not found"}), 404
    return jsonify(job.to_dict())


@mv_bp.route("/api/mv/health-gate/recent", methods=["GET"])
def mv_health_gate_recent():
    hg = _import_helper("health_gate")
    limit = int(request.args.get("limit", 20))
    return jsonify({"jobs": hg.list_recent_jobs(limit=limit), "limit": limit})


@mv_bp.route("/api/mv/gait/stats", methods=["GET"])
def mv_gait_stats():
    g = _import_helper("gait_audit")
    return jsonify(g.stats())


# ── Runbooks ───────────────────────────────────────────────────────────────────

@mv_bp.route("/api/mv/runbooks", methods=["GET"])
def mv_runbooks():
    rb_dir = os.path.join(_HERE, "runbooks")
    out: list[dict] = []
    if os.path.isdir(rb_dir):
        for fn in sorted(os.listdir(rb_dir)):
            if not fn.endswith(".yaml"):
                continue
            path = os.path.join(rb_dir, fn)
            try:
                with open(path) as f:
                    content = f.read()
                # naive YAML head extraction (no PyYAML dep)
                meta: dict[str, str] = {}
                for line in content.splitlines()[:10]:
                    m = re.match(r"^(id|title|category|severity):\s*(.+?)\s*$", line)
                    if m:
                        meta[m.group(1)] = m.group(2).strip()
                meta["file"] = fn
                meta["raw"] = content
                out.append(meta)
            except OSError:
                continue
    return jsonify({"count": len(out), "runbooks": out})


@mv_bp.route("/api/mv/runbook/execute", methods=["POST"])
def mv_runbook_execute():
    """Dry-run a runbook: returns the canonical commands per step + per-vendor CLI."""
    body = request.get_json(silent=True) or {}
    runbook_id = body.get("runbook_id") or ""
    device = body.get("device") or ""
    if not runbook_id or not device:
        return jsonify({"error": "runbook_id and device required"}), 400

    rb_path = os.path.join(_HERE, "runbooks", f"{runbook_id}.yaml")
    if not os.path.exists(rb_path):
        return jsonify({"error": f"runbook {runbook_id} not found"}), 404
    with open(rb_path) as f:
        content = f.read()

    # Find the device's vendor / os
    dev = next((d for d in _ALL_DEVICES if d["hostname"] == device), None)
    if not dev:
        return jsonify({"error": f"device {device} not in inventory"}), 404
    vt = _import_helper("vendor_translator")
    vendor = vt.vendor_for_os(dev.get("os", dev.get("vendor", "")))

    # Naive extraction of canonical_task: <name> from yaml
    tasks = re.findall(r'canonical_task:\s*(\S+)', content)
    steps: list[dict] = []
    for t in tasks:
        try:
            cli = vt.translate(t, vendor)
        except KeyError:
            cli = f"# task {t} unsupported on vendor {vendor}"
        steps.append({"canonical_task": t, "vendor": vendor, "cli": cli, "destructive": vt.is_destructive(t)})

    g = _import_helper("gait_audit")
    g.record(actor="runbook", action=f"dry_run:{runbook_id}", target=device,
             tools_called=[t for t in tasks], status="ok",
             extra={"steps": len(steps)})

    return jsonify({
        "runbook_id": runbook_id,
        "device": device,
        "vendor": vendor,
        "dry_run": True,
        "steps": steps,
    })


# ── CVE scanner ────────────────────────────────────────────────────────────────

@mv_bp.route("/api/mv/cve", methods=["GET"])
def mv_cve():
    """Return CVEs that match each device's (vendor, OS version)."""
    cve_path = os.path.join(_HERE, "cve_db.json")
    if not os.path.exists(cve_path):
        return jsonify({"error": "cve_db.json missing"}), 500
    with open(cve_path) as f:
        db = json.load(f)
    entries = db.get("entries", [])

    matches: list[dict] = []
    for dev in _ALL_DEVICES:
        if not dev.get("config"):
            continue
        full = os.path.join(_DEMO_DIR, dev["config"])
        try:
            with open(full, errors="replace") as f:
                txt = f.read()[:8000]
        except OSError:
            continue

        # Heuristic version extraction
        ver: str | None = None
        for pat in (r'version\s+(\d{2}\.\d[\w.-]*)', r'os version (\d[\w.-]+)'):
            m = re.search(pat, txt, re.I)
            if m:
                ver = m.group(1)
                break

        device_cves: list[dict] = []
        for entry in entries:
            if entry["vendor"] != dev["vendor"] or entry["os"] != dev.get("os"):
                continue
            if ver and ver.startswith(entry["version_prefix"]):
                device_cves.extend(entry["cves"])
            elif not ver and entry["version_prefix"] in txt[:2000]:
                device_cves.extend(entry["cves"])

        if device_cves:
            matches.append({
                "hostname": dev["hostname"],
                "vendor": dev["vendor"],
                "os": dev.get("os"),
                "detected_version": ver,
                "cve_count": len(device_cves),
                "cves": device_cves,
            })

    crit = sum(1 for m in matches for c in m["cves"] if c.get("severity") == "critical")
    high = sum(1 for m in matches for c in m["cves"] if c.get("severity") == "high")
    return jsonify({
        "devices_scanned": sum(1 for d in _ALL_DEVICES if d.get("config")),
        "devices_with_cves": len(matches),
        "critical": crit,
        "high": high,
        "matches": matches,
    })


# ── Vendor command translator (read-only) ─────────────────────────────────────

@mv_bp.route("/api/mv/translator", methods=["GET", "POST"])
def mv_translator():
    vt = _import_helper("vendor_translator")
    if request.method == "GET":
        return jsonify({"tasks": vt.supported_tasks(), "vendors": vt.supported_vendors()})
    body = request.get_json(silent=True) or {}
    task = body.get("task")
    vendor = body.get("vendor")
    fmt = body.get("fmt") or {}
    if not task or not vendor:
        return jsonify({"error": "task and vendor required"}), 400
    try:
        cli = vt.translate(task, vendor, **fmt)
    except KeyError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"task": task, "vendor": vendor, "cli": cli, "destructive": vt.is_destructive(task)})


# ── TOON serializer endpoint ─────────────────────────────────────────────────

@mv_bp.route("/api/mv/toon", methods=["GET"])
def mv_toon():
    """Return any list endpoint serialized in TOON format with size savings."""
    target = request.args.get("target", "devices")
    toon = _import_helper("toon_serializer")
    if target == "devices":
        rows = _ALL_DEVICES
    elif target == "sessions":
        rows = _BGP_SESSIONS
    else:
        return jsonify({"error": f"unknown target: {target}"}), 400
    text = toon.to_toon(rows)
    stats = toon.size_savings(rows)
    return jsonify({"target": target, "toon": text, "rows": len(rows), **stats})


# ══════════════════════════════════════════════════════════════════════════════
# ── Blueprint startup hook ─────────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════════════

def init_mv_services():
    """Call from app startup to seed demo data and start receivers."""
    inject_demo_syslog(25)
    inject_demo_traps(12)
    try:
        start_syslog_receiver()
    except Exception as e:
        log.warning(f"Syslog receiver not started: {e}")
    try:
        start_trap_receiver()
    except Exception as e:
        log.warning(f"SNMP trap receiver not started: {e}")
    log.info(f"Multivendor extensions ready — {len(_ALL_DEVICES)} devices, "
             f"{sum(1 for d in _ALL_DEVICES if d.get('live'))} live FRR containers")
