#!/usr/bin/env python3
"""
MCP Server wrapper for DCN Network Tool.
Exposes all 17 API endpoints as MCP tools for AI agent integration.

Usage:
    python mcp_dcn_server.py

Environment:
    DCN_API_URL  — Base URL of the DCN Network Tool API (default: http://localhost:5757)
"""
import os
import json
import urllib.request
import urllib.error
from mcp.server.fastmcp import FastMCP

DCN_URL = os.environ.get("DCN_API_URL", "http://localhost:5757")

mcp = FastMCP(
    "dcn-network-tool",
    instructions=(
        "DCN Network Tool — 34 legacy network ops APIs + LibreNMS + bandwidth forecasting + "
        "network-wide reports, plus Phase 3 multivendor capabilities: 26-device demo lab "
        "(Juniper/Arista/FRR), Batfish-style fleet audit, SuzieQ-style observability, "
        "gNMI telemetry, intent verification, hop-by-hop path trace, CVE scanner, "
        "vendor-agnostic command translator, eval harness with 10 scenarios + LLM-as-judge, "
        "Pydantic-AI multi-agent orchestrator (Routing/ACL/Incident), auto-remediation "
        "runbooks (BGP/OSPF/Interface/ACL), and immutable GAIT audit trail."
    ),
)


def _post(path: str, body: dict, timeout: int = 180) -> dict:
    """POST JSON to DCN API and return parsed response."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        f"{DCN_URL}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode()[:500]}"}
    except Exception as e:
        return {"error": str(e)}


def _get(path: str, params: dict = None, timeout: int = 30) -> str:
    """GET from DCN API and return raw text."""
    url = f"{DCN_URL}{path}"
    if params:
        qs = "&".join(f"{k}={v}" for k, v in params.items() if v)
        if qs:
            url += f"?{qs}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.read().decode()
    except Exception as e:
        return json.dumps({"error": str(e)})


# ── GET Endpoints ─────────────────────────────────────────────────────────────

@mcp.tool()
def dcn_health() -> str:
    """Check if the DCN Network Tool API is running."""
    return _get("/api/health")


@mcp.tool()
def dcn_list_devices(site: str = "", role: str = "", search: str = "") -> str:
    """List network devices. Filter by site code (e.g. DE-FRA), role (switch/firewall/router), or hostname search."""
    return _get("/api/devices", {"site": site, "role": role, "search": search})


@mcp.tool()
def dcn_list_sites() -> str:
    """List all unique datacenter site codes."""
    return _get("/api/sites")


@mcp.tool()
def dcn_available_commands(dtype: str = "junos") -> str:
    """List available named commands for a device type (junos or eos)."""
    return _get(f"/api/commands/{dtype}")


# ── POST Endpoints ────────────────────────────────────────────────────────────

@mcp.tool()
def dcn_run_command(ip: str, dtype: str = "junos", cmd_key: str = "", raw: str = "") -> str:
    """Run a CLI command on a device via SSH. Use cmd_key for named commands (e.g. 'version', 'bgp') or raw for custom commands."""
    body = {"ip": ip, "dtype": dtype}
    if raw:
        body["raw"] = raw
    elif cmd_key:
        body["cmd_key"] = cmd_key
    return json.dumps(_post("/api/run", body))


@mcp.tool()
def dcn_ping(ip: str, dtype: str = "junos") -> str:
    """Quick SSH reachability test for a device."""
    return json.dumps(_post("/api/ping", {"ip": ip, "dtype": dtype}, timeout=45))


@mcp.tool()
def dcn_snapshot(ip: str, dtype: str = "junos") -> str:
    """Collect full device snapshot: version, uptime, interfaces, ARP, routes, BGP, alarms, logs."""
    return json.dumps(_post("/api/snapshot", {"ip": ip, "dtype": dtype}, timeout=300))


@mcp.tool()
def dcn_port_capacity(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Get port capacity breakdown: total physical slots, in use, empty, admin disabled, optics installed, by-speed table."""
    return json.dumps(_post("/api/ports", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=180))


@mcp.tool()
def dcn_capacity_forecast(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Analyze interface utilization: traffic rates, speed breakdown, high-utilization ports."""
    return json.dumps(_post("/api/capacity", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=180))


@mcp.tool()
def dcn_incident(ip: str, dtype: str = "junos") -> str:
    """Collect incident investigation data: logs, alarms, BGP, IKE/IPsec, interfaces, firewall, ISP optics, MTU."""
    return json.dumps(_post("/api/incident", {"ip": ip, "dtype": dtype}, timeout=300))


@mcp.tool()
def dcn_analyze(hostname: str, dtype: str = "junos", data: dict = None) -> str:
    """AI pattern-match analysis on collected command outputs. Pass data as {cmd_key: output_string}."""
    return json.dumps(_post("/api/analyze", {"hostname": hostname, "dtype": dtype, "data": data or {}}))


@mcp.tool()
def dcn_recommendations(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Generate best-practice recommendations with severity and remediation steps."""
    return json.dumps(_post("/api/recommendations", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=300))


@mcp.tool()
def dcn_deep_analysis(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Comprehensive AI health report: 20+ commands, cross-correlated analysis, scored with severity breakdown."""
    return json.dumps(_post("/api/deep-analysis", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=600))


@mcp.tool()
def dcn_log_analysis(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Log Intelligence: collect ~1000 syslog messages, classify by severity/category/action."""
    return json.dumps(_post("/api/log-analysis", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=180))


@mcp.tool()
def dcn_config_drift(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Config Drift & Compliance: 18 checks (NTP, SNMP, syslog, AAA, BGP, firewall) + drift detection vs baseline."""
    return json.dumps(_post("/api/config-drift", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=300))


@mcp.tool()
def dcn_topology(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Topology Discovery: map neighbors via LLDP, descriptions, BGP, OSPF, ISIS, LACP, MLAG."""
    return json.dumps(_post("/api/topology", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=300))


@mcp.tool()
def dcn_security_audit(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Security Posture Audit: firmware CVE awareness, crypto, ACL, users, SNMP, BGP auth, VPN status. Returns scored report."""
    return json.dumps(_post("/api/security-audit", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=300))


# ── LibreNMS Integration Tools ───────────────────────────────────────────────

@mcp.tool()
def dcn_librenms_device(hostname: str, region: str = "") -> str:
    """Get device info from LibreNMS: model, OS version, uptime, location, poll status. Auto-detects region from hostname."""
    return _get(f"/api/librenms/device/{hostname}", {"region": region})


@mcp.tool()
def dcn_librenms_ports(hostname: str, region: str = "") -> str:
    """Get all port traffic rates from LibreNMS: current IN/OUT Mbps, utilization %, errors. Sorted by traffic."""
    return _get(f"/api/librenms/ports/{hostname}", {"region": region})


@mcp.tool()
def dcn_librenms_bandwidth(hostname: str, ifname: str, period: str = "24h", region: str = "") -> str:
    """Get bandwidth data for a specific port. Period: 1h, 6h, 24h, 7d, 30d, 90d, 1y. Returns graph URL and stats."""
    return _get(f"/api/librenms/bandwidth/{hostname}/{ifname}", {"period": period, "region": region})


@mcp.tool()
def dcn_librenms_top_ports(site: str, limit: int = 20, region: str = "") -> str:
    """Get busiest ports at a site from LibreNMS, sorted by total traffic. Shows hostname, interface, Mbps, utilization %."""
    return _get("/api/librenms/top-ports", {"site": site, "limit": str(limit), "region": region})


@mcp.tool()
def dcn_librenms_alerts(site: str = "", region: str = "") -> str:
    """Get active LibreNMS alerts. Filter by site code (e.g. DE-FRA). Shows hostname, rule, severity, timestamp."""
    return _get("/api/librenms/alerts", {"site": site, "region": region})


@mcp.tool()
def dcn_librenms_health(hostname: str, region: str = "") -> str:
    """Get device health from LibreNMS: CPU, memory, temperature, fans, PSU, voltage readings."""
    return _get(f"/api/librenms/health/{hostname}", {"region": region})


@mcp.tool()
def dcn_librenms_forecast(hostname: str, growth: str = "", region: str = "") -> str:
    """Bandwidth capacity forecast for a device: current utilization + 6-month projection. Identifies critical/warning/at-risk ports. Optional growth=N for monthly growth % override."""
    return _get(f"/api/librenms/forecast/{hostname}", {"growth": growth, "region": region})


@mcp.tool()
def dcn_librenms_forecast_site(site: str, growth: str = "", limit: int = 30, region: str = "") -> str:
    """Site-wide bandwidth capacity forecast: all devices at a site with 6-month projection. Shows critical ports that will exceed capacity."""
    return _get("/api/librenms/forecast-site", {"site": site, "growth": growth, "limit": str(limit), "region": region})


# ── IP Analysis Tools ────────────────────────────────────────────────────────

@mcp.tool()
def dcn_subnet_analysis(ip: str, dtype: str = "junos", hostname: str = "") -> str:
    """Subnet IP exhaustion analysis: per-subnet utilization from ARP table, active hosts with MAC/hostname, free IPs, critical/warning thresholds. Works on firewalls, routers, L3 switches."""
    return json.dumps(_post("/api/subnet-analysis", {"ip": ip, "dtype": dtype, "hostname": hostname}, timeout=120))


# ── Network-Wide Report Tools ────────────────────────────────────────────────

@mcp.tool()
def dcn_isp_links(site: str = "") -> str:
    """Network-wide ISP link scan: all ISP/transit/IX links across all 3 LibreNMS regions with traffic, utilization, 6-month projection, and risk level."""
    return _get("/api/isp-links", {"site": site}, timeout=300)


@mcp.tool()
def dcn_report_ports(site: str = "") -> str:
    """Network-wide port capacity report via LibreNMS: scans all routers, switches, firewalls. Shows total/used/free ports per device."""
    return _get("/api/report/ports", {"site": site}, timeout=300)


@mcp.tool()
def dcn_report_bgp(site: str = "") -> str:
    """Network-wide BGP session health via LibreNMS: scans all routers for BGP peers, states, prefix counts, down sessions."""
    return _get("/api/report/bgp", {"site": site}, timeout=300)


@mcp.tool()
def dcn_report_ip_exhaustion(site: str = "") -> str:
    """Network-wide IP exhaustion report: scans firewalls/routers via SSH, analyzes subnets per site with utilization and critical thresholds."""
    return _get("/api/report/ip-exhaustion", {"site": site}, timeout=600)


# ── NetPortal Capacity Tools ─────────────────────────────────────────────────

@mcp.tool()
def dcn_netportal_reports() -> str:
    """List available NetPortal capacity reports (daily auto-generated). Shows report ID, date, site count."""
    return _get("/api/netportal/reports")


@mcp.tool()
def dcn_netportal_summary() -> str:
    """NetPortal all-sites summary: 40+ sites with switch count, ports (total/used/free), racks, IP prefixes, ISP links."""
    return _get("/api/netportal/summary", timeout=60)


@mcp.tool()
def dcn_netportal_site(site_code: str) -> str:
    """NetPortal per-site detail: ports by speed, ISP links with 90d 97th percentile bandwidth, IP prefixes with undocumented IPs, switches, racks, data quality."""
    return _get(f"/api/netportal/site/{site_code}")


@mcp.tool()
def dcn_netportal_download(report_id: int) -> str:
    """Download a full NetPortal capacity report by ID. Returns complete JSON report data."""
    return _get(f"/api/netportal/download/{report_id}", timeout=120)


# ── Multivendor Phase 3 tools ────────────────────────────────────────────────


@mcp.tool()
def mv_list_devices(vendor: str = "", site: str = "", live: str = "") -> str:
    """List the 26 multivendor demo devices. Filters: vendor (juniper|arista|frr), site (DE-FRA|UK-LON|NL-AMS|EU-CDG|US-NYC), live (true|false)."""
    return _get("/api/mv/devices", {"vendor": vendor, "site": site, "live": live})


@mcp.tool()
def mv_topology() -> str:
    """Return the full 26-device topology including BGP sessions and site coordinates for diagram rendering."""
    return _get("/api/mv/topology")


@mcp.tool()
def mv_fleet_audit(site: str = "", vendor: str = "") -> str:
    """Batfish-style audit across all 16 sanitized configs. Returns issues per device (auth weaknesses, missing services, security findings)."""
    return json.dumps(_post("/api/mv/batfish/fleet", {"site": site, "vendor": vendor}))


@mcp.tool()
def mv_suzieq(verb: str = "show", table: str = "bgp", site: str = "", vendor: str = "") -> str:
    """SuzieQ-style offline observability. verb: show|assert|unique|summarize. table: bgp|ospf|interfaces|inventory."""
    return _get("/api/mv/suzieq/analyze", {"verb": verb, "table": table, "site": site, "vendor": vendor})


@mcp.tool()
def mv_gnmi(hostname: str, oc_path: str) -> str:
    """gNMI-style telemetry query. oc_path: an OpenConfig-style XPath, mapped to vtysh on FRR containers."""
    return json.dumps(_post("/api/mv/gnmi/query", {"hostname": hostname, "path": oc_path}))


@mcp.tool()
def mv_intent_verify() -> str:
    """Cross-reference inventory.json BGP sessions against parsed configs to flag drift (claimed-but-missing, observed-but-undeclared)."""
    return _get("/api/mv/intent/verify")


@mcp.tool()
def mv_path_trace(src: str, dst: str) -> str:
    """Compute hop-by-hop path between two devices using the BGP session graph. Returns nodes and edges for SVG render."""
    return _get("/api/mv/path/trace", {"src": src, "dst": dst})


@mcp.tool()
def mv_eval_scenarios() -> str:
    """List the 10 pre-defined incident scenarios available for the eval harness."""
    return _get("/api/mv/eval/scenarios")


@mcp.tool()
def mv_eval_run(scenario_id: str, agent: str = "ai_command") -> str:
    """Run a single scenario through an AI agent (ai_command|orchestrator) and return keyword + LLM-judge scores."""
    return json.dumps(_post("/api/mv/eval/run", {"scenario_id": scenario_id, "agent": agent}))


@mcp.tool()
def mv_orchestrator(prompt: str) -> str:
    """Pydantic-AI multi-agent orchestrator. Auto-classifies and delegates to RoutingAgent / ACLAgent / IncidentAgent. Returns structured + rendered output."""
    return json.dumps(_post("/api/mv/orchestrator", {"prompt": prompt}))


@mcp.tool()
def mv_runbooks() -> str:
    """List available auto-remediation runbooks (bgp_peer_down, interface_down, ospf_neighbor_stuck, acl_block)."""
    return _get("/api/mv/runbooks")


@mcp.tool()
def mv_runbook_execute(runbook_id: str, device: str) -> str:
    """Dry-run a runbook on a target device. Returns canonical steps + vendor-specific CLI per step. No state changes."""
    return json.dumps(_post("/api/mv/runbook/execute", {"runbook_id": runbook_id, "device": device}))


@mcp.tool()
def mv_cve_scan() -> str:
    """Scan all 16 static configs for known CVEs by (vendor, OS version) and return critical/high counts + per-device matches."""
    return _get("/api/mv/cve")


@mcp.tool()
def mv_translate(task: str, vendor: str) -> str:
    """Translate a canonical task (e.g. bgp_summary) to vendor-specific CLI (junos|eos|frr|ios|nxos)."""
    return json.dumps(_post("/api/mv/translator", {"task": task, "vendor": vendor}))


@mcp.tool()
def mv_gait_recent(limit: int = 50, actor: str = "") -> str:
    """Return the most recent GAIT audit events. actor filter: orchestrator|eval_harness|ai_command|runbook."""
    return _get("/api/mv/gait/recent", {"limit": str(limit), "actor": actor})


# ════════════════════════════════════════════════════════════════════════
# Phase-5 additions (2026-05-25) — closed-loop pipeline, ADTK detector,
# predictive forecast, clab fabric status, knowledge layer, gnmic
# ════════════════════════════════════════════════════════════════════════
#
# These wrap the new Phase-5 endpoints shipped during the audit hardening
# pass + roadmap #3/#4/#5 deliveries. They let Claude Code drive the
# full remediation loop directly — observe (clab-status, anomaly), reason
# (correlate, knowledge), act (closed-loop), forecast (run-fleet).

@mcp.tool()
def mv_clab_status() -> str:
    """Live BGP / interface / OSPF state of every clab Clos-EVPN routing node (9 hosts), refreshed every 15 s by the launchd-supervised collector. Returns per-host counters + a stale flag if the collector hasn't ticked in >60 s."""
    return _get("/api/mv/clab-status")


@mcp.tool()
def mv_fabric_topology(fabric: str = "clos-evpn") -> str:
    """Return the device-level topology of a fabric. fabric=clos-evpn (15 nodes, 24 physical links), fabric=dcn (10 FRR nodes, 10 BGP sessions), or fabric=all (merged)."""
    return _get("/api/mv/fabric-topology", {"fabric": fabric})


@mcp.tool()
def mv_gnmic_status() -> str:
    """Health of the gnmic streaming-telemetry sidecar — target count, per-host freshness, and a green flag when all SRL targets are <30 s old."""
    return _get("/api/telemetry/gnmic-status")


@mcp.tool()
def mv_knowledge_correlate(site: str = "") -> str:
    """Correlate live InfluxDB alerts + ADTK anomalies + predictive forecast alerts into incidents, enriched with netlog-ai compliance findings. Returns incident list with root_cause from the LLM correlator. Optional site filter."""
    return json.dumps(_post("/api/keep/correlate", {"site": site} if site else {}))


@mcp.tool()
def mv_anomaly_detect(window_min: int = 30) -> str:
    """Run the ADTK-style anomaly detector (Z-score + flap-count) over the last `window_min` minutes of BGP + interface time series. Returns structured anomalies before binary up<total rules trip — typically 5-30 min earlier."""
    return json.dumps(_post("/api/anomaly/detect", {"window_min": window_min}))


@mcp.tool()
def mv_forecast_fleet(window_min: int = 60, horizon: int = 32) -> str:
    """Run forecast against every routing node's BGP + interface counters and emit predictive alerts when P95 upper bound crosses threshold within the horizon. Returns ETA-bearing alerts ('in ~X seconds, host Y metric Z will breach')."""
    return json.dumps(_post("/api/mv/forecast/run-fleet",
                            {"window_min": window_min, "horizon": horizon}))


@mcp.tool()
def mv_forecast_status() -> str:
    """Recent fleet-forecast summary: last run timestamp, total alerts emitted, per-host alert counts."""
    return _get("/api/mv/forecast/fleet-status")


@mcp.tool()
def mv_change_closed_loop(hostname: str, proposed_change: str,
                          timeout_s: int = 30, dry_run: bool = False,
                          skip_predict: bool = False,
                          skip_batfish: bool = False) -> str:
    """Run the 6-stage closed-loop change pipeline: Predict → Batfish → Apply (Health Gate) → Watch → POST snapshot diff → Intent verify. Returns a change_id you can poll. Auto-rollback on regression. Use dry_run=true to stop after Predict+Batfish (no apply)."""
    body = {
        "hostname": hostname, "proposed_change": proposed_change,
        "timeout_s": timeout_s, "dry_run": dry_run,
        "skip_predict": skip_predict, "skip_batfish": skip_batfish,
    }
    return json.dumps(_post("/api/change/closed-loop", body))


@mcp.tool()
def mv_change_status(change_id: str) -> str:
    """Poll the status of a closed-loop change run. Returns phase (queued|predict|batfish|applying|watching|post_snapshot|verify_intent|done), verdict (APPROVED|REJECTED|ROLLED_BACK|FAILED), elapsed_s, and per-stage detail."""
    return _get(f"/api/change/closed-loop/{change_id}")


@mcp.tool()
def mv_change_recent() -> str:
    """List the most recent closed-loop change runs and any in-flight jobs."""
    return _get("/api/change/closed-loop")


@mcp.tool()
def mv_chaos_bgp(action: str, fabric: str = "dcn", target: str = "") -> str:
    """BGP Chaos Monkey — stress-test the auto-remediation loop. action in {status, break, fix, chaos}; fabric in {dcn, clab}. target optional (single hostname). Live docker exec on clab; sim_bgp_failure.sh on DCN."""
    return json.dumps(_post("/api/chaos/bgp",
                            {"action": action, "fabric": fabric, "target": target}))


@mcp.tool()
def mv_napalm_bgp(site: str = "", hostname: str = "") -> str:
    """Vendor-aware NAPALM-equivalent BGP collection — works for Juniper, Arista EOS, Nokia SR Linux, and FRR via docker exec. Returns per-device peers with state, AS, prefix counts. Async; returns job_id."""
    body = {}
    if site:     body["site"] = site
    if hostname: body["hostname"] = hostname
    return json.dumps(_post("/api/napalm/bgp-status", body))


@mcp.tool()
def mv_napalm_job(job_id: str) -> str:
    """Poll a NAPALM job by id (returned by mv_napalm_bgp and friends)."""
    return _get(f"/api/napalm/jobs/{job_id}")


@mcp.tool()
def mv_shadow_audit(site: str = "all", check: str = "all") -> str:
    """Shadow Config Auditor — compares NetBox SoT to live running-config (via docker exec) for every device. Returns drift findings tagged P1/WARNING. site in {all, clab-dc1, de-fra, uk-lon, nl-ams, us-nyc}. check in {all, bgp, ospf}."""
    return json.dumps(_post("/api/shadow/audit", {"site": site, "check": check}))


@mcp.tool()
def mv_device_health(hostname: str) -> str:
    """Single-device operational snapshot — version, BGP, OSPF, interfaces, routes, memory, CPU — all in parallel via vendor-aware show commands. Works for FRR (vtysh), Arista cEOS (Cli), Nokia SR Linux (sr_cli), and Juniper (PyEZ). Typically completes in <2 s for the clab fabric."""
    return _get(f"/api/health/{hostname}")


if __name__ == "__main__":
    mcp.run()
