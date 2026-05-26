#!/usr/bin/env python3
"""
GESH Monitor Bridge — Connects the running containerlab fabric
to the AI Network Tool and netlog-ai for live monitoring.

Collects: BGP state, interface counters, LLDP neighbors, logs
Outputs:  JSON for DCN Network Tool ingestion + log stream for netlog-ai

Usage:
    python3 monitor-bridge.py                # One-shot collection
    python3 monitor-bridge.py --continuous   # Poll every 30s
    python3 monitor-bridge.py --logs         # Stream logs to netlog-ai format
"""

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


NODES = {
    "spine1": {"vendor": "srl", "container": "clab-clos-evpn-spine1", "role": "spine", "as": 65100},
    "spine2": {"vendor": "ceos", "container": "clab-clos-evpn-spine2", "role": "spine", "as": 65100},
    "spine3": {"vendor": "frr", "container": "clab-clos-evpn-spine3", "role": "spine", "as": 65100},
    "leaf1": {"vendor": "ceos", "container": "clab-clos-evpn-leaf1", "role": "leaf", "as": 65001},
    "leaf2": {"vendor": "srl", "container": "clab-clos-evpn-leaf2", "role": "leaf", "as": 65002},
    "leaf3": {"vendor": "frr", "container": "clab-clos-evpn-leaf3", "role": "leaf", "as": 65003},
    "leaf4": {"vendor": "ceos", "container": "clab-clos-evpn-leaf4", "role": "leaf", "as": 65004},
    "leaf5": {"vendor": "srl", "container": "clab-clos-evpn-leaf5", "role": "leaf", "as": 65005},
    "leaf6": {"vendor": "frr", "container": "clab-clos-evpn-leaf6", "role": "leaf", "as": 65006},
}


def run_cmd(container: str, cmd: str, timeout: int = 10) -> str:
    try:
        result = subprocess.run(
            ["docker", "exec", container] + cmd.split(),
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        return ""


def collect_srl(name: str, container: str) -> dict:
    bgp_raw = run_cmd(container, "sr_cli show network-instance default protocols bgp neighbor")
    bgp_sessions = []
    for line in bgp_raw.split("\n"):
        if "established" in line.lower():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 6:
                bgp_sessions.append({
                    "neighbor": parts[1],
                    "group": parts[2],
                    "peer_as": parts[4],
                    "state": "established",
                    "afi": parts[7] if len(parts) > 7 else "ipv4-unicast",
                })

    iface_raw = run_cmd(container, "sr_cli show interface brief")
    interfaces = []
    for line in iface_raw.split("\n"):
        if "ethernet" in line.lower() or "system" in line.lower():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if len(parts) >= 3:
                interfaces.append({
                    "name": parts[0],
                    "admin": parts[1],
                    "oper": parts[2],
                })

    return {"bgp": bgp_sessions, "interfaces": interfaces, "vendor": "nokia_srl"}


def collect_ceos(name: str, container: str) -> dict:
    bgp_raw = run_cmd(container, "Cli -p 15 -c show bgp summary")
    bgp_sessions = []
    for line in bgp_raw.split("\n"):
        if "Estab" in line:
            parts = line.split()
            if len(parts) >= 2:
                bgp_sessions.append({
                    "neighbor": parts[0],
                    "peer_as": parts[1] if len(parts) > 1 else "",
                    "state": "established",
                })

    iface_raw = run_cmd(container, "Cli -p 15 -c show interfaces status")
    return {"bgp": bgp_sessions, "interfaces_raw": iface_raw[:500], "vendor": "arista_eos"}


def collect_frr(name: str, container: str) -> dict:
    bgp_raw = run_cmd(container, "vtysh -c show bgp summary")
    bgp_sessions = []
    for line in bgp_raw.split("\n"):
        if "Estab" in line.lower() or ("65" in line and ("0" in line or "1" in line)):
            parts = line.split()
            if len(parts) >= 10 and parts[-1].isdigit():
                bgp_sessions.append({
                    "neighbor": parts[0],
                    "peer_as": parts[2] if len(parts) > 2 else "",
                    "state": "established",
                    "prefixes_rcvd": parts[-1],
                })

    return {"bgp": bgp_sessions, "vendor": "frr"}


def collect_all() -> dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    report = {
        "timestamp": timestamp,
        "lab": "clos-evpn",
        "total_nodes": len(NODES),
        "nodes": {},
        "summary": {
            "total_bgp_sessions": 0,
            "established_sessions": 0,
            "down_sessions": 0,
        },
    }

    for name, info in NODES.items():
        container = info["container"]

        running = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", container],
            capture_output=True, text=True,
        ).stdout.strip() == "running"

        if not running:
            report["nodes"][name] = {"status": "down", "vendor": info["vendor"]}
            continue

        if info["vendor"] == "srl":
            data = collect_srl(name, container)
        elif info["vendor"] == "ceos":
            data = collect_ceos(name, container)
        elif info["vendor"] == "frr":
            data = collect_frr(name, container)
        else:
            data = {}

        data["status"] = "running"
        data["role"] = info["role"]
        data["as"] = info["as"]
        report["nodes"][name] = data

        established = len([s for s in data.get("bgp", []) if s.get("state") == "established"])
        report["summary"]["established_sessions"] += established
        report["summary"]["total_bgp_sessions"] += len(data.get("bgp", []))

    report["summary"]["down_sessions"] = (
        report["summary"]["total_bgp_sessions"] - report["summary"]["established_sessions"]
    )

    return report


def collect_logs(tail: int = 50) -> list[dict]:
    logs = []
    for name, info in NODES.items():
        try:
            result = subprocess.run(
                ["docker", "logs", "--tail", str(tail), "--timestamps", info["container"]],
                capture_output=True, text=True, timeout=5,
            )
            raw = result.stdout + result.stderr
            for line in raw.strip().split("\n"):
                if line.strip():
                    logs.append({
                        "source": name,
                        "vendor": info["vendor"],
                        "role": info["role"],
                        "message": line.strip(),
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                    })
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            pass

    return logs


def main():
    import argparse

    parser = argparse.ArgumentParser(description="GESH Monitor Bridge")
    parser.add_argument("--continuous", action="store_true", help="Poll every 30s")
    parser.add_argument("--logs", action="store_true", help="Collect and output logs")
    parser.add_argument("--output", type=str, default=None, help="Output file path")
    args = parser.parse_args()

    output_dir = Path(__file__).parent.parent / "ansible"

    if args.logs:
        logs = collect_logs()
        log_path = output_dir / "fabric_logs.json"
        log_path.write_text(json.dumps(logs, indent=2))
        print(f"Collected {len(logs)} log entries → {log_path}")
        return

    if args.continuous:
        print("Continuous monitoring mode — Ctrl+C to stop")
        while True:
            report = collect_all()
            report_path = output_dir / "fabric_state.json"
            report_path.write_text(json.dumps(report, indent=2))
            est = report["summary"]["established_sessions"]
            total = report["summary"]["total_bgp_sessions"]
            ts = report["timestamp"][:19]
            print(f"[{ts}] BGP: {est}/{total} established | Nodes: {len(report['nodes'])}")
            time.sleep(30)
    else:
        report = collect_all()
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2))
        else:
            report_path = output_dir / "fabric_state.json"
            report_path.write_text(json.dumps(report, indent=2))

        est = report["summary"]["established_sessions"]
        total = report["summary"]["total_bgp_sessions"]
        print(f"\nFabric State: {est}/{total} BGP sessions established")
        print(f"Nodes: {len(report['nodes'])} ({sum(1 for n in report['nodes'].values() if n.get('status') == 'running')} running)")
        print(f"\nReport saved to: {report_path}")

        for name, data in report["nodes"].items():
            bgp_count = len(data.get("bgp", []))
            status = data.get("status", "unknown")
            vendor = data.get("vendor", "?")
            print(f"  {name:<10} {vendor:<12} {status:<8} BGP peers: {bgp_count}")


if __name__ == "__main__":
    main()
