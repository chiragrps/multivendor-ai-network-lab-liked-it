#!/usr/bin/env python3
"""
nornir_engine.py — Parallel Multi-Device Task Engine
=====================================================
Standalone module extracted from app.py to keep concerns separated.
Provides ThreadPoolExecutor-based parallel SSH execution across lab/prod devices.

This is the DCN equivalent of Nornir — same pattern (inventory + tasks + workers)
but using our existing run_command_on_device() SSH engine instead of Nornir's
connection plugins. Zero extra dependencies.

Usage (from app.py):
    from nornir_engine import NORNIR_TASKS, nornir_run

Usage (standalone / CLI):
    python3 nornir_engine.py --task bgp_health --site DE-FRA --workers 10

Architecture:
    ┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
    │  HTTP POST  │────▶│  nornir_run  │────▶│ _nornir_worker  │ × N workers
    │  /api/nornir│     │  (orchestr.) │     │ (per-device SSH)│
    └─────────────┘     └──────────────┘     └─────────────────┘
                                                      │
                                              run_command_on_device()
                                              (paramiko / vtysh for FRR)
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


# ── Task Catalogue ─────────────────────────────────────────────────────────────
# Each task defines the vendor-specific CLI command and a human-readable label.
# cmd_frr  → FRRouting (lab containers, vtysh -c)
# cmd_junos → JunOS (SRX/MX/EX/QFX)
# cmd_eos   → Arista EOS
NORNIR_TASKS: dict[str, dict[str, str]] = {
    "bgp_health": {
        "cmd_junos": "show bgp summary",
        "cmd_eos":   "show bgp summary",
        "cmd_frr":   "show bgp summary",
        "label":     "BGP Health Check",
    },
    "interface_check": {
        "cmd_junos": "show interfaces terse",
        "cmd_eos":   "show interfaces status",
        "cmd_frr":   "show interface brief",
        "label":     "Interface Status",
    },
    "version": {
        "cmd_junos": "show version",
        "cmd_eos":   "show version",
        "cmd_frr":   "show version",
        "label":     "Software Version",
    },
    "routing_table": {
        "cmd_junos": "show route summary",
        "cmd_eos":   "show ip route summary",
        "cmd_frr":   "show ip route summary",
        "label":     "Routing Table Summary",
    },
    "alarm_check": {
        "cmd_junos": "show chassis alarms",
        "cmd_eos":   "show system environment all",
        "cmd_frr":   "show ip ospf neighbor",
        "label":     "System Alarms / OSPF Neighbors",
    },
    "ospf_neighbors": {
        "cmd_junos": "show ospf neighbor",
        "cmd_eos":   "show ip ospf neighbor",
        "cmd_frr":   "show ip ospf neighbor",
        "label":     "OSPF Neighbor State",
    },
}


def _pick_command(task_def: dict, dtype: str) -> str:
    """Select the correct CLI command for the device type."""
    if dtype == "eos":
        return task_def["cmd_eos"]
    if dtype == "frr":
        return task_def.get("cmd_frr", task_def["cmd_junos"])
    return task_def["cmd_junos"]


def _classify_output(output: str, success: bool) -> str:
    """
    Heuristic status classification from raw CLI output.

    Returns one of: "ok" | "warn" | "error"

    Rules (order matters — checked top-down):
    - SSH/connection failure → error
    - Contains alarm/error/down keywords → warn
    - Non-empty meaningful output → ok
    - Empty or very short output → error
    """
    if not success:
        return "error"

    lower = output.lower()

    # Hard error indicators
    if any(k in lower for k in ("connection refused", "no route to host", "authentication failed", "timed out")):
        return "error"

    # BGP-specific: "Active" state = peer down
    if "active" in lower and "established" not in lower and "bgp" in lower:
        return "warn"

    # Alarm/fault keywords
    # Strip "up/down" column header before checking "down" — FRR/JunOS BGP summary
    # always prints this header on healthy sessions and would otherwise always warn.
    scrubbed = lower.replace("up/down", "").replace("up-down", "")
    if any(k in scrubbed for k in ("alarm", "major", "error", "down", "fault", "failed")):
        return "warn"

    # Meaningful output present
    if output and len(output.strip()) > 10:
        return "ok"

    return "error"


def _nornir_worker(dev: dict[str, Any], cmd: str, run_fn: Any) -> dict[str, Any]:
    """
    Execute a single CLI command on one device via SSH.

    Parameters
    ----------
    dev     : device dict from DEVICES inventory
              Required keys: hostname, ip/host, type, port
    cmd     : CLI command string to execute
    run_fn  : callable — run_command_on_device(ip, dtype, cmd, port=22)
              Passed in to keep this module importable without app context.

    Returns
    -------
    {
        "hostname": str,
        "status":   "ok" | "warn" | "error",
        "output":   str,
        "elapsed":  float   # seconds
    }
    """
    t0 = time.monotonic()
    hostname = dev.get("hostname", dev.get("host", "unknown"))
    try:
        ip    = dev.get("ip") or dev.get("host", "")
        dtype = dev.get("type", "junos")
        port  = int(dev.get("port", 22))

        result = run_fn(ip, dtype, cmd, port=port)
        elapsed = round(time.monotonic() - t0, 2)

        success  = result.get("success", True) if isinstance(result, dict) else True
        out_text = result.get("output", "") if isinstance(result, dict) else str(result)
        status   = _classify_output(out_text, success)

        return {
            "hostname": hostname,
            "status":   status,
            "output":   out_text,
            "elapsed":  elapsed,
        }
    except Exception as exc:
        return {
            "hostname": hostname,
            "status":   "error",
            "output":   str(exc),
            "elapsed":  round(time.monotonic() - t0, 2),
        }


def nornir_run(
    devices: list[dict],
    task_name: str,
    site_filter: str = "",
    workers: int = 50,
    run_fn: Any = None,
) -> dict[str, Any]:
    """
    Parallel multi-device task execution.

    Parameters
    ----------
    devices     : full device list (DEVICES from app.py)
    task_name   : key from NORNIR_TASKS  (e.g. "bgp_health")
    site_filter : case-insensitive site name to filter by ("de-fra", "uk-lon", ...)
                  Pass "" to run against all devices.
    workers     : max concurrent SSH threads (capped at 200)
    run_fn      : run_command_on_device callable (injected to avoid circular import)

    Returns
    -------
    {
        "task":    str,          # human label
        "site":    str,          # filter used ("all" if none)
        "devices": int,          # number of targets
        "workers": int,
        "elapsed": float,        # total wall time in seconds
        "ok":      int,
        "warn":    int,
        "error":   int,
        "results": list[dict],   # one entry per device
    }

    Raises
    ------
    ValueError  : unknown task_name or no devices match site_filter
    """
    if run_fn is None:
        raise ValueError("run_fn (run_command_on_device) must be provided")

    task_def = NORNIR_TASKS.get(task_name)
    if task_def is None:
        raise ValueError(f"Unknown task '{task_name}'. Valid tasks: {list(NORNIR_TASKS)}")

    # Filter by site (case-insensitive)
    targets = [
        d for d in devices
        if not site_filter or d.get("site", "").lower() == site_filter.lower()
    ]
    if not targets:
        raise ValueError(f"No devices found for site '{site_filter}'")

    max_workers = min(max(1, workers), 200, len(targets))
    t0 = time.monotonic()
    results: list[dict] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _nornir_worker,
                dev,
                _pick_command(task_def, dev.get("type", "junos")),
                run_fn,
            ): dev
            for dev in targets
        }
        for fut in as_completed(futures):
            results.append(fut.result())

    elapsed = round(time.monotonic() - t0, 2)

    ok_count   = sum(1 for r in results if r["status"] == "ok")
    warn_count = sum(1 for r in results if r["status"] == "warn")
    err_count  = sum(1 for r in results if r["status"] == "error")

    return {
        "task":    task_def["label"],
        "site":    site_filter.upper() if site_filter else "all",
        "devices": len(targets),
        "workers": max_workers,
        "elapsed": elapsed,
        "ok":      ok_count,
        "warn":    warn_count,
        "error":   err_count,
        "results": results,
    }


# ── CLI entrypoint ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    import json
    import sys
    import os

    parser = argparse.ArgumentParser(description="DCN Nornir Parallel Engine")
    parser.add_argument("--task",    default="bgp_health", choices=list(NORNIR_TASKS), help="Task to run")
    parser.add_argument("--site",    default="",           help="Site filter (e.g. DE-FRA)")
    parser.add_argument("--workers", default=10, type=int, help="Max parallel workers")
    parser.add_argument("--csv",     default=None,         help="Lab inventory CSV path")
    args = parser.parse_args()

    # Load inventory CSV
    csv_path = args.csv or os.environ.get(
        "DCN_SECURECRT_CSV",
        os.path.join(os.path.dirname(__file__), "../../network-lab/lab_inventory.csv")
    )
    if not os.path.exists(csv_path):
        print(f"ERROR: CSV not found: {csv_path}", file=sys.stderr)
        sys.exit(1)

    import csv
    devices = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            devices.append({
                "hostname": row.get("hostname", ""),
                "ip":       row.get("ip_address", row.get("ip", "localhost")),
                "port":     int(row.get("port", 22)),
                "type":     row.get("type", "frr"),
                "site":     row.get("site", ""),
            })

    # Import SSH runner from app context
    sys.path.insert(0, os.path.dirname(__file__))
    from app import run_command_on_device  # type: ignore

    try:
        result = nornir_run(devices, args.task, args.site, args.workers, run_command_on_device)
        print(json.dumps(result, indent=2))
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
