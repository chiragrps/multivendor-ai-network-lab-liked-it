#!/usr/bin/env python3
"""
GESH AI Bridge — Connects containerlab multi-vendor fabric
to the existing AI network tools (DCN_Network_Tool, netlog-ai,
multivendor-ai-network-lab).

Discovers running containerlab nodes, extracts inventory,
and generates compatible inventory files for each AI tool.

Usage:
    python3 ai-bridge.py                    # Generate all inventories
    python3 ai-bridge.py --format json      # JSON output only
    python3 ai-bridge.py --tool dcn         # DCN Network Tool format
    python3 ai-bridge.py --tool netlog      # netlog-ai format
    python3 ai-bridge.py --tool ansible     # Ansible inventory
"""

import json
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


@dataclass
class LabNode:
    name: str
    container: str
    kind: str
    vendor: str
    role: str
    mgmt_ip: str
    image: str
    tier: str = ""
    rack: str = ""
    interfaces: list = field(default_factory=list)
    ssh_port: int = 22
    api_port: Optional[int] = None
    credentials: dict = field(default_factory=dict)


def discover_nodes() -> list[LabNode]:
    """Discover running containerlab nodes from Docker."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Labels}}"],
            capture_output=True, text=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("ERROR: Docker not running or not found", file=sys.stderr)
        return []

    nodes = []
    for line in result.stdout.strip().split("\n"):
        if not line or "clab-" not in line:
            continue

        parts = line.split("\t")
        if len(parts) < 2:
            continue

        container_name = parts[0]
        image = parts[1]
        labels_str = parts[2] if len(parts) > 2 else ""

        labels = {}
        for label in labels_str.split(","):
            if "=" in label:
                k, v = label.split("=", 1)
                labels[k.strip()] = v.strip()

        short_name = container_name.split("-", 2)[-1] if container_name.count("-") >= 2 else container_name

        vendor, kind, creds = _detect_vendor(image)
        role = labels.get("clab-node-role", labels.get("role", "unknown"))
        tier = labels.get("tier", "")
        rack = labels.get("rack", "")

        mgmt_ip = _get_mgmt_ip(container_name)

        api_port = None
        if vendor == "arista":
            api_port = 443
        elif vendor == "nokia":
            api_port = 57400

        nodes.append(LabNode(
            name=short_name,
            container=container_name,
            kind=kind,
            vendor=vendor,
            role=role,
            mgmt_ip=mgmt_ip,
            image=image,
            tier=tier,
            rack=rack,
            ssh_port=22,
            api_port=api_port,
            credentials=creds,
        ))

    return sorted(nodes, key=lambda n: (n.tier, n.role, n.name))


def _detect_vendor(image: str) -> tuple[str, str, dict]:
    """Detect vendor, kind, and default credentials from image name."""
    image_lower = image.lower()
    if "srlinux" in image_lower or "srl" in image_lower:
        return "nokia", "srl", {"username": "admin", "password": "NokiaSrl1!"}
    elif "ceos" in image_lower or "arista" in image_lower:
        return "arista", "ceos", {"username": "admin", "password": "admin"}
    elif "frr" in image_lower:
        return "frr", "linux", {"username": "root", "password": ""}
    elif "multitool" in image_lower or "alpine" in image_lower:
        return "linux", "host", {"username": "root", "password": ""}
    return "unknown", "unknown", {}


def _get_mgmt_ip(container_name: str) -> str:
    """Get management IP from Docker inspect."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format",
             "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
             container_name],
            capture_output=True, text=True, check=True,
        )
        return result.stdout.strip() or "unknown"
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def generate_dcn_inventory(nodes: list[LabNode]) -> dict:
    """Generate inventory compatible with DCN Network Tool."""
    inventory = {
        "lab_name": "containerlab-multivendor",
        "devices": [],
        "topology": "clos-evpn",
    }

    vendor_map = {
        "nokia": {"nos": "nokia_srl", "driver": "srl"},
        "arista": {"nos": "arista_eos", "driver": "eos"},
        "frr": {"nos": "cisco_ios", "driver": "linux"},
    }

    for node in nodes:
        if node.role == "host":
            continue

        vm = vendor_map.get(node.vendor, {"nos": "generic", "driver": "linux"})

        inventory["devices"].append({
            "hostname": node.name,
            "ip": node.mgmt_ip,
            "vendor": node.vendor,
            "nos": vm["nos"],
            "role": node.role,
            "tier": node.tier,
            "rack": node.rack,
            "ssh_port": node.ssh_port,
            "credentials": node.credentials,
            "container": node.container,
        })

    return inventory


def generate_ansible_inventory(nodes: list[LabNode]) -> str:
    """Generate Ansible INI inventory."""
    groups: dict[str, list[LabNode]] = {}

    for node in nodes:
        if node.role == "host":
            continue

        group = f"{node.vendor}_{node.role}s"
        groups.setdefault(group, []).append(node)

        role_group = f"{node.role}s"
        groups.setdefault(role_group, []).append(node)

    lines = ["# Auto-generated by GESH AI Bridge", "# containerlab multi-vendor fabric", ""]

    for group_name, group_nodes in sorted(groups.items()):
        lines.append(f"[{group_name}]")
        seen = set()
        for node in group_nodes:
            if node.name in seen:
                continue
            seen.add(node.name)

            ansible_conn = "ansible.netcommon.network_cli"
            ansible_nos = "arista.eos.eos"
            if node.vendor == "nokia":
                ansible_conn = "ansible.netcommon.httpapi"
                ansible_nos = "nokia.srlinux.srlinux"
            elif node.vendor == "frr":
                ansible_conn = "ansible.netcommon.network_cli"
                ansible_nos = "frr.frr.frr"

            lines.append(
                f"{node.name} "
                f"ansible_host={node.mgmt_ip} "
                f"ansible_user={node.credentials.get('username', 'admin')} "
                f"ansible_password={node.credentials.get('password', '')} "
                f"ansible_network_os={ansible_nos} "
                f"ansible_connection={ansible_conn}"
            )
        lines.append("")

    return "\n".join(lines)


def generate_netlog_inventory(nodes: list[LabNode]) -> dict:
    """Generate inventory compatible with netlog-ai log analyzer."""
    devices = []
    for node in nodes:
        if node.role == "host":
            continue
        devices.append({
            "name": node.name,
            "host": node.mgmt_ip,
            "vendor": node.vendor,
            "role": node.role,
            "container": node.container,
            "log_source": f"docker logs {node.container}",
        })

    return {
        "lab": "containerlab-multivendor",
        "devices": devices,
        "log_collection_method": "docker_logs",
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="GESH AI Bridge — containerlab inventory generator")
    parser.add_argument("--format", choices=["json", "table"], default="table")
    parser.add_argument("--tool", choices=["dcn", "netlog", "ansible", "all"], default="all")
    parser.add_argument("--output-dir", type=str, default=None)
    args = parser.parse_args()

    nodes = discover_nodes()

    if not nodes:
        print("No running containerlab nodes found.")
        print("Deploy first: ./scripts/deploy.sh clos-evpn")
        sys.exit(1)

    if args.format == "table":
        print(f"\n{'Name':<15} {'Vendor':<10} {'Role':<12} {'Tier':<10} {'Mgmt IP':<18} {'Image'}")
        print("-" * 90)
        for node in nodes:
            print(f"{node.name:<15} {node.vendor:<10} {node.role:<12} {node.tier:<10} {node.mgmt_ip:<18} {node.image[:30]}")
        print(f"\nTotal: {len(nodes)} nodes ({len([n for n in nodes if n.role != 'host'])} network devices, {len([n for n in nodes if n.role == 'host'])} hosts)")

    output_dir = Path(args.output_dir) if args.output_dir else Path(__file__).parent.parent / "ansible"

    if args.tool in ("dcn", "all"):
        dcn_inv = generate_dcn_inventory(nodes)
        dcn_path = output_dir / "dcn_inventory.json"
        dcn_path.write_text(json.dumps(dcn_inv, indent=2))
        print(f"\nDCN inventory written to: {dcn_path}")

    if args.tool in ("netlog", "all"):
        netlog_inv = generate_netlog_inventory(nodes)
        netlog_path = output_dir / "netlog_inventory.json"
        netlog_path.write_text(json.dumps(netlog_inv, indent=2))
        print(f"Netlog inventory written to: {netlog_path}")

    if args.tool in ("ansible", "all"):
        ansible_inv = generate_ansible_inventory(nodes)
        ansible_path = output_dir / "inventory.ini"
        ansible_path.write_text(ansible_inv)
        print(f"Ansible inventory written to: {ansible_path}")

    if args.format == "json":
        print(json.dumps([asdict(n) for n in nodes], indent=2))


if __name__ == "__main__":
    main()
