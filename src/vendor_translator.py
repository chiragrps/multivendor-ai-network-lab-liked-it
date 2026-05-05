"""
vendor_translator.py — Vendor-agnostic command translator.

Maps a single canonical task (e.g. "bgp_summary") to vendor-specific CLI
for Juniper JunOS, Arista EOS, FRR, Cisco IOS-XE/NX-OS.

Usage:
    from vendor_translator import translate, supported_tasks

    cli = translate("bgp_summary", "junos")        # "show bgp summary"
    cli = translate("interface_status", "eos")     # "show interfaces status"
    cli = translate("route_lookup", "frr", prefix="10.0.0.0/24")
"""
from __future__ import annotations
from typing import Final


_TRANSLATE: Final[dict[str, dict[str, str]]] = {
    "bgp_summary": {
        "junos": "show bgp summary",
        "eos":   "show ip bgp summary",
        "frr":   "vtysh -c 'show ip bgp summary'",
        "ios":   "show ip bgp summary",
        "nxos":  "show ip bgp summary",
    },
    "ospf_neighbors": {
        "junos": "show ospf neighbor",
        "eos":   "show ip ospf neighbor",
        "frr":   "vtysh -c 'show ip ospf neighbor'",
        "ios":   "show ip ospf neighbor",
        "nxos":  "show ip ospf neighbor",
    },
    "interface_status": {
        "junos": "show interfaces terse",
        "eos":   "show interfaces status",
        "frr":   "vtysh -c 'show interface brief'",
        "ios":   "show ip interface brief",
        "nxos":  "show interface brief",
    },
    "route_lookup": {
        "junos": "show route {prefix}",
        "eos":   "show ip route {prefix}",
        "frr":   "vtysh -c 'show ip route {prefix}'",
        "ios":   "show ip route {prefix}",
        "nxos":  "show ip route {prefix}",
    },
    "version": {
        "junos": "show version",
        "eos":   "show version",
        "frr":   "vtysh -c 'show version'",
        "ios":   "show version",
        "nxos":  "show version",
    },
    "running_config": {
        "junos": "show configuration | display set",
        "eos":   "show running-config",
        "frr":   "vtysh -c 'show running-config'",
        "ios":   "show running-config",
        "nxos":  "show running-config",
    },
    "arp_table": {
        "junos": "show arp",
        "eos":   "show ip arp",
        "frr":   "vtysh -c 'show ip arp'",
        "ios":   "show ip arp",
        "nxos":  "show ip arp",
    },
    "mac_table": {
        "junos": "show ethernet-switching table",
        "eos":   "show mac address-table",
        "frr":   "ip neigh show",
        "ios":   "show mac address-table",
        "nxos":  "show mac address-table",
    },
    "lldp_neighbors": {
        "junos": "show lldp neighbors",
        "eos":   "show lldp neighbors",
        "frr":   "vtysh -c 'show lldp neighbors'",
        "ios":   "show lldp neighbors",
        "nxos":  "show lldp neighbors",
    },
    "system_health": {
        "junos": "show system processes extensive",
        "eos":   "show processes top",
        "frr":   "ps aux --sort=-%cpu | head -20",
        "ios":   "show processes cpu sorted",
        "nxos":  "show processes cpu sort",
    },
    "log_recent": {
        "junos": "show log messages | last 50",
        "eos":   "show logging last 50",
        "frr":   "tail -50 /var/log/frr/frr.log",
        "ios":   "show logging | last 50",
        "nxos":  "show logging last 50",
    },
    # Destructive (gated)
    "clear_bgp_neighbor": {
        "junos": "clear bgp neighbor {peer}",
        "eos":   "clear bgp ipv4 unicast {peer}",
        "frr":   "vtysh -c 'clear ip bgp {peer}'",
        "ios":   "clear ip bgp {peer}",
        "nxos":  "clear bgp ipv4 unicast {peer}",
    },
    "shutdown_interface": {
        "junos": "set interfaces {iface} disable",
        "eos":   "interface {iface}\\n shutdown",
        "frr":   "vtysh -c 'configure terminal' -c 'interface {iface}' -c 'shutdown'",
        "ios":   "interface {iface}\\n shutdown",
        "nxos":  "interface {iface}\\n shutdown",
    },
}


# Tasks that change device state — require approval gating
_DESTRUCTIVE: Final[frozenset[str]] = frozenset({
    "clear_bgp_neighbor",
    "shutdown_interface",
})


def supported_tasks() -> list[str]:
    """Return list of canonical task names."""
    return sorted(_TRANSLATE.keys())


def supported_vendors(task: str | None = None) -> list[str]:
    """Return list of vendor codes (junos, eos, frr, ios, nxos)."""
    if task:
        return sorted(_TRANSLATE.get(task, {}).keys())
    vendors: set[str] = set()
    for tmap in _TRANSLATE.values():
        vendors.update(tmap.keys())
    return sorted(vendors)


def translate(task: str, vendor: str, **fmt: str) -> str:
    """
    Translate a canonical task to vendor-specific CLI.

    Args:
        task:   canonical task name (e.g. "bgp_summary")
        vendor: vendor code (junos|eos|frr|ios|nxos)
        **fmt:  format params for templates (e.g. prefix="10.0.0.0/24")

    Returns:
        CLI command string ready to execute.

    Raises:
        KeyError if task or vendor unknown.
    """
    if task not in _TRANSLATE:
        raise KeyError(f"Unknown task: {task!r}. Supported: {supported_tasks()}")
    vmap = _TRANSLATE[task]
    if vendor not in vmap:
        raise KeyError(f"Vendor {vendor!r} not supported for task {task!r}. Have: {sorted(vmap.keys())}")
    template = vmap[vendor]
    if fmt:
        try:
            return template.format(**fmt)
        except KeyError as e:
            raise KeyError(f"Missing format param {e} for task {task!r}") from None
    return template


def is_destructive(task: str) -> bool:
    """Return True if task changes device state."""
    return task in _DESTRUCTIVE


def vendor_for_os(os_name: str) -> str:
    """Normalize an OS name (junos, eos, frr, ios-xe, nx-os) to a vendor code."""
    o = os_name.lower().strip()
    if o.startswith("junos"):
        return "junos"
    if o.startswith("eos"):
        return "eos"
    if o.startswith("frr"):
        return "frr"
    if "nx" in o or "nxos" in o:
        return "nxos"
    if "ios" in o:
        return "ios"
    return o
