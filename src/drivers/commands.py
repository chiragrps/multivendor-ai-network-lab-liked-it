"""Vendor command tables + alias map for the driver layer.

Migrated verbatim from ``src/health.py`` COMMAND_MAP so the drivers package is
self-contained (no import of the 25K-line health/app surface). Order matters
within a section: the first command that returns useful output wins, so JSON
variants come before text fallbacks.

The ``interface_counters`` section is new here (health.py never had it) — the
per-vendor counter commands come from ``clab_collector.py`` probe functions.
"""
from __future__ import annotations

FRR_COMMANDS: dict[str, list[str]] = {
    "version":            ["show version"],
    "bgp":                ["show ip bgp summary json", "show ip bgp summary"],
    "ospf":               ["show ip ospf neighbor json", "show ip ospf neighbor"],
    "interfaces":         ["show interface brief json", "show interface brief"],
    "interface_counters": ["show interface json", "show interface"],
    "routes":             ["show ip route summary json", "show ip route summary"],
    "memory":             ["show memory summary"],
    "cpu":                ["show thread cpu"],
}

EOS_COMMANDS: dict[str, list[str]] = {
    "version":            ["show version | json", "show version"],
    "bgp":                ["show ip bgp summary | json", "show ip bgp summary"],
    "ospf":               ["show ip ospf neighbor | json", "show ip ospf neighbor"],
    "interfaces":         ["show interfaces status | json", "show interfaces status"],
    "interface_counters": ["show interfaces counters | json", "show interfaces counters"],
    "routes":             ["show ip route summary | json", "show ip route summary"],
    "memory":             ["show processes top once | json", "show version"],
    "cpu":                ["show processes top once | json"],
}

JUNOS_COMMANDS: dict[str, list[str]] = {
    "version":            ["show version | display json", "show version"],
    "bgp":                ["show bgp summary | display json", "show bgp summary"],
    "ospf":               ["show ospf neighbor | display json", "show ospf neighbor"],
    "interfaces":         ["show interfaces terse | display json", "show interfaces terse"],
    "interface_counters": ["show interfaces extensive | display json", "show interfaces extensive"],
    "routes":             ["show route summary | display json", "show route summary"],
    "memory":             ["show system memory | display json", "show system memory"],
    "cpu":                ["show system processes extensive"],
}

# Nokia SR Linux uses sr_cli with a completely different grammar. JSON output
# isn't reliable across sr_cli commands; the text parsers handle these. Each
# entry is one command (no fallback variants — sr_cli either parses fully or
# rejects with "Parsing error").
SRL_COMMANDS: dict[str, list[str]] = {
    "version":            ["info from state /system information version"],
    "bgp":                ["show network-instance default protocols bgp neighbor"],
    "ospf":               ["show network-instance default protocols ospf neighbor"],
    "interfaces":         ["show interface"],
    "interface_counters": ["show interface detail"],
    "routes":             ["show network-instance default route-table ipv4-unicast summary"],
    "memory":             ["info from state /platform memory"],
    "cpu":                ["info from state /platform control cpu"],
}

# Canonical command table per canonical vendor.
COMMANDS_BY_VENDOR: dict[str, dict[str, list[str]]] = {
    "frr":        FRR_COMMANDS,
    "arista-eos": EOS_COMMANDS,
    "nokia-srl":  SRL_COMMANDS,
    "junos":      JUNOS_COMMANDS,
}

# Map every accepted spelling → canonical vendor key. Lower-cased lookups only.
VENDOR_ALIASES: dict[str, str] = {
    "frr":         "frr",
    "arista-eos":  "arista-eos",
    "arista":      "arista-eos",
    "eos":         "arista-eos",
    "nokia-srl":   "nokia-srl",
    "srl":         "nokia-srl",
    "nokia":       "nokia-srl",
    "junos":       "junos",
}


def canonical_vendor(vendor: str) -> str | None:
    """Resolve any accepted vendor spelling to its canonical key.

    Returns None when the vendor is unknown so callers can raise a clear error.
    """
    if not vendor:
        return None
    return VENDOR_ALIASES.get(vendor.strip().lower())


def commands_for(vendor: str) -> dict[str, list[str]] | None:
    """Return the command table for a vendor (any alias), or None if unknown."""
    canon = canonical_vendor(vendor)
    if canon is None:
        return None
    return COMMANDS_BY_VENDOR.get(canon)
