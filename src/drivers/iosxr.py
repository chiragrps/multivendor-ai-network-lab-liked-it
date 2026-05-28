"""Cisco IOS-XR driver.

IOS-XR JSON (`| json`) support is version-dependent (7.x+) and often partial,
so the command table leads with JSON then falls back to text — and the parsers
lean on the standard Cisco-style text tables (which `parse_bgp`/`parse_ospf`
already handle via their text fallback). Interfaces use an XR-specific branch
for `show ipv4 interface brief`. Reached over SSH (Scrapli/SSHRunnerTransport)
or via a cisco/iosxr container's exec.
"""
from __future__ import annotations

from . import parsers
from .base import BaseNetworkDriver
from .commands import IOSXR_COMMANDS

_DISPATCH = {
    "version": parsers.parse_version,
    "bgp": parsers.parse_bgp,
    "ospf": parsers.parse_ospf,
    "interfaces": parsers.parse_interfaces,
    "interface_counters": parsers.parse_interface_counters,
    "routes": parsers.parse_routes,
}


class IOSXRDriver(BaseNetworkDriver):
    vendor = "cisco-iosxr"
    commands = IOSXR_COMMANDS

    def _parse(self, section: str, raw: str) -> dict:
        fn = _DISPATCH.get(section)
        return fn(self.vendor, raw) if fn else {}
