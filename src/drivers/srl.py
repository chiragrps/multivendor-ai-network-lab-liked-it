"""Nokia SR Linux (sr_cli) driver."""
from __future__ import annotations

from . import parsers
from .base import BaseNetworkDriver
from .commands import SRL_COMMANDS

_DISPATCH = {
    "version": parsers.parse_version,
    "bgp": parsers.parse_bgp,
    "ospf": parsers.parse_ospf,
    "interfaces": parsers.parse_interfaces,
    "interface_counters": parsers.parse_interface_counters,
    "routes": parsers.parse_routes,
}


class SRLDriver(BaseNetworkDriver):
    vendor = "nokia-srl"
    commands = SRL_COMMANDS

    def _parse(self, section: str, raw: str) -> dict:
        fn = _DISPATCH.get(section)
        return fn(self.vendor, raw) if fn else {}
