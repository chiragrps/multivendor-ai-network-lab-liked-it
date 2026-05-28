"""Juniper Junos (cli / display json) driver.

Junos ``| display json`` emits a deeply-nested ``[{"data": value}]`` schema;
the parsers in :mod:`drivers.parsers` unwrap it via ``_jv``. Junos devices are
typically reached over SSH (Scrapli/NETCONF) rather than docker-exec — use
``get_driver("junos", runner=...)`` or a ScrapliTransport. The DockerExecTransport
``cli`` argv is included for cRPD / vJunos containers.
"""
from __future__ import annotations

from . import parsers
from .base import BaseNetworkDriver
from .commands import JUNOS_COMMANDS

_DISPATCH = {
    "version": parsers.parse_version,
    "bgp": parsers.parse_bgp,
    "ospf": parsers.parse_ospf,
    "interfaces": parsers.parse_interfaces,
    "interface_counters": parsers.parse_interface_counters,
    "routes": parsers.parse_routes,
}


class JunosDriver(BaseNetworkDriver):
    vendor = "junos"
    commands = JUNOS_COMMANDS

    def _parse(self, section: str, raw: str) -> dict:
        fn = _DISPATCH.get(section)
        return fn(self.vendor, raw) if fn else {}
