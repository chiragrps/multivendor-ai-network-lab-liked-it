"""Driver factory — resolve a vendor (any alias) to a wired-up driver.

``get_driver`` picks the concrete driver class for a vendor and auto-selects a
transport:

* ``transport=`` given          → use it as-is.
* ``container=`` given          → DockerExecTransport.
* ``runner=`` given             → SSHRunnerTransport (needs ``ip``).
* none of the above             → UnsupportedVendorError (no way to reach device).

An unknown vendor also raises UnsupportedVendorError.
"""
from __future__ import annotations

from typing import Callable

from .base import BaseNetworkDriver
from .commands import canonical_vendor
from .eos import EOSDriver
from .frr import FRRDriver
from .junos import JunosDriver
from .srl import SRLDriver
from .transport import DockerExecTransport, SSHRunnerTransport, Transport


class UnsupportedVendorError(ValueError):
    """Raised for an unknown vendor or when no transport can be constructed."""


# canonical vendor → driver class
_REGISTRY: dict[str, type[BaseNetworkDriver]] = {
    "frr": FRRDriver,
    "arista-eos": EOSDriver,
    "nokia-srl": SRLDriver,
    "junos": JunosDriver,
}


def get_driver(
    vendor: str,
    *,
    transport: Transport | None = None,
    container: str | None = None,
    ip: str | None = None,
    port: int = 22,
    hostname: str | None = None,
    runner: Callable[..., dict] | None = None,
) -> BaseNetworkDriver:
    """Build a driver for ``vendor`` with an appropriate transport.

    Raises:
        UnsupportedVendorError: unknown vendor, or no transport could be chosen.
    """
    canon = canonical_vendor(vendor)
    if canon is None or canon not in _REGISTRY:
        raise UnsupportedVendorError(
            f"no driver registered for vendor {vendor!r} "
            f"(known: {', '.join(sorted(_REGISTRY))})"
        )

    driver_cls = _REGISTRY[canon]

    chosen = _select_transport(
        transport=transport, container=container, ip=ip, port=port,
        runner=runner, vendor=canon,
    )

    return driver_cls(chosen, hostname=hostname, ip=ip, port=port)


def _select_transport(
    *,
    transport: Transport | None,
    container: str | None,
    ip: str | None,
    port: int,
    runner: Callable[..., dict] | None,
    vendor: str,
) -> Transport:
    if transport is not None:
        return transport
    if container:
        return DockerExecTransport(container)
    if runner is not None:
        if not ip:
            raise UnsupportedVendorError(
                "SSHRunnerTransport requires 'ip' alongside 'runner'"
            )
        return SSHRunnerTransport(runner, ip=ip, port=port, dtype=vendor)
    raise UnsupportedVendorError(
        "no transport available: pass one of transport=, container=, or runner="
    )
