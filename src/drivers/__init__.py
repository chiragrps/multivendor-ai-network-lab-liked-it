"""drivers — ABC-based multi-vendor driver abstraction.

Public surface:
    get_driver(vendor, *, transport|container|runner, ...) -> BaseNetworkDriver
    BaseNetworkDriver  — the ABC every vendor driver extends
    DriverResult       — immutable per-command result
    UnsupportedVendorError

This package imports NO flask / paramiko / scrapli at module top level — heavy
deps are lazy-imported inside transport methods only, so it stays importable on
the clab lab host.
"""
from __future__ import annotations

from .base import BaseNetworkDriver
from .factory import UnsupportedVendorError, get_driver
from .result import DriverResult

__all__ = [
    "get_driver",
    "BaseNetworkDriver",
    "DriverResult",
    "UnsupportedVendorError",
]
