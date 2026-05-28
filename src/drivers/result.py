"""DriverResult — the single immutable return shape for every driver command.

Every concrete driver method (get_bgp_summary, run_command, …) returns one of
these. It pairs the *raw* device output with a vendor-neutral *normalized* dict
so callers can choose either fidelity level without re-running the command.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class DriverResult:
    """Immutable result of a single driver command.

    Attributes:
        section: logical section name (version | bgp | ospf | interfaces |
            interface_counters | routes | …).
        vendor: canonical vendor the command ran against (frr | arista-eos | …).
        command: the actual CLI command string that produced ``raw``.
        raw: unparsed device output (stdout). Empty string on failure.
        normalized: vendor-neutral parsed dict — fixed shape per section.
        success: True if the command produced usable output.
        via: transport label (docker-exec | ssh | scrapli).
        error: human-readable error string, or None on success.
        elapsed_ms: wall-clock time for the command + parse, in milliseconds.
    """

    section: str
    vendor: str
    command: str
    raw: str
    normalized: dict = field(default_factory=dict)
    success: bool = False
    via: str = "docker-exec"
    error: str | None = None
    elapsed_ms: float = 0.0

    @property
    def ok(self) -> bool:
        """Alias for ``success`` — reads naturally at call sites (``if r.ok``)."""
        return self.success
