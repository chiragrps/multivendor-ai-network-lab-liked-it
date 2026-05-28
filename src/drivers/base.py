"""BaseNetworkDriver — the ABC every vendor driver extends.

The base owns all orchestration (command resolution, fallback iteration through
the per-section command list, transport invocation, timing, error wrapping).
Subclasses supply only two things:

* class attrs ``vendor`` and ``commands`` (the per-section command table),
* a ``_parse(section, raw)`` method dispatching to the section parsers.

Every command method returns a :class:`DriverResult`. ``get_health`` is the one
exception — it fans out all sections via a ThreadPoolExecutor and returns a
health.py-shaped dict so it can drop straight into the existing dashboard.

No method raises: transport / parse errors become an unsuccessful DriverResult.
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor, as_completed

from .result import DriverResult
from .transport import Transport

SNAPSHOT_TIMEOUT_S = 30.0


class BaseNetworkDriver(ABC):
    """Vendor-neutral driver template. Subclass per platform."""

    vendor: str = ""
    commands: dict[str, list[str]] = {}

    def __init__(
        self,
        transport: Transport,
        *,
        hostname: str | None = None,
        ip: str | None = None,
        port: int = 22,
    ) -> None:
        self.transport = transport
        self.hostname = hostname
        self.ip = ip
        self.port = port

    # ── subclass hook ─────────────────────────────────────────────────────────
    @abstractmethod
    def _parse(self, section: str, raw: str) -> dict:
        """Parse ``raw`` output for ``section`` into the normalized dict.

        Implementations dispatch to drivers.parsers functions. Must soft-fail
        (return the fixed empty shape), never raise.
        """
        raise NotImplementedError

    # ── core template method ────────────────────────────────────────────────
    def _run_section(self, section: str) -> DriverResult:
        """Resolve commands for ``section``, run with fallback, parse, time it.

        Tries each command in ``self.commands[section]`` in order; the first one
        that succeeds with non-empty output wins. Always returns a DriverResult.
        """
        t0 = time.monotonic()
        cmds = self.commands.get(section, [])
        if not cmds:
            return DriverResult(
                section=section, vendor=self.vendor, command="", raw="",
                normalized=self._safe_parse(section, ""), success=False,
                via="n/a", error=f"no command defined for section {section!r}",
                elapsed_ms=0.0,
            )

        last_raw, last_via, last_cmd = "", "docker-exec", cmds[-1]
        for cmd in cmds:
            try:
                raw, success, via = self.transport.exec(self.vendor, cmd)
            except Exception:  # noqa: BLE001 — transport must never escape
                last_cmd, last_via, last_raw = cmd, "error", ""
                continue
            last_cmd, last_raw, last_via = cmd, raw, via
            if success and (raw or "").strip():
                normalized = self._safe_parse(section, raw)
                return DriverResult(
                    section=section, vendor=self.vendor, command=cmd, raw=raw,
                    normalized=normalized, success=True, via=via, error=None,
                    elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
                )

        # Nothing succeeded — return the best-effort empty shape.
        return DriverResult(
            section=section, vendor=self.vendor, command=last_cmd, raw=last_raw,
            normalized=self._safe_parse(section, last_raw), success=False,
            via=last_via, error="no command returned usable output",
            elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    def _safe_parse(self, section: str, raw: str) -> dict:
        """Call ``_parse`` but never let a parser bug propagate."""
        try:
            return self._parse(section, raw)
        except Exception as exc:  # noqa: BLE001
            return {"_parse_error": str(exc)}

    # ── public command methods (all return DriverResult) ──────────────────────
    def get_bgp_summary(self) -> DriverResult:
        return self._run_section("bgp")

    def get_ospf_neighbors(self) -> DriverResult:
        return self._run_section("ospf")

    def get_interface_status(self) -> DriverResult:
        return self._run_section("interfaces")

    def get_interface_counters(self) -> DriverResult:
        return self._run_section("interface_counters")

    def get_routes(self) -> DriverResult:
        return self._run_section("routes")

    def get_version(self) -> DriverResult:
        return self._run_section("version")

    def run_command(self, cmd: str) -> DriverResult:
        """Run an arbitrary raw command. ``normalized`` is empty (no section)."""
        t0 = time.monotonic()
        try:
            raw, success, via = self.transport.exec(self.vendor, cmd)
        except Exception as exc:  # noqa: BLE001
            return DriverResult(
                section="raw", vendor=self.vendor, command=cmd, raw="",
                normalized={}, success=False, via="error", error=str(exc),
                elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
            )
        return DriverResult(
            section="raw", vendor=self.vendor, command=cmd, raw=raw or "",
            normalized={}, success=bool(success and (raw or "").strip()),
            via=via, error=None if success else "command returned no output",
            elapsed_ms=round((time.monotonic() - t0) * 1000, 2),
        )

    # ── health fan-out (returns dict, not DriverResult) ───────────────────────
    def get_health(self) -> dict:
        """Run version/bgp/ospf/interfaces/routes in parallel; return health dict.

        Output mirrors health.py's collect_health schema closely enough to feed
        the existing dashboard:
            {meta, version, bgp, ospf, interfaces, routes}
        """
        t0 = time.time()
        sections = ["version", "bgp", "ospf", "interfaces", "routes"]
        results: dict[str, DriverResult] = {}
        errors: list[str] = []

        with ThreadPoolExecutor(max_workers=len(sections)) as pool:
            future_to_section = {
                pool.submit(self._run_section, sec): sec for sec in sections
            }
            deadline = time.time() + SNAPSHOT_TIMEOUT_S
            try:
                for fut in as_completed(future_to_section, timeout=SNAPSHOT_TIMEOUT_S):
                    sec = future_to_section[fut]
                    try:
                        results[sec] = fut.result(timeout=max(1.0, deadline - time.time()))
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"{sec}: {exc}")
            except Exception as exc:  # noqa: BLE001 — overall timeout etc.
                errors.append(f"health fan-out: {exc}")

        for sec, res in results.items():
            if not res.success and res.error:
                errors.append(f"{sec}: {res.error}")

        version_res = results.get("version")
        via = version_res.via if version_res else "docker-exec"

        snapshot: dict = {
            "meta": {
                "hostname": self.hostname,
                "ip": self.ip,
                "dtype": self.vendor,
                "collected_at": t0,
                "collect_time": round(time.time() - t0, 3),
                "via": via,
                "errors": errors,
            },
            "version":    (version_res.normalized if version_res
                           else {"raw": "", "version": None, "uptime": None}),
            "bgp":        self._norm(results.get("bgp"),
                                     {"peers": [], "established": 0, "total": 0}),
            "ospf":       self._norm(results.get("ospf"),
                                     {"neighbors": [], "full": 0, "total": 0}),
            "interfaces": self._norm(results.get("interfaces"),
                                     {"list": [], "up": 0, "total": 0}),
            "routes":     self._norm(results.get("routes"),
                                     {"total": None, "by_protocol": {}}),
        }
        return snapshot

    @staticmethod
    def _norm(res: DriverResult | None, default: dict) -> dict:
        """Pull the normalized dict from a DriverResult, or fall back to default."""
        if res is None:
            return default
        return res.normalized or default
