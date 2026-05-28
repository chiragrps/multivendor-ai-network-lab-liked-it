"""Transport layer for drivers — how a command actually reaches a device.

Three concrete transports + a Protocol the drivers depend on:

* ``DockerExecTransport``  — runs commands inside a clab container via
  ``docker exec``, translating the per-vendor argv (vtysh / Cli / sr_cli).
  Includes a persistent session pool (ported from clab_collector.py) so the
  per-call docker startup cost is paid once per container.
* ``SSHRunnerTransport``   — wraps an existing ``runner(ip, dtype, cmd, port)``
  callable (e.g. app.run_command_on_device) without importing paramiko here.
* ``ScrapliTransport``     — lazy-imports scrapli; raises a clear
  NotImplementedError if scrapli isn't installed.

CRITICAL: this module imports NOTHING heavy at top level. ``subprocess``,
``shlex``, ``threading`` are stdlib and cheap. paramiko / scrapli / flask are
lazy-imported inside methods only — clab_collector hosts run without them.

All subprocess use is argv-list based (never shell=True); the only shell is the
container-internal ``sh`` whose input is shlex-quoted before being sent.
"""
from __future__ import annotations

import shlex
import subprocess
import threading
import time
from typing import Callable, Protocol, runtime_checkable

# Per-vendor argv prefix for docker exec. The command string is appended as the
# final argv element so the container's shell never re-splits it.
_DOCKER_ARGV: dict[str, list[str]] = {
    "frr":        ["vtysh", "-c"],
    "arista-eos": ["Cli", "-p", "15", "-c"],
    "nokia-srl":  ["sr_cli", "-d"],
    "junos":      ["cli", "-c"],   # cRPD / vJunos-router container CLI
    "cisco-iosxr": ["xrcmd"],      # cisco/iosxr container helper; SSH otherwise
}


@runtime_checkable
class Transport(Protocol):
    """A transport executes one command for one vendor and reports the outcome.

    Returns ``(raw, success, via)``:
        raw:     unparsed stdout (empty string on failure).
        success: True when the command produced usable output.
        via:     transport label for observability (docker-exec | ssh | scrapli).
    """

    def exec(self, vendor: str, command: str) -> tuple[str, bool, str]:
        ...


# ───────────────────── persistent docker-exec session pool ────────────────────
# Ported from network-lab/telemetry/clab_collector.py so the drivers package can
# share it. Module-level state is process-wide and thread-safe via _SESSION_LOCK.

_SESSION_LOCK = threading.Lock()
_SESSIONS: dict[str, "subprocess.Popen[str]"] = {}
_SESSION_MISSES: dict[str, int] = {}
_END_MARKER = "__DCN_END__"


def _open_session(container: str) -> "subprocess.Popen[str] | None":
    """Spawn a long-running ``docker exec -i <container> sh``. None on failure."""
    try:
        return subprocess.Popen(
            ["docker", "exec", "-i", container, "sh"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    except Exception:  # noqa: BLE001 — container not running / docker missing
        return None


def _read_until_marker(p: "subprocess.Popen[str]", timeout: float = 12.0) -> str:
    """Read p.stdout until the END marker; return everything before it."""
    deadline = time.monotonic() + timeout
    chunks: list[str] = []
    if p.stdout is None:
        return ""
    while time.monotonic() < deadline:
        line = p.stdout.readline()
        if not line:
            break
        if _END_MARKER in line:
            return "".join(chunks)
        chunks.append(line)
    return "".join(chunks)


def docker_run(container: str, *cmd: str, timeout: int = 15) -> str:
    """Run a command inside a container via a persistent shell session.

    Falls back to one-shot ``subprocess.run`` if the session can't be opened or
    breaks mid-command (auto-recovery for container restart).
    """
    if not cmd:
        return ""
    with _SESSION_LOCK:
        sess = _SESSIONS.get(container)
        if sess is None or sess.poll() is not None:
            sess = _open_session(container)
            if sess is None:
                return _docker_run_oneshot(container, *cmd, timeout=timeout)
            _SESSIONS[container] = sess
            _SESSION_MISSES[container] = 0

    line = " ".join(shlex.quote(c) for c in cmd) + f"; printf '%s\\n' '{_END_MARKER}'\n"
    try:
        if sess.stdin is None:
            raise BrokenPipeError("no stdin on session")
        sess.stdin.write(line)
        sess.stdin.flush()
        return _read_until_marker(sess, timeout=timeout)
    except (BrokenPipeError, OSError):
        with _SESSION_LOCK:
            _SESSION_MISSES[container] = _SESSION_MISSES.get(container, 0) + 1
            try:
                sess.kill()
            except Exception:  # noqa: BLE001
                pass
            _SESSIONS.pop(container, None)
        return _docker_run_oneshot(container, *cmd, timeout=timeout)


def _docker_run_oneshot(container: str, *cmd: str, timeout: int = 15) -> str:
    """One-shot ``docker exec`` path used as a fallback by docker_run."""
    full = ["docker", "exec", container, *cmd]
    result = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
    if result.returncode != 0:
        raise RuntimeError(
            f"{container}: rc={result.returncode}: {(result.stderr or '').strip()[:200]}"
        )
    return result.stdout


# ───────────────────────────── DockerExecTransport ────────────────────────────

class DockerExecTransport:
    """Run commands inside a clab container, translating per-vendor argv.

    ``runner`` is injectable purely for tests — production leaves it None so the
    persistent-session ``docker_run`` is used.
    """

    def __init__(
        self,
        container: str,
        *,
        timeout: int = 15,
        runner: Callable[..., str] | None = None,
    ) -> None:
        self.container = container
        self.timeout = timeout
        self._runner = runner or docker_run

    def _argv(self, vendor: str, command: str) -> list[str]:
        from .commands import canonical_vendor
        canon = canonical_vendor(vendor) or vendor
        prefix = _DOCKER_ARGV.get(canon)
        if prefix is None:
            # Unknown vendor — run the command verbatim and let the shell handle it.
            return shlex.split(command)
        return [*prefix, command]

    def exec(self, vendor: str, command: str) -> tuple[str, bool, str]:
        if not command:
            return "", False, "docker-exec"
        argv = self._argv(vendor, command)
        try:
            raw = self._runner(self.container, *argv, timeout=self.timeout)
        except Exception:  # noqa: BLE001 — never raise out of a transport
            return "", False, "docker-exec"
        success = bool((raw or "").strip())
        return raw or "", success, "docker-exec"


# ───────────────────────────── SSHRunnerTransport ─────────────────────────────

class SSHRunnerTransport:
    """Wrap an existing ``runner(ip, dtype, cmd, port=...) -> dict`` callable.

    The runner result is expected to carry ``output`` and ``success`` keys (the
    shape app.run_command_on_device returns). No paramiko import here — the
    runner owns the SSH session.
    """

    def __init__(
        self,
        runner: Callable[..., dict],
        *,
        ip: str,
        port: int = 22,
        dtype: str | None = None,
    ) -> None:
        self._runner = runner
        self.ip = ip
        self.port = port
        self._dtype = dtype

    def exec(self, vendor: str, command: str) -> tuple[str, bool, str]:
        if not command:
            return "", False, "ssh"
        dtype = self._dtype or vendor
        try:
            try:
                result = self._runner(self.ip, dtype, command, port=self.port)
            except TypeError:
                # Some runners don't accept the port kwarg.
                result = self._runner(self.ip, dtype, command)
        except Exception:  # noqa: BLE001
            return "", False, "ssh"
        result = result or {}
        raw = (result.get("output") or "")
        success = bool(result.get("success")) and bool(raw.strip())
        return raw, success, "ssh"


# ───────────────────────────── ScrapliTransport ───────────────────────────────

class ScrapliTransport:
    """Scrapli-backed transport stub.

    Scrapli is an optional dependency; importing it eagerly would break the
    lab-host import surface. We lazy-import on first ``exec`` and raise a clear
    NotImplementedError when scrapli isn't installed (or the driver path isn't
    wired yet).
    """

    def __init__(self, host: str, *, platform: str | None = None, **kwargs: object) -> None:
        self.host = host
        self.platform = platform
        self._kwargs = kwargs

    def exec(self, vendor: str, command: str) -> tuple[str, bool, str]:
        try:
            import scrapli  # noqa: F401 — presence check only
        except ImportError as exc:
            raise NotImplementedError(
                "ScrapliTransport requires the optional 'scrapli' package "
                "(pip install scrapli). It is not installed."
            ) from exc
        raise NotImplementedError(
            "ScrapliTransport is a stub: the scrapli driver path is not wired "
            "yet. Use DockerExecTransport or SSHRunnerTransport."
        )
