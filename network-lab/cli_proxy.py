#!/usr/bin/env python3
"""
cli_proxy.py — HTTP-to-vtysh command proxy for FRR lab containers.

Mirrors the Cisco ASA HTTP CLI interface pattern described in
network-notes.com/posts/2026/cli-over-https-2/

Endpoints:
  GET /health                        → {"status":"ok","hostname":"..."}
  GET /exec/<url-encoded-cmd>        → run single vtysh command
  GET /batch/<cmd1>/<cmd2>/...       → run N commands in one subprocess (key speedup)

All responses: {"hostname":str, "commands":[str], "results":[{"cmd":str,"output":str,"elapsed_ms":int}],
                "total_elapsed_ms":int}

Auth: HTTP Basic (user=admin, password read from CLI_PROXY_PASSWORD env, default "change-me-in-prod")
Listens: 0.0.0.0:8080
"""

import base64
import json
import os
import socket
import subprocess
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

HOSTNAME  = socket.gethostname()
PORT      = int(os.environ.get("CLI_PROXY_PORT", "8080"))
PASSWORD  = os.environ.get("CLI_PROXY_PASSWORD", "change-me-in-prod")
_CRED_B64 = base64.b64encode(f"admin:{PASSWORD}".encode()).decode()


def _run_vtysh(commands: list[str]) -> list[dict]:
    """Run one or more vtysh commands in a single subprocess call."""
    results = []
    for cmd in commands:
        t0 = time.perf_counter()
        try:
            proc = subprocess.run(
                ["vtysh", "-c", cmd],
                capture_output=True, text=True, timeout=10
            )
            output = proc.stdout or proc.stderr or ""
        except subprocess.TimeoutExpired:
            output = "ERROR: vtysh timeout"
        except FileNotFoundError:
            output = "ERROR: vtysh not found"
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        results.append({"cmd": cmd, "output": output.strip(), "elapsed_ms": elapsed_ms})
    return results


class ProxyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress access log noise

    def _auth_ok(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        return auth[6:] == _CRED_B64

    def _send_json(self, code: int, body: dict):
        data = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(data))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if not self._auth_ok():
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="cli-proxy"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        parsed = urllib.parse.urlparse(self.path)
        path   = parsed.path.rstrip("/")

        # ── /health ──────────────────────────────────────────────────────────
        if path == "/health":
            self._send_json(200, {"status": "ok", "hostname": HOSTNAME})
            return

        # ── /exec/<cmd> ───────────────────────────────────────────────────────
        if path.startswith("/exec/"):
            raw = path[6:]          # strip "/exec/"
            cmd = urllib.parse.unquote_plus(raw)
            t0  = time.perf_counter()
            results = _run_vtysh([cmd])
            self._send_json(200, {
                "hostname":         HOSTNAME,
                "commands":         [cmd],
                "results":          results,
                "total_elapsed_ms": int((time.perf_counter() - t0) * 1000),
            })
            return

        # ── /batch/<cmd1>/<cmd2>/... ──────────────────────────────────────────
        if path.startswith("/batch/"):
            raw_parts = path[7:].split("/")   # strip "/batch/"
            commands  = [urllib.parse.unquote_plus(p) for p in raw_parts if p]
            if not commands:
                self._send_json(400, {"error": "no commands in path"})
                return
            t0      = time.perf_counter()
            results = _run_vtysh(commands)
            self._send_json(200, {
                "hostname":         HOSTNAME,
                "commands":         commands,
                "results":          results,
                "total_elapsed_ms": int((time.perf_counter() - t0) * 1000),
            })
            return

        self._send_json(404, {"error": "unknown endpoint", "path": path})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization")
        self.end_headers()


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), ProxyHandler)
    print(f"cli_proxy listening on :{PORT}  hostname={HOSTNAME}", flush=True)
    server.serve_forever()
