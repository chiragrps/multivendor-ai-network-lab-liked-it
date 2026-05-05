"""
test_cli_transport.py — Unit tests for CLI-over-HTTPS transport endpoints.

Tests three new endpoints added as part of the CLI-over-HTTPS feature:
  POST /api/cli-https         — batch commands via HTTP proxy (single round-trip)
  POST /api/transport-bench   — concurrent SSH vs HTTPS benchmark
  GET  /api/cli-proxy/health  — check proxy status on all lab devices

All HTTP proxy calls are mocked via requests.get; SSH calls are mocked via
paramiko.SSHClient so no real containers are required.
"""

from unittest.mock import MagicMock, patch


# ── /api/cli-https ─────────────────────────────────────────────────────────────

class TestCliHttps:
    def test_batch_commands_success(self, app_client):
        """POST /api/cli-https returns proxy JSON on success."""
        proxy_resp = {
            "hostname": "de-fra-core-01",
            "commands": ["show version"],
            "results": [{"cmd": "show version", "output": "FRRouting 8.4", "elapsed_ms": 34}],
            "total_elapsed_ms": 34,
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = proxy_resp
        mock_resp.raise_for_status.return_value = None

        with patch("requests.get", return_value=mock_resp) as mock_get:
            r = app_client.post(
                "/api/cli-https",
                json={"hostname": "de-fra-core-01", "commands": ["show version"]},
            )

        assert r.status_code == 200
        body = r.get_json()
        assert body["transport"] == "https"
        assert body["hostname"] == "de-fra-core-01"
        assert len(body["results"]) == 1
        assert body["results"][0]["output"] == "FRRouting 8.4"
        # Verify batch URL constructed correctly
        assert mock_get.called
        call_url = mock_get.call_args[0][0]
        assert "/batch/" in call_url
        assert "show%20version" in call_url

    def test_unknown_hostname_returns_404(self, app_client):
        """Hostname not in _CLI_PROXY_PORTS returns 404."""
        r = app_client.post(
            "/api/cli-https",
            json={"hostname": "not-a-real-device", "commands": ["show version"]},
        )
        assert r.status_code == 404
        assert "not in CLI proxy map" in r.get_json()["error"]

    def test_missing_hostname_returns_400(self, app_client):
        """Missing hostname field returns 400."""
        r = app_client.post("/api/cli-https", json={"commands": ["show version"]})
        assert r.status_code == 400

    def test_missing_commands_returns_400(self, app_client):
        """Missing commands field returns 400."""
        r = app_client.post("/api/cli-https", json={"hostname": "de-fra-core-01"})
        assert r.status_code == 400

    def test_proxy_failure_returns_502(self, app_client):
        """Proxy connection error returns 502."""
        with patch("requests.get", side_effect=ConnectionError("refused")):
            r = app_client.post(
                "/api/cli-https",
                json={"hostname": "de-fra-core-01", "commands": ["show version"]},
            )
        assert r.status_code == 502

    def test_multiple_commands_url_encoding(self, app_client):
        """Multiple commands are URL-encoded and joined with /."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "hostname": "de-fra-core-01",
            "results": [],
            "total_elapsed_ms": 10,
        }
        mock_resp.raise_for_status.return_value = None

        cmds = ["show version", "show bgp summary"]
        with patch("requests.get", return_value=mock_resp) as mock_get:
            r = app_client.post(
                "/api/cli-https",
                json={"hostname": "de-fra-core-01", "commands": cmds},
            )

        assert r.status_code == 200
        call_url = mock_get.call_args[0][0]
        assert "show%20version" in call_url
        assert "show%20bgp%20summary" in call_url


# ── /api/transport-bench ───────────────────────────────────────────────────────

class TestTransportBench:
    def _make_ssh_client(self, output: str = "FRRouting 8.4"):
        """Return a mocked paramiko SSHClient that yields output."""
        stdout_mock = MagicMock()
        stdout_mock.read.return_value = output.encode()
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        cli = MagicMock()
        cli.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)
        return cli

    def test_bench_returns_timing_fields(self, app_client):
        """Bench response includes ssh_ms, https_ms, speedup, and per-transport results."""
        proxy_body = {
            "hostname": "de-fra-core-01",
            "results": [{"cmd": "show version", "output": "FRRouting 8.4", "elapsed_ms": 30}],
            "total_elapsed_ms": 30,
        }
        proxy_resp = MagicMock()
        proxy_resp.status_code = 200
        proxy_resp.json.return_value = proxy_body
        proxy_resp.raise_for_status.return_value = None

        ssh_cli = self._make_ssh_client("FRRouting 8.4")

        with patch("paramiko.SSHClient", return_value=ssh_cli), \
             patch("requests.get", return_value=proxy_resp):
            r = app_client.post(
                "/api/transport-bench",
                json={"hostname": "de-fra-core-01", "commands": ["show version"]},
            )

        assert r.status_code == 200
        body = r.get_json()
        assert "ssh_ms" in body
        assert "https_ms" in body
        assert "speedup" in body
        assert "ssh_results" in body
        assert "https_results" in body
        assert body["hostname"] == "de-fra-core-01"
        assert isinstance(body["speedup"], (int, float))

    def test_bench_computes_speedup(self, app_client):
        """Speedup ratio = ssh_ms / https_ms rounded to 1 decimal."""
        import time

        def slow_ssh_connect(*args, **kwargs):
            time.sleep(0.1)

        stdout_mock = MagicMock()
        stdout_mock.read.return_value = b"FRRouting 8.4"
        stderr_mock = MagicMock()
        stderr_mock.read.return_value = b""
        ssh_cli = MagicMock()
        ssh_cli.connect.side_effect = slow_ssh_connect
        ssh_cli.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)

        proxy_resp = MagicMock()
        proxy_resp.status_code = 200
        proxy_resp.json.return_value = {
            "hostname": "de-fra-core-01",
            "results": [{"cmd": "show version", "output": "FRRouting", "elapsed_ms": 10}],
            "total_elapsed_ms": 10,
        }
        proxy_resp.raise_for_status.return_value = None

        with patch("paramiko.SSHClient", return_value=ssh_cli), \
             patch("requests.get", return_value=proxy_resp):
            r = app_client.post(
                "/api/transport-bench",
                json={"hostname": "de-fra-core-01", "commands": ["show version"]},
            )

        body = r.get_json()
        # SSH should be slower because of the artificial connect sleep
        assert body["ssh_ms"] >= body["https_ms"]
        assert isinstance(body["speedup"], (int, float))

    def test_bench_unknown_hostname_returns_404(self, app_client):
        r = app_client.post(
            "/api/transport-bench",
            json={"hostname": "not-a-real-host", "commands": ["show version"]},
        )
        assert r.status_code == 404

    def test_bench_defaults_to_standard_command_set(self, app_client):
        """Omitting commands uses the built-in 5-command benchmark set."""
        proxy_resp = MagicMock()
        proxy_resp.status_code = 200
        proxy_resp.json.return_value = {
            "hostname": "de-fra-core-01",
            "results": [{"cmd": c, "output": "ok", "elapsed_ms": 10}
                        for c in ["show version", "show bgp summary",
                                  "show ip ospf neighbor", "show interface brief",
                                  "show ip route summary"]],
            "total_elapsed_ms": 50,
        }
        proxy_resp.raise_for_status.return_value = None

        ssh_cli = self._make_ssh_client()
        with patch("paramiko.SSHClient", return_value=ssh_cli), \
             patch("requests.get", return_value=proxy_resp):
            r = app_client.post(
                "/api/transport-bench",
                json={"hostname": "de-fra-core-01"},
            )

        assert r.status_code == 200
        body = r.get_json()
        assert len(body["commands"]) == 5


# ── /api/cli-proxy/health ──────────────────────────────────────────────────────

class TestCliProxyHealth:
    def test_health_returns_all_10_devices(self, app_client):
        """Health endpoint checks all 10 lab devices and returns up/total counts."""
        ok_resp = MagicMock()
        ok_resp.status_code = 200

        with patch("requests.get", return_value=ok_resp):
            r = app_client.get("/api/cli-proxy/health")

        assert r.status_code == 200
        body = r.get_json()
        assert body["total"] == 10
        assert "up" in body
        assert "proxies" in body
        hostnames = [p["hostname"] for p in body["proxies"]]
        assert "de-fra-core-01" in hostnames
        assert "uk-lon-core-01" in hostnames
        assert "us-nyc-core-01" in hostnames

    def test_health_marks_unreachable_proxy_as_down(self, app_client):
        """Connection errors set ok=False for the affected host."""
        def selective_get(url, **kwargs):
            if "8801" in url:
                raise ConnectionError("refused")
            resp = MagicMock()
            resp.status_code = 200
            return resp

        with patch("requests.get", side_effect=selective_get):
            r = app_client.get("/api/cli-proxy/health")

        body = r.get_json()
        core01 = next(p for p in body["proxies"] if p["hostname"] == "de-fra-core-01")
        assert core01["ok"] is False
        assert body["up"] == 9

    def test_health_includes_port_per_device(self, app_client):
        """Each proxy entry includes the port number."""
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        with patch("requests.get", return_value=ok_resp):
            r = app_client.get("/api/cli-proxy/health")

        body = r.get_json()
        for p in body["proxies"]:
            assert "port" in p
            assert 8801 <= p["port"] <= 8810
