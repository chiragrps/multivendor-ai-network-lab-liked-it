"""Phase 5 — comprehensive stress / regression suite.

Hammers every Phase 5 endpoint (and a few critical Phase 4 ones) with
concurrent load, records latency percentiles, and emits a structured
report. Run with:

    pytest test_phase5_stress.py -v -s        # verbose with prints
    pytest test_phase5_stress.py::TestStress::test_full_suite_report -s

Requires the Flask app to be running on localhost:5757. If unreachable,
tests are skipped (not failed) so this file is safe in CI without the
app.
"""
from __future__ import annotations

import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlreq

import pytest

API = "http://127.0.0.1:5757"
TIMEOUT_S = 10


def _api_up() -> bool:
    try:
        with urlreq.urlopen(f"{API}/api/devices", timeout=2) as r:
            return r.status == 200
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _api_up(), reason="Flask app not running on :5757")


def _post(path: str, body: dict, timeout: float = TIMEOUT_S) -> tuple[int, dict, float]:
    """POST JSON, return (status_code, response_dict, elapsed_ms)."""
    data = json.dumps(body).encode("utf-8")
    req = urlreq.Request(
        f"{API}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urlreq.urlopen(req, timeout=timeout) as r:
            payload = json.loads(r.read())
            ms = (time.perf_counter() - t0) * 1000
            return r.status, payload, ms
    except urlerror.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {"error": str(e)}
        return e.code, payload, ms


def _get(path: str, timeout: float = TIMEOUT_S) -> tuple[int, dict, float]:
    t0 = time.perf_counter()
    try:
        with urlreq.urlopen(f"{API}{path}", timeout=timeout) as r:
            payload = json.loads(r.read())
            ms = (time.perf_counter() - t0) * 1000
            return r.status, payload, ms
    except urlerror.HTTPError as e:
        ms = (time.perf_counter() - t0) * 1000
        return e.code, {"error": str(e)}, ms


def _percentiles(latencies: list[float]) -> dict[str, float]:
    if not latencies:
        return {"p50": 0, "p95": 0, "p99": 0, "max": 0, "mean": 0}
    s = sorted(latencies)
    return {
        "p50":  s[len(s) // 2],
        "p95":  s[int(len(s) * 0.95)],
        "p99":  s[int(len(s) * 0.99)] if len(s) >= 100 else s[-1],
        "max":  s[-1],
        "mean": statistics.fmean(s),
    }


# ─── Smoke tests on every Phase 5 endpoint ──────────────────────────────────


class TestSmoke:
    def test_forecast_predict_smoke(self):
        code, body, ms = _post("/api/mv/forecast/predict",
                                 {"device": "de-fra-core-01", "metric": "cpu_pct",
                                  "horizon": 64, "synth": "cpu"})
        assert code == 200
        assert "forecast" in body
        assert len(body["forecast"]) == 64
        print(f"\n  forecast/predict: HTTP {code} in {ms:.1f}ms · backend={body.get('model')}")

    def test_forecast_status_smoke(self):
        code, body, ms = _get("/api/mv/forecast/status")
        assert code == 200
        assert body["available"] is True
        print(f"  forecast/status:  HTTP {code} in {ms:.1f}ms · backend={body.get('backend')}")

    def test_forecast_anomalies_smoke(self):
        code, body, ms = _get("/api/mv/forecast/anomalies?since_seconds=600")
        assert code == 200
        assert "alerts" in body
        print(f"  forecast/anomalies: HTTP {code} in {ms:.1f}ms · count={body.get('count')}")

    def test_predict_run_smoke(self):
        code, body, ms = _post("/api/mv/predict/run",
                                 {"target_device": "de-fra-core-01",
                                  "proposed_change": "no neighbor de-fra-core-02"})
        assert code == 200
        assert body["verdict"] in ("APPROVE", "WARN", "REJECT")
        print(f"  predict/run:       HTTP {code} in {ms:.1f}ms · verdict={body['verdict']}")

    def test_predict_history_smoke(self):
        code, body, ms = _get("/api/mv/predict/history?limit=10")
        assert code == 200
        assert "history" in body
        print(f"  predict/history:   HTTP {code} in {ms:.1f}ms · rows={body.get('count')}")

    def test_predict_status_smoke(self):
        code, body, ms = _get("/api/mv/predict/status")
        assert code == 200
        assert body["available"] is True
        print(f"  predict/status:    HTTP {code} in {ms:.1f}ms · backend={body.get('backend')}")

    def test_blast_compute_smoke(self):
        code, body, ms = _post("/api/mv/blast-radius/compute",
                                 {"action": "shutdown_interface",
                                  "target_device": "de-fra-core-01",
                                  "target_object": "ge-0/0/1",
                                  "depth": 3})
        assert code == 200
        assert body["risk_score"] in ("LOW", "MEDIUM", "HIGH", "CRIT")
        print(f"  blast/compute:     HTTP {code} in {ms:.1f}ms · risk={body['risk_score']}")

    def test_blast_history_smoke(self):
        code, body, ms = _get("/api/mv/blast-radius/history?limit=10")
        assert code == 200
        print(f"  blast/history:     HTTP {code} in {ms:.1f}ms · rows={body.get('count')}")


# ─── Concurrent load ─────────────────────────────────────────────────────────


class TestConcurrentLoad:
    def test_forecast_50_concurrent(self):
        """50 concurrent forecast requests — measures lock contention."""
        def _do(_):
            code, body, ms = _post("/api/mv/forecast/predict",
                                     {"device": f"dev-{_}", "metric": "cpu_pct",
                                      "horizon": 64, "synth": "cpu"}, timeout=15)
            return code == 200, ms

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(_do, range(50)))
        successes = sum(1 for ok, _ in results if ok)
        latencies = [ms for _, ms in results]
        p = _percentiles(latencies)
        assert successes == 50, f"only {successes}/50 succeeded"
        assert p["p95"] < 2000, f"p95 {p['p95']:.0f}ms exceeded 2000ms"
        print(f"\n  forecast 50@10:  100% success · p50={p['p50']:.0f}ms p95={p['p95']:.0f}ms mean={p['mean']:.0f}ms")

    def test_predict_50_concurrent(self):
        def _do(i):
            code, _, ms = _post("/api/mv/predict/run",
                                 {"target_device": f"dev-{i}",
                                  "proposed_change": "no neighbor 10.0.0.1"}, timeout=10)
            return code == 200, ms

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(_do, range(50)))
        successes = sum(1 for ok, _ in results if ok)
        latencies = [ms for _, ms in results]
        p = _percentiles(latencies)
        assert successes == 50
        assert p["p95"] < 1000
        print(f"  predict  50@10:  100% success · p50={p['p50']:.0f}ms p95={p['p95']:.0f}ms")

    def test_blast_50_concurrent(self):
        def _do(_):
            code, _b, ms = _post("/api/mv/blast-radius/compute",
                                  {"action": "shutdown_interface",
                                   "target_device": "de-fra-core-01",
                                   "target_object": "eth0", "depth": 3}, timeout=10)
            return code == 200, ms

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(_do, range(50)))
        successes = sum(1 for ok, _ in results if ok)
        latencies = [ms for _, ms in results]
        p = _percentiles(latencies)
        assert successes == 50
        assert p["p95"] < 1000
        print(f"  blast    50@10:  100% success · p50={p['p50']:.0f}ms p95={p['p95']:.0f}ms")


# ─── Error paths ─────────────────────────────────────────────────────────────


class TestErrorPaths:
    def test_forecast_missing_metric(self):
        code, body, _ = _post("/api/mv/forecast/predict", {"device": "x"})
        assert code == 400
        assert "metric" in body.get("error", "").lower() or "metric" in str(body)

    def test_predict_missing_target(self):
        code, _, _ = _post("/api/mv/predict/run", {"proposed_change": "no neighbor 1.1.1.1"})
        assert code == 400

    def test_predict_missing_change(self):
        code, _, _ = _post("/api/mv/predict/run", {"target_device": "x"})
        assert code == 400

    def test_blast_unknown_action(self):
        code, body, _ = _post("/api/mv/blast-radius/compute",
                                {"action": "delete_universe", "target_device": "x"})
        assert code == 400
        assert "supported" in body

    def test_blast_missing_device(self):
        code, _, _ = _post("/api/mv/blast-radius/compute",
                            {"action": "shutdown_interface"})
        assert code == 400


# ─── End-to-end Phase 5 scenario ─────────────────────────────────────────────


class TestE2E:
    def test_forecast_to_predict_to_blast_pipeline(self):
        """Simulate the full Phase 5 pipeline: forecast spikes → predict change →
        compute blast radius → approve."""
        # 1. Forecast hits anomaly threshold on the anomaly synth series
        code, fcast, _ = _post("/api/mv/forecast/predict",
                                 {"device": "uk-lon-core-01", "metric": "cpu_pct",
                                  "horizon": 64, "synth": "anomaly"})
        assert code == 200
        assert len(fcast["anomaly_alerts"]) >= 1, "expected at least one alert on anomaly series"

        # 2. Operator proposes a mitigating change → predict
        code, pred, _ = _post("/api/mv/predict/run",
                                {"target_device": "uk-lon-core-01",
                                 "proposed_change": "no neighbor de-fra-core-01"})
        assert code == 200
        assert pred["verdict"] in ("APPROVE", "WARN", "REJECT")

        # 3. Compute blast radius for the same action
        code, blast, _ = _post("/api/mv/blast-radius/compute",
                                 {"action": "drop_bgp_peer",
                                  "target_device": "uk-lon-core-01",
                                  "target_object": "de-fra-core-01"})
        assert code == 200
        assert blast["risk_score"] in ("LOW", "MEDIUM", "HIGH", "CRIT")

        print(f"\n  E2E pipeline: alerts={len(fcast['anomaly_alerts'])} "
              f"verdict={pred['verdict']} risk={blast['risk_score']}")


# ─── Final report ────────────────────────────────────────────────────────────


class TestStress:
    def test_full_suite_report(self, capsys):
        """Final summary — total throughput and per-endpoint stats."""
        report_lines = ["", "", "════════ PHASE 5 STRESS REPORT ════════"]

        for name, op in [
            ("forecast/predict (cpu)",  lambda: _post("/api/mv/forecast/predict",
                                                       {"device":"d","metric":"cpu_pct","synth":"cpu","horizon":128})),
            ("forecast/predict (anom)", lambda: _post("/api/mv/forecast/predict",
                                                       {"device":"d","metric":"cpu_pct","synth":"anomaly","horizon":128})),
            ("predict/run (drop)",      lambda: _post("/api/mv/predict/run",
                                                       {"target_device":"de-fra-core-01",
                                                        "proposed_change":"no neighbor de-fra-core-02"})),
            ("predict/run (reject)",    lambda: _post("/api/mv/predict/run",
                                                       {"target_device":"de-fra-core-01",
                                                        "proposed_change":"no router bgp 65001"})),
            ("blast (shutdown)",        lambda: _post("/api/mv/blast-radius/compute",
                                                       {"action":"shutdown_interface",
                                                        "target_device":"de-fra-core-01",
                                                        "target_object":"eth0","depth":3})),
            ("blast (drop_peer)",       lambda: _post("/api/mv/blast-radius/compute",
                                                       {"action":"drop_bgp_peer",
                                                        "target_device":"de-fra-core-01",
                                                        "target_object":"de-fra-core-02"})),
        ]:
            lat = []
            okc = 0
            for _ in range(20):
                code, _b, ms = op()
                if code == 200: okc += 1
                lat.append(ms)
            p = _percentiles(lat)
            report_lines.append(
                f"  {name:30s} {okc}/20 ok · p50={p['p50']:5.1f}ms p95={p['p95']:5.1f}ms max={p['max']:5.1f}ms"
            )

        report_lines.append("═══════════════════════════════════════")
        # Write to disk for inspection
        report_path = Path(__file__).parent / "phase5_stress_report.txt"
        report_path.write_text("\n".join(report_lines))
        print("\n".join(report_lines))
