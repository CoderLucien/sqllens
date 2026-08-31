from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = ROOT / "tests" / "fixtures" / "prometheus" / "fake_prometheus.py"


def load_server_module():
    spec = importlib.util.spec_from_file_location("fake_prometheus", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fake Prometheus: {SERVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakePrometheusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_server_module()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.servers = []

    def start_server(self, mode: str, *, timeout_seconds: float = 0.2):
        capture_path = Path(self.temp_dir.name) / f"{mode}.ndjson"
        server = self.module.create_server(
            host="127.0.0.1",
            port=0,
            mode=mode,
            capture_path=capture_path,
            timeout_seconds=timeout_seconds,
            high_cardinality_series=257,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append((server, thread))
        self.addCleanup(self.stop_server, server, thread)
        host, port = server.server_address
        return f"http://{host}:{port}", capture_path

    @staticmethod
    def stop_server(server, thread) -> None:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    def request(self, base_url: str, path: str, *, timeout: float = 1):
        request = urllib.request.Request(
            f"{base_url}{path}",
            headers={"Authorization": "Bearer qa-prometheus-secret"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    @staticmethod
    def range_path() -> str:
        params = urllib.parse.urlencode(
            {
                "query": "sum(rate(tidb_server_query_total[5m])) by (instance)",
                "start": "1577836800",
                "end": "1577836860",
                "step": "30",
            }
        )
        return f"/api/v1/query_range?{params}"

    def test_ok_returns_a_bounded_matrix_for_two_nodes(self) -> None:
        base_url, _ = self.start_server("ok")
        status, body = self.request(base_url, self.range_path())
        response = json.loads(body)

        self.assertEqual(status, 200)
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["data"]["resultType"], "matrix")
        self.assertEqual(len(response["data"]["result"]), 2)
        self.assertTrue(
            all(len(series["values"]) == 3 for series in response["data"]["result"])
        )

    def test_partial_and_stale_modes_are_observably_distinct(self) -> None:
        partial_url, _ = self.start_server("partial")
        _, partial_body = self.request(partial_url, self.range_path())
        partial = json.loads(partial_body)
        self.assertEqual(len(partial["data"]["result"]), 1)

        stale_url, _ = self.start_server("stale")
        _, stale_body = self.request(stale_url, self.range_path())
        stale = json.loads(stale_body)
        newest = max(
            value[0]
            for series in stale["data"]["result"]
            for value in series["values"]
        )
        self.assertLess(newest, 1577836800)

    def test_high_cardinality_mode_returns_the_configured_series_count(self) -> None:
        base_url, _ = self.start_server("high-cardinality")
        _, body = self.request(base_url, self.range_path())
        response = json.loads(body)

        self.assertEqual(len(response["data"]["result"]), 257)

    def test_auth_and_api_error_modes_use_prometheus_error_envelopes(self) -> None:
        for mode, expected_status in {
            "unauthorized": 401,
            "forbidden": 403,
            "api-error": 422,
        }.items():
            with self.subTest(mode=mode):
                base_url, _ = self.start_server(mode)
                status, body = self.request(base_url, self.range_path())
                response = json.loads(body)
                self.assertEqual(status, expected_status)
                self.assertEqual(response["status"], "error")
                self.assertIn("errorType", response)

    def test_invalid_json_and_timeout_modes_are_distinct(self) -> None:
        invalid_url, _ = self.start_server("invalid-json")
        status, body = self.request(invalid_url, self.range_path())
        self.assertEqual(status, 200)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(body)

        timeout_url, _ = self.start_server("timeout")
        with self.assertRaises(TimeoutError):
            self.request(timeout_url, self.range_path(), timeout=0.02)

    def test_capture_redacts_authorization_and_records_query_budget_inputs(self) -> None:
        base_url, capture_path = self.start_server("ok")
        self.request(base_url, self.range_path())
        record = json.loads(capture_path.read_text(encoding="utf-8"))

        self.assertTrue(record["authorizationPresent"])
        self.assertNotIn("qa-prometheus-secret", json.dumps(record))
        self.assertEqual(record["params"]["start"], ["1577836800"])
        self.assertEqual(record["params"]["end"], ["1577836860"])
        self.assertEqual(record["params"]["step"], ["30"])
        self.assertEqual(record["path"], "/api/v1/query_range")

    def test_buildinfo_exposes_a_pinned_synthetic_version(self) -> None:
        base_url, _ = self.start_server("ok")
        status, body = self.request(base_url, "/api/v1/status/buildinfo")

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["data"]["version"], "3.0.0-fixture")


if __name__ == "__main__":
    unittest.main()
