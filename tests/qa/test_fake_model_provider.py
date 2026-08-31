from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = ROOT / "tests" / "fixtures" / "model_provider" / "fake_openai.py"


def load_server_module():
    spec = importlib.util.spec_from_file_location("fake_openai_provider", SERVER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fake provider: {SERVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeModelProviderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_server_module()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.capture_path = Path(self.temp_dir.name) / "requests.ndjson"
        self.server = self.module.create_server(
            host="127.0.0.1",
            port=0,
            capture_path=self.capture_path,
            timeout_seconds=0.2,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_server)
        host, port = self.server.server_address
        self.url = f"http://{host}:{port}/v1/chat/completions"

    def _stop_server(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, model: str, *, timeout: float = 1) -> tuple[int, bytes, dict]:
        body = json.dumps(
            {
                "model": model,
                "messages": [{"role": "user", "content": "synthetic fixture"}],
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={
                "Authorization": "Bearer qa-provider-secret",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read(), dict(response.headers)
        except urllib.error.HTTPError as error:
            return error.code, error.read(), dict(error.headers)

    def test_ok_returns_an_openai_compatible_structured_message(self) -> None:
        status, body, _ = self.request("fixture/ok")
        response = json.loads(body)
        content = json.loads(response["choices"][0]["message"]["content"])

        self.assertEqual(status, 200)
        self.assertEqual(response["object"], "chat.completion")
        self.assertEqual(content["schemaVersion"], "model-explanation/v1")
        self.assertEqual(content["evidenceIds"], ["ev_0000000000000001"])

    def test_error_modes_are_deterministic(self) -> None:
        for model, expected_status in {
            "fixture/http-429": 429,
            "fixture/http-500": 500,
        }.items():
            with self.subTest(model=model):
                status, body, _ = self.request(model)
                response = json.loads(body)
                self.assertEqual(status, expected_status)
                self.assertEqual(response["error"]["type"], "fixture_error")

    def test_malformed_and_invalid_output_modes_are_distinct(self) -> None:
        status, malformed, _ = self.request("fixture/malformed-json")
        self.assertEqual(status, 200)
        with self.assertRaises(json.JSONDecodeError):
            json.loads(malformed)

        status, invalid_schema, _ = self.request("fixture/invalid-schema")
        provider_envelope = json.loads(invalid_schema)
        content = json.loads(provider_envelope["choices"][0]["message"]["content"])
        self.assertEqual(status, 200)
        self.assertEqual(content, {"unexpected": True})

        status, unknown_evidence, _ = self.request("fixture/unknown-evidence")
        provider_envelope = json.loads(unknown_evidence)
        content = json.loads(provider_envelope["choices"][0]["message"]["content"])
        self.assertEqual(status, 200)
        self.assertEqual(content["evidenceIds"], ["ev_9999999999999999"])

    def test_oversized_response_exceeds_the_fixture_output_budget(self) -> None:
        status, body, headers = self.request("fixture/oversized-content")

        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertGreater(len(body), self.module.OVERSIZED_RESPONSE_BYTES)
        envelope = json.loads(body)
        content = json.loads(envelope["choices"][0]["message"]["content"])
        self.assertGreaterEqual(
            len(content["summary"]), self.module.OVERSIZED_RESPONSE_BYTES
        )

    def test_schema_valid_unsafe_display_text_is_preserved_for_ui_testing(self) -> None:
        status, body, _ = self.request("fixture/unsafe-display-text")
        envelope = json.loads(body)
        content = json.loads(envelope["choices"][0]["message"]["content"])

        self.assertEqual(status, 200)
        self.assertEqual(content["schemaVersion"], "model-explanation/v1")
        self.assertEqual(content["evidenceIds"], ["ev_0000000000000001"])
        for marker in ("<script>", "{{7*7}}", "IGNORE PREVIOUS INSTRUCTIONS"):
            with self.subTest(marker=marker):
                self.assertIn(marker, content["summary"])

    def test_transport_content_type_and_encoding_failures_are_distinct(self) -> None:
        status, wrong_type, headers = self.request("fixture/wrong-content-type")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"synthetic wrong content type", wrong_type)

        status, invalid_utf8, headers = self.request("fixture/invalid-utf8")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Content-Type"], "application/json")
        with self.assertRaises(UnicodeDecodeError):
            invalid_utf8.decode("utf-8")

    def test_timeout_mode_exceeds_the_client_deadline(self) -> None:
        with self.assertRaises(TimeoutError):
            self.request("fixture/timeout", timeout=0.02)

    def test_capture_redacts_authorization_but_preserves_test_payload(self) -> None:
        self.request("fixture/ok")
        records = [
            json.loads(line)
            for line in self.capture_path.read_text(encoding="utf-8").splitlines()
        ]

        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["authorizationPresent"])
        self.assertNotIn("qa-provider-secret", json.dumps(records[0]))
        self.assertEqual(records[0]["request"]["model"], "fixture/ok")
        self.assertRegex(records[0]["bodySha256"], r"^[a-f0-9]{64}$")

    def test_health_endpoint_does_not_create_a_capture_record(self) -> None:
        host, port = self.server.server_address
        with urllib.request.urlopen(f"http://{host}:{port}/healthz", timeout=1) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(json.loads(response.read()), {"status": "ok"})

        time.sleep(0.01)
        self.assertFalse(self.capture_path.exists())


if __name__ == "__main__":
    unittest.main()
