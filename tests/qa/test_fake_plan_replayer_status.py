from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = (
    ROOT / "tests" / "fixtures" / "plan_replayer" / "fake_status_port.py"
)
TOKEN = "qa-plan-replayer-token-secret"


def load_server_module():
    spec = importlib.util.spec_from_file_location(
        "fake_plan_replayer_status", SERVER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load fake Plan Replayer status port: {SERVER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class FakePlanReplayerStatusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module = load_server_module()

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.servers = []

    def start_server(
        self,
        mode: str,
        *,
        timeout_seconds: float = 0.2,
        response_bytes: int = 64 * 1024,
    ):
        capture_path = Path(self.temp_dir.name) / f"{mode}.ndjson"
        server = self.module.create_server(
            host="127.0.0.1",
            port=0,
            mode=mode,
            capture_path=capture_path,
            expected_token=TOKEN,
            timeout_seconds=timeout_seconds,
            response_bytes=response_bytes,
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

    @staticmethod
    def path(token: str = TOKEN) -> str:
        return f"/plan_replayer/dump/{token}"

    @staticmethod
    def request(
        base_url: str,
        path: str,
        *,
        timeout: float = 1,
        follow_redirects: bool = True,
    ):
        request = urllib.request.Request(
            f"{base_url}{path}",
            headers={"Authorization": "Bearer qa-status-port-secret"},
        )
        opener = urllib.request.build_opener()
        if not follow_redirects:
            opener = urllib.request.build_opener(NoRedirect())
        try:
            with opener.open(request, timeout=timeout) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.headers, error.read()

    def test_valid_mode_returns_a_deterministic_synthetic_zip(self) -> None:
        base_url, _ = self.start_server("ok")

        status, headers, body = self.request(base_url, self.path())

        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "application/zip")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(hashlib.sha256(body).hexdigest(), self.module.VALID_ZIP_SHA256)
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            self.assertEqual(
                archive.namelist(),
                [
                    "meta/version.txt",
                    "schema/test.orders.sql",
                    "stats/test.orders.json",
                    "explain.txt",
                ],
            )
            combined = b"".join(archive.read(name) for name in archive.namelist())
            self.assertNotIn(b"customer@example.com", combined)
            self.assertNotIn(b"qa-plan-replayer-token", combined)

    def test_unknown_and_expired_tokens_return_non_sensitive_not_found(self) -> None:
        for mode, token in (("ok", "unknown-secret-token"), ("expired", TOKEN)):
            with self.subTest(mode=mode):
                base_url, _ = self.start_server(mode)
                status, _, body = self.request(base_url, self.path(token))

                self.assertEqual(status, 404)
                response = json.loads(body)
                self.assertEqual(response["error"], "plan_replayer_dump_not_found")
                self.assertNotIn(token, body.decode("utf-8"))

    def test_redirect_does_not_embed_the_capability_token(self) -> None:
        base_url, _ = self.start_server("redirect")

        status, headers, body = self.request(
            base_url, self.path(), follow_redirects=False
        )

        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "https://redirect.example.invalid/dump")
        self.assertNotIn(TOKEN, headers["Location"])
        self.assertNotIn(TOKEN, body.decode("utf-8"))

    def test_corrupt_and_wrong_content_type_modes_are_observably_distinct(self) -> None:
        corrupt_url, _ = self.start_server("corrupt")
        status, headers, body = self.request(corrupt_url, self.path())
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "application/zip")
        with self.assertRaises(zipfile.BadZipFile):
            zipfile.ZipFile(io.BytesIO(body))

        wrong_type_url, _ = self.start_server("wrong-content-type")
        status, headers, body = self.request(wrong_type_url, self.path())
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_content_type(), "text/html")
        self.assertIn(b"synthetic wrong content type", body)

    def test_oversized_disconnect_and_timeout_modes_exercise_stream_limits(self) -> None:
        oversized_url, _ = self.start_server("oversized", response_bytes=8193)
        status, headers, body = self.request(oversized_url, self.path())
        self.assertEqual(status, 200)
        self.assertEqual(int(headers["Content-Length"]), 8193)
        self.assertEqual(len(body), 8193)

        disconnect_url, _ = self.start_server("disconnect", response_bytes=8192)
        with self.assertRaises(http.client.IncompleteRead):
            self.request(disconnect_url, self.path())

        timeout_url, _ = self.start_server("timeout")
        with self.assertRaises(TimeoutError):
            self.request(timeout_url, self.path(), timeout=0.02)

    def test_capture_hashes_tokens_and_never_records_authorization(self) -> None:
        base_url, capture_path = self.start_server("ok")
        self.request(base_url, self.path())
        record = json.loads(capture_path.read_text(encoding="utf-8"))

        self.assertEqual(record["method"], "GET")
        self.assertEqual(record["pathTemplate"], "/plan_replayer/dump/{token}")
        self.assertEqual(record["tokenSha256"], hashlib.sha256(TOKEN.encode()).hexdigest())
        self.assertTrue(record["authorizationPresent"])
        serialized = json.dumps(record)
        self.assertNotIn(TOKEN, serialized)
        self.assertNotIn("qa-status-port-secret", serialized)

    def test_only_the_exact_get_path_without_query_is_supported(self) -> None:
        base_url, _ = self.start_server("ok")

        status, _, body = self.request(base_url, f"{self.path()}?download=1")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["error"], "unexpected_query")

        status, _, _ = self.request(base_url, "/plan_replayer/dump")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
