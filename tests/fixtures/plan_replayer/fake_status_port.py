from __future__ import annotations

import argparse
import hashlib
import io
import json
import socket
import threading
import time
import zipfile
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


DUMP_PREFIX = "/plan_replayer/dump/"
FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
TOKEN_FOR_MANUAL_FIXTURE = "qa-plan-replayer-token-secret"


def _zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def _valid_zip() -> bytes:
    files = (
        ("meta/version.txt", b"TiDB-v8.5.0-synthetic-fixture\n"),
        (
            "schema/test.orders.sql",
            b"CREATE TABLE `orders` (`id` BIGINT PRIMARY KEY);\n",
        ),
        (
            "stats/test.orders.json",
            b'{"count":1000,"modify_count":0,"source":"synthetic"}\n',
        ),
        (
            "explain.txt",
            b"TableReader_5 root 1000.00 data:TableFullScan_4\n",
        ),
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in files:
            archive.writestr(_zip_info(name), content)
    return output.getvalue()


VALID_ZIP_BYTES = _valid_zip()
VALID_ZIP_SHA256 = hashlib.sha256(VALID_ZIP_BYTES).hexdigest()


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        mode: str,
        capture_path: Path,
        expected_token: str,
        timeout_seconds: float,
        response_bytes: int,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.mode = mode
        self.capture_path = capture_path
        self.expected_token = expected_token
        self.timeout_seconds = timeout_seconds
        self.response_bytes = response_bytes
        self.capture_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_bytes(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
        headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def _send_json(self, status: int, error: str) -> None:
        body = json.dumps({"error": error}, separators=(",", ":")).encode("utf-8")
        self._send_bytes(status, body, content_type="application/json")

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if not parsed.path.startswith(DUMP_PREFIX):
            self._send_json(HTTPStatus.NOT_FOUND, "fixture_route_not_found")
            return

        token = parsed.path.removeprefix(DUMP_PREFIX)
        if not token or "/" in token:
            self._send_json(HTTPStatus.NOT_FOUND, "fixture_route_not_found")
            return

        self._capture(token)
        if parsed.query:
            self._send_json(HTTPStatus.BAD_REQUEST, "unexpected_query")
            return
        if token != self.server.expected_token or self.server.mode == "expired":
            self._send_json(
                HTTPStatus.NOT_FOUND, "plan_replayer_dump_not_found"
            )
            return

        if self.server.mode == "redirect":
            self._send_bytes(
                HTTPStatus.FOUND,
                b'{"error":"synthetic_redirect"}',
                content_type="application/json",
                headers={"Location": "https://redirect.example.invalid/dump"},
            )
            return
        if self.server.mode == "timeout":
            time.sleep(self.server.timeout_seconds)
        if self.server.mode == "corrupt":
            self._send_bytes(
                HTTPStatus.OK,
                b"synthetic corrupt zip",
                content_type="application/zip",
            )
            return
        if self.server.mode == "wrong-content-type":
            self._send_bytes(
                HTTPStatus.OK,
                b"<p>synthetic wrong content type</p>",
                content_type="text/html; charset=utf-8",
            )
            return
        if self.server.mode == "oversized":
            self._send_bytes(
                HTTPStatus.OK,
                b"Z" * self.server.response_bytes,
                content_type="application/zip",
            )
            return
        if self.server.mode == "disconnect":
            self._send_partial_response()
            return

        self._send_bytes(
            HTTPStatus.OK,
            VALID_ZIP_BYTES,
            content_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="synthetic-plan.zip"'
            },
        )

    def _send_partial_response(self) -> None:
        partial = b"synthetic-partial"
        try:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Length", str(self.server.response_bytes))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(partial)
            self.wfile.flush()
            self.connection.shutdown(socket.SHUT_WR)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def _capture(self, token: str) -> None:
        record = {
            "authorizationPresent": bool(self.headers.get("Authorization")),
            "method": self.command,
            "pathTemplate": f"{DUMP_PREFIX}{{token}}",
            "tokenSha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        }
        encoded = json.dumps(record, separators=(",", ":"), sort_keys=True) + "\n"
        self.server.capture_path.parent.mkdir(parents=True, exist_ok=True)
        with self.server.capture_lock:
            with self.server.capture_path.open("a", encoding="utf-8") as stream:
                stream.write(encoded)


def create_server(
    *,
    host: str,
    port: int,
    mode: str,
    capture_path: Path,
    expected_token: str,
    timeout_seconds: float,
    response_bytes: int,
) -> FixtureServer:
    return FixtureServer(
        (host, port),
        Handler,
        mode=mode,
        capture_path=capture_path,
        expected_token=expected_token,
        timeout_seconds=timeout_seconds,
        response_bytes=response_bytes,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run deterministic TiDB Plan Replayer status-port fixtures."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19091)
    parser.add_argument(
        "--mode",
        choices=(
            "ok",
            "expired",
            "redirect",
            "corrupt",
            "wrong-content-type",
            "oversized",
            "disconnect",
            "timeout",
        ),
        default="ok",
    )
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--expected-token", default=TOKEN_FOR_MANUAL_FIXTURE)
    parser.add_argument("--timeout-seconds", type=float, default=5)
    parser.add_argument("--response-bytes", type=int, default=64 * 1024)
    args = parser.parse_args()

    server = create_server(
        host=args.host,
        port=args.port,
        mode=args.mode,
        capture_path=args.capture,
        expected_token=args.expected_token,
        timeout_seconds=args.timeout_seconds,
        response_bytes=args.response_bytes,
    )
    host, port = server.server_address
    print(f"fake TiDB status port listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
