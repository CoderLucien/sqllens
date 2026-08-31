from __future__ import annotations

import argparse
import json
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


START = 1_577_836_800
END = 1_577_836_860
STEP = 30


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        handler_class: type[BaseHTTPRequestHandler],
        *,
        mode: str,
        capture_path: Path,
        timeout_seconds: float,
        high_cardinality_series: int,
    ) -> None:
        super().__init__(server_address, handler_class)
        self.mode = mode
        self.capture_path = capture_path
        self.timeout_seconds = timeout_seconds
        self.high_cardinality_series = high_cardinality_series
        self.capture_lock = threading.Lock()


def _values(*, stale: bool = False) -> list[list[object]]:
    offset = -3600 if stale else 0
    return [
        [START + offset, "10"],
        [START + STEP + offset, "11"],
        [END + offset, "12"],
    ]


def _series(index: int, *, stale: bool = False, single_value: bool = False):
    values = _values(stale=stale)
    if single_value:
        values = values[:1]
    return {
        "metric": {
            "__name__": "tidb_server_query_total",
            "instance": f"tidb-{index}.example.invalid:4000",
            "job": "tidb",
        },
        "values": values,
    }


def _success(result: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "status": "success",
        "data": {"resultType": "matrix", "result": result},
    }


def _error(error_type: str, message: str) -> dict[str, str]:
    return {"status": "error", "errorType": error_type, "error": message}


class Handler(BaseHTTPRequestHandler):
    server: FixtureServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_bytes(self, status: int, body: bytes) -> None:
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        self._send_bytes(
            status, json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/v1/status/buildinfo":
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "success",
                    "data": {
                        "version": "3.0.0-fixture",
                        "revision": "synthetic0001",
                    },
                },
            )
            return
        if parsed.path != "/api/v1/query_range":
            self._send_json(
                HTTPStatus.NOT_FOUND, _error("not_found", "fixture route not found")
            )
            return

        params = parse_qs(parsed.query, keep_blank_values=True)
        self._capture(parsed.path, params)

        if self.server.mode == "unauthorized":
            self._send_json(
                HTTPStatus.UNAUTHORIZED,
                _error("unauthorized", "synthetic authentication failure"),
            )
            return
        if self.server.mode == "forbidden":
            self._send_json(
                HTTPStatus.FORBIDDEN,
                _error("forbidden", "synthetic authorization failure"),
            )
            return
        if self.server.mode == "api-error":
            self._send_json(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                _error("bad_data", "synthetic query failure"),
            )
            return
        if self.server.mode == "invalid-json":
            self._send_bytes(HTTPStatus.OK, b'{"status":"success","data":')
            return
        if self.server.mode == "timeout":
            time.sleep(self.server.timeout_seconds)

        if self.server.mode == "partial":
            result = [_series(0)]
        elif self.server.mode == "stale":
            result = [_series(0, stale=True), _series(1, stale=True)]
        elif self.server.mode == "high-cardinality":
            result = [
                _series(index, single_value=True)
                for index in range(self.server.high_cardinality_series)
            ]
        else:
            result = [_series(0), _series(1)]
        self._send_json(HTTPStatus.OK, _success(result))

    def _capture(self, path: str, params: dict[str, list[str]]) -> None:
        record = {
            "authorizationPresent": bool(self.headers.get("Authorization")),
            "path": path,
            "params": params,
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
    timeout_seconds: float,
    high_cardinality_series: int,
) -> FixtureServer:
    return FixtureServer(
        (host, port),
        Handler,
        mode=mode,
        capture_path=capture_path,
        timeout_seconds=timeout_seconds,
        high_cardinality_series=high_cardinality_series,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run deterministic Prometheus HTTP API fixtures."
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=19090)
    parser.add_argument(
        "--mode",
        choices=(
            "ok",
            "partial",
            "stale",
            "high-cardinality",
            "unauthorized",
            "forbidden",
            "api-error",
            "invalid-json",
            "timeout",
        ),
        default="ok",
    )
    parser.add_argument("--capture", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=5)
    parser.add_argument("--high-cardinality-series", type=int, default=257)
    args = parser.parse_args()

    server = create_server(
        host=args.host,
        port=args.port,
        mode=args.mode,
        capture_path=args.capture,
        timeout_seconds=args.timeout_seconds,
        high_cardinality_series=args.high_cardinality_series,
    )
    host, port = server.server_address
    print(f"fake Prometheus listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
