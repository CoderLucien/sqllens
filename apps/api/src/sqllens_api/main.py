from __future__ import annotations

import argparse
import re
import sys
from datetime import UTC, datetime
from typing import BinaryIO

import uvicorn

from sqllens_api.app import create_app
from sqllens_api.config import Settings
from sqllens_api.setup import SetupStore

_MAX_BOOTSTRAP_INPUT_BYTES = 256
_BOOTSTRAP_INPUT_PATTERN = re.compile(r"^[A-Za-z0-9-]{12,80}$")


def run() -> None:
    settings = Settings()
    uvicorn.run(create_app(settings=settings), host=settings.bind_host, port=settings.port)


def ingest_bootstrap_stdin(
    settings: Settings,
    stream: BinaryIO,
    *,
    now: datetime | None = None,
    replace_existing: bool = False,
) -> bool:
    raw = stream.read(_MAX_BOOTSTRAP_INPUT_BYTES + 1)
    if len(raw) > _MAX_BOOTSTRAP_INPUT_BYTES:
        raise ValueError("bootstrap input is too large")
    try:
        code = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise ValueError("bootstrap input must be ASCII") from error
    if not _BOOTSTRAP_INPUT_PATTERN.fullmatch(code):
        raise ValueError("bootstrap input has an invalid format")
    store = SetupStore(settings)
    timestamp = now or datetime.now(UTC)
    if replace_existing:
        return store.reissue_bootstrap_code(code, timestamp)
    return store.ingest_bootstrap_code(code, timestamp)


def cli() -> None:
    parser = argparse.ArgumentParser(prog="sqllens-runtime")
    parser.add_argument(
        "command",
        choices=("web-api", "migrate", "bootstrap-ingest", "bootstrap-reissue"),
        nargs="?",
        default="web-api",
    )
    args = parser.parse_args()
    if args.command in {"bootstrap-ingest", "bootstrap-reissue"}:
        try:
            created = ingest_bootstrap_stdin(
                Settings(),
                sys.stdin.buffer,
                replace_existing=args.command == "bootstrap-reissue",
            )
        except ValueError:
            print("Bootstrap input is invalid.", file=sys.stderr)
            raise SystemExit(64) from None
        if args.command == "bootstrap-reissue" and not created:
            print("Setup is finalized; bootstrap recovery is unavailable.", file=sys.stderr)
            raise SystemExit(73)
        if created:
            action = "reissued" if args.command == "bootstrap-reissue" else "persisted"
            print(f"Bootstrap hash {action}.")
        else:
            print("Bootstrap hash already persisted.")
        return
    if args.command == "migrate":
        SetupStore(Settings()).migrate()
        return
    run()


if __name__ == "__main__":
    cli()
