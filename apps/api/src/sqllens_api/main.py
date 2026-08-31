from __future__ import annotations

import argparse

import uvicorn

from sqllens_api.app import create_app
from sqllens_api.config import Settings
from sqllens_api.setup import SetupStore


def run() -> None:
    settings = Settings()
    uvicorn.run(create_app(settings=settings), host=settings.bind_host, port=settings.port)


def cli() -> None:
    parser = argparse.ArgumentParser(prog="sqllens-runtime")
    parser.add_argument("command", choices=("web-api", "migrate"), nargs="?", default="web-api")
    args = parser.parse_args()
    if args.command == "migrate":
        SetupStore(Settings()).migrate()
        return
    run()


if __name__ == "__main__":
    cli()
