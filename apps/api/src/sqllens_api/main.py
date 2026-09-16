from __future__ import annotations

import argparse

import uvicorn

from sqllens_api.app import create_app
from sqllens_api.config import Settings


def run() -> None:
    settings = Settings()
    uvicorn.run(
        create_app(settings=settings),
        host=settings.bind_host,
        port=settings.port,
        proxy_headers=False,
        forwarded_allow_ips="",
    )


def cli() -> None:
    parser = argparse.ArgumentParser(prog="sqllens-runtime")
    parser.add_argument(
        "command",
        choices=("web-api",),
        nargs="?",
        default="web-api",
    )
    parser.parse_args()
    run()


if __name__ == "__main__":
    cli()
