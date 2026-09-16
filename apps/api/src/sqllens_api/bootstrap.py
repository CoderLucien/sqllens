from __future__ import annotations

from datetime import UTC, datetime

from sqllens_api.config import Settings
from sqllens_api.setup import SetupStore


def issue_bootstrap_code(settings: Settings, *, now: datetime | None = None) -> str:
    return SetupStore(settings).issue_bootstrap_code(now or datetime.now(UTC))


def main() -> None:
    code = issue_bootstrap_code(Settings())
    print(f"Initialization code: {code}")


if __name__ == "__main__":
    main()
