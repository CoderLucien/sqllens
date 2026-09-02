from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from sqllens_api.evidence_connector.queries import ServerQuery

type QueryValue = str | int | float | bool | None


@dataclass(frozen=True, slots=True)
class QueryResult:
    columns: tuple[str, ...]
    rows: tuple[Mapping[str, QueryValue], ...]
    truncated: bool
    observed_bytes: int


class ReadOnlyQueryClient(Protocol):
    async def execute(
        self,
        *,
        execution_id: str,
        query: ServerQuery,
        parameters: Mapping[str, QueryValue],
    ) -> QueryResult: ...

    async def cancel(self, execution_id: str) -> None: ...
