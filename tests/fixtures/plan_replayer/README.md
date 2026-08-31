# Plan Replayer Status-Port Fixture

This deterministic HTTP server models only the package-download boundary used
by the privileged P0 Plan Replayer workflow. It follows the documented TiDB
download path:

```text
GET /plan_replayer/dump/{file_token}
```

Reference: <https://docs.pingcap.com/tidb/stable/sql-plan-replayer/>

The `expired` mode represents a token whose server-side ZIP has expired or was
removed. Other modes exercise redirect, content-type, corrupt ZIP, response
size, partial transfer and timeout handling. Captures contain only a SHA-256 of
the synthetic token and whether an Authorization header was present.

The successful ZIP contains synthetic schema, statistics and plan text. It has
no table rows or customer data. Passing these fixture tests does **not** verify
the MySQL command that generates a token, TiDB version compatibility, status
port TLS/authentication behavior or a real TiDB package. Those remain E2 tests
against an approved TiDB environment.
