# ADR 0007: Parser-Backed SQL Classification

Status: Accepted for P0 Layer 1
Date: 2026-09-01

## Context

Layer 1 accepts pasted TiDB/MySQL SQL but must never treat DML, DDL,
administrative commands, multiple statements, locking reads, or `EXPLAIN
ANALYZE` as a safe diagnostic query. Splitting strings on semicolons or matching
keywords fails for comments, quoted literals, CTEs, nested statements, and
dialect-specific syntax.

## Decision

SQLLens pins `sqlglot==30.17.0` and parses with its MySQL dialect. The service
uses the returned expression tree for statement count, root allowlisting,
nested mutation detection, and structural feature extraction. It accepts only
query expressions plus ordinary `EXPLAIN` over a query. Unknown roots and
SQLGlot `Command` fallbacks fail closed; mutation, output, and locking nodes fail
as not read-only. A small structural validator rejects incomplete trees that a
lenient dialect parser can still represent.

Neither normalized SQL nor AST identifiers and literals are persisted. Cases
store only a one-way input fingerprint, bounded structural counts/flags, and
generic evidence-gap language. Every new SQL case pins
`parser=sqlglot/mysql@30.17.0`, `ruleSet=sql-rules/v1`, and
`redaction=sql-structure/v1`.

SQLGlot documents that callers should specify a known source dialect, and that
unsupported syntax can fall back to a `Command` expression. The implementation
therefore never interprets a successful parse alone as permission.

Sources:

- <https://github.com/tobymao/sqlglot/blob/main/README.md>
- <https://github.com/tobymao/sqlglot/blob/main/sqlglot/__init__.py>
- <https://github.com/tobymao/sqlglot/blob/main/posts/onboarding.md>

## Consequences

- Parser and rule revisions are audit data and change only through an explicit
  tested revision.
- TiDB syntax not represented safely by the pinned MySQL parser is rejected
  rather than guessed.
- Tests cover comments, quoted semicolons, CTEs, set operations, ordinary and
  analyzing EXPLAIN, nested writes, administrative commands, and incomplete
  trees.
