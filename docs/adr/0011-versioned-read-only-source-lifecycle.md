# ADR 0011: Versioned Read-Only Source Lifecycle

Status: Accepted for vNext P0
Date: 2026-09-02

## Context

The product needs database, Prometheus, TEM, and Alertmanager evidence. A single
setup form is insufficient: customers must understand where credentials come
from, what they permit, how they are tested, and how they are revoked. Sources
must also be editable in daily operation without rewriting historical cases.

TiDB v8.5.x and PingKaiDB v7.1.x differ in supported fields and operational
context. Prometheus authentication depends on deployment topology. TEM public
documentation confirms API Key lifecycle but does not guarantee a fine-grained
read-only scope in every version.

## Decision

Source/v1 is a revisioned domain object. Public metadata and encrypted
credentials are stored separately. Every enabled revision records product,
version, endpoint identity, capability matrix, allowed scope, query budgets,
credential owner, expiry, last test, and audit events.

The Web UI supports add, test, edit, enable, disable, rotate, and delete.
Diagnosis admission snapshots the source revision. Later edits affect only new
jobs; historical cases retain immutable source/evidence provenance without a
usable credential.

Every connector supplies an in-product acquisition guide:

1. identify the responsible customer role;
2. obtain or create a dedicated credential;
3. apply the minimum required permission;
4. paste the secret only into the local UI;
5. run a bounded capability test;
6. record owner, expiry, rotation, and revoke instructions.

Database PROCESS is optional and explicitly sensitive. Refusal activates a
visible degraded mode. Prometheus modes are trusted internal access, Basic
Auth, or gateway Token/mTLS. TEM permissions are capability-tested; an
over-broad key requires explicit customer risk acceptance or a safer fallback.

Unknown database versions, missing required capabilities, endpoint redirects,
TLS failures, or source/cluster identity mismatches fail closed. Connector tests
report granular capabilities and do not silently request broader access.

## Consequences

- Initialization can register several sources, while daily operation owns their
  lifecycle.
- Connector and source contracts must precede implementation work.
- Credential changes require optimistic concurrency and active-job protection.
- Documentation and copyable scripts become versioned product assets and test
  fixtures, not prose maintained outside the application.
