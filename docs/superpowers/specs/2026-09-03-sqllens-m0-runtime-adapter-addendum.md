# SQLLens M0 Runtime Adapter Addendum

Status: Approved for the localhost private preview on 2026-09-03
Core contract: `a39ba55`
Applies to: `#t18`, specification sections 4/5.3/9, and implementation-plan Tasks 5–9

## 1. Decision And Non-Goal

M0 keeps the exact dependency `asyncmy==0.2.14` and uses a narrow compatibility
adapter. This is the fastest bounded choice; changing drivers is deferred. The
adapter is not a reusable database abstraction and is not approved for a
production or unattended release.

This addendum may not change the report/evidence interfaces, rules, thresholds,
or `M0ReportInput -> bytes` boundary frozen at `a39ba55`.

## 2. Verified Driver Facts

The official CPython 3.12 x86_64 wheel inspected during design was:

~~~text
asyncmy-0.2.14-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl
sha256:fd8e23d2eab3d9249a206f2446e2896ef99893d03ccda900ba5e17018fd44136
~~~

Its shipped `asyncmy/connection.pyx` shows:

- constructor lines 456–459 retain `_password` and `_password_creator`;
- constructor line 477 unconditionally adds `MULTI_STATEMENTS`;
- TLS mapping lines 545–564 select `CERT_NONE` when no CA/capath is supplied;
- `ensure_closed()` lines 606–615 drains and waits for transport closure;
- the public arguments include `connect_timeout` and `read_timeout`, not
  `write_timeout`.

The wheel hash above is inspection evidence, not a cross-platform artifact
claim. The final candidate records its own installed distribution filename and
SHA256 and reruns the behavioral invariants below inside that image. Official
references are the [PyPI 0.2.14 release](https://pypi.org/project/asyncmy/0.2.14/)
and the [upstream changelog](https://github.com/long2ice/asyncmy/blob/dev/CHANGELOG.md).

## 3. Exact Connection Sequence

The sole adapter performs these steps in order:

1. Validate the closed request DTO. `password` must encode to 1–512 UTF-8 bytes;
   the adapter passes those bytes, not a Python string, to avoid the driver's
   implicit Latin-1 conversion. The byte buffer and DTO remain local only.
2. Require `importlib.metadata.version("asyncmy") == "0.2.14"`.
3. For `verify_ca`, create an `ssl.create_default_context()` with
   `verify_mode=ssl.CERT_REQUIRED` and `check_hostname=True`; pass that context.
   Never pass `ssl=True`. For `disabled`, pass `ssl=None`.
4. Directly construct `asyncmy.connection.Connection` with the validated
   host/port/database/user, password bytes, `client_flag=0`, `charset="utf8mb4"`,
   `autocommit=None`, `local_infile=False`, `init_command=None`,
   `read_default_file=None`, `unix_socket=None`, `sock=None`, `echo=False`,
   `query_callback=None`, `connect_timeout=5`, and `read_timeout=5`.
5. Before network I/O, require writable `_client_flag`, `_password`, and
   `_password_creator` fields by round-tripping the two current password-field
   values without clearing them. Clear only the `MULTI_STATEMENTS` bit in
   `_client_flag` using
   `asyncmy.constants.CLIENT.MULTI_STATEMENTS`, and read the expression back as
   zero. Any mismatch fails without calling `Connection.connect()`.
6. Register the not-yet-connected object as the pending socket, then call
   `Connection.connect()` within `asyncio.timeout(5)`.
7. In the immediate `finally` path after `Connection.connect()` returns or
   raises, set
   `_password=b""` and `_password_creator=None`, then read both values back.
   A failed scrub closes/aborts the socket and returns only a closed error code.
8. Only after a successful scrub, execute the registered `server.identity`
   query under the same single-statement executor. Accept only TiDB
   `>=8.5.0,<8.6.0` with `@@autocommit = 1`; otherwise close the candidate.
   Never issue `SET autocommit` or another session initialization statement.
9. Atomically install the candidate and safe eight-field projection, close the
   replaced socket, and discard all request/password references. Never call
   `ping(reconnect=True)`, use a pool, or expose reconnect.

The adapter does not replace driver methods and must not support another
version or private-field layout. An upgrade requires a new decision and tests.

## 4. Execution And TLS Boundary

Clearing the capability bit is mandatory but not sufficient authorization.
Immediately before every driver call, the executor must independently prove
that the query:

- equals one immutable registry entry plus its bound parameters, or equals a
  fresh reconstruction from `bind_m0_ordinary_explain()`;
- parses as exactly one statement after final construction;
- contains no mutation, control, locking read, outfile, user-supplied EXPLAIN,
  `EXPLAIN ANALYZE`, wildcard projection, or undeclared output;
- uses bound values and a declared timeout/row/byte budget; and
- is reachable only through the M0 candidate/diagnosis services, never through
  a route-facing generic cursor or execute method.

A test-injected second statement must be rejected before the driver spy records
I/O. The executor also asserts the live connection's multi-statement bit is
still zero before each call; drift invalidates and closes the slot.

`verify_ca` means both chain and hostname verification using the host trust
store. M0 has no custom-CA upload or skip-verification mode. TLS failure is a
sanitized connection failure and never falls back to plaintext.

## 5. Lease And Lifecycle Cleanup

Normal `PUT /connection`, `DELETE /connection`, candidate collection, and
Diagnosis share one non-queuing operation lease. Acquisition is one immediate
attempt; contention returns `409 M0_BUSY` and never queues. Replacement holds
that lease through construction, handshake, password scrub, identity probe,
and atomic swap. Probe failure preserves the prior ready connection.

The store tracks the active task, lifecycle generation, pending candidate, and
installed connection. Logout and shutdown call idempotent `force_close`, not the
ordinary DELETE operation:

1. logout commits session revocation first;
2. increment the lifecycle generation so an old operation cannot install a
   connection after cleanup;
3. cancel an active probe/query unless it is the cleanup caller itself;
4. close and await every pending and installed socket;
5. if graceful close reaches the 5-second deadline, abort the transport;
6. clear all references before returning.

`force_close` never returns `M0_BUSY`. Shutdown has no HTTP error path and must
perform the same cleanup. Ordinary DELETE remains idempotent when idle and may
return `409 M0_BUSY` during another normal operation.

Driver `connect_timeout=5` and `read_timeout=5` are combined with a 5-second
outer `asyncio.timeout()` around each connect, execute/read, and asynchronous
close. A query timeout/cancellation enters `force_close`; the slot is not
reusable and no background query may survive.

## 6. Required RED/GREEN Evidence

`#t18` must add focused tests proving:

- exact version and three-field layout; wrong version/layout fails before I/O;
- capability bit is zero before connect and before every query;
- password fields are empty after connect success and failure, before identity;
- password is absent from repr/log/HTTP/SQLite/`/data`/environment/subsequent GET;
- real SSLContext has `CERT_REQUIRED` and hostname checking; `ssl=True` and TLS
  downgrade are absent;
- normal contention returns `M0_BUSY` without waiting;
- failed replacement preserves the old connection;
- logout revokes then cancels/closes; shutdown and repeated cleanup close; a
  prior generation cannot install after cleanup;
- timeout/cancellation leaves no socket, task, or reusable slot;
- a second parsed statement and every unsafe SQL class fail before driver I/O;
- final candidate records the installed distribution filename/SHA256 and these
  behavior tests pass inside the built image.

Reviewer scope is exactly this adapter/lifecycle/TLS boundary plus the existing
read-only, secret, localhost, and deferred-route checks. Any failed invariant is
BLOCKED; it is not waived as a private-preview limitation.
