# SQLLens P0 Design

Status: approved product direction, implementation baseline under review
Working name: `sqllens` (public release name is blocked pending brand review)

## Objective

Build an open-source, evidence-first TiDB SQL diagnosis service that runs outside
the business request path. A user can start with only SQL, add bounded read-only
TiDB and Prometheus evidence, or import an existing Clinic diagnostic package.
Every path produces one auditable `DiagnosisCase` instead of an unconstrained
chat response.

P0 is successful when a new user can start the delivery package, complete the
Web setup wizard, run all three supported paths, inspect evidence and missing
evidence, and receive recommendations with explicit risk, validation, and
rollback guidance. The product must abstain when evidence is insufficient.

## Assumptions And Resolved Decisions

1. `sqllens` is a working code name only. Public GitHub creation waits for a
   naming and trademark decision because several active SQL diagnosis products
   already use SQLLens.
2. One delivery package may contain multiple containers and Compose overrides;
   it does not mean one failure domain or one large image.
3. Model selection happens in the Web setup wizard. Host resource provisioning
   does not: GPU devices must already be exposed when Docker starts. The wizard
   must disable local mode when the runtime cannot see the required device.
4. The low-resource P0 target is the complete external-model path under a total
   `2 CPU / 4 GiB RAM` container budget. No local weights are downloaded there.
5. Local inference is a high-resource capability with a pinned model artifact,
   controller, and separate resource limits. It is not declared validated until
   it passes on real target GPU hardware.
6. Clinic P0 accepts an existing package or exported report. Clinic URL reading
   remains disabled unless an official, testable read API and supported auth
   contract are available. Browser scraping and stored plaintext passwords are
   prohibited.
7. P0 may import an existing Plan Replayer archive or generate one through a
   separate, explicitly authorized privileged workflow. Capture is outside the
   default read-only path and must preview its actions, fields, privileges, and
   resource budget before a DBA/Admin confirms it. Replaying a plan requires a
   version-matched external sandbox and does not prove runtime performance.

## Product Paths

### Layer 1: SQL-Only Triage

Input is SQL plus optional TiDB version and schema metadata. Local parsing and
rules can identify structural observations, risky patterns, and evidence gaps.
Without schema, statistics, or runtime evidence, output is labelled as an
optimization hypothesis. It must not promise a new index, executable DDL, or a
performance gain.

### Layer 2: Controlled Workload Diagnosis

Input is a Prometheus endpoint and a least-privilege TiDB account. The collector
uses a versioned query-to-privilege allowlist and hard budgets for time window,
rows, points, concurrency, server execution time, cancellation, and total job
duration. It can correlate Statement Summary, slow-query metadata, schema,
statistics health, ordinary plans, configuration, and metrics.

P0 never runs DML or `EXPLAIN ANALYZE`. Ordinary `EXPLAIN` is version-gated and
rejected for constructs that TiDB may execute while optimizing, including
unsafe scalar-subquery cases.

An optional Plan Replayer capture is an active P0 workflow, never an automatic
side effect of diagnosis. It requires an Admin/DBA permission, preflight preview,
explicit confirmation, bounded execution, audit events, cancellation, and a
kill switch. The resulting archive enters the same imported-evidence boundary.

### Layer 3: Historical Clinic Evidence

P0 streams an uploaded diagnostic archive or report into a bounded temporary
workspace and normalizes supported metrics, logs, configuration, topology, and
plan artifacts. The importer rejects traversal, links, special files, excessive
entry counts, compression ratios, uncompressed size, and time/disk budgets.

No P0 endpoint accepts an arbitrary Clinic URL. A future URL connector requires
an official read API, supported token scope, redirect policy, pinned DNS/IP
handling, and a separate threat-model review.

## Architecture

### Services

- `web-api`: FastAPI application, setup state machine, session/RBAC, job API,
  evidence engine, provider gateway, audit events, and static Web assets.
- `worker`: bounded asynchronous jobs. It can be a separate process using the
  same image, with concurrency `1` by default under 2C4G.
- `model-controller`: an authenticated internal-only control service included
  in the same delivery package. It starts idle and owns the local inference
  subprocess; it never receives the Docker Socket or host filesystem.
- `sqlite`: P0 metadata and audit store on a mounted volume. Large source
  packages and temporary extraction never enter SQLite.

The base Compose file starts application services. A GPU override from the same
package exposes the accelerator to `model-controller`; an installer or explicit
startup command selects that override before Docker starts. Web setup then
selects external or local inference. Switching to local mode without an exposed
GPU returns a precise restart prerequisite instead of attempting host control.

P0 publishes `linux/amd64` and `linux/arm64` images and exposes the same browser
Web App on Mac, Linux, and Windows. External-model mode is the cross-platform
baseline. Local GPU support is gated by exact host/runtime qualification; Linux
NVIDIA is the first target, while macOS Apple GPU and Windows WSL2 GPU remain
unverified until separately tested.

### Technology Baseline

- Python `3.12`, FastAPI, Pydantic v2, SQLAlchemy 2, SQLite.
- React `19`, TypeScript, Vite, served as immutable static assets by `web-api`.
- SQLGlot in MySQL mode plus explicit TiDB compatibility fixtures; unsupported
  TiDB syntax is preserved as an evidence gap rather than silently rewritten.
- `httpx` for outbound HTTP, a MySQL protocol driver for TiDB, and explicit
  Prometheus HTTP API requests.
- Pytest, Vitest, Playwright, Ruff, mypy, and container-level smoke tests.
- Docker Compose for P0; dependency versions and image digests are locked by
  committed lockfiles during scaffold implementation.

### Core Contracts

`DiagnosisCase` is immutable by revision and contains:

- case ID, source layer, status, input fingerprint, and timestamps;
- evidence items with stable IDs, source, collection time, coverage/freshness,
  sensitivity, and integrity metadata;
- competing hypotheses with supporting and contradicting evidence IDs; favored
  conclusions require supporting evidence and rejected alternatives require
  contradicting evidence, while candidate/unresolved states preserve abstention;
- evidence completeness and calibrated confidence as separate fields;
- recommendations with risk, prerequisites, validation, rollback, and owner;
- append-only review and user-feedback records with independent decisions;
- processing workflow independent from a business outcome that is either
  pending or one of: validated effective, rolled back, evidence insufficient,
  or risk accepted;
- validated-effective and rolled-back results bound to immutable effect
  evidence IDs, not only user comments or process milestones; approval,
  implementation, effect evidence, and terminal feedback must reference the
  same recommendation and preserve causal time order;
- pre-freeze imports identify their contract revision through trusted bundle
  metadata; ambiguous legacy rollback records are normalized without
  downgrading a current evidence-backed rollback.

The two state fields are independently stored but not freely mutable. The legal
workflow/outcome transitions, cross-field prerequisites, and atomic review or
feedback triggers are the executable contract documented in
`docs/contracts/README.md`.

Jobs pin provider, model artifact/revision, prompt version, policy version, and
redaction version at creation. Model switching drains or cancels old jobs before
an atomic configuration revision becomes active.

### API Baseline

- `GET /api/v1/setup/status`
- `POST /api/v1/setup/bootstrap`
- `PUT /api/v1/setup/security-policy`
- `POST /api/v1/setup/model-probes`
- `POST /api/v1/setup/finalize`
- `POST /api/v1/cases/sql`
- `POST /api/v1/cases/workload`
- `POST /api/v1/plan-replayer/captures`
- `POST /api/v1/imports/clinic`
- `GET /api/v1/jobs/{job_id}`
- `GET /api/v1/cases/{case_id}`
- `POST /api/v1/cases/{case_id}/reviews`
- `POST /api/v1/cases/{case_id}/feedback`

All errors use one versioned envelope with stable codes. Async creation returns
`202` plus a job resource. Idempotency keys are required for job-producing
POSTs. The application exposes no API to execute recommendations.

## Security And Data Boundaries

### Trust Boundaries

- Browser to setup/session API.
- SQL and connection settings to the application.
- Application to TiDB, Prometheus, Clinic files, and model providers.
- Untrusted archive contents to the streaming importer.
- Untrusted LLM output back to the evidence engine and UI.

### Required Controls

- Setup binds to loopback by default. Bootstrap uses a single-use, short-TTL
  secret file or explicit CLI read; the token is never retained in normal logs.
- Security and egress policy is committed before the first external model probe.
- Credentials are encrypted at rest, redacted from errors and logs, rotatable,
  and deleted through a verifiable cascade.
- Outbound model payloads are constructed from a typed sensitivity allowlist.
  SQL literals, row data, credentials, tokens, and raw confidential evidence
  cannot reach the model gateway. Payload fingerprints and policy decisions are
  audited without logging the sensitive payload.
- LLM output is schema-validated, treated as untrusted text, and cannot invoke
  tools, collectors, SQL, or operating-system commands.
- Uploads are streamed with hard compressed/uncompressed/entry/time/disk limits.
- Connector traffic uses TLS verification, bounded timeouts, explicit proxy
  policy, and cancellation. Future server-side URL retrieval must pin resolved
  addresses and reject all private/reserved destinations and redirects.
- Sessions use secure HttpOnly SameSite cookies, CSRF protection, idle/absolute
  expiry, RBAC, login throttling, and security headers.

## Setup Journey

The visible deployment journey has three steps:

1. Install Docker Desktop on Mac/Windows, or Docker Engine plus Compose on Linux.
2. Download one release archive and double-click its launcher or run one command.
   The launcher performs platform/artifact/port/disk/migration preflight, starts
   services, and prints the local URL plus a one-time initialization code.
3. Open the Web URL, enter the code, select a model mode, commit security/data
   policy and optional connectors, run the self-test, and enter the home page.

There are no hidden `.env`/Compose edits, migration commands, token-file lookups,
or extra product commands on the supported happy path. Inside step 3, Web setup
is resumable and reports each subsystem as `verified`, `declared`, or
`unverified`. Diagnosis APIs stay disabled until setup finalization.

## Commands

The scaffold must make these commands authoritative:

```bash
make bootstrap
make dev
make lint
make typecheck
make test
make test-integration
make test-e2e
make build
make smoke
make benchmark-2c4g
```

## Project Structure

```text
apps/api/                 FastAPI routes and setup/session boundaries
apps/web/                 React application
packages/domain/          Diagnosis/evidence contracts and policies
packages/connectors/      TiDB, Prometheus, model, and Clinic adapters
packages/worker/          Bounded jobs and importer
deploy/                   Base and GPU Compose definitions
tests/                    Contract, integration, security, and load fixtures
docs/                     ADRs, threat model, operations, and validation reports
tasks/                    Implementation plan and live checklist
```

## Code Style

Boundary functions accept validated types and return typed results; domain code
does not depend on FastAPI, SQL drivers, or model SDKs. Example:

```python
def build_case(request: SqlDiagnosisRequest, evidence: list[Evidence]) -> DiagnosisCase:
    completeness = assess_completeness(request, evidence)
    return DiagnosisCase.from_evidence(
        source_layer=SourceLayer.SQL,
        evidence=evidence,
        completeness=completeness,
    )
```

Python is formatted/linted with Ruff and typed with mypy. TypeScript is strict,
uses discriminated unions for setup/job/case states, and never uses `any` at an
API boundary.

## Testing Strategy

- Unit tests: parsing, policy, taint/egress filtering, evidence completeness,
  confidence boundaries, archive budgets, and state machines.
- Contract tests: every API error/success envelope, model provider adapter, and
  versioned TiDB/Prometheus query fixture.
- Integration tests: disposable TiDB/Prometheus or recorded fixtures, SQLite
  migrations, job cancellation, and encrypted secret lifecycle.
- Security tests: auth/bootstrap abuse, CSRF, SSRF primitives, archive attacks,
  prompt injection, data-egress canaries, and dependency/container scanning.
- E2E tests: first setup plus all three paths, abstention, failures, and review.
- Performance tests: container-limited 2C4G runs recording peak RSS/CPU/temp
  disk/P95, queue behavior, degradation, cancellation, and OOM/fuse outcome.
- Local-model qualification: exact model repository/revision, tokenizer,
  quantization method, runtime build, checksums, SBOM, context, concurrency,
  quality corpus, latency, GPU/CPU/RAM, and failure behavior on target hardware.

## Boundaries

Always:

- validate inputs and outputs at every trust boundary;
- bind every conclusion to evidence or an explicit missing-evidence marker;
- use least privilege, budgets, audit events, and cancellable jobs;
- run focused tests before each atomic commit.

Ask first:

- enable a new outbound host or data field;
- add an active production collector beyond the approved, privileged Plan
  Replayer capture workflow;
- change stored sensitive-data categories, auth, or retention;
- change the public API or DiagnosisCase schema.

Never:

- execute DML, `EXPLAIN ANALYZE`, recommendations, or OS commands from LLM text;
- mount Docker Socket, scrape Clinic login pages, or store plaintext secrets;
- claim runtime benefit from Plan Replayer alone;
- mark simulated or unavailable infrastructure as verified.

## P0 Success Criteria

1. External-model mode completes setup and Layer 1 under a 2C4G limit and still
   produces rule evidence when the model is unavailable.
2. Layer 2 passes its version/privilege matrix and bounded-impact A/B tests on a
   disposable TiDB environment.
3. Layer 3 safely imports approved Clinic fixtures without exceeding configured
   memory/disk/time budgets.
4. Every conclusion has provenance; insufficient evidence produces abstention.
5. Setup, all three paths, fault cases, and review are covered by reproducible
   automated tests and an independent QA/Reviewer report.
6. Local-model mode is either qualified on real target hardware or visibly
   marked `unverified` and excluded from release claims.
7. Mac, Linux, and Windows each pass a real three-step clean install in external
   mode, including restart, upgrade, uninstall, data retention, and failure
   remediation; published images cover `linux/amd64` and `linux/arm64`.

## Known Blockers

- Public product/repository name conflicts with existing SQLLens products.
- Clinic URL direct read has no verified official API contract.
- Target GPU hardware is required to validate the proposed local model sizing.
- A real TiDB/Prometheus validation environment is required for compatibility
  and incremental-impact claims.
