# Implementation Plan: SQLLens P0

## Overview

Deliver a runnable, evidence-first TiDB diagnosis P0 as vertical slices. The
external-model 2C4G path is the release baseline. Clinic URL access and local
30B inference are qualification-gated capabilities, not assumptions.

## Dependency Graph

```text
Specification and contracts
  -> repository/tooling baseline
     -> secure setup + provider gateway
        -> Layer 1 + DiagnosisCase
           -> shared jobs/evidence UI
              -> Layer 2 connectors
              -> Layer 3 importer
                 -> Docker/resource controls
                    -> E2E/performance/security
                       -> independent review and release decision
```

## Phase 0: Freeze And Scaffold (T+0 to T+2h)

### Task 1: Freeze versioned domain and API contracts

**Acceptance criteria:** DiagnosisCase, Evidence, Job, setup states, error
envelope, provider pinning, and sensitivity policy have versioned schemas.

**Verification:** schema fixtures validate; invalid state transitions fail.

**Dependencies:** None.
**Files likely touched:** `packages/domain/*`, `docs/adr/*`.
**Estimated scope:** Medium.

### Task 2: Establish build and test baseline

**Acceptance criteria:** backend/frontend install from lockfiles; `make lint`,
`make typecheck`, `make test`, and `make build` work in a clean checkout.

**Verification:** CI-equivalent commands run locally and in the builder image.

**Dependencies:** Task 1.
**Files likely touched:** root configs, `apps/api`, `apps/web`.
**Estimated scope:** Medium.

### Checkpoint A

- Contracts and threat boundaries reviewed.
- Clean build/test commands are reproducible.
- No secrets or generated vendor content committed.

## Phase 1: First Runnable Slice (T+2 to T+6h)

### Task 3: Secure first-run setup state machine

**Acceptance criteria:** setup API is the only available API before finalize;
bootstrap is single-use/short-lived; policy is saved before outbound probes.

**Verification:** unit and API abuse tests plus browser setup happy/failure paths.

**Dependencies:** Task 2.
**Files likely touched:** setup routes/service/store and setup UI.
**Estimated scope:** Medium.

### Task 4: External provider gateway and rule fallback

**Acceptance criteria:** OpenAI-compatible structured response adapter is
timeout/cancellation/schema/policy bounded; tainted fields cannot leave; rule
results remain available on provider failure.

**Verification:** fake provider contract tests and outbound canary tests.

**Dependencies:** Tasks 1-3.
**Files likely touched:** provider interface/adapter/policy/tests.
**Estimated scope:** Medium.

### Task 5: Layer 1 end-to-end case

**Acceptance criteria:** SQL input creates an async job and auditable case;
invalid/oversized/unsupported inputs and missing evidence are explicit.

**Verification:** unit, API contract, and Playwright happy/abstention tests.

**Dependencies:** Tasks 3-4.
**Files likely touched:** SQL service/routes and case UI.
**Estimated scope:** Medium.

### Checkpoint B

- Docker -> Web setup -> provider -> SQL case is runnable.
- Model outage demonstrates deterministic degradation.
- No cluster access is needed for the slice.

## Phase 2: Evidence Expansion (T+6 to T+12h)

### Task 6: Bounded job runtime and audit lifecycle

**Acceptance criteria:** idempotency, queue/concurrency/disk limits,
cancellation, retries, timeouts, cleanup, and immutable audit events work.

**Verification:** concurrency/failure injection and restart recovery tests.

**Dependencies:** Task 5.
**Files likely touched:** worker/job store/audit/tests.
**Estimated scope:** Medium.

### Task 7: TiDB and Prometheus connector preflight

**Acceptance criteria:** supported version/deployment and privilege matrix is
checked before collection; secrets never appear in responses or logs.

**Verification:** recorded fixtures plus disposable integration environment.

**Dependencies:** Tasks 1, 6.
**Files likely touched:** connector clients/preflight/tests.
**Estimated scope:** Medium.

### Task 8: Layer 2 evidence and abstention

**Acceptance criteria:** bounded collection produces timestamped coverage and
freshness; missing/evicted/skewed evidence lowers completeness or abstains.

**Verification:** representative workload fixtures, budget/fuse tests, API/E2E.

**Dependencies:** Task 7.
**Files likely touched:** workload service/queries/correlation/UI/tests.
**Estimated scope:** Medium per connector increment.

### Task 9: Safe Clinic archive importer

**Acceptance criteria:** streaming archive/report import enforces all entry,
ratio, byte, time, disk, path, link, type, cancellation, and cleanup budgets.

**Verification:** malicious archive corpus and valid Clinic fixture E2E.

**Dependencies:** Task 6.
**Files likely touched:** importer/parser/policy/tests.
**Estimated scope:** Medium.

### Checkpoint C

- All three supported P0 paths create the same case contract.
- Unsupported Clinic URL access is visibly disabled with rationale.
- Connector impact limits have machine-verifiable evidence.

## Phase 3: Deployment And Qualification (T+12 to T+18h)

### Task 10: One-package deployment topology

**Acceptance criteria:** base and GPU override share one release manifest;
2C4G mode pulls no weights; app has no Docker Socket; internal services are not
published; local mode refuses unavailable devices. Release images cover
`linux/amd64` and `linux/arm64`, and launchers preserve the three-step deployment
journey without manual configuration or migration commands.

**Verification:** Mac/Linux/Windows clean low-resource install, network
inspection, restart/upgrade/uninstall/data retention, failure remediation, and
mode-switch state tests.

**Dependencies:** Tasks 3-9.
**Files likely touched:** `deploy/*`, operations docs, smoke tests.
**Estimated scope:** Medium.

### Task 11: Security and dependency gate

**Acceptance criteria:** bootstrap, session, archive, connector, egress, prompt
injection, secrets, dependency, image, and SBOM checks have evidence.

**Verification:** security suite and native package/container audits.

**Dependencies:** Tasks 3-10.
**Files likely touched:** security tests/config/report.
**Estimated scope:** Medium.

### Task 12: 2C4G performance qualification

**Acceptance criteria:** three paths record RSS/CPU/temp disk/P95/queue and
fuse/OOM behavior under enforced limits; results meet stated budgets or fail.

**Verification:** `make benchmark-2c4g` plus raw machine-readable report.

**Dependencies:** Tasks 8-10.
**Files likely touched:** load harness, fixtures, report.
**Estimated scope:** Medium.

### Checkpoint D

- Release candidate installs from a clean environment.
- Security and 2C4G reports contain raw evidence.
- Local-model support is not claimed without hardware qualification.

## Phase 4: Independent Acceptance (T+18 to T+24h)

### Task 13: QA regression and exploratory pass

**Acceptance criteria:** requirements-to-test traceability is complete; failed,
skipped, and environment-blocked tests are reported separately.

**Verification:** QA signs `PASS`, `CONDITIONAL`, or `FAIL` with reproductions.

**Dependencies:** Tasks 1-12.
**Files likely touched:** validation report only.
**Estimated scope:** Small to Medium.

### Task 14: Independent reviewer gate

**Acceptance criteria:** architecture, code, evidence claims, deployment, and
residual risk are independently reviewed; critical/high findings are resolved
or block release.

**Verification:** review report maps findings to commits/tests/tasks.

**Dependencies:** Task 13.
**Files likely touched:** review report only.
**Estimated scope:** Small to Medium.

### Task 15: Release decision and validation guide

**Acceptance criteria:** a clean-room operator can repeat install, test, and
benchmark commands; a new-machine user reaches the Web App in exactly three
visible steps; known blockers and unsupported claims are visible.

**Verification:** reviewer repeats the guide from a clean checkout.

**Dependencies:** Tasks 13-14.
**Files likely touched:** README, operations and validation docs.
**Estimated scope:** Medium.

## Parallel Work

- After Task 2, QA can author fixtures and test contracts while RD builds setup.
- After Task 6, Layer 2 and Layer 3 can proceed independently if ownership
  capacity exists; they converge only on the case and job contracts.
- Reviewer can examine ADRs, security boundaries, and contract tests before the
  release candidate, then perform the final evidence gate after QA.

## Timing And Reporting

The estimate is `22-28` engineering hours. With RD, QA, Reviewer, and manager
working in parallel, expected elapsed time is `16-24` hours for a P0 candidate.
Real-environment compatibility and local-model GPU qualification require
`2-3` working days when infrastructure is available.

Each hourly checkpoint reports completed tasks, exact verification evidence,
blockers, the next one-hour target, and revised remaining ETA.

## Risks And Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| No official Clinic read API | Blocks URL mode | P0 archive/report import; connector stays disabled |
| GPU not exposed at start | Local mode unavailable | Preflight plus same-package GPU override; no Docker Socket |
| 2C4G exceeded by archives/jobs | Low-mode failure | streaming, concurrency 1, disk/queue/fuse budgets |
| False confidence from LLM | Unsafe recommendations | evidence binding, competing hypotheses, abstention, no execution API |
| TiDB version/privilege drift | Connector breakage/impact | versioned query matrix and fail-closed preflight |
| SQLLens name collision | Public launch risk | working code name only; rename/brand gate before GitHub release |
| Cross-platform environment unavailable | Cannot claim Mac/Windows/Linux support | require real clean-install evidence; mark missing hosts unverified |
