# SQLLens P0 QA Test Matrix

Status: baseline v1, execution not started
Owner: `#t14` / swat-qa
Specification: `docs/superpowers/specs/2026-08-31-sqllens-p0-design.md`

## Purpose

This matrix is the independent QA contract for P0. It maps the product and child
task acceptance criteria to reproducible tests. An item is not considered passed
because a unit test exists, a page renders, or an implementation owner reports
success. PASS requires the environment and evidence named here.

## Result Vocabulary

| Result | Meaning |
|---|---|
| `NOT_RUN` | Test is specified but has not been executed. |
| `BLOCKED` | A named environment, artifact, threshold, or contract is missing. |
| `PASS` | Actual result matches every assertion and raw evidence is retained. |
| `FAIL` | At least one assertion failed; a defect ID and reproduction are required. |
| `N/A` | The frozen P0 contract excludes the behavior; the exclusion must be cited. |

Skipped tests are never treated as PASS. Simulated services can prove contract
handling, but cannot prove TiDB compatibility, production impact, Clinic format
compatibility, or local-model GPU sizing.

## Requirement Traceability

| Requirement | Source | Test groups |
|---|---|---|
| `R-T14-1` Three paths cover success, missing evidence, insufficient privilege, timeout, fuse, and degradation | `#t14` AC 1 | `L1`, `L2`, `L3`, `CASE` |
| `R-T14-2` Enforced 2C4G run records peak RSS/CPU/temp disk/P95/queue/degradation/OOM/fuse | `#t14` AC 2 | `PERF` |
| `R-T14-3` Read-only A/B quantifies incremental impact and proves Kill Switch | `#t14` AC 3 | `AB` |
| `R-T10-1` Diagnosis APIs stay closed until setup finalization | `#t10` AC 1 | `SETUP` |
| `R-T10-2` Low-resource mode downloads no model weights and has no Docker Socket | `#t10` AC 2 | `DEPLOY`, `SEC` |
| `R-T10-3` Local mode is unavailable when the device is not exposed | `#t10` AC 3 | `SETUP`, `DEPLOY` |
| `R-T11-1` Layer 1 handles valid, invalid, oversized, insufficient-evidence, and provider-outage cases | `#t11` AC 1 | `L1` |
| `R-T11-2` Missing version/schema never yields executable DDL or benefit promises | `#t11` AC 2 | `L1`, `CASE` |
| `R-T11-3` Every conclusion has evidence, completeness, risk, validation, and rollback | `#t11` AC 3 | `CASE` |
| `R-T12-1` Layer 2 budgets, cancellation, server kill, audit, and compatibility are testable | `#t12` AC 1 | `L2`, `AB` |
| `R-T12-2` DML and EXPLAIN ANALYZE are prohibited; risky EXPLAIN fails closed | `#t12` AC 2 | `L2`, `SEC` |
| `R-T12-3` Missing/evicted/skewed/incomplete evidence degrades or abstains | `#t12` AC 3 | `L2`, `CASE` |
| `R-T13-1` No Clinic scraping/plaintext password; package/report fallback is explicit | `#t13` AC 1 | `L3`, `SEC` |
| `R-T13-2` URL and archive abuse cases are covered | `#t13` AC 2 | `L3`, `SEC` |
| `R-T13-3` Import enforces disk/idempotency/cancel/cleanup/audit | `#t13` AC 3 | `L3`, `PERF` |
| `R-P0-PR` One-click Plan Replayer capture is an explicitly authorized privileged workflow | `#t7` P0 acceptance / ADR 0002 amendment | `PR`, `SEC`, `AB` |
| `R-P0-PLAT` Browser Web App and external-model mode support Mac, Linux and Windows from one package in three user steps | Human platform/deployment requirement | `PLAT`, `DEPLOY`, `UI` |
| `R-P0-LOCAL` A pinned 30B artifact requires real target GPU qualification | `#t14` review checklist | `GPU` |

## Environments

| ID | Environment | What it may prove | Required evidence |
|---|---|---|---|
| `E0` | Clean checkout, no external services | schema, static policy, unit and contract behavior | commit, commands, stdout/JUnit |
| `E1` | Base Compose under enforced total `2 CPU / 4 GiB`, fake external provider | setup, Layer 1, API/E2E, fallback, container limits | Compose config, image digests, cgroup stats, traces |
| `E2` | Disposable real TiDB and Prometheus | privilege/version behavior, real query cancellation, A/B impact | topology/version, grants, workload seed, before/after metrics |
| `E3` | Isolated hostile-input lab with no production credentials | archive, report, prompt-injection and egress abuse | generated corpus manifest, hashes, temp-dir observations |
| `E4` | Target GPU host with pinned local-model artifact | local inference quality, latency, memory and failure behavior | GPU/runtime/model revisions, hashes, benchmark raw data |
| `E5` | Clean supported Mac, Linux and Windows hosts/runners | native image, three-step install, filesystem, networking, lifecycle and platform-mode compatibility | OS/runtime versions, architecture, commands, screenshots/logs |

`E2`, `E4` and `E5` must not be replaced by mocks or cross-architecture emulation
for release claims.

## Setup And Deployment

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `SETUP-001` | E1 | Fresh start exposes only setup/status endpoints; every diagnosis, case, job, review, connector and import endpoint returns the frozen pre-setup error. | `NOT_RUN` |
| `SETUP-002` | E1 | Bootstrap token is single-use, expires at the configured TTL, is rate-limited, and never appears in application/access/error logs or API bodies. | `NOT_RUN` |
| `SETUP-003` | E1 | Concurrent bootstrap attempts create exactly one first admin; losing requests fail without disclosing state or token validity. | `NOT_RUN` |
| `SETUP-004` | E1 | Setup interruption at every step resumes from committed state without skipping mandatory policy or creating duplicate admins/secrets. | `NOT_RUN` |
| `SETUP-005` | E1 | An outbound model probe is rejected until retention, TLS, egress, redaction, and audit policy is committed. | `NOT_RUN` |
| `SETUP-006` | E1 | External provider probe validates timeout, cancellation, TLS, structured output and redaction using non-sensitive fixture data. | `NOT_RUN` |
| `SETUP-007` | E1 | Missing GPU/device disables local mode and returns an actionable restart prerequisite; no fabricated hardware result is stored. | `NOT_RUN` |
| `SETUP-008` | E1 | Finalize is rejected until every mandatory step is complete; successful finalize atomically enables diagnosis APIs. | `NOT_RUN` |
| `SETUP-009` | E1 | Switching provider revisions drains or cancels pinned jobs; completed cases retain original provider/model/prompt/policy/redaction revisions. | `NOT_RUN` |
| `DEPLOY-001` | E1 | Effective Compose configuration has an enforced aggregate 2 CPU/4 GiB budget and persists only documented volumes. | `NOT_RUN` |
| `DEPLOY-002` | E1 | Base-mode pull/start downloads no local model weights and creates no weight volume content. | `NOT_RUN` |
| `DEPLOY-003` | E1 | No application container mounts `/var/run/docker.sock`, a host root, or another broad host path; internal services publish no host ports. | `NOT_RUN` |
| `DEPLOY-004` | E1 | Restart preserves finalized setup and cases, cleans orphaned temporary jobs, and does not reuse the bootstrap secret. | `NOT_RUN` |
| `DEPLOY-005` | E0/E1 | Clean bootstrap, lint, typecheck, unit, integration, E2E, build and smoke commands are reproducible from lockfiles and pinned images. | `NOT_RUN` |

## Layer 1: SQL-Only Triage

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `L1-001` | E1 | Supported TiDB SELECT creates one async job and one Layer 1 case with a stable input fingerprint. | `NOT_RUN` |
| `L1-002` | E1 | Missing TiDB version and schema is represented as missing evidence; all recommendations remain hypotheses. | `NOT_RUN` |
| `L1-003` | E1 | Invalid SQL returns the versioned validation envelope without stack trace, case creation, or provider call. | `NOT_RUN` |
| `L1-004` | E1 | Input at the byte/token limit succeeds; one byte/token above it fails before parse/provider work. | `BLOCKED` |
| `L1-005` | E1 | Unsupported TiDB syntax is preserved and disclosed as an evidence gap; it is not silently rewritten. | `NOT_RUN` |
| `L1-006` | E1 | DML, DDL, multi-statement, comments-only and empty input follow the frozen Layer 1 acceptance policy and never execute. | `BLOCKED` |
| `L1-007` | E1 | Provider timeout, invalid schema, 429, 5xx, disconnect and cancellation yield deterministic rule evidence plus explicit degradation. | `NOT_RUN` |
| `L1-008` | E1 | SQL literals, comments containing canaries, credentials and business identifiers never appear in the provider request, audit payload, logs or error body. | `NOT_RUN` |
| `L1-009` | E1 | Prompt injection in identifiers/comments cannot change the output schema, call tools, create evidence, run collectors or generate commands. | `NOT_RUN` |
| `L1-010` | E1 | Reusing an idempotency key with identical input returns the same job; changed input yields a stable conflict error. | `NOT_RUN` |
| `L1-011` | E1 | Without schema/statistics/runtime evidence, output contains no executable CREATE INDEX/ALTER statement, numeric benefit or claim of a real bottleneck. | `NOT_RUN` |
| `L1-012` | E1 | Concurrent submission beyond queue limits is bounded and observable; accepted work remains cancellable and deterministic. | `NOT_RUN` |

## Layer 2: Prometheus And TiDB Read-Only Evidence

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `L2-001` | E2 | Supported versions and exact least-privilege grants pass preflight; missing grants name only the required capability, not credentials. | `BLOCKED` |
| `L2-002` | E2 | Unsupported/unknown TiDB, Prometheus, deployment or statement schema fails closed with a versioned compatibility result. | `BLOCKED` |
| `L2-003` | E2 | Every TiDB statement is in the versioned allowlist and parameterized; audit records statement ID/version, duration, row count and outcome. | `BLOCKED` |
| `L2-004` | E2 | DML, DDL, EXPLAIN ANALYZE, unrestricted system-table scans and multiple statements cannot be requested through any API or LLM output. | `NOT_RUN` |
| `L2-005` | E2 | Ordinary EXPLAIN for scalar-subquery or version-unsafe constructs is rejected before cluster access and routed to offline evidence guidance. | `BLOCKED` |
| `L2-006` | E2 | Default and maximum windows, metric step, returned points, SQL rows, concurrency and total job duration are enforced at boundaries. | `BLOCKED` |
| `L2-007` | E2 | TiDB and Prometheus connect/read/server-execution timeouts produce explicit partial evidence and do not become generic root-cause claims. | `NOT_RUN` |
| `L2-008` | E2 | User cancellation stops outbound requests, cancels/kills permitted server work, closes connections and records the terminal audit state. | `NOT_RUN` |
| `L2-009` | E2 | Kill Switch prevents new collection, terminates active work within the frozen deadline and leaves Layer 1 available. | `BLOCKED` |
| `L2-010` | E2 | Insufficient TiDB privilege and Prometheus 401/403 are distinguished, redact credentials, and offer only safe remediation. | `NOT_RUN` |
| `L2-011` | E2 | Missing/evicted Statement Summary or slow-query evidence lowers coverage/completeness and causes abstention when required. | `NOT_RUN` |
| `L2-012` | E2 | Node/metric coverage gaps and stale samples are shown per source; no cluster-wide conclusion is made from partial nodes. | `NOT_RUN` |
| `L2-013` | E2 | Clock skew across app, TiDB and Prometheus is detected; correlation is blocked or uncertainty widened per policy. | `NOT_RUN` |
| `L2-014` | E2 | Digest match, plan change, statistics health and metric timeline preserve source timestamps and cannot be joined outside tolerance. | `BLOCKED` |
| `L2-015` | E2 | Prometheus query injection, pathological regex/range, high-cardinality results and malicious labels are bounded and output-encoded. | `NOT_RUN` |
| `L2-016` | E2 | TiDB/Prometheus credentials are encrypted at rest, absent from DB dumps/logs/errors, rotatable, and verifiably deleted. | `NOT_RUN` |
| `L2-017` | E2 | Connector TLS verification is on; invalid/expired/untrusted certificates fail closed and proxy behavior follows committed policy. | `NOT_RUN` |
| `L2-018` | E2 | Collection budget exhaustion trips the fuse, records the exact budget, cleans work, and prevents retry storms. | `BLOCKED` |

## Layer 3: Clinic Package Or Report Import

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `L3-001` | E3 | Approved Clinic archive fixture streams into one Layer 3 case with per-artifact provenance, coverage, freshness and integrity metadata. | `BLOCKED` |
| `L3-002` | E1/E3 | Clinic URL/password fields and browser-scraping routes are absent or visibly disabled; package/report import is the documented P0 path. | `NOT_RUN` |
| `L3-003` | E3 | Absolute, `../`, encoded, Unicode-confusable and Windows path traversal entries are rejected without writing outside the job directory. | `NOT_RUN` |
| `L3-004` | E3 | Symlinks, hardlinks, devices, FIFOs, sockets and other special entries are rejected. | `NOT_RUN` |
| `L3-005` | E3 | Compressed bytes, uncompressed bytes, entry count, per-entry bytes, nesting and compression-ratio limits trip before resource exhaustion. | `BLOCKED` |
| `L3-006` | E3 | Disk, wall-clock and parse budgets trip the fuse; the terminal state names the exceeded budget without leaking paths/content. | `BLOCKED` |
| `L3-007` | E3 | Cancellation during upload, extraction and parse stops work and removes partial files within the cleanup deadline. | `BLOCKED` |
| `L3-008` | E3 | Truncated, corrupt, encrypted, unsupported and polyglot archives fail closed and do not leave a partial case. | `NOT_RUN` |
| `L3-009` | E3 | Duplicate names, case-collisions, sparse files, misleading extensions and nested archives follow the frozen importer policy. | `BLOCKED` |
| `L3-010` | E3 | Reusing an idempotency key with the same file digest returns the same job; changed content conflicts and creates no orphan. | `NOT_RUN` |
| `L3-011` | E3 | Report HTML/log/metric labels containing script, formula or template payloads are inert in UI and exports. | `NOT_RUN` |
| `L3-012` | E3 | Prompt injection and sensitive canaries inside reports/logs cannot enter model egress, invoke tools, or create unsupported evidence. | `NOT_RUN` |
| `L3-013` | E3 | Secret scanning marks or rejects sensitive fields according to policy; raw secrets never enter logs, SQLite or provider traffic. | `NOT_RUN` |
| `L3-014` | E3 | Failed, cancelled and expired imports clean temporary files and preserve only bounded audit metadata. | `NOT_RUN` |
| `L3-015` | E3 | Audit records archive digest, importer/policy versions, budgets, counts, outcome and cleanup without recording sensitive content. | `NOT_RUN` |

## Privileged Plan Replayer Capture

This workflow is separate from default Layer 2 collection. Every test verifies
that capture is active production evidence acquisition and never described as
strict read-only or zero-impact.

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `PR-001` | E2 | Only an authorized DBA/Admin can request and confirm capture; ordinary DBA/SRE/read-only roles receive a stable forbidden result. | `NOT_RUN` |
| `PR-002` | E2 | Confirmation preview names cluster, digest/SQL fingerprint, referenced objects, exact action, data classes, privilege, timeout/resource budget, retention and destination before any cluster call. | `BLOCKED` |
| `PR-003` | E2 | Capture executes only the versioned Plan Replayer dump statement for an approved single statement; arbitrary SQL, DML, DDL, EXPLAIN ANALYZE and multi-statement input are impossible. | `BLOCKED` |
| `PR-004` | E2 | Confirmation is CSRF-protected, short-lived, bound to actor/preview/input/policy revisions and single-use; changing any field requires a new preview and approval. | `NOT_RUN` |
| `PR-005` | E2 | Timeout, user cancellation and Kill Switch stop capture/download within the frozen deadline, prevent new work and record whether server-side work was terminated. | `BLOCKED` |
| `PR-006` | E2 | Token/status-port download is bound to the initiating job and expected TiDB endpoint; tokens, credentials, URLs and raw SQL literals never appear in logs/errors/audit payloads. | `NOT_RUN` |
| `PR-007` | E2/E3 | Downloaded package is streamed through size/time/disk limits, integrity and hostile-archive checks, sensitivity scan and encrypted storage before download or sandbox import. | `BLOCKED` |
| `PR-008` | E2 | Unsupported version, missing privilege, token failure, status-port/TLS error, corrupt package and restart leave no partial case, reusable token or orphaned temporary file. | `NOT_RUN` |
| `PR-009` | E2/E3 | Product offers only approved download or isolated-sandbox import and has no path to load the package into the source/production cluster. | `NOT_RUN` |
| `PR-010` | E2/E3 | Result is labelled plan-level reproducibility; it never claims runtime latency, skew, concurrency, lock, hotspot or benefit proof without separate representative evidence. | `NOT_RUN` |

## Unified Case And Safety Contract

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `CASE-001` | E1/E2/E3 | All three paths produce the same versioned DiagnosisCase schema and immutable revisions. | `NOT_RUN` |
| `CASE-002` | E1/E2/E3 | Every conclusion and recommendation references existing evidence IDs; fabricated/dangling IDs are rejected. | `NOT_RUN` |
| `CASE-003` | E1/E2/E3 | Supporting and contradicting evidence remain distinct; confidence and completeness are independent bounded fields. | `FAIL` |
| `CASE-004` | E1/E2/E3 | Insufficient or contradictory evidence produces an abstention with minimum next evidence, not a generic recommendation. | `NOT_RUN` |
| `CASE-005` | E1/E2/E3 | Recommendation includes risk, prerequisites, owner, validation and rollback; no API executes recommendations or production changes. | `NOT_RUN` |
| `CASE-006` | E1/E2/E3 | Evidence/provider/prompt/policy/redaction revisions and input fingerprints are retained across review and outcome changes. | `NOT_RUN` |
| `CASE-007` | E1/E2/E3 | Allowed terminal outcome is separate from workflow status and is one of validated-effective, rolled-back, evidence-insufficient, or risk-accepted. | `FAIL` |
| `CASE-008` | E1/E2/E3 | Concurrent reviews and retries cannot overwrite an immutable revision or lose audit events. | `NOT_RUN` |

## Cross-Cutting Security

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `SEC-001` | E1 | Session cookies are Secure/HttpOnly/SameSite with idle/absolute expiry; fixation and reuse after logout fail. | `NOT_RUN` |
| `SEC-002` | E1 | State-changing routes enforce CSRF and authorization; object IDs cannot be used for cross-tenant/cross-role access. | `NOT_RUN` |
| `SEC-003` | E1 | Login/bootstrap/provider/import endpoints enforce request size, rate, concurrency and timeout limits. | `NOT_RUN` |
| `SEC-004` | E1 | CSP, HSTS where TLS is configured, frame, MIME, referrer and cache headers meet the frozen policy; setup/secrets are never cached. | `NOT_RUN` |
| `SEC-005` | E0/E1 | Repository, images, runtime env, logs, SQLite and generated artifacts contain no committed or emitted test canary secret. | `NOT_RUN` |
| `SEC-006` | E1/E3 | LLM output and imported content are untrusted text: schema validation and output encoding prevent XSS, command, SQL and tool execution. | `NOT_RUN` |
| `SEC-007` | E1 | Error envelopes expose stable codes but no stack, SQL literals, credential, token, internal path or provider body. | `NOT_RUN` |
| `SEC-008` | E0 | Locked dependencies and final images pass native audits, secret scan, vulnerability scan and SBOM generation under the release policy. | `NOT_RUN` |
| `SEC-009` | E1 | Outbound destinations, redirects, proxies and DNS resolution follow committed allowlists; private/reserved endpoints cannot be reached by user-controlled input. | `NOT_RUN` |
| `SEC-010` | E1 | Audit events are append-only/ordered, identify actor/action/policy/outcome, and avoid raw sensitive payloads. | `FAIL` |

## 2C4G Performance Qualification

All `PERF` tests run against the release images with the aggregate cgroup limit
enforced, not merely requested. Warmup, sample count, input corpus and pass/fail
thresholds are recorded before execution.

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `PERF-001` | E1 | Idle and post-warmup baseline records per-container and aggregate RSS/working set, CPU, open files, threads and persistent/temp disk. | `NOT_RUN` |
| `PERF-002` | E1 | Layer 1 fixed corpus records throughput and P50/P95/P99 end-to-end latency with provider latency separated from local work. | `BLOCKED` |
| `PERF-003` | E2 | Layer 2 fixed window/workload records P50/P95/P99, rows/points, RSS/CPU/temp disk and connector-side query duration. | `BLOCKED` |
| `PERF-004` | E3 | Layer 3 small/medium/maximum approved fixtures record ingest rate, P95, RSS/CPU/temp disk and cleanup time. | `BLOCKED` |
| `PERF-005` | E1/E3 | Queue saturation demonstrates bounded concurrency, backpressure, fair cancellation and no unbounded memory/disk growth. | `BLOCKED` |
| `PERF-006` | E1/E3 | Slow provider, high-cardinality metrics and archive expansion trip configured timeout/fuse before cgroup OOM. | `BLOCKED` |
| `PERF-007` | E1/E3 | Deliberate over-budget input produces a controlled terminal state; restart recovery leaves no retry storm or orphaned temp data. | `BLOCKED` |
| `PERF-008` | E1 | A forced model-gateway/worker OOM or kill does not corrupt cases/setup; service recovers within the frozen objective. | `BLOCKED` |
| `PERF-009` | E1 | Repeated corpus run detects RSS/temp-disk growth and reports regression slope, peak and final cleanup delta. | `BLOCKED` |

## Read-Only Cluster A/B And Kill Switch

The A/B run uses the same seeded workload and topology for collector OFF, ON and
OFF-again periods. Order is repeated or randomized to distinguish collector cost
from workload drift. App and cluster measurements use synchronized clocks.

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `AB-001` | E2 | Record topology, TiDB/Prometheus versions, grants, configuration, workload seed and collector query manifest before the run. | `BLOCKED` |
| `AB-002` | E2 | OFF/ON/OFF records TiDB CPU, process RSS, query latency/throughput, RU where available, internal SQL duration/rows and Prometheus load. | `BLOCKED` |
| `AB-003` | E2 | Incremental impact is reported with raw time series, sample size and uncertainty against an approved budget; absence of significance is not called zero overhead. | `BLOCKED` |
| `AB-004` | E2 | Kill Switch during the slowest permitted query stops active collection within the deadline and prevents new connector work while Layer 1 remains available. | `BLOCKED` |
| `AB-005` | E2 | Network loss and TiDB/Prometheus restart during collection leave no stuck session, retry storm, leaked secret or false complete-evidence state. | `BLOCKED` |

## Local Model Qualification

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `GPU-001` | E4 | Record exact model repository/revision, weight/tokenizer hashes, quantization, runtime/image digest, driver and GPU firmware. | `BLOCKED` |
| `GPU-002` | E4 | Fixed SQL diagnosis corpus measures evidence-grounded output quality, abstention, P50/P95 tokens/sec and end-to-end latency at the supported context/concurrency. | `BLOCKED` |
| `GPU-003` | E4 | Record VRAM, host RAM, CPU and disk during load/inference; context overflow and OOM fail without affecting diagnosis persistence. | `BLOCKED` |
| `GPU-004` | E4 | Device absent/incompatible, corrupt weights and controller restart produce explicit unavailable/unverified state and safe external/rule fallback. | `BLOCKED` |

## Browser And Accessibility Acceptance

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `UI-001` | E1 | Setup and three paths are keyboard-operable with visible focus, correct labels, error association and no focus trap. | `NOT_RUN` |
| `UI-002` | E1 | 390x844 and 1440x1000 viewports have no incoherent overlap or horizontal page overflow; dynamic states do not shift fixed controls. | `NOT_RUN` |
| `UI-003` | E1 | Evidence level, missing evidence, abstention, source freshness, job progress, cancellation and degraded states are exposed in text, not color alone. | `NOT_RUN` |
| `UI-004` | E1 | Reload/back/duplicate-submit/resume behavior preserves state and does not create duplicate work. | `NOT_RUN` |
| `UI-005` | E1 | Browser console has no uncaught errors and failed requests produce actionable, non-sensitive UI states. | `NOT_RUN` |

## Cross-Platform Web App Acceptance

The shipped service remains a Linux-container Web App, not three native desktop
clients. Docker Desktop includes Compose on Mac, Windows and Linux, while native
Linux may also use the Compose plugin. Release images must provide native
`linux/amd64` and `linux/arm64` variants. Docker Desktop GPU passthrough is a
separate platform capability and, per Docker documentation, is available only on
Windows with the WSL2 backend; platform Web support must not imply local-model
GPU support.

Official references:

- <https://docs.docker.com/compose/install/>
- <https://docs.docker.com/build/building/multi-platform/>
- <https://docs.docker.com/desktop/features/gpu/>

| ID | Environment | Scenario and assertions | Result |
|---|---|---|---|
| `PLAT-001` | E0/E5 | Published manifest contains native `linux/amd64` and `linux/arm64` variants for every base-mode image, with matching application version, labels and SBOM/provenance. | `BLOCKED` |
| `PLAT-002` | E5 | Clean Linux amd64 Docker Engine + Compose-plugin install completes Web setup, external-provider probe, Layer 1 case, restart and smoke test. | `BLOCKED` |
| `PLAT-003` | E5 | Clean Intel Mac Docker Desktop install completes the same external-model acceptance flow without emulation warnings. | `BLOCKED` |
| `PLAT-004` | E5 | Clean Apple Silicon Mac Docker Desktop pulls native arm64 variants and completes the same external-model acceptance flow without amd64 emulation. | `BLOCKED` |
| `PLAT-005` | E5 | Supported Windows 10/11 Docker Desktop with WSL2 and Linux containers completes the same external-model acceptance flow from documented PowerShell commands. | `BLOCKED` |
| `PLAT-006` | E5 | Paths with spaces/non-ASCII, CRLF invocation, volume ownership, case sensitivity, localhost/port mapping and browser launch behave per documented policy on all three OS families. | `BLOCKED` |
| `PLAT-007` | E5 | Restart and supported upgrade preserve setup/cases; uninstall retains or deletes data only through an explicit documented choice on all platforms. | `BLOCKED` |
| `PLAT-008` | E5 | Default port binding is local-only on every platform; another LAN host cannot reach setup/API without explicit remote-access configuration. | `BLOCKED` |
| `PLAT-009` | E5 | Explicit remote access requires TLS, authentication and allowed-interface/origin policy and never exposes bootstrap or internal model-controller ports. | `BLOCKED` |
| `PLAT-010` | E5 | Mac local-model GPU mode is shown as unavailable/unverified for the NVIDIA container path; the UI never converts Web compatibility into a GPU-support claim. | `BLOCKED` |
| `PLAT-011` | E5 | Windows local GPU mode is enabled only after a real in-container probe on WSL2 plus supported NVIDIA hardware/driver; other backends/devices fail closed. | `BLOCKED` |
| `PLAT-012` | E4/E5 | Linux local GPU mode is enabled only on an explicitly supported distribution/architecture with the pinned NVIDIA runtime and a successful in-container device/model probe. | `BLOCKED` |
| `PLAT-013` | E5 | From a clean supported host, deployment has exactly three user steps: install container runtime, run one launcher/command, then finish Web setup; manual env/Compose edits, migrations, token-file lookup, GPU setup or extra operations fail acceptance. | `BLOCKED` |
| `PLAT-014` | E5 | Launcher performs architecture/image-integrity/port/disk preflight, prints the local URL and one-time code, and keeps actionable remediation within the current step; unavailable local GPU degrades to external mode without adding a deployment step. | `BLOCKED` |

## Current Open Defects

- `CASE-007`: [QA-003](defects/QA-003-terminal-outcome-vocabulary.md) - the
  contract cannot represent all four approved terminal business outcomes.
- `CASE-003`: [QA-004](defects/QA-004-conflicting-evidence-polarity.md) - one
  evidence ID can simultaneously support and contradict a hypothesis.
- `SEC-010`: [QA-005](defects/QA-005-revision-audit-time-consistency.md) - newly
  appended audit records are not bounded to their revision time window, and
  accepted RFC 3339 input is parsed inconsistently.

These are contract-level failures. Product API/database validation remains
`NOT_RUN` until an executable runtime slice exists.

## Current Blocking Inputs

These inputs are required before the named tests can move from BLOCKED to an
executable PASS/FAIL decision:

1. Supported TiDB/Prometheus version and deployment matrix.
2. Versioned TiDB statement allowlist, exact grants and scalar-subquery policy.
3. Numeric Layer 1 input, connector window/row/point/concurrency/timeout/cancel,
   Kill Switch and correlation-skew budgets.
4. Clinic fixture versions/formats plus compressed/uncompressed/entry/ratio/time/
   disk/nesting/cleanup budgets.
5. Version/privilege/statement policy, preview schema, timeout/cancel/Kill Switch,
   download and retention budgets for privileged Plan Replayer capture.
6. Performance corpus, warmup/sample counts and numeric latency/resource/impact
   pass thresholds. `2 CPU / 4 GiB` alone is a containment limit, not a service
   quality threshold.
7. Disposable TiDB/Prometheus environment access for E2.
8. Supported host OS/runtime version matrix plus clean Intel Mac, Apple Silicon
   Mac, Linux amd64 and Windows WSL2 hosts for E5.
9. Target GPU plus pinned model/runtime artifacts for E4. Until available, every
   local-model claim remains visibly unverified and excluded from release claims.

## Evidence Package Per Run

Each run stores, outside source control when sensitive or large:

- source commit and dirty-worktree diff;
- host/kernel/architecture, container runtime, Compose render and image digests;
- dependency lock hashes and fixture manifest/hashes;
- exact commands, start/end timestamps, exit codes, stdout/stderr and test report;
- sanitized request/response and audit identifiers needed to reproduce failures;
- cgroup/container/host metrics and raw time series for performance/A/B tests;
- defect IDs for FAIL and a precise missing prerequisite for BLOCKED;
- reviewer-visible summary containing PASS, FAIL, BLOCKED and NOT_RUN counts.

Secrets, raw SQL literals, business data and credentials are never attached to
the evidence package.
