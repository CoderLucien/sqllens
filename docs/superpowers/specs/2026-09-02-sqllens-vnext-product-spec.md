# SQLLens vNext Product Specification

Status: Approved implementation baseline
Date: 2026-09-02
Owner: swat-mgr

## Objective

Deliver a local, evidence-first SQL diagnosis product for TiDB v8.5.x and
PingKaiDB v7.1.x. A DBA/SRE must be able to start one official Docker image,
connect an approved read-only evidence source, select an abnormal SQL, and
receive a Chinese report that explains impact, evidence, reasoning, actions,
validation, rollback, and uncertainty.

The working name SQLLens remains internal until naming and brand review.

## Product Outcome

The product is successful only when a customer can decide and act safely. A
completed job, a hypothesis ID, or an English paragraph is not a product
outcome.

The primary audience is DBA/SRE. The same facts also render as:

- an application-developer view focused on SQL/schema changes;
- an incident-owner view focused on impact, priority, and decision status.

All views share one immutable evidence set and may not contradict each other.

## Frozen Decisions

1. Installation/initialization and daily diagnosis are separate phases and
   separate navigation shells.
2. P0 customers receive an official multi-architecture Docker image. They do
   not compile source, edit environment files, or select a platform.
3. The only happy-path install action is one copied docker run command,
   followed by opening http://localhost:18080.
4. The first implementation slice is abnormal SQL diagnosis.
5. Three evidence entry modes converge on one Diagnosis Case:
   managed read-only sources, Plan Replayer upload, and manual materials.
6. TiDB v8.5.x and PingKaiDB v7.1.x have explicit version packs. Unknown
   versions fail closed for version-specific conclusions.
7. Rules determine facts, evidence coverage, and safety limits. AI may produce
   evidence-bound Chinese explanations and recommendation candidates, but may
   not create evidence or execute actions.
8. Production changes are never executed automatically.

## Customer Journey

### Phase A: Install And Initialize

#### A1. Start the official image

The release page presents exactly one command. Its image reference is pinned to
a published digest and replaced only by the release pipeline:

~~~bash
docker run -d --name sqllens --restart unless-stopped \
  --read-only --security-opt no-new-privileges --cap-drop ALL \
  -p 127.0.0.1:18080:8080 \
  -v sqllens-data:/data -v sqllens-secrets:/secrets \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  <official-registry>/sqllens@sha256:<published-digest>
~~~

Docker selects linux/amd64 or linux/arm64 from the OCI manifest. The Web UI
remains loopback-only. Remote access, custom ports, Kubernetes, offline
packages, and source builds are outside the P0 customer journey.

#### A2. Create the local Owner

On an empty instance, the first canonical `http://localhost:18080` visit creates
the Owner password. No default password or terminal bootstrap code is shown.
Owner creation requires the exact Host and Origin plus a short-lived,
single-use setup nonce bound to an HttpOnly SameSite=Strict cookie. Docker
loopback publication is exposure control; container peer IP and proxy headers
are not caller identity. Creation atomically closes the first-run endpoint.
The no-code P0 journey explicitly trusts the local operating-system/Docker
administrator during empty-instance setup. Recovery is a separate local,
audited flow.

#### A3. Configure initial sources

Initialization may register multiple sources. At least one database or imported
evidence package is required before a diagnosis can start. Prometheus and
TEM/Alertmanager may be added later.

Each source has a guided acquisition path:

- who creates or supplies the credential;
- exact copyable commands or product-navigation steps;
- minimum required permission and optional sensitive permission;
- bounded connectivity/capability self-test;
- owner, expiry, rotation, disable, and revoke instructions.

Secrets are entered only in the local Web UI and stored encrypted in the
secrets volume. They never appear in chat, command history, API responses,
normal logs, or model payloads.

#### A4. Configure diagnosis mode

The user explicitly selects:

- **Rules + AI**: deterministic evidence/rules plus a validated model-authored
  Chinese explanation and recommendation layer;
- **Rules only**: the same deterministic facts without model-authored content.

The configured and effective mode are visible globally and on every report.
Provider preflight verifies model discovery and one minimal real structured
diagnosis request. A failed provider degrades visibly to rules-only mode.

### Phase B: Daily Diagnosis

Daily navigation contains only Diagnosis workbench, New diagnosis, Reports,
Data sources, and System settings. It does not expose the first-run wizard.

#### B1. Select an entry mode

**Managed read-only source (default)**

1. Select cluster and time window.
2. Discover abnormal SQL Statements/Slow Query records.
3. Select a SQL Digest.
4. Preview the exact evidence categories and bounded queries.
5. Start collection and diagnosis.

**Plan Replayer**

The page provides version-aware, copyable steps to generate, locate, download,
inspect, and upload a Plan Replayer package. It explains token expiry, package
sensitivity, unsupported versions, parser errors, and the fact that a replay
package does not prove production runtime performance.

**Manual materials**

The user selects TiDB v8.5.x, PingKaiDB v7.1.x, or unknown, then supplies any
available SQL, schema, index, statistics, ordinary plan, runtime excerpt, and
business symptom. Missing materials remain explicit and reduce the conclusion
ceiling.

#### B2. Run the evidence pipeline

The customer can inspect these stages:

1. input normalization and version detection;
2. evidence acquisition with per-source budgets;
3. deterministic feature extraction;
4. versioned rule evaluation;
5. optional evidence-bound AI synthesis;
6. server-side claim validation and report publication.

Every stage shows status, source, duration, and degradation reason.

#### B3. Read and act on the report

The Chinese-first report always contains:

1. one-sentence conclusion and priority;
2. affected cluster/database/SQL/time window and business impact;
3. evidence cards with source, timestamp, freshness, coverage, and identifiers;
4. why the system reached the conclusion;
5. rule hits and AI contribution shown separately;
6. one to three ordered actions with owner, risk, prerequisite, and expected
   gain;
7. validation metrics and success threshold;
8. rollback steps;
9. uncertainty, missing evidence, and abstention reason;
10. official document/rule references.

Internal IDs remain available in a trace drawer, not as the primary UI.

## Data Source Management

Sources are first-class records and support add, test, edit, enable, disable,
rotate credential, and delete. A source revision includes:

- source ID, type, display name, product/version, and endpoint identity;
- associated cluster and allowed schemas;
- authentication kind and encrypted credential reference;
- capability/permission matrix;
- owner, created time, expiry, last verified time, and state;
- query/rate/row/time budgets;
- immutable audit events.

A diagnosis snapshots the source revision and evidence. Later source edits or
deletion affect only new jobs and do not rewrite historical reports.

Admission also pins the credential revision and acquires a lease. Rotation,
disable, and delete stop new admission and drain existing leases. Rotation
activates a new revision for new jobs; deletion destroys the usable secret only
after leases reach zero and retains a metadata-only tombstone. A forced cancel
requires Owner confirmation and an audit record. Hard deletion with active
leases is forbidden.

### Database read-only account

The guided scripts cover TiDB v8.5.x and PingKaiDB v7.1.x. Required privileges
are separated from optional PROCESS. PROCESS may expose other users'
statement/session information and therefore requires explicit customer
approval, a restricted source host, an expiry date, and a documented owner.

If PROCESS is refused, SQLLens uses schema-scoped SELECT and visibly degrades
cross-user Statement Summary/Slow Query discovery. It must not request broader
privileges automatically.

The collector executes only parser-validated, allowlisted SELECT, SHOW, DESC,
and ordinary EXPLAIN. It rejects DML, DDL, ADMIN, SET GLOBAL, multiple
statements, and EXPLAIN ANALYZE.

### Prometheus

Prometheus has no universal default account. The wizard branches into:

- trusted TiUP/PingKai internal network with no application credential;
- Basic Auth managed by Prometheus/reverse-proxy administrators;
- Bearer Token or mTLS managed by a gateway/Kubernetes administrator.

The UI provides copyable discovery and up-query checks without placing a secret
in shell history. Grafana credentials are not treated as Prometheus credentials.
The collector uses fixed PromQL templates and never enables admin APIs or
exposes port 9090 publicly.

### TEM and Alertmanager

For TEM, the official navigation is Settings -> API Keys -> Create API Key. The
key is shown once and can be disabled or deleted. It must be dedicated to
SQLLens and tracked with an owner and expiry.

Public documentation does not guarantee fine-grained read-only scopes on every
TEM version. If preflight detects an over-broad key, the customer must explicitly
approve the residual risk or use a controlled Alertmanager read endpoint/manual
export. SQLLens never acknowledges, closes, silences, or modifies alerts.

## Evidence And Rule Architecture

### Evidence levels

- **E0**: SQL structure only. No production root-cause claim.
- **E1**: SQL + schema/index metadata.
- **E2**: E1 + statistics + ordinary plan.
- **E3**: E2 + runtime Statement/Slow Query evidence.
- **E4**: E3 + correlated Prometheus/TEM evidence.

Rules declare minimum evidence level, supported product/version range, required
fields, incompatible conditions, confidence ceiling, recommended action
template, validation, rollback, and official references.

The first rule pack is derived from the official SQL tuning documentation,
including SQL tuning overview, execution plan interpretation, indexes,
statistics, SQL Statements/Slow Query, optimizer behavior, and Plan Replayer.
Every implemented rule has fixtures for a positive hit, negative case, missing
evidence, and supported version.

### Rules and AI

Deterministic code owns source/version detection, evidence integrity and
completeness, measured values and derived features, rule matches and conflicts,
permission policy, and the recommendation allowlist.

AI may synthesize a Chinese explanation from validated facts and rule cards,
rank findings, propose bounded non-executing recommendations, and identify
missing evidence or competing explanations.

AI may not create or alter evidence, measurements, versions, or rule matches;
invent object names, SQL literals, gains, or confidence; invoke tools, fetch
URLs, execute SQL, apply a change, bypass the evidence ceiling, or publish
output that fails the schema and reference validator.

Each AI claim references existing evidence IDs and rule IDs. Invalid,
unreferenced, unsupported, timed-out, or oversized output is rejected and the
report degrades to rules only.

## Initial Contracts

### Source/v1

Source metadata is separate from an encrypted credential reference. Mutating
operations require CSRF protection, optimistic revision checks, and an audit
reason. Tests return capability details, not just a Boolean.

### Evidence/v2

Evidence is a standalone immutable envelope bound to one Case and, when
collected from a managed Source, one exact Source revision. It records payload
integrity, observation/collection time, freshness, coverage, sensitivity,
collector/query/redaction revisions, and timeout/row/byte budget consumption.
Large or sensitive payloads remain behind a storage reference.

### DiagnosisCase/v2

Raw evidence, derived facts, rule findings, AI contribution, actions,
review/feedback, workflow/outcome transition events, and validation results are
separate typed collections. Every reference resolves within the Case. AI claims
and actions are deterministic renderings of server-owned templates with typed
parameters. Provider, model, prompt, redacted-payload, payload digest, rule pack,
parser, redaction, source, and document revisions are pinned with field labels.

### DiagnosisReport/v1

The report is a rendered projection of a Case, not a second source of facts.
DBA/SRE, developer, and incident-owner views differ in emphasis only.

## Reuse And Refactor Decision

Keep:

- Python 3.12, FastAPI, React, and the parser-backed read-only SQL classifier;
- encrypted credential vault, session handling, idempotency, persistent job
  lease, audit foundations, and model egress budgets;
- immutable evidence references and provider revision pinning.

Refactor:

- first-run setup from terminal bootstrap code to localhost-only Owner creation;
- setup UI into a separate initialization shell and daily application shell;
- monolithic setup/diagnosis modules behind explicit Source, Evidence, Rule,
  Model Synthesis, and Report interfaces;
- model output from ID ranking only to the bounded structured synthesis contract;
- the current case UI into the Chinese decision report.

Remove from the customer path:

- fixed English low-confidence hypotheses and the fixed 20% report;
- terminal bootstrap-ingest and launcher-specific setup as the default path;
- RC, cross-platform clean-room, provenance, and full performance gates before
  the first product-value slice is approved.

This is an incremental refactor, not a language rewrite. Proven security and
durability code is retained while product-facing boundaries are replaced.

## Milestones

### M0: Product and contract freeze

- this spec, ADRs, clickable UI, three Chinese report fixtures, and typed
  contracts are reviewed;
- current code has a retain/refactor/remove map;
- no runtime feature starts against an unresolved contract.

### M1: Local value slice

- one official-image command reaches localhost first-run setup;
- Owner setup and data-source CRUD work;
- one fixture-backed abnormal SQL produces the approved Chinese report in rules
  and rules+AI modes;
- Human product review occurs before release work.

### M2: Managed TiDB evidence

- TiDB v8.5.x and PingKaiDB v7.1.x read-only preflight and bounded collection;
- Statement Summary/Slow Query/schema/stats/ordinary-plan evidence correlation;
- optional Prometheus and TEM/Alertmanager correlation.

### M3: Alternative evidence entry

- versioned Plan Replayer import with hostile-input controls;
- manual SQL/schema/plan/stats/runtime submission;
- all paths converge on DiagnosisCase/v2.

### M4: Release qualification

Only after Human product acceptance: multi-architecture image publication,
clean-machine verification, SBOM/signing/provenance, 2C4G qualification, upgrade,
rollback, and release review.

## P0 Acceptance

P0 does not pass unless:

- a new user reaches setup through one copied Docker command and localhost URL;
- data-source guidance is executable without consulting chat;
- the effective analysis mode is unmistakable;
- the primary abnormal-SQL journey uses real or representative TiDB evidence;
- the report is Chinese, actionable, evidence-bound, version-aware, and shows
  validation/rollback/uncertainty;
- no unsupported version, missing evidence, model output, or optional permission
  silently widens a conclusion;
- QA validates one frozen object once; Reviewer reviews only high-risk contracts
  and diffs; Human accepts the customer journey before release gates begin.

## Non-Goals For M1

- Kubernetes, remote/LAN deployment, offline installer, source-build journey;
- Windows/macOS/Linux clean-room matrix or formal release candidate;
- local GPU/model packaging;
- automatic SQL/index/binding/config changes;
- Clinic login scraping or generic server-side URL fetching;
- broad TEM administration or alert mutation;
- generic database support outside the two frozen product/version families.

## Reference Sources

- SQL tuning overview:
  https://pingkai.cn/docs/pingkaidb/stable/sql-tuning-overview
- Plan Replayer:
  https://pingkai.cn/docs/tidb/stable/sql-plan-replayer/
- PingKaiDB privilege management:
  https://pingkai.cn/docs/pingkaidb/stable/privilege-management
- TiDB Statement Summary:
  https://docs.pingcap.com/tidb/stable/statement-summary-tables/
- PingKaiDB Statement Summary:
  https://pingkai.cn/docs/pingkaidb/stable/statement-summary-tables
- TEM API Keys:
  https://pingkai.cn/docs/tem/stable/tem-system-management-api
- Prometheus Basic Auth:
  https://prometheus.io/docs/guides/basic-auth/
- Prometheus security:
  https://prometheus.io/docs/operating/security/
