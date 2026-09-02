# P0 Threat Model

## Assets

- TiDB and Prometheus credentials and endpoints.
- External model API credentials.
- SQL text, schema identifiers, statistics, metrics, logs, and plan artifacts.
- Admin session, setup state, policy configuration, audit records, and cases.
- Host CPU, memory, GPU, disk, network, and the production database budget.

## Trust Boundaries

1. Browser to Web/API.
2. Empty-instance local first run to initialized Owner/session state.
3. Application to TiDB and Prometheus.
4. Application to an external or local model provider.
5. Uploaded archives/reports to the importer workspace.
6. Internal application network to a future local model controller (deferred
   from vNext P0; retained as a historical design boundary).
7. LLM output to the domain engine and rendered UI.

## Primary Abuse Cases And Controls

| Boundary | Abuse case | Required control | Verification |
|---|---|---|---|
| Setup | Remote or hostile-origin user races first Owner creation | Loopback publication; exact `Host` and `Origin`; no forwarded-header trust or CORS; short-TTL single-use nonce bound to HttpOnly SameSite=Strict cookie; CSRF header; rate limit; atomic uniqueness | Host/Origin/DNS-rebinding/forwarded-spoof tests, nonce expiry/replay, parallel creation |
| Session | CSRF, fixation, brute force, stolen cookie | Rotation, HttpOnly Secure SameSite cookie, CSRF token, idle/absolute expiry, throttling | API/browser abuse tests |
| Connector | Credential disclosure or privilege escalation | Encrypted secret store, log redaction, fixed query/privilege matrix, TLS verification | Canary secret tests and least-privilege integration |
| Source lifecycle | Rotation/delete/verification failure invalidates an active job, silently erases or invents a lease, rewrites old audit history, poisons a prior snapshot, or leaves a usable deleted secret | Immutable source and credential revisions; unified full-history state/lease replay from revision 1; append-only acquisition/release/cancel ledger; never-reused lease/job IDs; active snapshot and count rebuilt from ledger; admission/release/cancel must be strictly earlier than the same-revision state snapshot (equal timestamps fail closed); drain admission preserves identities; each release/cancel removes one acquired identity; forced cancel requires prior Owner approval; operation matches pending operation; delete only at zero leases; metadata-only tombstone | Standalone-snapshot and prior/proposed tamper tests; concurrent rotation/disable/delete/verification failure; acquisition, entry-with-live-leases, identity mismatch, normal-release, forced-cancel, equal-time/cross-ledger event-order, crash-recovery, verification-state, and tombstone tests |
| TiDB | Expensive or active query harms workload | Time/row/concurrency budget, service timeout, cancel/kill, version gate, kill switch | Enabled/disabled A/B and fault injection |
| Prometheus | Huge range/cardinality exhausts service | Query/range/step/series/point budgets, timeout, cancellation, queue limit | Cardinality and timeout tests |
| Provider | Confidential data leaves deployment | Typed sensitivity allowlist, redaction, egress host allowlist, payload audit digest | Data-egress canary suite |
| LLM output | Hallucination or prompt injection injects a destructive conclusion/action, fabricated measurement, non-hit rule, suppressed eligible Evidence, or self-declared evidence strength | Model selects only server-owned template IDs and typed parameters; numeric/object fields originate in eligible evidence-bound typed facts; restricted RFC 8785 digest and strict ingress reject duplicate keys and non-finite/fractional measurements; versioned rule registry owns predicates/status/severity/text/references; the service selects role candidates and derives level/completeness/uncertainty; incomplete roles produce only an actionless gap decision; full fact/decision/claim/action deterministic rendering; explicit degraded versus non-invoked abstention; labeled provider/model/prompt/redacted-payload digest/redaction provenance; no tool/execution path | Destructive SQL, low-signal/non-hit rule, stale/zero/truncated or deliberately ignored eligible Evidence, action injection into evidence-insufficient Cases, self-raised level, duplicate keys, NaN/Infinity, fabricated measurement, typed-payload/summary tampering, altered priority/evidence summary, wrong evidence kind, silent fallback, unknown template/pack, altered rendering, provenance omission, injection, and malformed-output corpus |
| Outcome audit | A terminal state combines unrelated approvals/results, uses an automated or replayed stale approval, forges authorization, rewrites an approved Action threshold, changes strict/inclusive boundary semantics, omits required measurements, or claims effect/rollback without qualifying Evidence | One singular Action/approval/implementation/result/terminal-feedback tuple owned by the current Case revision; exact event projection; opaque lookup into a trusted server authorization audit for a real user and exact canonical Action digest, captured within the Case/revision authorization window; eligible result Evidence whose metric code/unit/target are bound to the complete versioned Action measurement policy; numeric predicates recomputed by the server with no writable pass flag and boundary semantics matching the approved Action text; confirmed rollback after a failed predicate; causal timestamp order | Multiple-tuple, system/forged/stale approval, missing resolver/record, Action-digest mismatch, old revision, equality at a strict threshold, missing/wrong metric, contradictory numeric effect, failed rollback, ineligible/extra result, and time-travel counterexamples |
| Archive | Traversal, links, special files, zip bomb | Stream processing, path normalization, reject links/special files, entry/ratio/size/time/disk limits | Malicious archive corpus |
| URL import | SSRF, DNS rebinding, redirect credential leak | Disabled in P0; future pinned resolution, private/reserved rejection, no redirects | Contract/security review before enablement |
| Jobs | Queue or temp disk denial of service | Admission control, concurrency 1 default, per-job/global disk budget, cancellation and cleanup | Load, restart, and disk-exhaustion tests |
| Deferred local model | Future controller enables lateral movement or host takeover | Not shipped in vNext P0; any future controller requires internal auth, no host port, no Docker Socket, no host filesystem, pinned artifact | New ADR plus Compose/network inspection and image scan before enablement |
| UI | Stored/reflected XSS from SQL/log/model text | Framework escaping, CSP, no unsafe HTML, safe downloads | Browser security tests |

## Security Invariants

- Setup-finalized diagnosis APIs cannot be reached before initialization.
- First-run trust never derives from container peer IP or proxy headers.
- Owner creation requires the canonical localhost Host/Origin and a fresh
  cookie-bound nonce; the database uniqueness constraint remains authoritative.
- No application API executes a recommendation or arbitrary SQL.
- No secret appears in response bodies, normal logs, traces, or model payloads.
- Any evidence reference in model output resolves to existing immutable evidence.
- Model-authored output cannot persist free-form measurements, decision text,
  priority, evidence summary, action steps, or rollback text; typed fact
  parameters bind exact evidence kinds, derived ratios are recomputed from raw
  measurements, and every fact/decision/claim/action must equal its
  deterministic server-template rendering.
- Evidence strength is not a caller assertion: kind-specific freshness,
  coverage, completion, truncation, records, and rows determine eligibility;
  only supporting Fact roles derive level and completeness. The versioned rule
  pack deterministically owns predicates, hit status, severity, conclusion, and
  document references, and only a hit rule may support a decision or action.
- Every JSON ingress rejects duplicate object members. Typed Evidence
  canonicalization rejects NaN, Infinity, fractional measurements, and
  integers outside the cross-language safe range.
- An applied or degraded model attempt records the exact provider, model, prompt,
  redacted payload revision/digest, and redaction revision.
- A configured Rules + AI request that becomes Rules only records either a
  failed attempted invocation (`degraded`) or a non-invoked policy decision
  (`abstained`), each with a machine code and Chinese reason.
- A configured Rules-only request records `not_requested`, has no invocation or
  provider pins, and projects the server-owned Chinese reason into the report.
- Source, Case, and outcome audits are append-only; referenced audit/evidence
  records exist no later than the event that consumes them. Drain admission
  preserves the replayed active lease identities; the complete state and lease
  ledgers are replayed together before trusting any snapshot; acquisitions and
  each later release/cancel are individually audited and the Source count is
  derived from that ledger.
- All evidence frozen into the ready diagnosis exists no later than the ready
  event and the Case revision `updatedAt`. The first `pending -> terminal`
  outcome event carries one singular causal tuple and cannot be backfilled.
  Human approval is a real user bound through an opaque reference to a trusted
  server authorization audit; all tuple records belong to the current Case
  revision. Terminal effect/rollback Evidence must be eligible and provide the
  complete Action-owned measurement set; the server recomputes every numeric
  predicate instead of trusting a persisted pass flag.
- Archive processing cannot write outside its job directory.
- A failed/cancelled job releases queue, file, and connector resources.
- External mode does not download local model weights.
- A missing GPU cannot be represented as a verified local runtime.

## Declared Trust Assumptions

During empty-instance first run, vNext P0 trusts the local operating-system
account, browser profile, and Docker administrator. Loopback publication blocks
network peers but cannot distinguish the intended browser from a malicious
process already running under that local authority. Docker bridge/NAT source IP
is therefore not an identity signal. Defending against a hostile local peer
requires an out-of-band secret or operating-system identity integration and is
outside the no-code P0 journey.

## Release Evidence

QA must record environment, commands, fixtures, expected and actual outcomes,
and raw machine-readable results. Failed, blocked, skipped, and unverified are
separate states. Critical/high findings block release unless the Human explicitly
accepts the exact residual risk.
