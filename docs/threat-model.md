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
| Source lifecycle | Rotation/delete invalidates an active job, silently erases a lease, rewrites old audit history, or leaves a usable deleted secret | Immutable source and credential revisions; append-only state and per-lease audit; monotonic revision/credentialRevision; drain admission preserves leases; each release/cancel names lease and job and decrements one; forced cancel requires prior Owner approval; operation matches pending operation; delete only at zero leases; metadata-only tombstone | Prior/proposed tamper tests; concurrent rotation/disable/delete; entry-with-live-leases, normal-release, forced-cancel, crash-recovery, verification-state, and tombstone tests |
| TiDB | Expensive or active query harms workload | Time/row/concurrency budget, service timeout, cancel/kill, version gate, kill switch | Enabled/disabled A/B and fault injection |
| Prometheus | Huge range/cardinality exhausts service | Query/range/step/series/point budgets, timeout, cancellation, queue limit | Cardinality and timeout tests |
| Provider | Confidential data leaves deployment | Typed sensitivity allowlist, redaction, egress host allowlist, payload audit digest | Data-egress canary suite |
| LLM output | Hallucination or prompt injection injects a destructive conclusion/action or fabricated measurement | Model selects only server-owned template IDs and typed parameters; numeric/object fields originate in evidence-bound typed facts; full fact/decision/claim/action deterministic rendering; explicit degraded versus non-invoked abstention; labeled provider/model/prompt/redacted-payload digest/redaction provenance; no tool/execution path | Destructive SQL, fabricated measurement, altered priority/evidence summary, wrong evidence kind, silent fallback, unknown template, altered rendering, provenance omission, injection, and malformed-output corpus |
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
- An applied or degraded model attempt records the exact provider, model, prompt,
  redacted payload revision/digest, and redaction revision.
- A configured Rules + AI request that becomes Rules only records either a
  failed attempted invocation (`degraded`) or a non-invoked policy decision
  (`abstained`), each with a machine code and Chinese reason.
- Source, Case, and outcome audits are append-only; referenced audit/evidence
  records exist no later than the event that consumes them. Drain admission
  preserves active leases; each later release/cancel is individually audited.
- All evidence frozen into the ready diagnosis exists no later than the ready
  event and the Case revision `updatedAt`. The first `pending -> terminal`
  outcome event carries its complete causal chain and cannot be backfilled.
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
