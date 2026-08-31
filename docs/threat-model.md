# P0 Threat Model

## Assets

- TiDB and Prometheus credentials and endpoints.
- External model API credentials.
- SQL text, schema identifiers, statistics, metrics, logs, and plan artifacts.
- Admin session, setup state, policy configuration, audit records, and cases.
- Host CPU, memory, GPU, disk, network, and the production database budget.

## Trust Boundaries

1. Browser to Web/API.
2. One-time bootstrap to initialized admin/session state.
3. Application to TiDB and Prometheus.
4. Application to an external or local model provider.
5. Uploaded archives/reports to the importer workspace.
6. Internal application network to the model controller.
7. LLM output to the domain engine and rendered UI.

## Primary Abuse Cases And Controls

| Boundary | Abuse case | Required control | Verification |
|---|---|---|---|
| Setup | Remote user races first admin creation | Loopback default, single-use short-TTL secret, rate limit, setup API allowlist | Parallel/bootstrap expiry tests |
| Session | CSRF, fixation, brute force, stolen cookie | Rotation, HttpOnly Secure SameSite cookie, CSRF token, idle/absolute expiry, throttling | API/browser abuse tests |
| Connector | Credential disclosure or privilege escalation | Encrypted secret store, log redaction, fixed query/privilege matrix, TLS verification | Canary secret tests and least-privilege integration |
| TiDB | Expensive or active query harms workload | Time/row/concurrency budget, service timeout, cancel/kill, version gate, kill switch | Enabled/disabled A/B and fault injection |
| Prometheus | Huge range/cardinality exhausts service | Query/range/step/series/point budgets, timeout, cancellation, queue limit | Cardinality and timeout tests |
| Provider | Confidential data leaves deployment | Typed sensitivity allowlist, redaction, egress host allowlist, payload audit digest | Data-egress canary suite |
| LLM output | Hallucination or prompt injection triggers action | Strict output schema, evidence-ID validation, no tool/execution path, safe rendering | Injection and malformed-output corpus |
| Archive | Traversal, links, special files, zip bomb | Stream processing, path normalization, reject links/special files, entry/ratio/size/time/disk limits | Malicious archive corpus |
| URL import | SSRF, DNS rebinding, redirect credential leak | Disabled in P0; future pinned resolution, private/reserved rejection, no redirects | Contract/security review before enablement |
| Jobs | Queue or temp disk denial of service | Admission control, concurrency 1 default, per-job/global disk budget, cancellation and cleanup | Load, restart, and disk-exhaustion tests |
| Model controller | Lateral movement or host takeover | Internal-only auth, no host port, no Docker Socket, no host filesystem, pinned artifact | Compose/network inspection and image scan |
| UI | Stored/reflected XSS from SQL/log/model text | Framework escaping, CSP, no unsafe HTML, safe downloads | Browser security tests |

## Security Invariants

- Setup-finalized diagnosis APIs cannot be reached before initialization.
- No application API executes a recommendation or arbitrary SQL.
- No secret appears in response bodies, normal logs, traces, or model payloads.
- Any evidence reference in model output resolves to existing immutable evidence.
- Archive processing cannot write outside its job directory.
- A failed/cancelled job releases queue, file, and connector resources.
- External mode does not download local model weights.
- A missing GPU cannot be represented as a verified local runtime.

## Release Evidence

QA must record environment, commands, fixtures, expected and actual outcomes,
and raw machine-readable results. Failed, blocked, skipped, and unverified are
separate states. Critical/high findings block release unless the Human explicitly
accepts the exact residual risk.
