# ADR 0008: Bounded External Model Ranking

Status: Accepted for P0 Layer 1
Date: 2026-09-01

## Context

External-model mode must exercise the configured provider in Layer 1 without
allowing SQL text, identifiers, literals, credentials, or model-created facts to
cross the trust boundary. OpenAI-compatible providers also vary in their support
for Structured Outputs, so a provider incompatibility cannot make deterministic
diagnosis unavailable.

## Decision

The gateway calls the configured HTTPS origin's `/chat/completions` endpoint
with `response_format.type=json_schema`, `strict=true`, no tools, and a fixed
prompt revision. The outbound user payload is a typed metadata-only allowlist:
evidence completeness, generic structural evidence, existing hypothesis IDs,
generic deterministic statements, bounded confidence, and existing evidence
references. It never contains SQL text, schema identifiers, literal values, or
the API key.

The only accepted model output is a complete permutation of the hypothesis IDs
already created by deterministic rules. The service validates the provider
envelope, finish reason, strict response object, item count, uniqueness, and
exact ID set. It then changes only display order; it does not create evidence,
change confidence, promote a candidate, add a recommendation, or persist model
prose.

The HTTP exchange has a total deadline and a streamed response byte limit.
Timeouts, HTTP errors, rate limits, oversized bodies, unsupported Structured
Outputs, malformed JSON, and unknown or missing IDs produce an explicit
degradation code while the deterministic Diagnosis Case remains available. The
job records the payload schema, egress policy, and SHA-256 digest of the
redacted payload, not the payload or credential.

Job admission is a persistent singleton lease by default. The idempotency key
is reserved before SQL parsing or provider egress; replays read the same job,
while a different key over capacity receives `429` without parsing or leaving
the deployment. The admission transaction also snapshots the provider model,
egress policy, allowlist, and encrypted credential reference. Actual provider
calls and Case provenance use only that snapshot. Credential rotation or
deletion returns `409` while the lease is active, and every completed, failed,
cancelled, or startup-recovered job releases the lease.

OpenAI documents `json_schema` as the preferred structured response format for
models that support it and documents `strict` schema adherence as a supported
option with a JSON Schema subset. These sources define the wire shape used by
the P0 compatibility adapter:

- <https://platform.openai.com/docs/api-reference/chat/create>
- <https://platform.openai.com/docs/guides/structured-outputs>

## Consequences

- Model quality can affect hypothesis order only; deterministic evidence and
  abstention remain authoritative.
- Providers without compatible Structured Outputs operate in deterministic
  degraded mode instead of blocking the SQL workflow.
- Prompt, payload schema, egress policy, provider, model, parser, rule, policy,
  and redaction revisions remain auditable per job/case.
- Adding model-authored explanations later requires a new output contract,
  rendering threat review, and explicit provenance rather than widening this
  adapter silently.
