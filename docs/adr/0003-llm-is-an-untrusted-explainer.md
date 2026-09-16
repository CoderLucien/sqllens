# ADR 0003: The LLM Is An Untrusted Explainer

Status: Accepted for P0 baseline
Date: 2026-08-31

## Context

Diagnosis uses sensitive SQL and operational evidence. A model can hallucinate,
follow prompt injection embedded in logs, return invalid data, or expose input
to an external provider. It must not become the source of truth or an execution
control plane.

## Decision

Deterministic collectors, parsers, rules, and policy code create evidence and
evidence completeness. The LLM may rank or explain bounded hypotheses using an
allowlisted, redacted summary. It cannot create evidence, invoke tools, execute
SQL, fetch URLs, or apply recommendations.

Every outbound field has a sensitivity label. Only fields allowed by the active
egress policy can enter the provider payload. Credentials, tokens, SQL literals,
row data, raw logs, and confidential evidence are excluded. The system records
the payload schema, policy decision, and digest without retaining the sensitive
payload in normal logs.

Model output must validate against a strict versioned schema. Evidence IDs must
exist in the case, numeric values must stay within declared ranges, and unknown
fields are rejected. Invalid, timed-out, or unavailable model output degrades to
deterministic rule results.

## Consequences

- Model quality affects explanation quality, not collection authority.
- Prompt injection is treated as untrusted input, not an instruction channel.
- Provider/model/prompt/policy/redaction revisions are pinned per job.
- The UI distinguishes deterministic observations, hypotheses, and human
  approval; no model response is presented as an executed change.
