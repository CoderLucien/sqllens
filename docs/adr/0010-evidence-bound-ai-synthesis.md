# ADR 0010: Evidence-Bound AI Synthesis

Status: Accepted for vNext P0
Date: 2026-09-02
Clarifies: ADR 0003
Replaces: the earlier ranking-only provider response contract

## Context

The first model adapter could only reorder deterministic hypothesis IDs.
Combined with SQL-structure-only rules, this produced low-confidence English
statements and no useful explanation or action. It was secure, but it did not
meet the promised AI diagnosis outcome.

Allowing free-form model diagnosis would create a different failure: invented
facts, unsupported object names, unsafe changes, and conclusions that exceed
the collected evidence.

## Decision

Deterministic collectors, parsers, feature extractors, rules, and policy remain
the authority for facts and safety. They produce:

- versioned evidence with integrity, time, freshness, and coverage;
- derived facts with input references;
- matched and contradicted rule cards;
- an evidence ceiling and uncertainty list;
- an allowlisted set of action templates.

The model receives only an allowlisted, redacted structured payload. It may
return template IDs, typed parameters, and existing evidence/rule IDs. It does
not return persisted customer-facing prose or executable steps. The service
deterministically renders the approved Chinese decision/claim/action templates
for:

- an executive conclusion assembled from validated facts;
- ordering and explanation of rule findings;
- bounded recommendation candidates selected from allowed action families;
- competing explanations and missing-evidence requests;
- audience-specific emphasis.

Every returned claim references existing evidence IDs and rule IDs. Every
recommendation references an allowed action family and includes risk,
prerequisites, validation, rollback, and human-approval requirements.

The validator rejects unknown IDs/templates, parameter mismatch, altered
rendered text, unknown action families, new measurements, new object names,
unsupported confidence, extra fields, unsafe verbs, and output above the
evidence ceiling. Invalid, unavailable, timed-out, or oversized output degrades
to a deterministic Chinese rules report.

The model cannot create evidence, change rule results, invoke a tool, fetch a
URL, execute SQL, apply a recommendation, or authorize data egress.

## Report Provenance

The report exposes:

- configured mode and effective mode;
- deterministic observations and rule IDs;
- model-authored sections and validation status;
- provider/model/prompt/payload/redaction revisions;
- the digest of the exact redacted structured payload;
- degradation or abstention reason.

Audience projections may rephrase emphasis but cannot alter facts, priority,
evidence, or action state.

## Consequences

- AI can add customer-visible value without becoming the evidence authority.
- The model contract and report renderer require new schemas and threat tests.
- Ranking-only provider code may be reused for transport/budgets, but its
  request and response contracts are replaced.
- ADR 0003 remains valid: the model is still an untrusted explainer. The
  ranking-only implementation remains historical code, not an active contract.
