# ADR 0010: Evidence-Bound AI Synthesis

Status: Accepted for vNext P0
Date: 2026-09-02
Clarifies: ADR 0003
Supersedes: ADR 0008 ranking-only output

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
return a typed Chinese synthesis containing:

- an executive conclusion assembled from validated facts;
- ordering and explanation of rule findings;
- bounded recommendation candidates selected from allowed action families;
- competing explanations and missing-evidence requests;
- audience-specific emphasis.

Every returned claim references existing evidence IDs and rule IDs. Every
recommendation references an allowed action family and includes risk,
prerequisites, validation, rollback, and human-approval requirements.

The validator rejects unknown IDs, unknown action families, new measurements,
new object names, unsupported confidence, unbounded text, extra fields, unsafe
verbs, and output above the evidence ceiling. Invalid, unavailable, timed-out,
or oversized output degrades to a deterministic Chinese rules report.

The model cannot create evidence, change rule results, invoke a tool, fetch a
URL, execute SQL, apply a recommendation, or authorize data egress.

## Report Provenance

The report exposes:

- configured mode and effective mode;
- deterministic observations and rule IDs;
- model-authored sections and validation status;
- provider/model/prompt/payload/redaction revisions;
- degradation or abstention reason.

Audience projections may rephrase emphasis but cannot alter facts, priority,
evidence, or action state.

## Consequences

- AI can add customer-visible value without becoming the evidence authority.
- The model contract and report renderer require new schemas and threat tests.
- Ranking-only provider code may be reused for transport/budgets, but its
  request and response contracts are replaced.
- ADR 0003 remains valid: the model is still an untrusted explainer. ADR 0008
  remains historical evidence for the narrower implementation.
