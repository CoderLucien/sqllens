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

The pinned database version selects one versioned rule pack. A rule pack owns
its Evidence roles, eligibility requirements, predicate/threshold, hit/miss or
conflict state, severity, minimum evidence level, Chinese conclusion, and
document references as one deterministic projection. Only a `hit` rule may
support a Decision, Claim, or Action. `evidenceLevel`, completeness, and
uncertainty are computed from eligible Evidence used by the typed Fact; they
are not writable model or client assertions, and unrelated Evidence cannot
raise the ceiling.

The model receives only an allowlisted, redacted structured payload. It may
return template IDs, typed parameters, and existing evidence/rule IDs. It does
not return persisted customer-facing prose or executable steps. Numeric and
object parameters used by a decision reference a typed fact profile whose raw
fields are rebuilt from exact typed Evidence roles, kinds, schema revision, and
extraction revision. The typed projection has its own canonical digest and
server-rendered Evidence summary; ratios and
display-scale values are recomputed from those raw fields. The service
deterministically renders the fact plus every customer-visible decision field
(title, priority, conclusion, and evidence summary) and the approved Chinese
claim/action templates for:

- an executive conclusion assembled from validated facts;
- ordering and explanation of rule findings;
- bounded recommendation candidates selected from allowed action families;
- competing explanations and missing-evidence requests;
- audience-specific emphasis.

Every returned claim references existing evidence IDs and rule IDs. Every
recommendation references an allowed action family and includes risk,
prerequisites, validation, rollback, and human-approval requirements.

The validator rejects unknown IDs/templates, parameter mismatch, altered
rendered fact/decision/claim/action fields, unknown action families, new
measurements, new object names, unsupported confidence, extra fields, unsafe
verbs, and output above the evidence ceiling. Invalid, unavailable, timed-out,
or oversized output degrades to a deterministic Chinese rules report.

Typed Evidence digests pin `rfc8785-safe-integer/v1`, a restricted RFC
8785-compatible canonical JSON profile: keys use JCS ordering and measurements
use integer base units in the IEEE-754 safe range. Non-finite or fractional
typed measurements are rejected. JSON ingress rejects duplicate object members
before any parser can collapse them. This revision is part of the Evidence
envelope, not an implementation-specific JSON encoder default.

Evidence eligibility and diagnostic publication are separate. A missing,
stale, truncated, or zero-coverage role remains representable as a typed gap
Fact with deterministic per-role reasons, derived completeness, and an
actionless `evidence_insufficient` decision. Such a Fact cannot be converted
into a rule hit, AI claim, or Action. The service, not the Case caller, selects
role candidates: `MISSING_EVIDENCE` is legal only when the Case contains no
matching Evidence candidate, and a role cannot select an ineligible candidate
when an eligible one exists. Candidate matching uses both kind and the shared
typed profile fields declared by the dependency registry. Same-kind Evidence
whose declared object fields conflict cannot displace the compatible
candidate, and selected roles must form one jointly compatible profile.
When a corroborating role is missing, the selected role's declared shared
identity fields still anchor same-role candidate priority.

AI state is explicit. `applied` means a validated invocation contributed at
least one claim. `degraded` means an invocation was attempted and failed and
therefore retains the labeled invocation provenance plus a code and Chinese
reason. `abstained` means policy prevented invocation and therefore carries a
code and Chinese reason but no invocation pins. A configured `rules_ai` request
may become effective `rules` only through `degraded` or `abstained`; silence is
not a valid fallback. A configured `rules` request is always effective `rules`
with status `not_requested`; it cannot contain an invocation, model claim, or
provider/model/prompt/payload pin. Degradation, abstention, and not-requested
reasons are selected by server-owned codes and deterministically rendered into
the report rather than persisted as provider-authored prose.

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

Audience projections may select emphasis but cannot alter the deterministic
facts, decision priority or summary, evidence, or action state.

## Consequences

- AI can add customer-visible value without becoming the evidence authority.
- The model contract and report renderer require new schemas and threat tests.
- Ranking-only provider code may be reused for transport/budgets, but its
  request and response contracts are replaced.
- ADR 0003 remains valid: the model is still an untrusted explainer. The
  ranking-only implementation remains historical code, not an active contract.
