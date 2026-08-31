# QA-001: DiagnosisCase V1 Does Not Enforce Required Provenance Integrity

Status: OPEN, release blocking
Severity: High
Detected against: `main@024f2ce`
Owner: contract/domain owner (`#t8`), not QA
Regression tests: `tests/qa/test_diagnosis_case_contract.py`

## Impact

The current schema and example validator allow an apparently valid case to lose
or ambiguously rewrite the evidence and model/policy revisions behind a
recommendation. That breaks the evidence-first and auditable-case guarantees and
can make two readers resolve the same stable ID to different records.

## Findings

### QA-001A: A Recommendation Can Have No Evidence

Severity: High

Set a valid recommendation's `evidenceIds` to `[]`. JSON Schema validation still
succeeds because `minItems` is absent. The P0 contract requires every conclusion
to have provenance and insufficient evidence to produce abstention.

Expected: reject the case, or represent the evidence gap as a real referenced
evidence item under a separately frozen contract.

### QA-001B: Stable IDs Are Not Unique

Severity: High

Append a second evidence or recommendation record reusing the first record's ID.
`validate_references()` succeeds because it converts IDs to sets but never checks
for duplicates. References are then ambiguous and append-only history does not
restore their meaning.

Expected: domain validation rejects duplicate evidence, hypothesis,
recommendation, review and feedback IDs before persistence.

### QA-001C: Pinned Revisions Are Incomplete And Mutable

Severity: High

The Schema requires only `ruleSet`, `policy` and `redaction`; it accepts cases
that omit `provider`, `model`, `modelArtifact` or `prompt` instead of explicitly
recording `null`. `validate_revision()` also accepts changing a pinned policy or
model field in a later case revision.

Expected: all pin fields are required (nullable where no model participated) and
the complete `pinnedRevisions` object is immutable across case revisions.

### QA-001D: Claimed Workflow Transition Validation Is Missing

Status: BLOCKED pending state-transition contract
Severity: High if shipped as documented

`docs/contracts/README.md` says legal workflow transitions are domain contract
checks in `validate_examples.py`, but that file currently validates revision
increments, selected stable fields, timestamps and append-only arrays only. No
allowed transition graph or outcome-transition check exists.

Expected: freeze the workflow/outcome transition table, implement negative
fixtures for illegal transitions, and keep workflow, review decision, feedback
and outcome independent as required by the design.

## Minimum Reproduction

```bash
python3 -m unittest discover \
  -s tests/qa \
  -p 'test_diagnosis_case_contract.py' \
  -v
```

Actual result at detection: 5 tests fail with 8 failed assertions. The four
nullable pin fields account for four subtest failures.

## Location Hints

- `docs/contracts/diagnosis-case-v1.schema.json`: `pinnedRevisions` required
  fields and `recommendation.evidenceIds` cardinality.
- `docs/contracts/validate_examples.py`: ID uniqueness, pinned revision
  immutability and legal transition validation.
- `docs/contracts/examples/`: add focused negative examples rather than relying
  only on mutations inside the script.

## Retest And Regression Scope

1. Run the focused command above and require all tests to pass.
2. Run `python3 docs/contracts/validate_examples.py`.
3. Run the complete QA suite.
4. Verify product persistence calls the same domain rules before writing a new
   revision; passing a documentation-only validator is not product acceptance.
