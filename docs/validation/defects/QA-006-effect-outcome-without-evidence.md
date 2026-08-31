# QA-006: Effect Outcomes Have No Evidence Binding

**Status:** OPEN  
**Severity:** High  
**Release impact:** Blocks the evidence-first DiagnosisCase contract and the
change-effect closure journey.

## Requirement

After a DBA-approved production change, the product compares the same SQL
Digest's P95/P99, total time, scanned rows, RU and plan stability. A completed
case may be `validated_effective` or `rolled_back` only from auditable result
evidence, not from an ungrounded user label. QA cases `CASE-002`, `CASE-006` and
`CASE-007` cover evidence binding, retained revisions and terminal outcomes.

## Actual

The contract's feedback record can reference a recommendation but cannot
reference evidence. There is no alternative top-level outcome-evidence field.
The current outcome draft accepts `validated_effective` when it finds approved,
implemented and validated records, even if the only evidence kind in the case
is the original `sql_rule`.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_effect_outcomes_have_a_machine_validated_evidence_binding \
  -v
```

Expected: the serialized contract has a machine-validatable outcome evidence
binding, omitting it is rejected, and dangling evidence IDs are rejected.

Actual: neither `feedback.evidenceIds` nor `case.outcomeEvidenceIds` exists.

## Required Disposition

Add a non-empty evidence binding for `validated_effective` and `rolled_back`.
QA accepts either terminal-feedback evidence IDs or a dedicated top-level
outcome-evidence collection. Domain validation must reject empty, dangling and
inappropriate references and preserve the binding across immutable revisions.
The exact evidence kinds and minimum metric set should be frozen with the
effect-validation policy; a comment or thumbs-up is not sufficient evidence.
