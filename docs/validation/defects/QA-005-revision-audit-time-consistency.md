# QA-005: Revision Audit Times Are Not Consistently Enforced

**Status:** OPEN  
**Severity:** Medium  
**Release impact:** Blocks audit-ordering claims for the contract baseline.

## QA-005A: Appended Audit Records Can Be Backdated Or Future-Dated

For revision 2 with `updatedAt=2026-08-31T10:00:02Z`, append a feedback record
whose `createdAt` is either before revision 1's `updatedAt` or after revision
2's `updatedAt`. `validate_revision()` accepts both because it checks only the
top-level `updatedAt` values and append-only prefixes.

Impact: approval/feedback history can be ordered outside the revision that
persisted it, undermining same-revision trigger, audit ordering and freshness
claims.

Expected: every newly appended review/feedback record is later than the prior
revision's `updatedAt` and no later than the proposed revision's `updatedAt`.
Records appended together must be chronological. For revision 1, review and
feedback timestamps must fall between the case's `createdAt` and `updatedAt`.
The domain owner should define corresponding bounds for other newly appended
record types where their timestamps have different semantics.

## QA-005B: Accepted RFC 3339 Input Fails Revision Parsing

The exported `FORMAT_CHECKER` accepts a lower-case RFC 3339 `z`, but
`validate_revision()` parses it with `datetime.fromisoformat()` after replacing
only upper-case `Z`. Thus a schema-valid timestamp raises an unrelated parser
error in revision validation.

Expected: the format checker and temporal comparison use one normalization
function, or the format checker rejects values that the comparison path cannot
consume.

## Reproduction

```bash
python3 -m unittest \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_new_audit_records_must_fall_inside_the_revision_time_window \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_initial_audit_records_must_fall_inside_the_case_time_window \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_new_audit_records_are_chronologically_ordered \
  tests.qa.test_diagnosis_case_contract.DiagnosisCaseContractTest.test_schema_valid_lowercase_z_is_compatible_with_revision_validation \
  -v
```

Expected: both tests pass.

Actual: the time-window test raises no validation error, and the lower-case
`z` path raises `ValueError: Invalid isoformat string`.
