# Contract Fixtures

`diagnosis-case-v1.schema.json` defines the serializable P0 case envelope.

The examples serve two different assertions:

- `examples/diagnosis-case-v1.valid.json` must validate.
- `examples/diagnosis-case-v1.invalid-missing-owner.json` must fail because a
  recommendation cannot omit its accountable owner.
- `examples/diagnosis-case-v1.invalid-reference.json` must pass JSON Schema but
  fail domain validation because it contains dangling evidence/recommendation
  references.

Run the local contract check with:

```bash
python3 docs/contracts/validate_examples.py
```

JSON Schema cannot prove that evidence and recommendation IDs referenced by a
hypothesis, review, or feedback record exist in the same case. The domain layer
must enforce referential integrity, append-only review/feedback records, legal
workflow transitions, and immutable prior revisions. Those are separate domain
contract checks in `validate_examples.py`, not release assumptions. Production
code will move the same rules into the domain package and call them before a
revision is persisted.
