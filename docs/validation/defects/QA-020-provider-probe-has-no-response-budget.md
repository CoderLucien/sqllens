# QA-020: Provider Probe Has No Response Budget

Status: OPEN
Severity: Medium
Detected against: `feature/p0-runtime@d2d4a76`
Owner: runtime owner (`#t10`), not QA
Regression tests: required against the fake provider

## Impact

The provider probe calls `response.json()` and constructs a set from every
model entry. It has socket-operation timeouts, but no total deadline, response
byte limit, model-entry limit, or field-size budget. An allowed but faulty or
hostile provider can force the 2C4G application to buffer and parse an
arbitrarily large response during setup.

This can cause excessive memory/CPU use or a cgroup OOM before the product can
degrade to rules mode.

## Reproduction

QA used `httpx.MockTransport` to return 25,001 model entries with the requested
model last. The exact gateway returned:

```json
{"model_entries": 25001, "result": {"status": "verified"}}
```

Static inspection confirms the response is fully buffered and parsed before
any validation of collection or field size.

## Required Disposition

- Enforce a total request deadline and stream a capped number of response
  bytes before JSON parsing.
- Bound model-entry count, identifier length, nesting, and accepted schema.
- On any limit, return the generic provider-unavailable result without
  reflecting provider content or credentials.
- Add exact-boundary and over-boundary tests plus a 2C4G/OOM regression.

This finding blocks provider-probe resource acceptance but not rules-only mode.
