# QA Evidence Record

Copy this template per execution batch. Do not replace raw artifacts with this
summary; link their sanitized locations and hashes.

## Run Identity

- Run ID:
- Test case IDs:
- Start/end time (UTC):
- QA owner:
- Source commit:
- Dirty worktree patch hash or `clean`:
- Result: `PASS` / `FAIL` / `BLOCKED`
- Defect IDs, when failed:

## Environment

- Environment ID: `E0` / `E1` / `E2` / `E3` / `E4`
- Host OS/kernel/architecture:
- CPU/RAM/disk:
- Container runtime and Compose versions:
- Rendered Compose config hash:
- Image names and immutable digests:
- TiDB/Prometheus topology and versions, when applicable:
- Grants hash and allowlist revision, when applicable:
- GPU/driver/runtime/model revisions and hashes, when applicable:

## Fixture And Policy Revisions

- Fixture manifest and hashes:
- Setup/security/egress/redaction policy revisions:
- Provider/model/prompt revision:
- Connector query policy revision:
- Importer budget policy revision:
- Performance corpus, warmup, samples and thresholds:

## Procedure

```text
Exact commands and ordered user actions.
```

## Expected Result

State every observable assertion, including terminal state, audit record,
cleanup, secret handling and resource budget.

## Actual Result

State what happened. Do not use "works", "looks good", or implementation-owner
claims as evidence.

## Raw Evidence

- Test/JUnit report path and SHA-256:
- Sanitized stdout/stderr path and SHA-256:
- Request/response trace path and SHA-256:
- Audit identifiers:
- Metrics/time-series path and SHA-256:
- Screenshot/trace/video path and SHA-256, when applicable:
- Temporary workspace before/after observations:

## Resource Result

- Aggregate cgroup CPU limit observed:
- Aggregate cgroup memory limit observed:
- Peak RSS/working set:
- CPU peak and integrated CPU time:
- Persistent and temporary disk peak/delta:
- P50/P95/P99 latency and sample count:
- Queue depth and rejection count:
- Cancellation/fuse/OOM behavior and recovery time:

## Security And Privacy Check

- Canary search locations and result:
- Logs/errors checked for SQL literals, credentials, tokens and internal paths:
- Provider egress capture checked:
- Raw evidence sanitized without destroying failure reproducibility:

## Disposition

- Requirement mapping:
- Pass/fail/block rationale:
- Missing prerequisite, when blocked:
- Minimum reproduction, when failed:
- Severity and user impact:
- Retest scope after fix:
- Residual risk and owner:
