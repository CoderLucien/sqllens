# QA-018: External Provider Credential Is Discarded At Finalize

Status: OPEN
Severity: High
Detected against: `feature/p0-runtime@d2d4a76`
Owner: runtime owner (`#t10`), not QA
Regression tests: required with a credential canary and a restarted runtime

## Impact

The external provider API key is used only for the setup `/models` probe.
`setup_state` stores the base URL, model, status, and timestamps, but no
encrypted credential or recoverable credential reference exists. Setup can
nevertheless finalize as `external`, and restart reports external mode ready.

Layer 1 cannot authenticate its next model request after setup or restart.
The product therefore persists a ready state that cannot provide the selected
mode's core capability.

## Reproduction

QA completed an external probe with a canary key, finalized, reopened the
application, and inspected the persistent store:

```text
probe HTTP status               = 200
finalize HTTP status            = 200
restart initialized/model_mode  = true / external
SQLite credential-like columns = []
SQLite tables                   = [setup_state]
plaintext canary on disk        = false
```

The plaintext exclusion is correct, but there is also no encrypted material
or reference from which an authenticated provider call can be made.

## Required Disposition

- Persist provider credentials through the frozen encrypted-secret boundary,
  or refuse to enter/retain `external` ready state when the credential cannot
  be recovered.
- Implement rotation, deletion, revision pinning, and cascade behavior without
  writing plaintext to API responses, logs, environment, command line,
  SQLite, diagnostics, or cases.
- Prove an authenticated provider request succeeds after application and
  container restart, then prove rotation and deletion take effect.
- Retain canary scans of all persisted and generated artifacts.

This finding blocks the external-model initial version.
