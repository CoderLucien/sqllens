# QA-014: Purge Leaves A Stale Bootstrap Marker

Status: OPEN
Severity: Medium
Detected against: `feature/cross-platform-release@7bbb8da`
Owner: cross-platform release owner (`#t16`), not QA
Regression tests: required in `tests/release/test_launch_sh.py`

## Impact

After a successful start, the host contains an empty `bootstrap-code` and a
`bootstrap-hash-persisted` marker. `uninstall --purge-data` deletes the Docker
volume but leaves both host files. A subsequent clean start trusts the stale
marker, skips code generation, and passes an empty secret to a new database.
The runtime cannot persist a verifier, so the launcher times out. Recovery
requires an undocumented manual deletion and violates the clean reinstall
contract.

## Reproduction

QA simulated a successful prior handshake, ran the real purge action, and
started against a new empty-volume fake runtime. The purge reported success,
the marker remained `v1`, OpenSSL was never called, and start failed with:

```text
runtime did not confirm bootstrap hash persistence
```

## Required Disposition

- On successful explicit data purge, remove the host bootstrap marker, secret,
  and other installation state that derives from the deleted database.
- Do not clear those files for `stop` or the default data-retaining uninstall.
- Add `start -> purge -> fresh start` coverage proving a new code is generated
  and the new runtime can persist its verifier.
- Define failure ordering so host state is not cleared when volume removal
  fails.

This finding blocks purge/reinstall acceptance but not the data-retaining stop
path.
