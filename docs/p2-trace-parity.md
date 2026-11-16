# P2 trace normalization and backend parity

## Purpose

P2 introduces a canonical TraceEvent contract so Forge state-diff and Anvil call traces can be compared without changing the meaning of missing evidence. The existing v1 trace fields remain available to older readers during migration. P2 v2 is emitted separately as canonical_trace_events with canonical_trace_schema_version: 2.

## Canonical TraceEvent v2

Each event contains exactly these fields:

| Field | Meaning |
|---|---|
| seq | Zero-based order in the normalized call stream |
| backend | forge-state-diff or anvil-calltracer |
| kind | Call, DelegateCall, StaticCall, Create, or Create2 |
| accessor | Caller address, or null when unavailable |
| account | Destination/created account, or null when unavailable |
| depth | Call depth, or null when unavailable |
| value | Native value in wei, or null when unavailable |
| selector | Four-byte selector derived from calldata, or null |
| calldata | Whole-byte hex calldata, or null |
| reverted | Boolean, or null when the backend did not expose the outcome |
| storage | Per-event/observed storage rows, or null when unavailable |
| storage_support | exact, partial, or declared_only |

Unsupported call kinds are refused by the canonical adapter. They are not silently rewritten into a different EVM operation.

## Storage evidence levels

- exact: Forge Vm.AccountAccess.storageAccesses observations associated with an ordered account-access context.
- partial: Anvil prestateTracer transaction-level changed slots. Lowkey attaches those observations only to the root event; it does not guess which nested frame touched a slot.
- declared_only: no measured storage trace is available. Manifest-declared slots do not become trace-derived observations.

A trace can have exact call-tree parity while storage parity remains degraded. The two results are reported separately.

## Compare saved evidence

Run the same frozen experiment on both backends, save the resulting lk control JSON reports, then compare the same scenario:

\`\`\`bash
lk trace-parity .audit/forge-control.json .audit/anvil-control.json \\
  --root . --forge-scenario attack --anvil-scenario attack
\`\`\`

The command writes .audit/godmode/trace-parity.json by default and returns:

- MATCHED: all compared call-tree/calldata fields were present and equal.
- MISMATCH: at least one field or event count differed.
- INCOMPLETE: a required compared field was null or a trace stream was empty.

Null never counts as a match. The output records both input artifact paths and SHA-256 digests.

## P2 acceptance boundary

The unit suite checks canonical schema validation, legacy adaptation, Forge/Anvil normalization, storage capability labelling, empty-stream refusal, missing-field handling, and positive/negative parity cases.

This is not yet the complete P2 gate. P2 still requires the same deterministic harness to be exercised through both backends on a pinned fork, plus a real deployed target whose chain identity, source hash, deployment block and proxy-to-implementation chain are independently verified. A matched synthetic test fixture is necessary test coverage, not the first-real-fork proof.

No P2 capability is accepted until the exact-head installed-CLI/Foundry acceptance and verified real-fork run pass.
