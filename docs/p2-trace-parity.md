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
| accessor | Solidity message sender for the event's call frame, or null when unavailable. For DELEGATECALL/CALLCODE this is inherited from the parent frame; callTracer.from is the opcode caller and is not always msg.sender. |
| account | Destination/created account, or null when unavailable |
| depth | Call depth, or null when unavailable |
| value | Native value in wei, or null when unavailable |
| selector | Four-byte selector derived from calldata, or null |
| calldata | Whole-byte hex calldata, or null |
| reverted | Boolean, or null when the backend did not expose the outcome |
| storage | Per-event/observed storage rows, or null when unavailable |
| storage_support | exact, partial, or declared_only |

Unsupported call kinds are refused by the canonical adapter. They are not silently rewritten into a different EVM operation.

Anvil's nested callTracer adapter derives this field using EVM message-sender semantics: ordinary CALL/STATICCALL frames use the opcode caller; DELEGATECALL/CALLCODE frames inherit the parent frame's `msg.sender`. This makes the canonical field comparable to Forge's `AccountAccess.accessor` without confusing it with the opcode's `from` address.

## Storage evidence levels

- exact (Forge): Vm.AccountAccess.storageAccesses observations associated with an ordered account-access context.
- exact (Anvil): opcode-level SLOAD/SSTORE accesses from structLogs, attributed to callTracer frames by call type, target and depth. CALL/STATICCALL use the callee storage context; DELEGATECALL/CALLCODE retain the caller storage context. Exactness is refused if a storage opcode has an invalid stack slot or cannot be mapped to a call frame.
- partial: Anvil prestateTracer transaction-level changed slots. Lowkey attaches those observations only to the root event; it does not guess which nested frame touched a slot. Read-only accesses are absent from this backend.
- declared_only: no measured storage trace is available. Manifest-declared slots do not become trace-derived observations.

Anvil structLogs records exact access identity and ordering, but some clients do not expose the previous value for SSTORE or the post-SLOAD stack result in every trace shape. Such values remain null. `lk trace-parity` separately reports `exact_comparable`, `accesses_matched_values_incomplete`, `mismatch`, or `degraded`; it never fills missing values or treats them as zero.

A trace can have exact call-tree parity while storage parity remains degraded. The two results are reported separately.

## Compare saved evidence

Run the same frozen experiment on both backends, save the resulting lk control JSON reports, then compare the same scenario:

\`\`\`bash
lk trace-parity .audit/forge-control.json .audit/anvil-control.json \\
  --root . --forge-scenario attack --anvil-scenario attack
\`\`\`

The command writes .audit/godmode/trace-parity.json by default. When both artifacts contain exact per-frame storage support, it compares access counts, account, slot, read/write kind, and every value exposed by both backends. It returns:

- MATCHED: all compared call-tree/calldata fields were present and equal.
- MISMATCH: at least one field or event count differed.
- INCOMPLETE: a required compared field was null or a trace stream was empty.

Null never counts as a match. The output records both input artifact paths and SHA-256 digests.

## First exact-identity mainnet fork

The P2 end-to-end acceptance uses Ethereum's canonical EntryPoint v0.7 deployment, which Sourcify currently lists as **Exact**:

- Target: 0x0000000071727De22E5E9d8BAf0edAc6f37da032
- Chain: Ethereum mainnet (chain ID 1)
- Read-only call: getNonce(address,uint192)
- Identity: direct contract; no proxy implementation is inferred
- Source identity: Sourcify v2 must return exact_match for match, runtimeMatch and creationMatch
- Deployment block: loaded from Sourcify's verified deployment metadata and independently checked against archive code immediately before and at that block
- Forge Std: pinned commit 15b2df92a05d4d2f76a06653872fefb287e0e01c

The previous Yearn yvUSDC candidate was deliberately rejected: its embedded implementation returned a Sourcify **Similar Match**, not an exact match. The acceptance does not relax that rule. EIP-1167 parsing and implementation verification remain supported and covered by dedicated unit tests; this first live fixture is a direct target with an exact Sourcify identity so the overall P2 proof can pass without misrepresenting the Yearn source.

The harness makes no live transaction and moves no user funds. It runs a getNonce() view call at a pinned common block on an Anvil fork, captures Forge state-diff, obtains an Anvil debug_traceCall callTracer tree for the same actor/target/calldata, and checks canonical call-tree parity. Storage parity is reported separately because Anvil callTracer does not expose per-access storage slots.

## P2 acceptance boundary

The unit suite checks canonical schema validation, legacy adaptation, Forge/Anvil normalization, storage capability labelling, empty-stream refusal, missing-field handling, and positive/negative parity cases.

The complete P2 gate additionally requires the same deterministic view-call harness to run against the pinned real deployment through both backends, a \`MATCHED\` canonical call tree, independently verified chain/source/deployment/proxy identity, and a truthful \`FORK_OBSERVED\` result. A matched synthetic fixture is necessary test coverage, not the first-real-fork proof.

No P2 capability is accepted until the exact-head installed-CLI/Foundry acceptance and verified real-fork run pass.
