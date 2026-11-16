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

## First real-fork candidate

The P2 end-to-end acceptance uses Yearn's Ethereum USDC-1 / yvUSDC-1 V3 vault:

- Target: \`0xbe53a109b494e5c9f97b9cd39fe969be68bf6204\`
- Chain: Ethereum mainnet (chain ID 1)
- Contract creation block: \`19,419,991\`
- Read-only call: \`totalAssets()\`
- Proxy family: canonical EIP-1167 minimal clone
- Forge Std: pinned commit \`15b2df92a05d4d2f76a06653872fefb287e0e01c\`

The Yearn factory source describes deployment of a minimal proxy clone of the original vault; the EIP-1167 runtime embeds the fixed implementation address. Lowkey verifies the exact 45-byte runtime form, extracts that address, then independently verifies implementation runtime, first-code block, Sourcify exact source, and trace-derived implementation code hash.

The harness makes no live transaction and moves no user funds. It runs a \`totalAssets()\` view call at a pinned common block on an Anvil fork, captures Forge state-diff, obtains an Anvil \`debug_traceCall\` callTracer tree for the same actor/target/calldata, and checks canonical call-tree parity. Storage parity is expected to remain degraded because Anvil callTracer does not expose per-access storage slots.

Default CI fork upstreams are MEV Blocker /noreverts and BlockTailor; the independent source/archive endpoint is Blast API. The script preflights each fork endpoint's chain ID and common pinned block, then preflights historical target code and EIP-1186 proof support on the source endpoint. It passes every matching fork endpoint to Anvil as a separate --fork-url, enabling Foundry's round-robin request distribution and failover. Anvil is given --fork-chain-id 1 so startup does not issue another remote eth_chainId probe; it uses bounded retries, a 120-second request timeout and retry backoff. A comma-separated LOWKEY_P2_FORK_UPSTREAM_RPC_URL override is supported, as is LOWKEY_P2_SOURCE_RPC_URL; latest-state-only or non-Ethereum endpoints are rejected. Public endpoint capability can change or become rate-limited, so the script preflights every run and reports provider failures rather than accepting an unverified fallback.

## P2 acceptance boundary

The unit suite checks canonical schema validation, legacy adaptation, Forge/Anvil normalization, storage capability labelling, empty-stream refusal, missing-field handling, and positive/negative parity cases.

The complete P2 gate additionally requires the same deterministic view-call harness to run against the pinned real deployment through both backends, a \`MATCHED\` canonical call tree, independently verified chain/source/deployment/proxy identity, and a truthful \`FORK_OBSERVED\` result. A matched synthetic fixture is necessary test coverage, not the first-real-fork proof.

No P2 capability is accepted until the exact-head installed-CLI/Foundry acceptance and verified real-fork run pass.
