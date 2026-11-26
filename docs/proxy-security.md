# Lowkey proxy security and upgrade intelligence

## Auditor-first commands

Set the address as the active Lowkey target, or pass it directly:

```bash
lk proxy inspect 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy audit 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy plan 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy validate --reference out/V1.json --candidate out/V2.json
```

- `inspect` collects runtime evidence at one block.
- `audit` adds local Solidity source anchors and supplied ABI upgrade signals, then saves a JSON report under `.audit/proxy/<address>/`.
- `plan` creates architecture-specific attack hypotheses. Every scenario is `NOT_EXECUTED`.
- `validate` compares compiler `storageLayout` objects from V1 and V2 artifacts.
- `simulate` deliberately fails closed until a deployment-specific adapter can establish the exact upgrade path, candidate implementation, initialization calldata, privileged caller and expected protocol invariants.

The no-subcommand form `lk proxy` is equivalent to `lk proxy inspect`. Existing `lk implementation` and `lk admin` remain available.

## Evidence model

Inspection records the chain ID, block number and block hash. It reads implementation, beacon and admin slots at the same block number, then checks that the block hash did not change before returning. A reorg, missing slot response or RPC error invalidates confidence rather than turning a failed read into an empty slot.

Implementation and beacon slots are mutually exclusive for ERC-1967 routing. If both are non-zero, the report records `CONFLICTING_EIP1967_SLOTS` and does not guess which route is authoritative. Beacon `implementation()` is probed from two caller addresses; caller-dependent responses become `REVIEW_REQUIRED`.

The admin slot is named `admin_slot_candidate`. It is not called the effective admin because immutable-admin designs can execute using an immutable address while the mirrored EIP-1967 slot diverges. The current engine does not recover every immutable admin from runtime bytecode.

A direct `proxiableUUID()` match on the implementation is a UUPS-compatibility signal. It does not prove `_authorizeUpgrade` is safe, and does not establish that a Transparent proxy cannot expose a second UUPS upgrade route. Transparent-versus-UUPS classification remains a separate, source/dispatch investigation rather than a forced single enum.

The Diamond probe requires a coherent `facetAddresses()` result, non-empty `facetFunctionSelectors(address)` for each returned facet and deployed facet bytecode. This is runtime interface evidence, not proof that `diamondCut` is authorized safely.

Canonical ERC-1167 detection matches the standard runtime template exactly. The implementation address is then checked for deployed code. Non-canonical clones and immutable/custom routers remain unclassified or require a dedicated adapter.

## Storage validation boundary

`lk proxy validate` checks existing field presence, slot, packed offset, recursive compiler type descriptors and append-only additions. It intentionally marks storage-gap changes inconclusive. Namespaced ERC-7201 storage may not appear as ordinary top-level layout entries and requires separate namespace/root-slot/member analysis or an independent OpenZeppelin validation run.

A `COMPATIBLE_CANDIDATE` result is a conservative local comparison, not formal proof that an upgrade is safe. Run the project's OpenZeppelin Foundry Upgrades validator when its build requirements are met, then write target-specific tests for migration behavior and protocol invariants.

## Current limitations — do not overclaim

The current implementation does not yet provide:
- definitive UUPS-versus-Transparent classification for every proxy build;
- effective immutable-admin recovery for all proxy bytecode;
- complete custom proxy slot discovery;
- historical upgrade reconstruction from events and historical slot snapshots;
- full ERC-7201 namespace compatibility proof;
- a generic broadcast, deploy or upgrade workflow;
- generic fork upgrade simulation;
- executable proxy exploit campaigns or a confirmed proxy BREAK result.

These stay blocked/partial until there are dedicated Solidity fixtures, target-specific adapters, paired controls, trace-backed state assertions, seeded mutations and CI acceptance. A source pattern, ABI method name, loupe response or storage comparison is never automatically reported as a vulnerability.

## Test boundary

`tests/test_proxy_engine.py` exercises slot decoding and conflict handling, exact clone matching, PUSH-data-safe opcode scanning, UUPS UUID interpretation, beacon caller-dependence, Diamond Loupe consistency, storage reordering/type/gap behavior, source anchors and non-executed attack plans. The tests use mocked RPC responses; they do not claim a live-chain campaign.
