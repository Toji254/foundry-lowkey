# Lowkey proxy security and upgrade intelligence

## Auditor-first commands

Set the address as the active Lowkey target, or pass it directly:

```bash
lk proxy inspect 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy audit 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy plan 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy history 0xTarget --from-block 18000000 --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy validate --reference out/V1.json --candidate out/V2.json
lk break --family proxy --function upgradeTo
```

- `inspect` collects runtime evidence at one block.
- `audit` adds local Solidity source anchors and supplied ABI upgrade signals, then saves a JSON report under `.audit/proxy/<address>/`.
- `plan` creates architecture-specific attack hypotheses. Every scenario is `NOT_EXECUTED`.
- `history` scans a bounded block range for standard EIP-1967 `Upgraded`, `BeaconUpgraded` and `AdminChanged` events, then reconciles the latest observed events with current slots.
- `validate` compares compiler `storageLayout` objects from V1 and V2 artifacts.
- `lk break --family proxy` runs a narrow Foundry fork experiment for standard `upgradeTo(address)` and `upgradeToAndCall(address,bytes)` ABI shapes. It only reports a candidate break if an unprivileged local-fork caller changes the EIP-1967 implementation slot to Lowkey's test implementation and the test implementation is reached through the proxy.
- `simulate` deliberately fails closed until a deployment-specific adapter can establish the exact upgrade path, candidate implementation, initialization calldata, privileged caller and expected protocol invariants.

The no-subcommand form `lk proxy` is equivalent to `lk proxy inspect`. Existing `lk implementation` and `lk admin` remain available.

## Evidence model

Inspection records the chain ID, block number and block hash. It reads implementation, beacon and admin slots at the same block number, then checks that the block hash did not change before returning. A reorg, missing slot response or RPC error invalidates confidence rather than turning a failed read into an empty slot.

Implementation and beacon slots are mutually exclusive for ERC-1967 routing. If both are non-zero, the report records `CONFLICTING_EIP1967_SLOTS` and does not guess which route is authoritative. Beacon `implementation()` is probed from two caller addresses; caller-dependent responses become `REVIEW_REQUIRED`.

The admin slot is named `admin_slot_candidate`. It is not called the effective admin because immutable-admin designs can execute using an immutable address while the mirrored EIP-1967 slot diverges. The current engine does not recover every immutable admin from runtime bytecode.

Authority and lifecycle checks add bounded, read-only investigation signals:

- `owner()` is probed from two caller contexts on a discovered admin-slot candidate or beacon. A consistent value is exposed only as an owner candidate; it is not proof that the owner can upgrade the proxy.
- A likely Transparent admin-routing behavior is reported only when a no-argument `view/pure` method succeeds directly on the implementation for both callers and through the proxy for a non-admin caller, but fails through the proxy from the admin-slot candidate. This remains a `TRANSPARENT_ROUTING_CANDIDATE`, not a definitive version/classification. Immutable-admin mismatch or missing safe view methods can make the check inconclusive.
- Declared initializer/reinitializer entrypoints are inventoried from the ABI. Only explicitly exposed read-only initialization-version getters are called; Lowkey never calls `initialize` or `reinitialize` during reconnaissance. A false/zero getter value is a recorded observation, not an assumption about who can initialize or whether migration is safe.
- A bounded nested-route walk follows standard ERC-1967 implementation/beacon slots and canonical ERC-1167 clone addresses for up to five hops. It records cycle detection, no-code hops, conflicts, and unresolved beacon responses. Custom slot schemes and arbitrary delegatecall graphs are not guessed.


A direct `proxiableUUID()` match on the implementation is a UUPS-compatibility signal. It does not prove `_authorizeUpgrade` is safe, and does not establish that a Transparent proxy cannot expose a second UUPS upgrade route. Transparent-versus-UUPS classification remains a separate, source/dispatch investigation rather than a forced single enum.

**Architecture confidence rule:** a populated EIP-1967 slot is reported as a slot candidate, not as proof of a proxy. Runtime `DELEGATECALL` opcode presence raises the evidence level only to a candidate because opcode presence does not prove a reachable dispatch path consumes that slot. A coherent Diamond Loupe is likewise a self-reported interface candidate; even with a `DELEGATECALL` opcode, the engine does not claim that each selector is actually routed to each reported facet. These states remain `REVIEW_REQUIRED`.

The Diamond probe requires a coherent `facetAddresses()` result, non-empty `facetFunctionSelectors(address)` for each returned facet, deployed facet bytecode and `facetAddress(bytes4)` agreement for every reported selector. It is bounded to 64 facets and 64 total selectors to keep RPC work predictable. This is runtime interface evidence, not proof that `diamondCut` is authorized safely.

Canonical ERC-1167 detection matches the standard runtime template exactly. The implementation address is then checked for deployed code. Non-canonical clones and immutable/custom routers remain unclassified or require a dedicated adapter.

## Storage validation boundary

`lk proxy validate` checks existing field presence, slot, packed offset, recursive compiler type descriptors and append-only additions. It intentionally marks storage-gap changes inconclusive. For namespaced storage, add `--reference-source` and `--candidate-source` to inventory ERC-7201 annotations (including `lib/` and `node_modules/` Solidity files), calculate each namespace root slot using the ERC-7201 formula, and compare namespace IDs and annotated struct declarations:

```bash
lk proxy validate \\
  --reference out/V1.json --candidate out/V2.json \\
  --reference-source ./V1 --candidate-source ./V2 --json
```

The namespace scan is a source-level guardrail, not a compiler layout diff: inheritance, struct packing, type aliases, nested types and custom assembly remain unverified. A removed namespace is an incompatibility candidate; changed members, newly-added namespaces, duplicate IDs, scan truncation or unreadable files remain review/inconclusive states. Namespaced storage still requires compiler-backed validation and an independent OpenZeppelin upgrade validation run.

Foundry/solc build-info files can contain multiple contracts. In that case, Lowkey refuses to choose one implicitly; provide both contract selectors. Each selector accepts a contract name or a fully-qualified `Source.sol:ContractName`:

```bash
lk proxy validate \
  --reference out/build-info/V1.json --candidate out/build-info/V2.json \
  --reference-contract Vault --candidate-contract Vault
```

A `COMPATIBLE_CANDIDATE` result is a conservative local comparison, not formal proof that an upgrade is safe. Run the project's OpenZeppelin Foundry Upgrades validator when its build requirements are met, then write target-specific tests for migration behavior and protocol invariants.

## Current limitations — do not overclaim

The current implementation does not yet provide:
- proof that an observed EIP-1967 slot is consumed by the target's reachable runtime dispatch path;
- proof of selector-to-facet DELEGATECALL routing for Diamonds or Diamond-cut authorization;
- effective immutable-admin recovery for every proxy build or full ProxyAdmin -> owner -> multisig -> timelock authority graph;
- complete custom proxy slot discovery;
- complete historical upgrade reconstruction: `history` currently covers only standard EIP-1967 events emitted by the target itself, within an explicit bounded range; it does not discover ProxyAdmin-emitted events, custom events, silent storage writes or events before the selected start block;
- full ERC-7201 namespace compatibility proof;
- a generic broadcast, deploy or upgrade workflow;
- generic fork upgrade simulation;
- broad executable proxy exploit campaigns: the first local adapter only probes standard UUPS-style `upgradeTo(address)` / `upgradeToAndCall(address,bytes)` shapes; Transparent ProxyAdmin contracts, Beacon upgrades, Diamond cuts, initializer replay and custom upgrade routes remain unimplemented.

These stay blocked/partial until there are dedicated Solidity fixtures, target-specific adapters, paired controls, trace-backed state assertions, seeded mutations and CI acceptance. A source pattern, ABI method name, loupe response or storage comparison is never automatically reported as a vulnerability.

## Test boundary

`tests/test_proxy_engine.py` exercises slot decoding and conflict handling, exact clone matching, PUSH-data-safe opcode scanning, UUPS UUID interpretation, beacon caller-dependence, Diamond Loupe candidate handling, storage reordering/type/gap behavior, source anchors, bounded EIP-1967 event decoding/reconciliation and non-executed attack plans. `tests/test_break_engine.py` checks the generated UUPS replacement harness and its telemetry gates. These are unit/mocked tests; they do not yet constitute an end-to-end Anvil proxy takeover acceptance fixture.

## Bounded upgrade history

Use an explicit start block so RPC work and the evidence window are visible:

```bash
lk proxy history 0xTarget --from-block 18000000 --to-block 19000000 --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk proxy history 0xTarget --from-block 18000000 --json
```

The scan is chunked, capped at 100,000 blocks and 20,000 returned logs, pinned to the selected end block and checked against its block hash after storage reconciliation. `AdminChanged(address,address)` is decoded from its non-indexed event data. A zero slot remains distinct from a missing or malformed read. The result is a partial event timeline, not a complete upgrade history or an authority proof.

## Executable local proxy probe

For a Foundry project with an Anvil node and an ABI exposing a standard UUPS upgrade entrypoint:

```bash
lk break --family proxy --function upgradeTo
```

The harness forks the configured Anvil RPC, deploys a marker implementation, calls the selected upgrade function as an unprivileged actor and checks the implementation slot plus an actual marker call through the target. It does not send transactions to the fork's upstream chain or to a production RPC. An observed local break still requires a matched control manifest and human review before it can be treated as a finding.

This adapter does **not** currently test a ProxyAdmin contract's `upgrade(proxy,implementation)`, immutable-admin behavior, Beacon upgrades, Diamond cuts, storage migration or reinitializer takeover. Unsupported ABI shapes are reported as blocked rather than silently treated as generic proxy checks.
