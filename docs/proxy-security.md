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
- `lk break --family proxy` runs bounded Foundry fork experiments for standard UUPS `upgradeTo(address)` / `upgradeToAndCall(address,bytes)` shapes and, when `--proxy-address` is supplied, OpenZeppelin-style ProxyAdmin `upgrade(address,address)` / `upgradeAndCall(address,address,bytes)` shapes. Candidate telemetry requires an unprivileged local-fork caller to change the EIP-1967 implementation slot to Lowkey's test implementation and reach its marker through the proxy. A candidate is still downgraded to OBSERVED unless a separate sequential-control and fidelity gate passes.
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

## Upgrade authority candidate graph

The inspector now supplements the raw EIP-1967 admin slot with a bounded candidate search:

- It scans runtime `PUSH20` constants for embedded contract addresses, which can reveal immutable-admin candidates in some TransparentUpgradeableProxy builds.
- It probes OpenZeppelin ProxyAdmin v5's `UPGRADE_INTERFACE_VERSION()` and v4-style `upgrade(address,address)` / `upgradeAndCall(address,address,bytes)` selector signals plus `owner()`.
- For an observed owner contract it probes Safe-style `getOwners()` / `getThreshold()` and timelock-style `getMinDelay()` getters.
- The JSON report preserves each candidate's origin, observed code, method signals, owner edge and limitations. Verbose terminal output shows the candidate graph.

These are **candidate signals only**. A PUSH20 address may be unrelated data; a function selector may be present but unreachable; a self-reported getter does not prove that the contract is the proxy's effective admin. Lowkey does not currently prove complete Safe module/guard policy, timelock proposer/executor roles, nested governance authority, or that the candidate can successfully upgrade this proxy. Confirm the routing and authority path with a target-specific local-fork paired-control test.

## Current limitations — do not overclaim

CI now accepts fixture-level paired-control campaigns for:

- Standard UUPS implementation replacement with an owner-gated control.
- UUPS UUID validation: the secure implementation rejects a candidate with a mismatched `proxiableUUID()`; the paired weak implementation accepts it and leaves the proxy unable to execute a subsequent UUPS recovery call.
- Transparent admin/non-admin selector routing and a UUPS second upgrade surface behind a Transparent proxy.
- OpenZeppelin-style ProxyAdmin upgrade routes with authorized and unauthorized controls.
- A shared Beacon controlling two proxies, including implementation replacement and independent application-storage preservation.
- EIP-2535 Diamond unauthorized cuts, selector removal and malicious initializer delegatecall takeover.

The Beacon and Diamond campaigns remain `SIMULATED_BREAK` with fixture authenticity. They demonstrate the tested mechanisms and Lowkey's paired evidence pipeline; they are not production-target exploit confirmation.

The live-deployment inspector and broader proxy subsystem still do not provide:

- Proof that an observed EIP-1967 slot is consumed by the target's reachable runtime dispatch path.
- Proof that a target's actual fallback dispatch reaches every facet reported by its self-reported Diamond Loupe interface.
- Definitive immutable-admin recovery or complete authority proof. The current graph surfaces bounded PUSH20, ProxyAdmin v4/v5, owner(), Safe-style and timelock-style candidates.
- Complete custom proxy slot discovery or arbitrary delegatecall-target resolution.
- Complete historical upgrade reconstruction. `history` currently covers bounded standard EIP-1967 events emitted by the target itself; it does not comprehensively discover ProxyAdmin-emitted events, custom events or silent storage writes.
- Full ERC-7201 compiler-backed namespace compatibility and migration proof.
- Generic production broadcast, deployment or upgrade execution.

The following executable attack areas remain pending: standalone implementation initialization and reinitializer replay; caller-dependent Beacon behavior and automatic dependent-proxy fan-out discovery; nested-clone and custom-proxy attack campaigns; and broader target-specific storage migration/invariant campaigns.

These remain partial until the relevant deployment-specific adapters, paired controls, trace-backed assertions and adversarial CI fixtures exist. A source pattern, ABI method name, coherent Loupe response or storage comparison is never automatically reported as a vulnerability.

## Test boundary

`tests/test_proxy_engine.py` covers slot decoding and conflicts, exact clone matching, UUPS UUID interpretation, Beacon caller-dependence, Diamond Loupe candidate handling, bounded authority candidates, storage-layout comparisons, source anchors, bounded event reconciliation and non-executed attack plans. The proxy P0 CI workflow additionally runs fixture-level UUPS authorization and UUID/lockout controls, Transparent admin/non-admin and hybrid dispatch, ProxyAdmin controls, the shared-Beacon paired campaign, and the EIP-2535 Diamond acceptance. The Diamond gate runs eight Forge scenarios and three independent Lowkey paired-control campaigns for cut authorization, selector removal and malicious initializer takeover. It also exercises authorized replacement, selector collision rejection, compatible/incompatible facet storage behavior, migration and Loupe consistency. Every fixture campaign remains `SIMULATED_BREAK`; none is a production vulnerability finding.

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

For an OpenZeppelin-style ProxyAdmin, select the **ProxyAdmin contract** as the Lowkey target and pass the controlled proxy separately:

```bash
lk target ProxyAdmin 0xProxyAdmin
lk break --family proxy --proxy-address 0xTransparentProxy --function upgradeAndCall
```

The first adapter supports UUPS `upgradeTo(address)` / `upgradeToAndCall(address,bytes)` entrypoints and ProxyAdmin v4/v5-style `upgrade(address,address)` / `upgradeAndCall(address,address,bytes)` shapes. The ProxyAdmin harness calls the admin contract as an unprivileged actor, reads the EIP-1967 implementation slot from the separate proxy address, and requires a challenge-specific marker call through the proxy after the change. It will not count an admin call or slot write alone as a BREAK. Unsupported ABI shapes are reported as blocked rather than silently treated as generic proxy checks.

All generated probes execute on Forge forks of the configured Anvil state; they do not send transactions to the fork's upstream chain or to a production RPC. The automated Anvil acceptance checks vulnerable-vs-authorized fixture telemetry and verifies that source Anvil implementation slots remain unchanged. It deliberately expects OBSERVED because this harness is simulated; only a separately verified sequential-control manifest can promote a candidate. Run it with `python3 scripts/proxy-break-acceptance-e2e.py` after installing Foundry/Lowkey and starting a disposable Anvil node.

Beacon upgrades, Diamond cuts, reinitializer replay, custom upgrade routes and full state-migration invariants remain outside this first executable adapter.
