# Verification benchmark matrix

This matrix is the acceptance contract for generic verification. "Implemented" means a reproducible fixture or gate exists; "pending" means the capability is not yet proven by this repository's CI. Passing a fixture is not evidence of general support for an entire language or protocol family.

## Current verified scope

| Dimension | Fixture / gate | Status | What it proves |
|---|---|---|---|
| Solidity + Foundry | Minimal state setter/getter fixture plus `lk verification engines --json` and a live Forge campaign | Live CI pass on pinned fixture | Detection, adapter selection and a real Forge campaign work for the tested project shape |
| Unit generation | Generated unit test includes a concrete getter assertion for the recognized setter | Live CI pass | The generated unit candidate executes and is used by the seeded mutation gate |
| Fuzz generation | Generated fuzz test passes arbitrary setter values to the getter assertion | Live CI pass | The generated fuzz candidate executes with a bounded fuzz run count on the fixture |
| Invariant generation | Handler tracks successful setter input and invariant compares the getter | Live CI pass | The generated handler-backed invariant executes on the fixture; it is a narrow setter property, not a protocol-wide invariant |
| Formal artifact | CVL starter generated for the recognized property | Artifact checked; proof pending | A specification is emitted and checked as an artifact; no authenticated Certora proof has been run |
| Behavioral validation | Baseline-first mutation runner; one seeded off-by-one source mutation | Live CI pass | The unit baseline passes and the seeded setter mutant is killed; this is one fixture, not a general mutation score |
| Failure classification | Unit tests cover killed, survived, invalid syntax, baseline failure, and path escape | Unit tests and CI pass | Invalid setup/syntax is not counted as a killed behavioral mutant |
| Resource profile | Light/balanced/deep selection and serial campaign runner | Unit tests and CI pass | High-memory engines are excluded from light campaigns; execution is serial |
| Evidence preservation | Raw stdout/stderr, command, working directory, timeout, hashes, report JSON | Unit tests and CI pass | Normalization retains native execution evidence for the tested fixture and result paths |
| External engine compatibility | Echidna 2.3.3, Medusa 1.5.1, Halmos 0.3.3, Slither 0.11.6; Certora CLI 8.20.2 startup | Live CI pass for listed smoke checks; remote Certora proof pending | Pinned fixtures execute; this is not universal version/project support or proof completion |

## Required expansion matrix

| Project / protocol family | Build system / language | Failure modes to seed | Status |
|---|---|---|---|
| Managed Anvil identity | Lowkey CLI + Anvil JSON-RPC | Session/process identity collisions; incorrect per-session chain/genesis provenance; actor alias leakage; cross-network transactions/deployments; ambiguous selection; explicit-RPC actor/target detachment | Live CI pass on current branch: two independent Anvil processes with distinct session UUIDs, PIDs/start identities and ports; same chain ID; each session's recorded genesis hash independently matches its own RPC; distinct account addresses; session-local Alice aliases; registry restart; ambiguous-selection rejection; explicit-RPC actor and target detachment; real isolated value transactions and contract deployment; deployment registry isolation; no owned processes remain after cleanup. Equal genesis hashes are permitted when sessions share the same genesis configuration. This is a focused live gate, not exhaustive cross-command RPC coverage. |
| Compiler-backed deployment intelligence | Solidity compiler build-info + project graph | Missing/ambiguous source-qualified library refs; nested constructor inputs; plain-address misclassification; factory-created child scheduled twice; unavailable ABI treated as empty | Partial: source-matched compiler evidence includes typed library-link edges, creation expressions, contract-typed reference leads and ABI constructor inputs (primitive, address, array and nested tuple/struct). A reusable typed deployment graph preserves source-qualified nodes, relationship categories, compiler provenance, exact link offsets, cycles and deployment order; `lk deps --json` exposes it for automation. Plain addresses remain unclassified and constructor arguments are never auto-deployed. Runtime/session-aware deployment records are available to the graph model, but are not yet supplied by the `lk deps` CLI. Generic external-infrastructure resolution, authority/role graphing and graph-driven deployment execution remain pending. |
| GMX V1 PositionUtils → PositionManager | Pinned GMX source + Solidity 0.6.12 + managed Anvil | Incorrect library offsets/address patching; unverified runtime reuse; cross-session library leakage; supporting contract promoted to primary target | Live CI pass on current branch: actual pinned GMX V1 source compiled; actual PositionManager compiler linkReferences at offsets 15857 and 16472 resolved to one PositionUtils address; library and linked PositionManager runtime matched; same-session reuse verified; cross-session reuse rejected; PositionManager retained as primary target. External protocol dependencies use explicit local fixtures; initialization, roles, protocol invariants and operational readiness are not verified. This is a concrete deployment/linking acceptance, not a complete GMX protocol deployment. |
| Access control / ownership | Solidity + Foundry | Unauthorized caller succeeds; role handoff regression | Pending |
| ERC-20 / allowance flows | Solidity + Foundry | Allowance bypass; incorrect transfer accounting | Pending |
| Vault / lending accounting | Solidity + Foundry | Share inflation; solvency invariant violation | Pending |
| Reentrancy / callbacks | Solidity + Foundry | State update after external call; nested withdrawal | Pending |
| Oracle / AMM integration | Solidity + Foundry | Stale price; slippage bound bypass; bad decimal assumptions | Pending |
| Proxy / upgradeable contracts | Solidity + Foundry | Pinned ERC-1967 slot/precedence, Beacon caller-dependence signal, UUPS UUID signal, Transparent routing candidate, bounded immutable PUSH20/ProxyAdmin v4-v5/owner/Safe/timelock candidate graph, initialization/owner getters, nested clone/proxy chain, Diamond Loupe cross-check, storage-layout and ERC-7201 namespace regression | Partial: CI-passing fixture-level paired controls cover UUPS authorization, mismatched-UUID rejection versus weak UUID validation with post-upgrade lockout, direct implementation initializer locking versus takeover on the same deployed implementation, UUPS reinitializer replay after V1/V2 setup with secure version guard versus vulnerable replay, Transparent admin/non-admin routing and UUPS-behind-Transparent hybrid dispatch, ProxyAdmin, shared-Beacon upgrades and EIP-2535 Diamond cut/removal/initializer takeover; Diamond also runs eight Forge scenarios for selector collisions, authorized replacement, storage migration and incompatible facet behavior. All fixture proofs remain SIMULATED_BREAK. Pending: proxy initialization ordering and implementation/proxy separation acceptance, caller-dependent Beacon and automatic fan-out discovery, nested-clone/custom-proxy attacks, effective authority proof and complete storage/history validation |
| Cross-contract behavioral integration | Solidity + Foundry | Wrong dependency wiring; token/oracle revert behavior; invariant failures across real protocol components | Pending; the GMX acceptance above verifies a narrow real library-link/deployment workflow, not protocol behavior or operational readiness |
| Solidity + Hardhat | Hardhat / JavaScript or TypeScript | Test failure, config mismatch, mutation | Pending |
| Vyper | Vyper + Foundry-compatible ABI tooling | ABI/build mismatch; state transition regression | Detection/build CI exists; generation pending |
| Sui / Move | Move toolchain | Capability/access control and resource invariants | Pending adapter |
| Soroban | Rust + Soroban SDK | Authorization, storage, and asset accounting invariants | Pending adapter |
| Cairo | Cairo/Starknet tooling | Caller validation and storage/accounting invariants | Pending adapter |
| Python / TypeScript / Rust / Go services | Native language build/test systems | Unit mutation, integration failure, timeout | Detection/generator adapters pending |
| Large monorepo / workspace | Multiple build systems and languages | Nested project selection, dependency boundaries | Pending |
| Resource-constrained laptop | Any supported local project | Timeout, missing tool, high-memory exclusion | Partial: serial execution/time budget; live RAM/CPU measurement pending |


### Proxy capability boundary

The current Lowkey proxy engine provides read-only, block-pinned reconnaissance; explicit slot/interface candidate states rather than automatic proxy confirmation; exact canonical ERC-1167 detection; a consistency-checked but self-reported Diamond Loupe candidate; a direct implementation `proxiableUUID()` compatibility signal; textual source/ABI investigation leads; a bounded EIP-1967 event timeline; a conservative compiler-layout comparator; and a local-fork implementation-replacement probe limited to standard UUPS upgrade entrypoint shapes. Separate CI fixture campaigns now include paired UUPS authorization, mismatched-UUID/upgrade-lockout, direct implementation initializer-lock/takeover, Transparent admin/non-admin and UUPS-behind-Transparent hybrid routing, ProxyAdmin, shared Beacon and Diamond cut/initializer cases. These remain fixture-level `SIMULATED_BREAK` evidence, not deployment-specific security findings.

It does **not** claim generic UUPS-versus-Transparent proof, reachable slot-to-dispatch proof for arbitrary targets, effective immutable-admin recovery, complete ProxyAdmin/Beacon/Diamond attack coverage, complete historical upgrade reconstruction, complete ERC-7201 namespace compatibility, generic upgrade simulation, or full proxy exploit campaigns. Reinitializer replay, proxy-versus-implementation initialization-order campaigns, caller-dependent Beacon behavior/fan-out discovery, nested clone/custom proxy attacks and end-to-end authority proof remain pending. Those remain pending until deployment-specific fixtures, paired controls, mutation tests and trace-backed acceptance gates exist. The `lk proxy plan` output is a list of NOT_EXECUTED hypotheses, not a BREAK result. The `lk proxy simulate` command intentionally fails closed without a target-specific adapter.


## Promotion gates

A row moves from pending only when its fixture is committed and automated checks demonstrate:

1. Native project detection selects the correct adapter and explains rejected tools.
2. The generated artifact preserves the stated property, expected behavior, assumptions, and source provenance.
3. The unmodified fixture's baseline suite passes.
4. At least one relevant seeded behavioral fault is killed; compile/setup-invalid mutants are reported separately.
5. The report is reproducible and retains native output, tool/version information, exit status, timeout, and artifact hashes.
6. CI verifies the fixture on every relevant change.

Do not aggregate results into one universal "verified" badge. Report coverage by project family, engine, test kind, and evidence strength. A passing Forge test, a fuzzer campaign, a symbolic run, a static-analysis finding, and a formal proof are different assurance claims.
