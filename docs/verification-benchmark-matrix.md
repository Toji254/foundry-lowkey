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
| Access control / ownership | Solidity + Foundry | Unauthorized caller succeeds; role handoff regression | Pending |
| ERC-20 / allowance flows | Solidity + Foundry | Allowance bypass; incorrect transfer accounting | Pending |
| Vault / lending accounting | Solidity + Foundry | Share inflation; solvency invariant violation | Pending |
| Reentrancy / callbacks | Solidity + Foundry | State update after external call; nested withdrawal | Pending |
| Oracle / AMM integration | Solidity + Foundry | Stale price; slippage bound bypass; bad decimal assumptions | Pending |
| Proxy / upgradeable contracts | Solidity + Foundry | Uninitialized implementation; storage-layout regression | Pending |
| Cross-contract integration | Solidity + Foundry | Wrong dependency wiring; token/oracle revert behavior | Pending |
| Solidity + Hardhat | Hardhat / JavaScript or TypeScript | Test failure, config mismatch, mutation | Pending |
| Vyper | Vyper + Foundry-compatible ABI tooling | ABI/build mismatch; state transition regression | Detection/build CI exists; generation pending |
| Sui / Move | Move toolchain | Capability/access control and resource invariants | Pending adapter |
| Soroban | Rust + Soroban SDK | Authorization, storage, and asset accounting invariants | Pending adapter |
| Cairo | Cairo/Starknet tooling | Caller validation and storage/accounting invariants | Pending adapter |
| Python / TypeScript / Rust / Go services | Native language build/test systems | Unit mutation, integration failure, timeout | Detection/generator adapters pending |
| Large monorepo / workspace | Multiple build systems and languages | Nested project selection, dependency boundaries | Pending |
| Resource-constrained laptop | Any supported local project | Timeout, missing tool, high-memory exclusion | Partial: serial execution/time budget; live RAM/CPU measurement pending |

## Promotion gates

A row moves from pending only when its fixture is committed and automated checks demonstrate:

1. Native project detection selects the correct adapter and explains rejected tools.
2. The generated artifact preserves the stated property, expected behavior, assumptions, and source provenance.
3. The unmodified fixture's baseline suite passes.
4. At least one relevant seeded behavioral fault is killed; compile/setup-invalid mutants are reported separately.
5. The report is reproducible and retains native output, tool/version information, exit status, timeout, and artifact hashes.
6. CI verifies the fixture on every relevant change.

Do not aggregate results into one universal "verified" badge. Report coverage by project family, engine, test kind, and evidence strength. A passing Forge test, a fuzzer campaign, a symbolic run, a static-analysis finding, and a formal proof are different assurance claims.
