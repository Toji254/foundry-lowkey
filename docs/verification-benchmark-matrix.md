# Verification benchmark matrix

This matrix is the acceptance contract for generic verification. "Implemented" means a reproducible fixture or gate exists; "pending" means the capability is not yet proven by this repository's CI. Passing a fixture is not evidence of general support for an entire language or protocol family.

## Current verified scope

| Dimension | Fixture / gate | Status | What it proves |
|---|---|---|---|
| Solidity + Foundry | Minimal state setter/getter fixture | CI validation pending | Generator can identify one narrow direct assignment property |
| Unit generation | Generated unit test includes a concrete getter assertion for the recognized setter | CI validation pending | The recognized property is represented as an executable assertion |
| Fuzz generation | Generated fuzz test passes arbitrary setter values to the getter assertion | CI validation pending | A generated property is exercised over fuzzed values |
| Invariant generation | Handler tracks successful setter input and invariant compares the getter | CI validation pending | The handler-driven invariant compiles and can detect the seeded mutation |
| Formal artifact | CVL starter generated for the recognized property | CI validation pending | A specification artifact is emitted; not yet a verified proof |
| Behavioral validation | Baseline-first mutation runner; one seeded off-by-one source mutation | CI validation pending | Generated suite must fail against the mutant while baseline passes |
| Failure classification | Unit tests cover killed, survived, invalid syntax, baseline failure, and path escape | CI validation pending | Invalid setup/syntax is not counted as a killed behavioral mutant |
| Resource profile | Light/balanced/deep selection and serial campaign runner | Unit tests added; CI validation pending | High-memory engines are excluded from light campaigns; execution is serial |
| Evidence preservation | Raw stdout/stderr, command, working directory, timeout, hashes, report JSON | Unit tests added; CI validation pending | Normalization does not discard native execution evidence |

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
