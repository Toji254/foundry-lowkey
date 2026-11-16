# Lowkey P0/P1 capability ledger

This ledger separates implementation, isolated component coverage, installed-command acceptance, behavioural phase acceptance, and real-deployment proof. A command, generated string, compile-only harness, or green unrelated CI job is not evidence of a completed family.

**Integration branch:** `integration-test-drive`  
**P0 baseline:** `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`  
**P0 full integration CI:** [run 7442](https://github.com/Toji254/foundry-lowkey/actions/runs/42163749361), on `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`, completed with all 10 jobs successful.  
**P0 latest installed-CLI acceptance:** [run 7485](https://github.com/Toji254/foundry-lowkey/actions/runs/42363585120), on the P1 feature branch before the renderer checksum fix; the dedicated P0 acceptance job passed. The full run remains separate from the P0 job result.  
**P1 integration PR:** [PR 64](https://github.com/Toji254/foundry-lowkey/pull/64) merged into integration-test-drive on 2026-11-15. Its paired reentrancy, frozen-control, mutation, and funded Anvil reproof acceptance is retained in the integration branch; target authenticity remains fixture-scoped.

| Capability | Current status | Evidence and limits |
|---|---|---|
| ABI-aware setup values | ACCEPTED for P0 scope | Installed `lk target` + `lk break` executed `AddressArraySetupTarget.deposit(address[])` and returned `OBSERVED`. The P0 extension in merged [PR 68](https://github.com/Toji254/foundry-lowkey/pull/68) adds bounded recursive tuple/array ABI handling and reuses Cast-backed ABI encoding. Unsupported layouts and depth/sample safety-limit overflows still refuse rather than guess. |
| Payable/nonpayable setup | ACCEPTED for P0 scope | Installed-`lk` payable `address[]` setup executed and produced `SETUP_SUCCESS true`. Nonpayable setup uses zero value; payable setup uses the generated seed value. |
| ERC-20 decimal-aware funding | ACCEPTED for P0 compatibility scope | The installed-CLI Anvil acceptance exercises a six-decimal USDC-style vault and a token without `decimals()`. The fallback is explicitly recorded as `ASSET_DECIMALS_FALLBACK_18`, with the assumed amount visible in telemetry. An unverified fallback must not support stronger token-profit claims. |
| Optional-return ERC-20 approval | ACCEPTED for P0 scope | Installed-`lk` USDT-style payer case exercises empty-return approval with an existing nonzero allowance. Generated telemetry confirms reset-to-zero and retry. False, revert, and malformed return data fail closed. |
| ERC-777 receiver | ACCEPTED for P0 fixture scope | Fixture exercises the standard `tokensReceived` callback and ERC-1820 registration handshake. A real chain still needs its canonical ERC-1820 registry. |
| ERC-1155 receiver | ACCEPTED for P0 fixture scope | Fixture exercises both single and batch callbacks and ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | ACCEPTED for P0 fixture scope | Fixture exercises the standard `onERC721Received` selector. |
| Machine-readable refusals | ACCEPTED for P0 scope | Python tests cover explicit refusal paths including `abi_discovery_failed`, `unsupported_abi`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, `target_rejected_without_revert_evidence`, and `forge_no_lowkey_telemetry`. |
| P1 frozen control validation | P1 fixture acceptance passed; full exact-head CI pending | PR 64 exercises the separate non-executing `lk control --validate` path. Valid freeze -> `PROPOSED`; tampered digest -> `REJECTED/digest_mismatch`; neither validation path executes the control or attack. |
| P1 paired Forge control + state diff | P1 fixture acceptance passed; full exact-head CI pending | PR 64 runs the one-deployment sequential-control vs reentrancy-attack fixture, matched entry calldata, same prestate excluding the declared mode slot, chain/block/fork anchor checks, exact call-count expectations, and non-empty trace-derived storage accesses. Forge AccountAccess balances are gross structural observations only and remain capped at `SIMULATED_BREAK`; they are not net profit. |
| P1 funded Anvil reproof | Setup-cost accounting wired; P1 fixture acceptance passed; full exact-head CI pending | The P1 E2E script independently reads receipts for actor deployment and deposit, includes deployment gas, deposit principal, and deposit transaction gas in `--prior-cost-wei`, and checks the reproof artifact reports the same measured total. The replay's actual receipt gas is charged separately, without double-subtracting when the gas payer is included in the measured portfolio. The exact-head P1 acceptance job passed; full PR CI is still pending. Target authenticity remains `unknown` and proof status remains `OBSERVED` for this controlled fixture. |
| P1 mutation acceptance | P1 fixture acceptance passed; full exact-head CI pending | The same paired test mutates the vulnerable vault to checks-effects-interactions and requires the verdict to flip to `REJECTED/control_passed`. A surviving exploit produces `BLOCKED/mutation_not_killed` and fails the gate. |
| P1 Step renderer | P1 runtime fixture acceptance passed; full exact-head CI pending | The installed `lk steps` renderer validates typed scalar/array values, generates hashed harnesses, records machine-readable refusals, and executes every generated harness against the deployed local fixture. Address arguments are emitted as `address(uint160(0x...))` to avoid Solidity checksum-literal errors. Generic callback steps remain explicitly unsupported. |
| Generic `flash_borrow` / `reenter` Step kinds | BLOCKED / unsupported by design | These require protocol-specific callback actors. The renderer must emit `backend_unsupported`; it must not fabricate an executable callback. |

## Family scope — no fake greens

The 15 strings in `STEP_FAMILIES` are accepted family labels for the generic Step renderer. They are **not** 15 independently implemented exploit generators. The generic renderer's common Step sequence proves that the plan schema can be rendered and executed, not that each family has a positive attack, paired control, rejection seed, mutation test, and family-specific evidence.

Until those acceptance cases exist in the same PR, the following remain **telemetry-only** and must not be placed in the evaluation table or promoted to a BREAK capability:

| Family label | Scope |
|---|---|
| reentrancy | P1 behavioural acceptance merged in PR 64; controlled fixture scope only |
| replay | telemetry-only |
| access | telemetry-only |
| accounting | telemetry-only |
| boundary | telemetry-only |
| time | telemetry-only |
| upgrade | telemetry-only |
| callback | telemetry-only |
| oracle | telemetry-only |
| economic | telemetry-only |
| erc20 | telemetry-only |
| proxy | telemetry-only |
| storage | telemetry-only |
| signature | telemetry-only |
| dos | telemetry-only |

This registry does not add these telemetry-only families to an evaluation or benchmark table. Each family needs acceptance cases 1–7 from the original plan in its own phase PR before promotion.

## P0 evidence and reproducibility

`scripts/p0-break-acceptance-e2e.py` deploys local Anvil fixtures and exercises four installed-`lk` cases: `address[]` setup, six-decimal USDC, USDT-style empty-return approval with allowance reset, and missing-decimals fallback. Every case must reach `OBSERVED` and assert its setup/funding/approval telemetry. The receiver-specific fixture under `tests/fixtures/acceptance/p0-compatibility/` separately exercises ERC-777, ERC-1155 single/batch, and ERC-721 callbacks.

P0 fixture acceptance is not a promise that every ABI, ERC-20 implementation, token extension, or production vault is supported. Unsupported ABI shapes must continue to produce machine-readable refusals.

## P1 gate and stop condition

PR 64 is merged; its acceptance criteria below describe the retained P1 gate. The dedicated P1 runtime job has passed on candidate head `9eb97460e780290f447280f1f4143453672bdb4a`; the following are the P1 acceptance requirements already exercised by that job:

1. Installed `lk steps` renders all 15 labels, validates template/harness hashes, records refusals, compiles, and **executes** every generated harness on the Anvil fixture.
2. One deployed vault and actor are reused for the sequential control and reentrant attack; the only scenario difference is the declared callback mode set outside each measured window.
3. The paired Forge evidence validates same entry call, matched prestate apart from the declared scenario parameter, same chain/block/fork anchor, expected control=1 vs attack=2 target calls, and non-empty trace-derived storage accesses.
4. The paired Forge result is `SIMULATED_BREAK`, never a profitability claim.
5. The frozen spec validates separately; tampering its digest yields `REJECTED/digest_mismatch` with no execution.
6. The CEI mutation kills the attack verdict and yields `REJECTED/control_passed`; otherwise the gate is `BLOCKED/mutation_not_killed`.
7. The separate funded Anvil replay has a successful mined receipt, trace-derived storage evidence, and positive net profit after both (a) the measured prior actor-deployment/deposit outlay supplied through `--prior-cost-wei` and (b) the replay transaction gas. The acceptance script asserts the recorded prior cost matches the independently measured setup outlay. Proof status remains `OBSERVED` because the target is a fixture.

If any item fails, P1 stays pending and the PR records the actual failing command/exit code and evidence. Do not start P2, do not claim `LOCAL_PROFITABLE` from Forge gross state deltas, and do not describe telemetry-only labels as executable family capabilities.

## Scope boundary

P0's installed compatibility gate and receiver fixture are implemented and covered by dedicated Anvil/Foundry acceptance. P0's result remains fixture-scoped.

P1 is accepted for its defined fixture scope and is merged through PR 64. No HUMAN_CONFIRMED or authentic-deployment claim is made by the fixture. P2 PR 69 now has all 11 exact-head CI jobs passing on candidate SHA 1425fdf4de92ddc93176b3f3651087ff2a03f36e in [run 7989](https://github.com/Toji254/foundry-lowkey/actions/runs/43797580616), including p2-first-fork-acceptance; PR 69 is still a draft and is not merged. The competing PR 70 is also still a draft and its earlier candidate run failed. Do not treat P2 as merged until PR 69 is merged into integration-test-drive.

## Attack-family strategy engine and chain composition (feature branch)

**Implementation branch:** feat/attack-family-chain-engine-20261116  
**Base:** P2 candidate PR 69 head 1425fdf4de92ddc93176b3f3651087ff2a03f36e; this branch does not modify integration-test-drive or master.

The new lowkey/attack_engine.py provides:
- a 15-family strategy contract registry with family-specific source signals, preconditions, expected property IDs, trace requirements, and impact-mode defaults;
- bounded source discovery that reports only CANDIDATE leads and pins the selected source file SHA-256 and entrypoint;
- strict experiment manifests that pin target address, runtime-code SHA-256, chain and fork block;
- target-specific attack/control Foundry test execution with role/run/evidence environment variables;
- canonical TraceEvent v2 validation, matched entry/prestate/setup anchors and family-specific precondition/property checks;
- mandatory independent source-verified fork reproof, including actual receipt, call trace, and changed-storage evidence where required;
- baseline-first mutation acceptance, requiring every declared mutant to be killed; and
- a chain schema/runner with explicit stage dependencies and artifacts, continuous pre/post-state hashes, attack/control stage predicates, failure injection, rollback verification, and mutation gates.

**Important status distinction:** this is an execution/evidence framework for protocol-specific family adapters, not 15 universal exploit generators. The existing reentrancy fixture remains the only family with a dedicated accepted behavioral fixture. The other 14 family contracts are explicitly adapter_required until target-specific attack/control adapters and their acceptance campaigns are added and pass. Do not promote their registry entries into BREAK capabilities.

Commands: lk attack engines, lk attack discover, lk attack verify, and lk attack chain validate|run. See [docs/attack-engine.md](attack-engine.md) for the strict manifest/evidence formats, impact-mode rules, chain-stage contract and remaining boundaries.

This feature branch's own CI, installed-runtime smoke, and acceptance status must be recorded against its exact head SHA before merge. A P2 green run does not validate this new engine.

## P3.1 — Deterministic protocol archetype discovery

**Status: PENDING exact-head CI.** P3 adds ten data-driven ArchetypePack records, a bounded deterministic source classifier, a conservative import/typed-call-candidate graph, source-hash-pinned assumption citations, and capability negotiation with a generic-mode skip list. Acceptance fixtures cover vault4626, constant-product AMM and an unknown target.

No archetype is an attack-family acceptance. An OBSERVED classification means only that source signals selected a pack; it does not authenticate a deployment or promote a vulnerability. Assumptions remain unverified. Full compiler AST/Slither call-graph/data-flow extraction remains outstanding. Model-driven novel hypotheses remain P9; full attack-chain composition remains in the attack-engine phase.

The exact-head P3 acceptance job must pass classification, citation re-read/tamper rejection, graph citations, package install/manifest and installed CLI checks before this ledger row can be marked accepted.

## Tier 0 hardening phase

Tier 0 is the reliability layer used by every later attack capability. The hardening implementation is under review on `feat/tier0-hardening-20261116`; it is not considered accepted until its exact-head CI and local sandbox smoke checks pass.

| Capability | Implementation contract | Required acceptance |
|---|---|---|
| Cheat fingerprint | Stable SHA-256 pattern IDs, normalized token scan, Aho-Corasick matching, ordered mapping-read → external-call → mapping-write sequences including struct-member writes and case-insensitive external method names, line/offset/snippet provenance, explicit heuristic limits | Fixtures detect ordered sequences, ignore comments, distinguish local assignments from mapping writes, and return stable pattern IDs |
| Control | Frozen experiment manifest, same entry-call/prestate checks, trace evidence and fail-closed BREAK downgrade | Existing control/freeze/tamper/trace tests plus P1 paired fixture |
| Mutation score | One family per manifest, passing baseline, every mutant accounted for; invalid, timeout, error, duplicate/missing IDs, inconsistent summary totals or a mismatched score fail the gate | Tests prove ≥90% valid score passes and malformed/inconsistent reports fail |
| Target coverage | Fresh LCOV only, target source/line filtering, optional test filters and explicit minimum percentage | Fresh-LCOV fixture test proves threshold pass and fail behavior |
| Provenance | Artifact hashes, Git revision/branch/dirty state, chain/fork/tool metadata, detached signature and public-key sidecar, verification against an independently pinned `--public-key`; private key must stay outside the project; malformed or empty artifact lists fail | Sign → verify passes with pinned key; artifact tamper, missing trust anchor, malformed and signed-empty-manifest cases fail verification |
| Sandbox | Disposable project copy, default network namespace isolation, architecture-checked seccomp syscall filter, per-sandbox systemd cgroup `MemoryMax`/`TasksMax`/`RuntimeMaxSec`, CPU/address-space/file-size/FD limits, read-only host/runtime mounts, whole-process-group timeout cleanup; opt-in IP allowlist uses system manager `IPAddressDeny/Allow` and fails closed | Unit tests cover network isolation, seccomp descriptor handoff, cgroup resource policy, timeout cleanup, allowlist policy and refusal without required dependencies |

"Implemented" in the registry means the documented command path exists and its acceptance tests pass. It does not mean heuristic source matching is a vulnerability verdict, coverage proves security, mutation score proves exploitability, or sandboxing makes arbitrary code harmless. Network allowlisting is IP-based; all ports to an allowed IP are available. Both network modes require `systemd-run` cgroup resource controls; network-disabled mode uses the user manager and a fresh network namespace. The IP-allowlist backend additionally requires `sudo` and cgroup v2. Lowkey refuses rather than running without requested controls.

## Family scope — no fake greens

The 15 strings in `STEP_FAMILIES` are accepted family labels for the generic Step renderer. They are **not** 15 independently implemented exploit generators. The generic renderer's common Step sequence proves that the plan schema can be rendered and executed, not that each family has a positive attack, paired control, rejection seed, mutation test, and family-specific evidence.

Until those acceptance cases exist in the same PR, the following remain **telemetry-only** and must not be placed in the evaluation table or promoted to a BREAK capability:

| Family label | Scope |
|---|---|
| reentrancy | P1 behavioural acceptance in PR 64; local fixture gate and exact-head CI passed |
| replay | telemetry-only |
| access | telemetry-only |
| accounting | telemetry-only |
| boundary | telemetry-only |
| time | telemetry-only |
| upgrade | telemetry-only |
| callback | telemetry-only |
| oracle | telemetry-only |
| economic | telemetry-only |
| erc20 | telemetry-only |
| proxy | telemetry-only |
| storage | telemetry-only |
| signature | telemetry-only |
| dos | telemetry-only |

This registry does not add these telemetry-only families to an evaluation or benchmark table. Each family needs acceptance cases 1–7 from the original plan in its own phase PR before promotion.

## P0 evidence and reproducibility

`scripts/p0-break-acceptance-e2e.py` deploys local Anvil fixtures and exercises four installed-`lk` cases: `address[]` setup, six-decimal USDC, USDT-style empty-return approval with allowance reset, and missing-decimals fallback. Every case must reach `OBSERVED` and assert its setup/funding/approval telemetry. The receiver-specific fixture under `tests/fixtures/acceptance/p0-compatibility/` separately exercises ERC-777, ERC-1155 single/batch, and ERC-721 callbacks.

P0 fixture acceptance is not a promise that every ABI, ERC-20 implementation, token extension, or production vault is supported. Unsupported ABI shapes must continue to produce machine-readable refusals.

## P1 gate and stop condition

PR #64 is merged into `integration-test-drive`; its exact merged head `d47891c60d8426e459187af06e842b3371278138` passed all 10 CI jobs in [run 7667](https://github.com/Toji254/foundry-lowkey/actions/runs/43762416186). The merge commit is `0dd08f52a10330322fccdb3bb21c455232b6934e`.

The P1 acceptance requirements were exercised by the dedicated runtime job and passed:

1. Installed `lk steps` renders the registered Step labels, validates template/harness hashes, records machine-readable refusals, compiles, and executes generated harnesses on the Anvil fixture.
2. One deployed vault and actor are reused for the sequential control and reentrant attack; the declared callback mode is the controlled scenario difference.
3. Paired Forge evidence validates the same entry call, matched prestate apart from the declared scenario parameter, chain/block/fork anchor, expected control=1 vs attack=2 target calls, and non-empty trace-derived storage accesses.
4. The paired Forge result remains `SIMULATED_BREAK`, never a profitability claim.
5. The frozen spec validates separately; digest tampering yields `REJECTED/digest_mismatch` without execution.
6. The CEI mutation kills the attack verdict and yields `REJECTED/control_passed`; surviving exploit behavior blocks acceptance.
7. The separate funded Anvil replay has a mined receipt, trace-derived storage evidence, and positive net profit after measured prior actor-deployment/deposit outlay and replay transaction gas. Proof status remains `OBSERVED` because the target is a controlled fixture.

P1 is accepted for this controlled fixture and implemented execution path. It is not a general exploit generator: all Step family labels share a generic renderer, generic `flash_borrow` / `reenter` callback Steps remain unsupported, and Forge state-diff cannot establish real EOA profitability. Do not claim `LOCAL_PROFITABLE`, `HUMAN_CONFIRMED`, or authentic production-target impact from this fixture.

## Scope boundary

P0's installed compatibility gate and receiver fixture are implemented and covered by dedicated Anvil/Foundry acceptance. P0's result remains fixture-scoped.

P1 is accepted for the controlled fixture and implemented execution path; the exact-head PR #64 CI matrix passed all 10 jobs. The result remains fixture-scoped. No `HUMAN_CONFIRMED` or authentic deployment claim is made by the fixture.
