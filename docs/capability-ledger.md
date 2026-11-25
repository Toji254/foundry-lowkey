# Lowkey capability ledger

**Ledger reconciled:** 2026-11-22.  
**Integration head reviewed:** `f01383b5cbdd6fb194eae067ee45a58cfc4a2cdb`.  
**Forensic AST candidate:** `8498eaac731548001176e8cc56c0c0f378dc803f`; its 12/12 exact-head CI is recorded below but is not yet merged into integration.  


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
| P1 frozen control validation | ACCEPTED for the P1 fixture scope; full workflow verified on candidate SHA 8498eaac731548001176e8cc56c0c0f378dc803f (not yet merged) | PR 64 exercises the separate non-executing `lk control --validate` path. Valid freeze -> `PROPOSED`; tampered digest -> `REJECTED/digest_mismatch`; neither validation path executes the control or attack. |
| P1 paired Forge control + state diff | ACCEPTED for the P1 fixture scope; full workflow verified on candidate SHA 8498eaac731548001176e8cc56c0c0f378dc803f (not yet merged) | PR 64 runs the one-deployment sequential-control vs reentrancy-attack fixture, matched entry calldata, same prestate excluding the declared mode slot, chain/block/fork anchor checks, exact call-count expectations, and non-empty trace-derived storage accesses. Forge AccountAccess balances are gross structural observations only and remain capped at `SIMULATED_BREAK`; they are not net profit. |
| P1 funded Anvil reproof | Setup-cost accounting wired; ACCEPTED for the P1 fixture scope; full workflow verified on candidate SHA 8498eaac731548001176e8cc56c0c0f378dc803f (not yet merged) | The P1 E2E script independently reads receipts for actor deployment and deposit, includes deployment gas, deposit principal, and deposit transaction gas in `--prior-cost-wei`, and checks the reproof artifact reports the same measured total. The replay's actual receipt gas is charged separately, without double-subtracting when the gas payer is included in the measured portfolio. The exact-head P1 acceptance job passed; full workflow [run #45056235388](https://github.com/Toji254/foundry-lowkey/actions/runs/45056235388) passed on the forensic candidate; integration merge remains pending. Target authenticity remains `unknown` and proof status remains `OBSERVED` for this controlled fixture. |
| P1 mutation acceptance | ACCEPTED for the P1 fixture scope; full workflow verified on candidate SHA 8498eaac731548001176e8cc56c0c0f378dc803f (not yet merged) | The same paired test mutates the vulnerable vault to checks-effects-interactions and requires the verdict to flip to `REJECTED/control_passed`. A surviving exploit produces `BLOCKED/mutation_not_killed` and fails the gate. |
| P1 Step renderer | ACCEPTED for the P1 fixture scope; full workflow verified on candidate SHA 8498eaac731548001176e8cc56c0c0f378dc803f (not yet merged) | The installed `lk steps` renderer validates typed scalar/array values, generates hashed harnesses, records machine-readable refusals, and executes every generated harness against the deployed local fixture. Address arguments are emitted as `address(uint160(0x...))` to avoid Solidity checksum-literal errors. Generic callback steps remain explicitly unsupported. |
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

P1 is accepted for its defined fixture scope and is merged through PR 64. No HUMAN_CONFIRMED or authentic-deployment claim is made by the fixture. P2 PR 69, **[Canonical trace parity and first verified fork](https://github.com/Toji254/foundry-lowkey/pull/69)**, was merged into `integration-test-drive` on 2026-11-16 (merge timestamp 04:31:48Z). Its exact-head PR workflow [run #43797580616](https://github.com/Toji254/foundry-lowkey/actions/runs/43797580616) passed, including `p2-first-fork-acceptance`; the accepted scope remains the validated canonical trace representation and one fixture-specific, read-only fork reproof. This does not establish universal client parity or a production exploit/profitability claim. PR [#70](https://github.com/Toji254/foundry-lowkey/pull/70) remains open as a draft and is not merged; do not infer acceptance of its changes from PR 69.

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

**Status: MERGED / accepted for the bounded P3.1 scope.** [PR 72](https://github.com/Toji254/foundry-lowkey/pull/72) was merged into `integration-test-drive` on 2026-11-16 (04:51:41Z). The exact-head PR workflow [run #43805655753](https://github.com/Toji254/foundry-lowkey/actions/runs/43805655753) and push run [#43805650714](https://github.com/Toji254/foundry-lowkey/actions/runs/43805650714) completed successfully.

P3.1 adds ten data-driven ArchetypePack records, a bounded deterministic source classifier, a conservative import/typed-call-candidate graph, source-hash-pinned assumption citations, and capability negotiation with a generic-mode skip list. Acceptance fixtures cover vault4626, constant-product AMM and an unknown target.

**Acceptance boundary:** an archetype is not an attack-family adapter. An OBSERVED classification means only that source signals selected a pack; it does not authenticate a deployment, establish a reachable exploit path, or confirm a vulnerability. Assumptions remain unverified. Full compiler AST/Slither call-graph and path-sensitive data-flow extraction remain outstanding. Model-driven novel hypotheses remain P9; full attack-chain composition remains in the attack-engine phase.


## 2026-11-22 reconciliation snapshot

**Current integration head reviewed:** `f01383b5cbdd6fb194eae067ee45a58cfc4a2cdb`.  
**Ledger purpose:** distinguish merged capabilities, branch-only evidence, open integration candidates, and remaining limitations. Historical statements above that conflict with this snapshot are superseded by the status updates below.

### AST declaration and storage-reference acceptance

**Candidate status: PASS; integration status: NOT YET MERGED.** The forensic branch [`forensic/ast-investigation-current`](https://github.com/Toji254/foundry-lowkey/tree/forensic/ast-investigation-current) is at `8498eaac731548001176e8cc56c0c0f378dc803f`, four commits ahead of the reviewed integration head and zero commits behind it. Exact-head workflow [run #45056235388](https://github.com/Toji254/foundry-lowkey/actions/runs/45056235388) completed with 12/12 jobs successful. The Python job ran 2,066 tests with 3 skipped; all passed. The focused compiler-AST suite passed 7/7, and the three individually reproduced AST acceptance cases passed.

This verifies the AST repair candidate, not an already-merged integration branch. The code and test changes remain on the forensic branch until their PR is merged; rerun exact-head CI after integration.

### P3 source-coverage integrity — PR 81

**Merged; bounded source-inventory integrity scope accepted.** [PR 81](https://github.com/Toji254/foundry-lowkey/pull/81), “Fail closed on incomplete Godmode source coverage,” was merged on 2026-11-22 at 08:51:20Z. The post-merge integration workflow [run #45004743287](https://github.com/Toji254/foundry-lowkey/actions/runs/45004743287) completed successfully.

The change builds one source inventory for mandatory Godmode scanners, records file stat/read failures, oversized files, skipped symlinks and unreadable subtrees, reuses the inspected snapshot across mandatory scanners, marks partial coverage as review and zero usable coverage as blocked, and returns non-zero for either integrity failure. Optional Slither failure remains visible without failing a source-only run when Slither was not requested.

This is a source-coverage integrity gate, **not** proof that every analysis is complete, that every scanner is sound, or that a candidate finding is exploitable.

### Outstanding integration PR reconciliation

The PRs below are assessed against the reviewed integration head, not their stale historical base commits.

| PR | Current finding | Recommended handling |
|---|---|---|
| [#73](https://github.com/Toji254/foundry-lowkey/pull/73) | Its complete 10-commit history is an ancestor of #76. It is not an independent feature stack. | Do not merge separately. Close as superseded after the useful #76 slices have been selected or ported. |
| [#76](https://github.com/Toji254/foundry-lowkey/pull/76) | Superset of #73, but its head is 442 commits behind the reviewed integration head, overlaps 13 current integration paths, and exact-head Python CI failed (2 failures, 1 import error; 1,949 tests ran, 3 skipped). | Keep temporarily as a source archive. Decompose into small ports against a fresh current base; do not merge wholesale. Fix the Python failures before any extracted slice can be accepted. |
| [#77](https://github.com/Toji254/foundry-lowkey/pull/77) | Exact-head run [#43815913397](https://github.com/Toji254/foundry-lowkey/actions/runs/43815913397) passed on its old base. Its opcode adapter overlaps #76 but is narrower: it drops transient TLOAD/TSTORE handling and some frame/code/access metadata, and relaxes ambiguous child-frame matching. | Do not merge as a second storage stack or replace the richer adapter wholesale. Port its proven empty-trace refusal, unmapped-access accounting and RPC/script-path acceptance fixes into the selected adapter. Preserve transient-storage evidence and fail-closed ambiguity handling; add repeated-same-target call-frame tests. |
| [#79](https://github.com/Toji254/foundry-lowkey/pull/79) | Project-scoped actor selection is safety-relevant. Its isolation/ephemeral-override tests passed, but its dispatch test failed because the test expected return code 0 while the version dispatch returned None; its remaining Python failures were Godmode help-label assertions. It also changes installer mode from 100644 to 100755. | Port onto the current base, correct the dispatch test oracle without weakening the actor assertion, and preserve executable installer mode. Run full exact-head CI. |
| [#80](https://github.com/Toji254/foundry-lowkey/pull/80) | Reset mode 2 removes only Anvil default/impersonated profiles and preserves private-key/env profiles and internal lab-deployer; its core reset test passed. Python CI remained red on four help assertions: two AI-help expectations for a missing recommendations-auto entry and two stale wizard/top-level help expectations for the obsolete `lk actor 0 Alice` example. These are help/test-contract issues, not evidence that reset-mode wallet preservation failed. One native-help description still says account 0 where the example correctly uses account 1. | Port together with #79, correct the help text, and add regression coverage for reset mode 2 when a project context still points to a profile being removed. Run full exact-head CI. |

**Shared guardrail:** these PR heads are based on old ancestors of `integration-test-drive`. Do not merge or cherry-pick their old stacks wholesale. Port by behavior and tests onto the current branch, preserving the executable bit on `install.sh`. No PR has been closed or retargeted as part of this ledger update.

### Phase 1 gate

**Opcode Intelligence Phase 1: NOT AUTHORIZED.** The AST-specific candidate gate is green, but the integration architecture is not reconciled. The #73/#76 feature stack must be decomposed, #77's adapter fixes must be evaluated against the richer storage implementation, and #79/#80 must be ported and jointly validated. Freeze the Phase 1 base only after those decisions are implemented on a current branch and its exact-head full CI passes.
