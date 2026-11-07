# Lowkey P0/P1 capability ledger

This ledger separates implementation, isolated component coverage, installed-command acceptance, behavioural phase acceptance, and real-deployment proof. A command, generated string, compile-only harness, or green unrelated CI job is not evidence of a completed family.

**Integration branch:** `integration-test-drive`  
**P0 baseline:** `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`  
**P0 full integration CI:** [run 7442](https://github.com/Toji254/foundry-lowkey/actions/runs/42163749361), on `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`, completed with all 10 jobs successful.  
**P0 latest installed-CLI acceptance:** [run 7485](https://github.com/Toji254/foundry-lowkey/actions/runs/42363585120), on the P1 feature branch before the renderer checksum fix; the dedicated P0 acceptance job passed. The full run remains separate from the P0 job result.  
**P1 implementation PR:** [PR 63](https://github.com/Toji254/foundry-lowkey/pull/63), targeting `integration-test-drive`. It is deliberately separate; do not start P2 until its exact-head behavioural gate is green. The PR's P1 runtime gate is currently pending/failing during development and is not accepted yet.

| Capability | Current status | Evidence and limits |
|---|---|---|
| ABI-aware setup values | ACCEPTED for P0 scope | Installed `lk target` + `lk break` executed `AddressArraySetupTarget.deposit(address[])` and returned `OBSERVED`. Primitive scalars and one-dimensional primitive arrays are supported. Tuple, nested arrays, and unsupported dynamic element types refuse rather than guess. |
| Payable/nonpayable setup | ACCEPTED for P0 scope | Installed-`lk` payable `address[]` setup executed and produced `SETUP_SUCCESS true`. Nonpayable setup uses zero value; payable setup uses the generated seed value. |
| ERC-20 decimal-aware funding | ACCEPTED for P0 compatibility scope | The installed-CLI Anvil acceptance exercises a six-decimal USDC-style vault and a token without `decimals()`. The fallback is explicitly recorded as `ASSET_DECIMALS_FALLBACK_18`, with the assumed amount visible in telemetry. An unverified fallback must not support stronger token-profit claims. |
| Optional-return ERC-20 approval | ACCEPTED for P0 scope | Installed-`lk` USDT-style payer case exercises empty-return approval with an existing nonzero allowance. Generated telemetry confirms reset-to-zero and retry. False, revert, and malformed return data fail closed. |
| ERC-777 receiver | ACCEPTED for P0 fixture scope | Fixture exercises the standard `tokensReceived` callback and ERC-1820 registration handshake. A real chain still needs its canonical ERC-1820 registry. |
| ERC-1155 receiver | ACCEPTED for P0 fixture scope | Fixture exercises both single and batch callbacks and ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | ACCEPTED for P0 fixture scope | Fixture exercises the standard `onERC721Received` selector. |
| Machine-readable refusals | ACCEPTED for P0 scope | Python tests cover explicit refusal paths including `abi_discovery_failed`, `unsupported_abi`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, `target_rejected_without_revert_evidence`, and `forge_no_lowkey_telemetry`. |
| P1 frozen control validation | IMPLEMENTED; acceptance pending | PR 63 adds a separate non-executing `lk control --validate` path. Valid freeze -> `PROPOSED`; tampered digest -> `REJECTED/digest_mismatch`; neither validation path executes the control or attack. |
| P1 paired Forge control + state diff | IMPLEMENTED; behavioural acceptance pending | PR 63 adds one-deployment sequential-control vs reentrancy-attack fixture, matched entry calldata, same prestate excluding the declared mode slot, chain/block/fork anchor checks, exact call-count expectations, and non-empty trace-derived storage accesses. Forge AccountAccess balances are gross structural observations only and must remain capped at `SIMULATED_BREAK`; they are not net profit. |
| P1 funded Anvil reproof | IMPLEMENTED; behavioural acceptance pending | Separate mined transaction is measured with its receipt, effective gas price, and portfolio including both gas payer and recipient. It must prove positive net after gas for `LOCAL_PROFITABLE`. Since the acceptance target is a fixture, target authenticity remains `unknown` and proof status remains `OBSERVED`. |
| P1 mutation acceptance | IMPLEMENTED; behavioural acceptance pending | PR 63 mutates the vulnerable vault to checks-effects-interactions and requires the paired verdict to flip to `REJECTED/control_passed`. A surviving exploit produces `BLOCKED/mutation_not_killed` and fails the gate. |
| P1 Step renderer | IMPLEMENTED; runtime acceptance pending | The installed `lk steps` renderer validates typed scalar/array values, generates hashed harnesses, and fails closed on unsupported callback steps. PR 63 extends acceptance from compilation to executing each generated harness against a deployed local fixture. The current run exposed an invalid Solidity address-literal checksum; address rendering is being corrected to emit `address(uint160(0x...))`. Do not call the runtime gate accepted until a new exact-head CI run passes. |
| Generic `flash_borrow` / `reenter` Step kinds | BLOCKED / unsupported by design | These require protocol-specific callback actors. The renderer must emit `backend_unsupported`; it must not fabricate an executable callback. |

## Family scope — no fake greens

The 15 strings in `STEP_FAMILIES` are accepted family labels for the generic Step renderer. They are **not** 15 independently implemented exploit generators. The generic renderer's common Step sequence proves that the plan schema can be rendered and executed, not that each family has a positive attack, paired control, rejection seed, mutation test, and family-specific evidence.

Until those acceptance cases exist in the same PR, the following remain **telemetry-only** and must not be placed in the evaluation table or promoted to a BREAK capability:

| Family label | Scope |
|---|---|
| reentrancy | P1 behavioural acceptance in PR 63; not accepted until exact-head CI passes |
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

PR 63 must pass, on its exact latest head SHA, all of the following before P1 is accepted:

1. Installed `lk steps` renders all 15 labels, validates template/harness hashes, records refusals, compiles, and **executes** every generated harness on the Anvil fixture.
2. One deployed vault and actor are reused for the sequential control and reentrant attack; the only scenario difference is the declared callback mode set outside each measured window.
3. The paired Forge evidence validates same entry call, matched prestate apart from the declared scenario parameter, same chain/block/fork anchor, expected control=1 vs attack=2 target calls, and non-empty trace-derived storage accesses.
4. The paired Forge result is `SIMULATED_BREAK`, never a profitability claim.
5. The frozen spec validates separately; tampering its digest yields `REJECTED/digest_mismatch` with no execution.
6. The CEI mutation kills the attack verdict and yields `REJECTED/control_passed`; otherwise the gate is `BLOCKED/mutation_not_killed`.
7. The separate funded Anvil replay has a successful mined receipt, non-zero measured gas, positive net profit after gas, and trace-derived storage evidence; proof status remains `OBSERVED` because the target is a fixture.

If any item fails, P1 stays pending and the PR records the actual failing command/exit code and evidence. Do not start P2, do not claim `LOCAL_PROFITABLE` from Forge gross state deltas, and do not describe telemetry-only labels as executable family capabilities.

## Scope boundary

P0's installed compatibility gate and receiver fixture are implemented and covered by dedicated Anvil/Foundry acceptance. P0's result remains fixture-scoped.

P1 is not yet accepted until PR 63's exact-head runtime, paired-control, mutation, and funded-reproof gates complete successfully. No `HUMAN_CONFIRMED` or authentic deployment claim is made by the fixture.
