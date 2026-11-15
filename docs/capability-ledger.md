# Lowkey P0/P1 capability ledger

This ledger separates implementation, isolated component coverage, installed-command acceptance, behavioural phase acceptance, and real-deployment proof. A command, generated string, compile-only harness, or green unrelated CI job is not evidence of a completed family.

**Integration branch:** `integration-test-drive`  
**P0 baseline:** `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`  
**P0 full integration CI:** [run 7442](https://github.com/Toji254/foundry-lowkey/actions/runs/42163749361), on `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`, completed with all 10 jobs successful.  
**P0 latest installed-CLI acceptance:** [run 7485](https://github.com/Toji254/foundry-lowkey/actions/runs/42363585120), on the P1 feature branch before the renderer checksum fix; the dedicated P0 acceptance job passed. The full run remains separate from the P0 job result.  
**P1 implementation PR:** [PR 63](https://github.com/Toji254/foundry-lowkey/pull/63), targeting `integration-test-drive`. Exact-head run [7565](https://github.com/Toji254/foundry-lowkey/actions/runs/42366897005) completed successfully on `30322d1592ebaa508a88ba2504159021058f0280` with all 10 jobs green, including installed lk steps, paired Forge reentrancy/mutation, and funded local Anvil replay. P1 remains pending only because the E2E reprove invocation still omits the measured prior deployment/deposit outlay from --prior-cost-wei; do not start P2 or merge as P1-complete until that final economic gate is wired and passes.

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
| P1 frozen control validation | ACCEPTED for the P1 fixture | PR 63 adds a separate non-executing `lk control --validate` path. Valid freeze -> `PROPOSED`; tampered digest -> `REJECTED/digest_mismatch`; neither validation path executes the control or attack. |
| P1 paired Forge control + state diff | ACCEPTED for the P1 fixture | PR 63 adds one-deployment sequential-control vs reentrancy-attack fixture, matched entry calldata, same prestate excluding the declared mode slot, chain/block/fork anchor checks, exact call-count expectations, and non-empty trace-derived storage accesses. Forge AccountAccess balances are gross structural observations only and must remain capped at `SIMULATED_BREAK`; they are not net profit. |
| P1 funded Anvil reproof | Replay passed; full setup-cost acceptance pending | `lk reprove` now accepts `--prior-cost-wei` and subtracts it from measured gross portfolio delta in addition to the mined replay gas (without double-subtracting gas when the payer is included in the portfolio). Unit tests cover the cost subtraction. The P1 E2E script still needs to pass its measured actor-deployment fee and deposit outlay into this flag; until that is verified in CI, the gate cannot claim `LOCAL_PROFITABLE` after all costs. Target authenticity remains `unknown` and proof status must remain `OBSERVED` for the fixture. |
| P1 mutation acceptance | ACCEPTED for the P1 fixture | PR 63 mutates the vulnerable vault to checks-effects-interactions and requires the paired verdict to flip to `REJECTED/control_passed`. A surviving exploit produces `BLOCKED/mutation_not_killed` and fails the gate. |
| P1 Step renderer | ACCEPTED for the P1 fixture | The installed `lk steps` renderer validates typed scalar/array values, generates hashed harnesses, and fails closed on unsupported callback steps. PR 63 extends acceptance from compilation to executing each generated harness against a deployed local fixture. Run 7485 exposed an invalid Solidity address-literal checksum during generated-harness compilation. PR 63 now emits address arguments as `address(uint160(0x...))`; the exact-head runtime acceptance after that correction is pending. Do not call this runtime gate accepted until the new exact-head CI run passes. |
| Generic `flash_borrow` / `reenter` Step kinds | BLOCKED / unsupported by design | These require protocol-specific callback actors. The renderer must emit `backend_unsupported`; it must not fabricate an executable callback. |

## Family scope — no fake greens

The 15 strings in `STEP_FAMILIES` are accepted family labels for the generic Step renderer. They are **not** 15 independently implemented exploit generators. The generic renderer's common Step sequence proves that the plan schema can be rendered and executed, not that each family has a positive attack, paired control, rejection seed, mutation test, and family-specific evidence.

Until those acceptance cases exist in the same PR, the following remain **telemetry-only** and must not be placed in the evaluation table or promoted to a BREAK capability:

| Family label | Scope |
|---|---|
| reentrancy | P1 paired fixture acceptance passed on exact-head CI; prior setup-cost accounting remains the outstanding P1 gate |
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

PR 63's exact-head run 7565 passed the runtime/paired-control/mutation/replay checks. The following final economic condition remains before P1 is accepted:

1. Installed `lk steps` renders all 15 labels, validates template/harness hashes, records refusals, compiles, and **executes** every generated harness on the Anvil fixture.
2. One deployed vault and actor are reused for the sequential control and reentrant attack; the only scenario difference is the declared callback mode set outside each measured window.
3. The paired Forge evidence validates same entry call, matched prestate apart from the declared scenario parameter, same chain/block/fork anchor, expected control=1 vs attack=2 target calls, and non-empty trace-derived storage accesses.
4. The paired Forge result is `SIMULATED_BREAK`, never a profitability claim.
5. The frozen spec validates separately; tampering its digest yields `REJECTED/digest_mismatch` with no execution.
6. The CEI mutation kills the attack verdict and yields `REJECTED/control_passed`; otherwise the gate is `BLOCKED/mutation_not_killed`.
7. The separate funded Anvil replay has a successful mined receipt, trace-derived storage evidence, and positive net profit after both (a) the measured prior actor-deployment/deposit outlay supplied through `--prior-cost-wei` and (b) the replay transaction gas. The acceptance script must assert the recorded prior cost matches the independently measured setup outlay. Proof status remains `OBSERVED` because the target is a fixture.

If the prior-cost assertion is missing or fails, P1 stays pending. Do not start P2, do not claim fully cost-adjusted `LOCAL_PROFITABLE`, do not claim profit from Forge gross state deltas, and do not describe telemetry-only labels as executable family capabilities.

## Scope boundary

P0's installed compatibility gate and receiver fixture are implemented and covered by dedicated Anvil/Foundry acceptance. P0's result remains fixture-scoped.

P1's exact-head runtime, paired-control, mutation, and funded-replay execution checks passed in run 7565. P1 is still not accepted because the fixture has not yet wired and asserted its measured actor deployment/deposit costs through `--prior-cost-wei`. No `HUMAN_CONFIRMED` or authentic deployment claim is made by the fixture.
