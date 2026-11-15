# Lowkey P0/P1 capability ledger

This ledger separates implementation, isolated component coverage, installed-command acceptance, behavioural phase acceptance, and real-deployment proof. A command, generated string, compile-only harness, or green unrelated CI job is not evidence of a completed family.

**Integration branch:** `integration-test-drive`  
**P0 baseline:** `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`  
**P0 full integration CI:** [run 7442](https://github.com/Toji254/foundry-lowkey/actions/runs/42163749361), on `0d13d33b91c1c2c7c82ad6f37fa7eb8f6d3f814c`, completed with all 10 jobs successful.  
**P0 latest installed-CLI acceptance:** [run 7485](https://github.com/Toji254/foundry-lowkey/actions/runs/42363585120), on the P1 feature branch before the renderer checksum fix; the dedicated P0 acceptance job passed. The full run remains separate from the P0 job result.  
**P1 integration PR:** [PR 64](https://github.com/Toji254/foundry-lowkey/pull/64) merged into `integration-test-drive` at `0dd08f52a10330322fccdb3bb21c455232b6934e`; `master` remains untouched. The exact merged head passed all 10 jobs in [run 7667](https://github.com/Toji254/foundry-lowkey/actions/runs/43762416186). P1 is accepted for its controlled fixture scope; production target authenticity and broad protocol coverage remain unproven.

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
| P1 frozen control validation | P1 fixture acceptance passed; PR #64 merged and all 10 exact-head CI jobs passed | PR 64 exercises the separate non-executing `lk control --validate` path. Valid freeze -> `PROPOSED`; tampered digest -> `REJECTED/digest_mismatch`; neither validation path executes the control or attack. |
| P1 paired Forge control + state diff | P1 fixture acceptance passed; PR #64 merged and all 10 exact-head CI jobs passed | PR 64 runs the one-deployment sequential-control vs reentrancy-attack fixture, matched entry calldata, same prestate excluding the declared mode slot, chain/block/fork anchor checks, exact call-count expectations, and non-empty trace-derived storage accesses. Forge AccountAccess balances are gross structural observations only and remain capped at `SIMULATED_BREAK`; they are not net profit. |
| P1 funded Anvil reproof | Setup-cost accounting wired; P1 fixture acceptance passed; PR #64 merged and all 10 exact-head CI jobs passed | The P1 E2E script independently reads receipts for actor deployment and deposit, includes deployment gas, deposit principal, and deposit transaction gas in `--prior-cost-wei`, and checks the reproof artifact reports the same measured total. The replay's actual receipt gas is charged separately, without double-subtracting when the gas payer is included in the measured portfolio. The exact merged-head PR CI run passed all 10 jobs. Target authenticity remains `unknown` and proof status remains `OBSERVED` for this controlled fixture. |
| P1 mutation acceptance | P1 fixture acceptance passed; PR #64 merged and all 10 exact-head CI jobs passed | The same paired test mutates the vulnerable vault to checks-effects-interactions and requires the verdict to flip to `REJECTED/control_passed`. A surviving exploit produces `BLOCKED/mutation_not_killed` and fails the gate. |
| P1 Step renderer | P1 runtime fixture acceptance passed; full exact-head CI pending | The installed `lk steps` renderer validates typed scalar/array values, generates hashed harnesses, records machine-readable refusals, and executes every generated harness against the deployed local fixture. Address arguments are emitted as `address(uint160(0x...))` to avoid Solidity checksum-literal errors. Generic callback steps remain explicitly unsupported. |
| Generic `flash_borrow` / `reenter` Step kinds | BLOCKED / unsupported by design | These require protocol-specific callback actors. The renderer must emit `backend_unsupported`; it must not fabricate an executable callback. |


## Tier 0 hardening phase

Tier 0 is the reliability layer used by every later attack capability. These implementation contracts are being made operational on the separate branch `feat/tier0-hardening-20261116`; they are not merged until the feature branch passes its own checks.

| Capability | Implementation contract | Required acceptance |
|---|---|---|
| Cheat fingerprint | Stable SHA-256 pattern IDs, normalized token scan, Aho-Corasick matching, ordered mapping-read → external-call → mapping-write sequences, line/offset/snippet provenance, explicit heuristic limits | Fixture detects the ordered sequence, ignores comments, and returns stable pattern IDs |
| Control | Frozen experiment manifest, same entry-call/prestate checks, trace evidence and fail-closed BREAK downgrade | Existing control/freeze/tamper/trace tests plus P1 paired fixture |
| Mutation score | One family per manifest, passing baseline, every mutant accounted for; invalid, timeout, error or missing outcomes fail the score gate | Tests prove ≥90% valid score passes and an excluded invalid mutant fails |
| Target coverage | Fresh LCOV only, target source/line filtering, optional test filters and explicit minimum percentage | Fresh-LCOV fixture test proves threshold pass/fail behavior |
| Provenance | Artifact hashes, Git revision/branch/dirty state, chain/fork/tool metadata, detached signature and public-key sidecar, signature + artifact re-verification | Sign → verify passes; artifact tamper fails verification |
| Sandbox | Disposable project copy, default network namespace isolation, seccomp syscall filter, CPU/address-space/file-size/FD limits, read-only host/tool mounts; opt-in IP allowlist through a system service or fail closed | Unit tests cover deny-by-default, seccomp, resource options, and refusal without required isolation dependencies |

"Implemented" in the registry means the documented command path exists and its acceptance tests pass. It does not mean heuristic source matching is a vulnerability verdict, coverage proves security, mutation score proves exploitability, or sandboxing makes arbitrary code harmless. Network allowlisting is IP-based; all ports to an allowed IP are available. The allowlist backend requires `sudo`, `systemd-run`, and cgroup v2, and refuses rather than running without the requested network policy.

## Family scope — no fake greens

The 15 strings in `STEP_FAMILIES` are accepted family labels for the generic Step renderer. They are **not** 15 independently implemented exploit generators. The generic renderer's common Step sequence proves that the plan schema can be rendered and executed, not that each family has a positive attack, paired control, rejection seed, mutation test, and family-specific evidence.

Until those acceptance cases exist in the same PR, the following remain **telemetry-only** and must not be placed in the evaluation table or promoted to a BREAK capability:

| Family label | Scope |
|---|---|
| reentrancy | P1 behavioural acceptance in PR 64; local fixture gate passed; full exact-head CI pending |
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

P1 remains pending until the complete exact-head CI matrix for PR 64 passes. Its dedicated runtime, paired-control, mutation, and funded-reproof job has passed, but other CI jobs were still running when this ledger was updated. No `HUMAN_CONFIRMED` or authentic deployment claim is made by the fixture.
