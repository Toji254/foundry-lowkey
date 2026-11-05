# Lowkey P0/P1 capability ledger

Statuses are evidence-based. Code presence, generated-string assertions, and isolated fixture tests are not substitutes for a passing end-to-end `lk` workflow.

**Snapshot:** branch `integration-test-drive`, commit `3ffc512782cb64f3a66f7c051a552f4e2ed1679a`.

**Latest CI:** [run 7212](https://github.com/Toji254/foundry-lowkey/actions/runs/42004667736) — all seven jobs passed on this snapshot (2026-11-05).

| Capability | Current status | Evidence | Scope and remaining gate |
|---|---|---|---|
| P0 ABI-aware setup discovery | IMPLEMENTED — unit/CI PASS; end-to-end gate OPEN | `tests/test_break_engine.py`: dynamic/fixed primitive array rendering, `address[]`, and unsupported tuple refusal; Python CI on the snapshot above | The required real `lk break` path for an `address[]` setup target has not yet been recorded as `OBSERVED` or a reason-coded refusal. One-dimensional primitive arrays only; tuple and nested arrays are explicitly refused. |
| P0 payable/nonpayable setup semantics | IMPLEMENTED — unit/CI PASS; end-to-end gate OPEN | Renderer tests verify zero value for nonpayable setup and configured value for payable setup | Needs the same command-level fixture evidence as the ABI setup gate. |
| P0 ERC-20 decimal-aware setup funding | IMPLEMENTED — unit/CI PASS; end-to-end gate OPEN | Renderer tests verify `decimals()`, the `<= 77` bound, scale calculation, telemetry, and token balance tracking; P0 fixture covers a six-decimal metadata token | The required real `lk` workflow against a USDC-style vault is not yet recorded. If metadata is absent or invalid, the harness deliberately uses one base unit and marks decimals unverified; that is not equivalent to funding one whole token. |
| P0 optional-return ERC-20 approval | IMPLEMENTED — unit/CI PASS; end-to-end gate OPEN | Renderer tests verify low-level optional-return handling and actor-owned approval; Foundry fixture tests a no-return, reset-required token | The fixture's `LowkeySafeApproveFixture` is a compatibility stand-in, not the compiled harness emitted by `lk break`. The required USDT-style payer workflow has not yet been recorded end-to-end. |
| P0 ERC-777 receiver | IMPLEMENTED — component CI PASS | Generated-harness tests check `tokensReceived` and ERC-1820 registration; Foundry fixture exercises the standard handshake and hook | Actual registration requires the ERC-1820 registry at its canonical address on the local chain/fork. |
| P0 ERC-1155 receiver | IMPLEMENTED — component CI PASS | Generated-harness tests check single/batch hooks and ERC-165 support; Foundry fixture exercises both callbacks | Does not claim every custom token extension is covered. |
| P0 ERC-721 receiver | IMPLEMENTED — component CI PASS | Generated-harness tests check `onERC721Received`; Foundry fixture checks the selector | Standard safe-transfer receiver path only. |
| P0 machine-readable refusals | REASON-CODED PATHS ADDED — CI pending | New tests cover refusal normalization, setup rejection, missing telemetry, and ABI-discovery failure | The CI run after this change must pass; real command-level refusal cases remain required for P0 acceptance. |
| P1 paired Forge control/attack | PAIRED EXPERIMENT — CI PASS; economic proof gate OPEN | Latest `foundry-integration` job reruns paired Forge workflow; CI asserts `SIMULATED_BREAK` | This is not `LOCAL_PROFITABLE`. P1 still needs the required reentrancy result with populated state diff, paired control, and tampered frozen-digest rejection before the phase is accepted. |

## Acceptance gates still open

P0 is **not accepted yet**. The current workflow runs the isolated compatibility fixture and Python renderer/unit tests, but it does not yet prove the three requested paths through the installed `lk` command:

1. An `address[]` setup call reaches `OBSERVED`, or returns an explicit reason-coded refusal.
2. A USDC-style vault discovers its asset, verifies six-decimal metadata, funds the attacker, and reaches `OBSERVED`, or returns an explicit reason-coded refusal.
3. A USDT-style payer handles empty-return approval and allowance-reset/retry through the generated `lk` harness, reaching `OBSERVED` or returning an explicit reason-coded refusal.

Do not promote the P0 ledger to accepted until those cases are committed as repeatable CI acceptance tests and pass on the current branch.

## Evidence rules

- `OBSERVED` means an execution and its stated evidence were captured; it is not a claim of universal exploitability.
- A simulated or cheatcode-funded break remains separate from a fork-backed reproof.
- Unsupported ABI shapes and discovery failures are blocked with machine-readable reason codes rather than silently replaced with zero/empty/native assumptions.
- P1's current paired result remains `SIMULATED_BREAK`; never report it as a profitable exploit.
