# Lowkey P0/P1 capability ledger

Statuses distinguish implementation, isolated component coverage, installed-command acceptance, and phase acceptance. A generated-string assertion or green unrelated CI job is not sufficient to accept a phase.

**Branch:** `integration-test-drive`  
**Code snapshot under validation:** `f7f795d40db7b3e2ba73c0fe03a21c5a04aa0422`  
**CI:** [run 7223](https://github.com/Toji254/foundry-lowkey/actions/runs/42011133526) — running when this ledger was prepared.

| Capability | Current status | Evidence and limits |
|---|---|---|
| ABI-aware setup values | IMPLEMENTED — unit coverage; installed-CLI gate pending | Scalar primitives and one-dimensional primitive arrays are generated. Fixed arrays are bounded. Tuple, nested arrays, and unsupported dynamic element types are refused instead of fabricated. |
| Payable/nonpayable setup | IMPLEMENTED — renderer coverage; installed-CLI gate pending | Nonpayable setup calls use zero value; payable setup calls use the generated seed value. The installed-CLI acceptance now exercises a payable `address[]` setup. |
| ERC-20 decimal-aware funding | IMPLEMENTED — renderer coverage; installed-CLI gate pending | Reads `decimals()`; accepts values through 77 and scales one whole token as `10 ** decimals`. Missing/invalid metadata deliberately falls back to one base unit and marks decimals unverified. |
| Optional-return ERC-20 approval | IMPLEMENTED — renderer and fixture coverage; installed-CLI gate pending | Empty return data and ABI-encoded true are accepted. False, revert, and malformed return data fail closed. A failed initial approval attempts reset-to-zero then retry. The installed-CLI acceptance exercises a six-decimal no-return token that requires the reset/retry path. |
| ERC-777 receiver | IMPLEMENTED — generator and Foundry fixture coverage | Uses standard `tokensReceived` and ERC-1820 registration handshake. Registration on a live chain requires the canonical ERC-1820 registry to exist there. |
| ERC-1155 receiver | IMPLEMENTED — generator and Foundry fixture coverage | Implements single and batch callbacks plus ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | IMPLEMENTED — generator and Foundry fixture coverage | Implements the standard `onERC721Received` selector. |
| Machine-readable refusals | IMPLEMENTED — unit coverage; CI pending | Includes fallback reason codes and specific codes such as `abi_discovery_failed`, `unsupported_abi`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, `target_rejected_without_revert_evidence`, and `forge_no_lowkey_telemetry`. |
| P1 paired control/attack | SIMULATED_BREAK — not phase accepted | The paired Forge workflow demonstrates matched control/attack execution for its fixture, but its verdict is capped at `SIMULATED_BREAK`. It does not satisfy the requested `LOCAL_PROFITABLE` reentrancy result with populated state diff and tampered frozen-digest rejection. |

## P0 installed-command acceptance

The workflow now runs `scripts/p0-break-acceptance-e2e.py` through the installed `lk` executable against local Anvil deployments. Each case must produce a campaign evidence record with status `OBSERVED` and the required telemetry:

1. **ABI setup:** `AddressArraySetupTarget.deposit(address[])` must be discovered and executed by `lk break`.
2. **USDC-style vault:** `asset()` discovery, verified six-decimal metadata, `1_000_000` funding unit, approval, and setup execution must be visible in the evidence.
3. **USDT-style payer:** empty-return approval must succeed after the forced zero-reset/retry sequence, with six-decimal funding and setup execution visible.

The compatibility fixture separately checks false-return and malformed-return approval behavior, existing-allowance reset/retry, ERC-777 registration, ERC-1155 single/batch hooks, ERC-721 receiver behavior, and six-decimal scaling.

**P0 remains OPEN until the installed-command cases and the full CI run pass on the current branch.** The script's presence is not proof that it passed.

## Evidence rules

- `OBSERVED` means an execution and its stated evidence were captured; it does not establish universal exploitability.
- A simulated or cheatcode-funded break is not a fork-backed reproof.
- Unsupported ABI shapes, failed discovery, failed setup, unusable token getters, and failed approvals must be explicitly refused with reason codes; never silently substitute zero values or claim a break.
- Do not promote P0 or P1 to accepted based only on code presence, generated-string assertions, or an unrelated green CI job.
