# Lowkey P0/P1 capability ledger

**Branch:** `integration-test-drive`  
**Snapshot:** `306924ac861aa349e2acfd694430a4248ac407b0`  
**Latest CI for this snapshot:** [run 7216](https://github.com/Toji254/foundry-lowkey/actions/runs/42009635081) — pending at the time this ledger was written.

This ledger distinguishes implementation, isolated fixture coverage, real `lk` command evidence, and phase acceptance. A green CI run does not close an acceptance case that the workflow never executes.

| Capability | Status | Evidence and remaining gate |
|---|---|---|
| ABI-aware setup values | IMPLEMENTED — unit coverage; P0 gate OPEN | Scalar primitives and one-dimensional primitive arrays are generated. Fixed arrays are bounded; tuple/nested arrays and unsupported dynamic element types are refused. Still need the required real `lk break` `address[]` target run or a reason-coded refusal captured in CI. |
| Payable/nonpayable setup | IMPLEMENTED — renderer coverage; P0 gate OPEN | Nonpayable calls use zero value; payable calls use the configured seed value. Must be demonstrated in the same real command-level acceptance workflow. |
| ERC-20 decimals discovery | IMPLEMENTED — renderer coverage; P0 gate OPEN | Calls `decimals()`; accepts values through 77; scales one whole token using `10 ** decimals`. If metadata is absent/invalid, deliberately uses one base unit and marks decimals unverified. The USDC-style vault path still needs to run through installed `lk`. |
| Optional-return approval | IMPLEMENTED — renderer coverage; fixture expanded; P0 gate OPEN | Empty return data is accepted; ABI true is accepted; false, revert, or malformed data fails closed; failed initial approval attempts reset-to-zero then retry. USDT-style payer must still pass through the generated `lk` harness, not only the isolated fixture helper. |
| ERC-777 receiver | IMPLEMENTED — generator and fixture coverage | Standard `tokensReceived` callback and ERC-1820 registration handshake. Runtime registration requires the canonical registry to exist on the selected chain. |
| ERC-1155 receiver | IMPLEMENTED — generator and fixture coverage | Single and batch callbacks plus ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | IMPLEMENTED — generator and fixture coverage | Standard `onERC721Received` callback selector. |
| Machine-readable refusals | IMPLEMENTED — parser/unit coverage; CI pending | Refusal normalization and specific reasons include `abi_discovery_failed`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, and `forge_no_lowkey_telemetry`. New malformed-return and failure-precedence changes are in the pending CI snapshot. |
| P1 paired control/attack | SIMULATED_BREAK — not phase accepted | Current paired Forge workflow proves matched control/attack execution for its fixture, but its verdict is capped at `SIMULATED_BREAK`. It does not satisfy the requested `LOCAL_PROFITABLE` reentrancy result with populated state diff and tampered frozen-digest rejection. |

## P0 acceptance cases still required

P0 is **not accepted** until the installed `lk` command runs all three cases on deterministic CI fixtures and each produces either `OBSERVED` with evidence or a machine-readable refusal:

1. **ABI setup:** a target requiring `address[]` setup arguments.
2. **USDC-style vault:** discover the asset getter, verify six-decimal metadata, fund the actor, and execute setup.
3. **USDT-style payer:** exercise empty-return approval and allowance reset/retry through the generated harness.

The current P0 compatibility fixture tests standard receiver callbacks, six-decimal metadata arithmetic, and optional-return approval semantics in isolation. Those are component tests, not substitutes for the three end-to-end `lk` cases above.

## Evidence rules

- `OBSERVED` means the execution and stated evidence were captured; it does not establish universal exploitability.
- A simulated or cheatcode-funded break is not a fork-backed reproof.
- Unsupported ABI shapes, missing ABI discovery, failed setup, unusable token getters, and failed approvals must be explicitly refused with reason codes; never silently substitute zero values or claim a break.
- Do not promote P0 or P1 to accepted based only on code presence, generated-string assertions, or an unrelated green CI job.
