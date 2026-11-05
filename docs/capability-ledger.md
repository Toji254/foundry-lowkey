# Lowkey P0/P1 capability ledger

Statuses are evidence-based. A feature is not marked accepted because its code exists or because a unit test checks a generated string. The acceptance run must pass on the current implementation.

| Capability | Status | Evidence / gate | Scope and limits |
|---|---|---|---|
| P0 ABI-aware setup discovery | IMPLEMENTED — CI pending | Python compile and unit suite on the branch; Foundry harness acceptance pending | Supports primitive ABI values and one-dimensional primitive arrays, including fixed arrays up to 64 entries. Tuple and nested arrays are explicitly refused. |
| P0 payable/nonpayable setup semantics | IMPLEMENTED — CI pending | Renderer tests plus full Python suite | Nonpayable setup calls are sent with zero value. Payable setup calls use the configured seed value. |
| P0 ERC-20 decimal-aware setup funding | IMPLEMENTED — CI pending | Python renderer tests and P0 Foundry fixture | Reads optional `decimals()`; when metadata is unavailable or invalid, uses one base unit and records decimals as unverified. |
| P0 optional-return ERC-20 approval | IMPLEMENTED — CI pending | Generated harness and P0 Foundry fixture | Accepts empty return data or ABI-encoded true; on false/revert, tries allowance reset to zero then retries. Malformed return data fails closed. |
| P0 ERC-777 receiver | IMPLEMENTED — CI pending | Generator test and P0 Foundry fixture | Implements `tokensReceived` and ERC-1820 registration. Actual registration is available only where the registry exists on the local chain/fork. |
| P0 ERC-1155 receiver | IMPLEMENTED — CI pending | Generator test and P0 Foundry fixture | Implements both single and batch callbacks and reports ERC-165/ERC-1155 interface support. |
| P0 ERC-721 receiver | IMPLEMENTED — CI pending | Generator test and P0 Foundry fixture | Implements `onERC721Received` with the standard selector. |
| P1 paired Forge control/attack | OBSERVED — prior CI pass | [CI run 41967873660](https://github.com/Toji254/foundry-lowkey/actions/runs/41967873660), commit `85859c2f44ea61111ac9d4ebbb0e7ff7689c1bd5` | One deployment; matched prestate except declared scenario parameter; exact target calldata, events and derived storage checked. The result applies to the checked reentrancy fixture, not every attack family. |

## Evidence rules

- `OBSERVED` means an execution and its stated evidence were captured; it is not a claim of universal exploitability.
- A simulated or cheatcode-funded break remains separate from a fork-backed reproof.
- Unsupported ABI shapes remain blocked rather than silently replaced with zero/empty values.
