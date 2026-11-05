# Lowkey P0/P1 capability ledger

Statuses distinguish implementation, isolated component coverage, installed-command acceptance, and phase acceptance. A generated-string assertion or unrelated green CI job is not sufficient to accept a phase.

**Branch:** `integration-test-drive`  
**Pre-follow-up code snapshot:** `5f481a9d1377da9fa4a0b579a2f48c25a2eed941`  
**Historical P0 CI:** [CI run 7228](https://github.com/Toji254/foundry-lowkey/actions/runs/42012621666), on `4199f4190588a7c567f656db78744946c5e4f968`, completed successfully. Its `foundry-integration` job confirms the three original installed-`lk` scenarios and the receiver fixture passed.  
**Current P0 follow-up:** explicit 18-decimal fallback telemetry, a no-metadata installed-`lk` scenario, and conservative token-profit guards are implemented in the follow-up commits below. CI on the new head is pending; do not treat the historical run as evidence for the added fourth scenario.

| Capability | Current status | Evidence and limits |
|---|---|---|
| ABI-aware setup values | ACCEPTED for P0 scope | Installed `lk target` + `lk break` executed `AddressArraySetupTarget.deposit(address[])` and returned `OBSERVED`. Primitive scalars and one-dimensional primitive arrays are supported; tuple, nested arrays, and unsupported dynamic element types are refused. |
| Payable/nonpayable setup | ACCEPTED for P0 scope | The installed-`lk` payable `address[]` setup executed and produced `SETUP_SUCCESS true`. Nonpayable setup uses zero value; payable setup uses the generated seed value. |
| ERC-20 decimal-aware funding | ACCEPTED for verified metadata; fallback follow-up pending CI | Historical installed-`lk` USDC case verifies six decimals and `TOKEN_FUNDING_AMOUNT 1000000`. This follow-up changes missing/invalid metadata to an explicit 18-decimal (`1e18`) fallback, emits `ASSET_DECIMALS_FALLBACK_18`, and prevents unverified token units from producing token-profit BREAKs. The new no-metadata installed-`lk` scenario must pass current-head CI before this row is fully accepted. |
| Optional-return ERC-20 approval | ACCEPTED for P0 scope | Installed-`lk` USDT-style payer case returned `OBSERVED` with empty-return approval success. The fixture preloaded a nonzero attacker-to-vault allowance; generated harness telemetry confirmed reset-to-zero was attempted and the retry succeeded. False, revert, and malformed return data fail closed. |
| ERC-777 receiver | ACCEPTED for P0 scope | Foundry fixture exercises standard `tokensReceived` and ERC-1820 registration handshake. Live registration still requires the canonical ERC-1820 registry on the selected chain. |
| ERC-1155 receiver | ACCEPTED for P0 scope | Foundry fixture exercises single and batch callbacks plus ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | ACCEPTED for P0 scope | Foundry fixture exercises the standard `onERC721Received` selector. |
| Machine-readable refusals | ACCEPTED for P0 scope | Python unit suite passes with fallback and specific refusal codes including `abi_discovery_failed`, `unsupported_abi`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, `target_rejected_without_revert_evidence`, and `forge_no_lowkey_telemetry`. |
| P1 paired control/attack | SIMULATED_BREAK — not phase accepted | The paired Forge workflow demonstrates matched control/attack execution for its fixture, but its verdict is capped at `SIMULATED_BREAK`. It does not satisfy the requested `LOCAL_PROFITABLE` reentrancy result with populated state diff and tampered frozen-digest rejection. |

## P0 evidence and reproducibility

The installed-command acceptance is committed in `scripts/p0-break-acceptance-e2e.py` and wired into the Foundry CI job. It deploys local Anvil fixtures and runs four cases through the installed `lk` executable: `address[]` setup, six-decimal USDC, USDT-style empty-return approval with allowance reset, and missing-decimals fallback. Each case must reach `OBSERVED` and assert its setup/funding/approval telemetry. The fourth case is added by this follow-up and is not accepted until current-head CI reports green.

The workflow now copies campaign JSON, experiment JSON, and the generated harness archive into `.audit/p0-break-acceptance/`, then uploads that directory as a CI artifact even if an acceptance assertion fails. Artifact-upload validation is pending the current workflow run.

## Scope boundary

P0 is accepted for the stated ABI setup, decimal-aware funding, optional-return/reset approval, standard receiver-hook, and refusal-reporting scope. This does not mean every ERC-20 implementation, ABI shape, or receiver extension is supported.

P1 remains separate and unaccepted. A simulated or cheatcode-funded break is not a fork-backed reproof, and no profitability or human-confirmation claim is made.

The full real-project corpus job is a broader repository gate and was still running on the referenced CI run; it is not being represented as passed here.
