# Lowkey P0/P1 capability ledger

Statuses distinguish implementation, isolated component coverage, installed-command acceptance, and phase acceptance. A generated-string assertion or unrelated green CI job is not sufficient to accept a phase.

**Branch:** `integration-test-drive`  
**P0/P1 code baseline:** `140346858b4c398605c28f0389f6185fa358ea89`  
**Historical P0 CI:** [run 7228](https://github.com/Toji254/foundry-lowkey/actions/runs/42012621666), on `4199f4190588a7c567f656db78744946c5e4f968`, passed the original three installed-`lk` cases and receiver fixture.  
**P0 follow-up CI:** [run 7285](https://github.com/Toji254/foundry-lowkey/actions/runs/42021562930), on `cc6e5e1ea21f772635ef7a913737157411cc6897`, passed Foundry integration including all four installed-`lk` compatibility cases. Its Python unit job failed with five unrelated/stale regression reports; later branch commits update the stale fallback expectation, DoS pattern coverage, workspace metadata, and project-scope handling. Current-head CI remains the acceptance authority.  
**P1 follow-up:** Step[] template, installed command routing, installer hashing, all-family compile acceptance and refusal checks are now wired. The current phase gate must pass before P2 starts.

| Capability | Current status | Evidence and limits |
|---|---|---|
| ABI-aware setup values | ACCEPTED for P0 scope | Installed `lk target` + `lk break` executed `AddressArraySetupTarget.deposit(address[])` and returned `OBSERVED`. Primitive scalars and one-dimensional primitive arrays are supported; tuple, nested arrays, and unsupported dynamic element types are refused. |
| Payable/nonpayable setup | ACCEPTED for P0 scope | The installed-`lk` payable `address[]` setup executed and produced `SETUP_SUCCESS true`. Nonpayable setup uses zero value; payable setup uses the generated seed value. |
| ERC-20 decimal-aware funding | ACCEPTED for installed-CLI compatibility; full P0 phase gate pending | Run 7285's Foundry job passed the four installed-`lk` scenarios, including missing-decimals fallback with `ASSET_DECIMALS_FALLBACK_18`, `ASSET_DECIMALS 18`, and `TOKEN_FUNDING_AMOUNT 1000000000000000000`. The overall run failed in the Python unit job, so phase-wide P0 acceptance still awaits current-head CI. Unverified fallback units are excluded from token-profit BREAK promotion. |
| Optional-return ERC-20 approval | ACCEPTED for P0 scope | Installed-`lk` USDT-style payer case returned `OBSERVED` with empty-return approval success. The fixture preloaded a nonzero attacker-to-vault allowance; generated harness telemetry confirmed reset-to-zero was attempted and the retry succeeded. False, revert, and malformed return data fail closed. |
| ERC-777 receiver | ACCEPTED for P0 scope | Foundry fixture exercises standard `tokensReceived` and ERC-1820 registration handshake. Live registration still requires the canonical ERC-1820 registry on the selected chain. |
| ERC-1155 receiver | ACCEPTED for P0 scope | Foundry fixture exercises single and batch callbacks plus ERC-165/ERC-1155 interface support. |
| ERC-721 receiver | ACCEPTED for P0 scope | Foundry fixture exercises the standard `onERC721Received` selector. |
| Machine-readable refusals | ACCEPTED for P0 scope | Python unit suite passes with fallback and specific refusal codes including `abi_discovery_failed`, `unsupported_abi`, `setup_call_reverted`, `asset_getter_unavailable`, `token_approval_failed`, `target_rejected_without_revert_evidence`, and `forge_no_lowkey_telemetry`. |
| P1 paired control, state diff and reproof | IMPLEMENTED; current-head CI pending | The Forge fixture uses one deployment, switches attacker mode outside measured windows, verifies control=1 vs attack=2 target calls, and normalizes populated per-access storage. The installed `lk control` runner checks matched entry calldata, transaction envelope, prestate, chain/block/fork anchor, trace delta, and semantic assertions. The fixture's status is intentionally capped at `SIMULATED_BREAK`; a separate funded Anvil reproof must report legacy `LOCAL_PROFITABLE`, positive net after gas and trace-derived target storage, while proof status remains `OBSERVED` because target authenticity is unknown. CI also tampers with the frozen digest and requires `REJECTED/digest_mismatch` with no execution. Current-head CI must pass all checks before P1 is accepted. |
| P1 Step[] renderer | IMPLEMENTED; compile gate pending | `lk steps` now routes through the installed CLI; `lowkey/templates/step_harness.sol.tmpl` is installed and included in the install manifest hash. CI renders all 15 declared family labels with typed scalar/array arguments, compiles the generated Foundry harnesses, and checks `flash_borrow`/`reenter` refusals as `backend_unsupported`. Generic callback execution remains unsupported and is not claimed. |

## P0 evidence and reproducibility

The installed-command acceptance is committed in `scripts/p0-break-acceptance-e2e.py` and wired into the Foundry CI job. It deploys local Anvil fixtures and runs four cases through the installed `lk` executable: `address[]` setup, six-decimal USDC, USDT-style empty-return approval with allowance reset, and missing-decimals fallback. Each case must reach `OBSERVED` and assert its setup/funding/approval telemetry. The fourth case (missing-decimals fallback) passed the installed-CLI portion of run 7285; the entire P0 phase remains pending current-head CI because that run's Python unit suite failed elsewhere.

The workflow copies campaign JSON, experiment JSON, and generated harness archives into `.audit/p0-break-acceptance/`, then uploads that directory even when an acceptance assertion fails. Run 7285 completed the upload step; current-head artifact validation is pending.

## Scope boundary

P0's three original compatibility cases and four installed-CLI acceptance scenarios have passed in the Foundry job; the P0 phase remains gated on the full current-head CI suite because run 7285's Python unit job failed. This does not mean every ERC-20 implementation, ABI shape, or receiver extension is supported.

P1 remains gated until the current-head workflow passes. A Forge fixture's `SIMULATED_BREAK` is not represented as deployment proof; the separate Anvil `LOCAL_PROFITABLE` reproof is kept distinct from the `OBSERVED` proof status for an unauthenticated target. No `HUMAN_CONFIRMED` claim is made.

The full real-project corpus job is a broader repository gate and was still running on the referenced CI run; it is not being represented as passed here.
