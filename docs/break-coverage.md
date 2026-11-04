# Lowkey break coverage

> This document describes executable coverage in the current branch. An attack-family name in the catalog is not proof that a protocol-specific exploit adapter exists.

## Verdict meanings

| Status | Meaning |
|---|---|
| `BREAK` | A generated harness reached its explicit break predicate. It still requires human review and realistic-fidelity validation. |
| `OBSERVED` | A call or state transition was executed and recorded, but the harness did not establish the security property. |
| `LAB_ISSUE` | Setup or fixture conditions prevented the intended experiment. |
| `BLOCKED` | Lowkey could not construct or execute a valid experiment. |
| `TIMEOUT` | Execution exceeded the configured timeout; no security conclusion is supported. |

A successful transaction, a revert, a suspicious name, a static finding, or a target-balance decrease is not by itself a vulnerability.

## Current attack-family coverage

| Family | Current implementation | Can generic `lk break` claim BREAK? | Limitation |
|---|---|---:|---|
| Reentrancy | Forge callback harness with a sequential non-reentrant control run from a reverted snapshot | Conditionally | Requires a valid target setup and measurable differential; simulated balances remain a fidelity limitation; runtime compile/fixture validation is still required |
| Replay | Repeat-call harness with optional address-keyed entitlement getter, two-call success check and attacker/target balance deltas | Conditionally | BREAK requires the pre-attack entitlement getter; setup/getter discovery is heuristic and this path does not yet use an independent sequential control |
| Accounting | Repeat-call harness with ETH/token balance observations, decimal-aware optional token seeding, safe no-return/bool-return approvals and same-asset payout/outflow comparison | Conditionally | BREAK requires both calls to succeed and payout to exceed entitlement in the same asset unit with target outflow corroboration; this is not a general accounting invariant and unusual token semantics need dedicated adapters |
| Access control | Generic unauthorized-call probe | No | Call success does not prove privilege escalation or state compromise |
| Upgrade | Generic lifecycle/privileged-call probe | No | Needs implementation/admin state verification and upgrade-specific invariants |
| Boundary | Zero/max argument probes | No | Successful edge calls are observations until a violated property is measured |
| Time | Fork-relative timestamp probe (+1 day and +30 days) | No | Records behavior differences; no protocol-specific state/price invariant yet |
| Callback | Generic call observation | No | Requires receiver-specific callback and state invariant |
| Signature | Generic call observation | No | Requires signature/nonce/domain-specific test vectors and replay assertions |
| DoS | Generic call observation | No | Requires bounded gas/resource measurements and a reachability model |
| Oracle | Generic call observation | No | No generic price-skew adapter or downstream-loss assertion yet |
| Economic | Generic call observation | No | No generic flash-loan/composition or net-profit model yet |
| ERC-20 | Generic call observation | No | No complete adversarial-token matrix in the breaker yet |
| Proxy | Generic lifecycle/call observation | No | Proxy resolver and storage/upgrade invariants are not complete attack adapters |
| Storage | Generic call observation | No | Raw storage observations are not semantic storage-layout recovery |

## Control and fidelity rules

The reentrancy harness now performs a sequential control experiment with callbacks disabled, reverts to the same snapshot, and then performs the callback-enabled experiment. The reentrancy BREAK predicate compares the attacker's measured gain and target loss against the control run.

The control makes the verdict more discriminating, but it does **not** by itself establish real-world profitability. The current harness can use Foundry balance-manipulation cheatcodes. Any result using synthetic ETH or token balances must be labelled simulated-funds until the necessary capital and asset flow are independently established.

Every PoC should ultimately record at least:

- Chain ID, fork block number and RPC/fork provenance.
- Target address, runtime bytecode hash and source/artifact hash where available.
- Harness hash, compiler version, Foundry/Cast versions and exact command.
- Cheatcodes used, synthetic balances and mocked external calls.
- Setup-discovery results and whether entitlement/asset getters were found.
- Attacker-side balance delta, target-side asset delta, gas and financing costs.
- Whether a sequential/control run exists and whether it began from the same state.
- A status that distinguishes observed, reproduced, realistic, profitable and human-confirmed.

Do not promote a simulated-funds or heuristic-only experiment into a confirmed finding.

## Known coverage gaps

1. The generated replay/accounting path still relies on heuristic setup and entitlement discovery and does not yet have the same control-run design as reentrancy.
2. Generic access and upgrade calls are observational. A future state-verification adapter must read authoritative owner/admin/implementation state before reporting privilege escalation.
3. Boundary and time probes do not have a violated-property oracle.
4. Oracle, economic, callback, signature, DoS, ERC-20, proxy and storage families are recognized, but generic family dispatch is not a substitute for real protocol-specific adapters.
5. Historical exploit replay, transaction-order reconstruction inside a block, calldata-derived fuzz corpora, and a full fidelity gate are not complete.
6. Generated Solidity harnesses still rely on the project's `forge-std` dependency. A standalone compile fixture for every family is required before these templates can be treated as reliably generated.
7. A generic command surface or a passing fixture must not be described as broad protocol coverage.

## Promotion gate for each family

A family is promoted to verified coverage only when the repository contains:

1. A known-good fixture and a known-bad fixture.
2. A complete generated harness that compiles under the supported toolchain.
3. A passing control run on the same starting state.
4. A break predicate tied to an explicit invariant or measured impact.
5. A fidelity record that lists synthetic state and cheatcodes.
6. A deterministic regression test in CI.
7. A reproducible report with tool versions, block identity and evidence hashes.

A family that lacks any of these remains partial or observational.