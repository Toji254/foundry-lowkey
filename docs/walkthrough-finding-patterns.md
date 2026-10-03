# Walkthrough finding-pattern research

The live walkthrough's pattern pass is based on recurring logic from adjudicated/public smart-contract security reports, not on copying individual bug titles into protocol-specific rules.

## How the research was distilled

The useful unit is the *logic family*:

`What assumption failed?` → `What observable invariant broke?` → `What is the smallest reproducible probe?`

Invalid or weak submissions are deliberately not treated as proof. A source pattern creates a **CANDIDATE**. A local-chain probe can create **REVIEW** or **CONFIRMED** only when the observed result supports the pattern's concrete impact.

## Pattern families

| ID | Logic family | What Lowkey checks |
| --- | --- | --- |
| REPLAY-001 | Replayable payout | Claim/withdraw/redeem-like paths that consume user state; repeat the same call and compare value/state deltas. |
| REENTRANCY-001 | CEI/reentrancy | External interaction before a later state update, without an obvious reentrancy guard. |
| AUTH-001 | Missing authorization | Sensitive state changes with no visible caller/role/owner boundary. |
| AUTH-002 | tx.origin | Detects tx.origin use and asks whether it crosses an authorization/signature boundary. |
| ORACLE-001 | Stale oracle | latestRoundData/getRoundData use without obvious freshness/round validation in the same function. |
| ROUND-001 | Zero-share/rounding loss | Share/amount conversion or division without an obvious zero-output guard. |
| SIG-001 | Signature replay/binding | Signature verification without obvious nonce plus contract/domain/chain binding. |
| DOS-001 | Unbounded growth/loop | Mutating paths looping directly over storage arrays whose size can grow. |
| TOKEN-001 | Transfer return handling | Raw ERC20 transfer/transferFrom without an obvious checked return or SafeERC20 wrapper. |
| ACCOUNTING-001 | Paired-variable mismatch | Related paired fields are validated together; auditor should verify each check uses the intended operand. |
| FOT-001 | Fee-on-transfer | transferFrom followed by crediting requested amount without measuring actual received balance. |
| RNG-001 | Weak randomness | Valuable/random-looking functions use predictable block-visible values. |
| INIT-001 | Initializer reuse | Initializer-like function remains exposed on a state-changing contract. |
| CALL-001 | Arbitrary external call | Generic call/delegatecall target or calldata appears caller-controlled without an obvious authorization boundary. |
| ZEROADDR-001 | Zero-address config | Configuration state writes accept address parameters with no obvious address(0) guard. |
| TIME-001 | Expiry/deadline boundary | Time-bounded calls are candidates for an expired-input probe. |

## Sources and recurring lessons

### CodeHawks

Public CodeHawks reports repeatedly show:
- state keyed by one value but checked/updated with another can enable claim replay;
- reentrancy can arise when ETH is transferred before cooldown/balance state is consumed;
- deposits can accept assets while minting zero shares;
- accounting can use the wrong variable/order;
- oracle reads can accept stale prices;
- unbounded loops and state-growth paths can become denial-of-service conditions.

Confidence Pools is deliberately kept as a separate stateful benchmark adapter because its attack stories require protocol-specific lifecycle knowledge.

### Immunefi

Immunefi's security library groups reentrancy, logic/authentication failures, oracle failures, access control, congestion/gas failure, frontrunning, replay/signature problems, randomness and timestamp manipulation among common smart-contract bug families.

Its bug-fix reviews also reinforce a recurring rule: accounting bugs are often not single-line arithmetic mistakes; they are state synchronization failures across deposits, redemptions, fees, rounding, or failure paths.

The live pattern suite therefore favors observable invariants over labels such as "reentrancy" or "oracle bug".

### Code4rena

C4 reports repeatedly provide the same recurrence:
- stale oracle price metadata;
- unbounded loops on growing storage;
- multiple initialization;
- rounding that strands funds or misprices shares;
- unchecked token transfer return values;
- arbitrary execution without sufficient caller validation;
- repeated claims/airdrops or incorrect state synchronization.

### Solodit / broader public reports

Solodit-style finding indexes reinforce recurrence around replay, access control, CEI, read-only reentrancy, share inflation/rounding, token-order mistakes, transfer-return assumptions, unbounded loops and oracle issues.

The walkthrough does not treat the number of reports for a pattern as evidence that a specific target is vulnerable. It uses recurrence to decide *which assumptions are worth probing*.

## Why the result is not an automatic audit verdict

A static match can be intentional. For example:
- a public setter may intentionally be public;
- a repeated withdrawal may intentionally support multiple partial withdrawals;
- a zero address may be a documented sentinel;
- an unchecked transfer may call a token wrapper with stronger guarantees;
- a deadline may be optional by design.

That is why the terminal categories are:

- **CANDIDATE** — source pattern matched; inspect it.
- **REVIEW** — a live probe produced interesting behavior, but impact/intent is not fully proven.
- **CONFIRMED** — the local-chain probe reproduced the pattern's concrete value/state condition.
- **NOT_REPRODUCED / NOT_TRIGGERED** — the candidate did not reproduce under this local state.
- **BLOCKED** — the lab could not safely execute the probe.

The generated evidence records the source location, observed behavior, reasoning, and the next verification step so a human auditor can turn a signal into a real finding test.
