# Lowkey next-generation audit engine

This roadmap combines the agreed recon/fork/adapter/invariant/detector/report architecture with the later force-multiplier and historical-exploit proposals.

It is a capability roadmap, not a claim that the listed features currently exist. See [break coverage](break-coverage.md) for the current executable boundary.

## Delivered in the current feature branch

The following first tranche is implemented in this branch; it is not a claim that the full roadmap is complete:

- Reentrancy now compares a callback-enabled run against a sequential callback-disabled control from the same snapshot and requires the attack to outperform that control.
- Generic Cast repeat/access probes no longer promote successful calls, target outflows or privileged-looking names into BREAK without a protocol-specific oracle.
- Time probes advance relative to the fork timestamp.
- Repeat/accounting probes include the test sender's balance when measuring ETH flow, and the optional token seed is decimal-aware with no-return/bool-return safe approval handling.
- Setup helper arguments are generated from supported ABI scalar types; discovery outcomes/errors are retained in evidence.
- Break evidence records chain/observed block, target bytecode/artifact/harness hashes and detected cheatcodes. Synthetic funds and missing gas/net-profit verification are explicit.
- Generated harnesses use `test/lowkey/` with exclusive creation.
- CI has a generated-harness Solidity compilation gate, including the same via-IR fallback used by the production runner.
- `lk unravel` reconstructs an existing transaction into a bounded call tree when the RPC supports callTracer, native ETH call flows, decoded ABI calls/events, gas fee and a saved JSON dossier. It falls back to Cast trace when callTracer is unavailable; this is not a net-profit or exploit verdict.
- `lk recon [address] --json` now emits a saved address dossier with chain/block identity, runtime code metadata, local ABI/function inventory, EIP-1967/EIP-1822 slot observations, EIP-1167 clone hints, and optional deep PUSH4/PUSH20 candidates or bounded raw storage observations. Candidate data is explicitly not treated as verified source, a confirmed implementation, or compiler storage layout.

The live compile/CI result for this branch must be checked before treating the new paths as validated. Dedicated end-to-end `lk unravel` tests and historical transaction reconstruction remain follow-up work.

## Design target

The goal is not "more commands." The goal is a reproducible workflow from an unfamiliar contract or historical transaction to an evidence-backed, human-reviewable security conclusion.

```text
RECON → UNDERSTAND → HYPOTHESIZE → ATTACK → CONTROL → PROVE → REPORT
```

Every stage must preserve provenance, show missing prerequisites, and distinguish observation from proof. AI can propose hypotheses and paths; native execution, assertions, and human review determine conclusions.

## Tier 0 — Trust and force multipliers

| Capability | Intended behavior | Acceptance gate |
|---|---|---|
| Sequential control runs | Compare attack behavior with the same calls executed without the adversarial callback/order | Both runs begin from the same snapshot and use equivalent setup/capital |
| Harness mutation score | Mutate a known-bad fixture and require the generated harness to detect the changed behavior | Per-family mutation tests; a decorative harness cannot pass |
| Target-line coverage | Map exercised target lines and call sites to the hypothesis under test | Coverage is evidence context, never a safety score by itself |
| Provenance | Hash harnesses/artifacts and record chain, observed block, bytecode, compiler and tool versions | Reproduction bundle contains hashes and exact command |
| Fidelity ledger | Record cheatcodes, synthetic funds, mocks, pranks, time changes and state overrides | No silent promotion of simulated-funds experiments |
| Sandbox | Run untrusted project builds/tests with resource limits and restricted filesystem/network permissions | Explicit threat model; no claim that process limits alone are a security sandbox |
| Cheatcode fingerprinting | Reuse the local cheatcode/reference corpus to locate state reads, external calls and writes in target source | Positive/negative fixtures; source order preserved |

## Tier 1 — Understand targets without verified source

| Capability | Intended behavior | Important limitation |
|---|---|---|
| Decompiler adapter | Invoke maintained decompilers and normalize pseudo-source for further inspection | Decompiled output is inferred, not verified source |
| Storage inference | Combine raw slot observations, execution traces and known keys to propose layouts | Output is probabilistic; never label raw slots as compiler storage layout |
| Proxy resolution | Check EIP-1967, EIP-1822, minimal proxies, beacon patterns, delegatecall evidence and diamond loupe surfaces | Candidate addresses require corroboration; scanning arbitrary slots is not proof |
| Selector intelligence | Harvest runtime selectors, query signature sources and generate bounded candidate signatures | Unknown selectors remain unknown; never present guesses as confirmed ABI |
| CFG/call graph | Show branches, call sites, storage reads/writes and reverts | Bytecode/source mapping confidence must be visible |
| Reentrancy graph | Correlate state reads, external calls and later writes within and across functions | A read-call-write pattern is a lead, not proof of exploitability |
| Fallback map | Inventory receive/fallback, proxy fallback, token/NFT hooks and callback entry points | Include inherited and delegated execution where resolvable |
| Calldata corpus | Collect historical calldata by selector and preserve real parameter examples | Respect RPC/archive limits; do not treat past calldata as valid fuzz input automatically |
| Transaction unraveling | Decode a transaction into a call tree, address labels, value flow, logs and storage changes | Trace availability is client-specific; failed traces are coverage gaps |

## Tier 2 — Reusable attack and protocol archetypes

| Capability | Intended behavior | Acceptance gate |
|---|---|---|
| Executable attack library | Promote catalogue entries into detector + fixture + harness + assertion bundles | Every pattern has known-good and known-bad fixtures |
| Archetype suites | Parameterized vault, lending, AMM, staking, bridge and governance handlers | Explicit assumptions, units, actors, accounting domains and valid properties |
| Invariant forge | Generate candidate ghost variables and property templates from a selected archetype | Human-reviewed property; never infer universal accounting from variable names |
| Adversarial token matrix | Exercise no-return, false-return, fee-on-transfer, rebasing, hook, blacklist and unusual-decimal tokens | Correctly model token-specific decimals, approvals and semantics |
| Oracle map/skew | Inventory price sources and test spot/TWAP/freshness/decimal assumptions in a controlled fork | Demonstrate downstream loss; restore state and record required capital |
| Flash-loan adapters | Integrate Aave, Balancer and Uniswap V3 with venue-specific callbacks, liquidity and fee accounting | Real fork liquidity and interfaces; mocks are labelled as mocks |
| Time campaign | Test fork-relative deadline, unlock, accrual and observation windows | Build observations and compare a control; never jump to arbitrary epoch timestamps |
| Signature matrix | Test nonce, expiry, chain/domain, signer, malleability and replay boundaries | Valid test vectors and an explicit authorization property |
| Initialization campaign | Test proxy and implementation initialization and privileged lifecycle transitions | Verify ownership/admin/implementation state rather than call success |
| Symbolic path exploration | Use Halmos to explore constrained paths and produce candidate predicates | Solver bounds and assumptions recorded; symbolic path is not automatically exploit proof |
| Composition planner | Search bounded chains across actors, adapters, targets, dependencies and assets | Every edge has a real precondition, cost, state transition and assertion |

## Tier 3 — Evidence that survives scrutiny

| Capability | Intended behavior | Acceptance gate |
|---|---|---|
| Fidelity-aware verification | Re-run experiments with synthetic state and mocks removed where possible | Unsupported removal produces UNPROVEN, never silent pass |
| Economic model | Compute assets extracted minus gas, financing, pool fees, slippage and other modeled costs | Assumptions and price source recorded; report gross and net separately |
| Gas ladder | Measure bounded input sizes and gas growth for loops/arrays/call fanout | DoS conclusion tied to a realistic block gas limit and reachable state |
| Predicted-vs-actual diff | Declare expected storage/balance changes and compare them with execution | Unexpected deltas become investigation leads with raw slots and trace references |
| Hack regression corpus | Reproduce curated public incidents on correct historical state and retain fixtures | Same-block prior transactions and target transaction ordering reconstructed |
| Upgrade diff | Compare runtime bytecode, selectors, storage layout, external calls and admin/beacon changes | Compiler/settings and implementation chain recorded |
| Signed reports | Produce a provenance-rich report with reproduction command, impact, severity rationale and hashes | Human reviewer signs off; signature does not certify the claim itself |

## Tier 4 — Guided autonomy

| Capability | Intended behavior | Acceptance gate |
|---|---|---|
| Watch/discovery | Track contract creations/factory events and enrich candidates with TVL/usage/risk information | Discovery source and attribution confidence visible; no auto-exploit |
| Godmode orchestrator | Chain recon, detectors, archetypes, adapters, controls, verification and report stages | Every stop includes a reason; only local/fork/authorized scopes execute tests |
| Custody/privilege graph | Map roles, owners, guardians, upgrade authority, timelocks, treasury and approval powers | Distinguish source-declared roles from live state |
| Question-driven loop | Feed unanswered audit questions from shared evidence and select the next falsifiable question | Human can inspect, defer and correct every question |
| Planner/attacker/verifier/critic | Separate hypothesis generation, harness proposal, execution verification and adversarial critique | Critic checks cheatcodes, synthetic capital, missing controls and unsupported assumptions |
| Learning loop | Turn human-confirmed findings and validated test procedures into reusable patterns | Only reviewed lessons enter the shared attack corpus |

## Tier 5 — Historical and chain simulation

| Capability | Intended behavior | Safety boundary |
|---|---|---|
| Historical exploit verifier | Reconstruct pre-transaction state, replay an authorized historical incident and compare state/value deltas | Public historical reproduction only; no live target broadcasting |
| Transaction unraveling | Analyze existing transaction hashes and emit replayable call sequences | Read-only chain investigation |
| Bundle simulation | Simulate ordered transaction bundles and report state/profit deltas | Simulation-only by default; no unauthorized bundle submission |
| MEV scenario analysis | Measure ordering, slippage and liquidity effects against controlled fixtures or authorized simulations | No live sandwich/JIT bot targeting unsuspecting users |
| Fork cache | Reuse immutable fork snapshots keyed by chain, block and state provenance | Cache identity includes RPC/client and block hash |
| Chain-specific backends | Add native detection and test adapters for Solana/Anchor, Move/Sui, Cairo/Starknet and Soroban | Detection alone does not count as execution or verification support |

## Tier 6 — Close the loop

- Promote only human-confirmed and regression-backed findings into the reusable attack corpus.
- Generate contest/bug-bounty reports with the selected severity rubric and concrete impact.
- Preserve false positives, unsupported cases and failures as first-class regression data.
- Benchmark by protocol family, chain, language, test type and evidence strength rather than one global coverage score.

## Recommended build order

1. Correct the existing break verdicts and add equivalent sequential controls.
2. Add a compile-every-harness CI gate and known-good/known-bad fixtures.
3. Add provenance and fidelity records, then make the evidence ledger consume them.
4. Build transaction unraveling and historical incident reconstruction.
5. Build archetype handlers and real adversarial token/oracle/flash-loan adapters.
6. Expand detectors only when each has a positive/negative corpus.
7. Add bounded composition planning and the critic/verifier loop.
8. Add discovery/watch and cross-VM adapters after the execution contract is stable.

## Explicit non-goals

Lowkey should be excellent at finding, explaining, reproducing and proving vulnerabilities in local labs, historical forks, competitions and explicitly authorized audits. It should not become an autonomous service for draining arbitrary live contracts, compromising keys, evading monitoring or attacking unsuspecting users. Mainnet reconnaissance and simulation can remain read-only; exploit execution belongs in controlled or explicitly authorized environments.