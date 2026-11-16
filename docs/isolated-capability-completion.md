# Isolated LK capability-completion track

## Current isolated implementation progress (acceptance is head-specific)

Last recorded isolated head: `ae1a2b3afe1975da78d99471401e08b30ba7db23`. Exact-head CI runs are still in progress; do not use an older green run as proof for later commits.

- **Storage parity:** Anvil opcode-level SLOAD/SSTORE/TLOAD/TSTORE extraction, callTracer frame reconciliation, per-access comparison, and separate value parity are implemented. The pinned EntryPoint read-only real-fork fixture passed on earlier isolated head `c8ce666d2a74187da0346814c38fe6d53b89f551` in [CI run 43816123233](https://github.com/Toji254/foundry-lowkey/actions/runs/43816123233): call tree `MATCHED`, storage accesses `exact_comparable`, values `matched`. This exercised one live storage access; it does not establish equivalence for every EVM opcode or client. Synthetic nested/delegatecall/revert/transient fixtures exist. The latest observed P2 job also passed on head `c16429a99e4c1c07fcb572fd2075802d35b93311` in [run 43835110172](https://github.com/Toji254/foundry-lowkey/actions/runs/43835110172), but newer commits still need their own completed run.
- **Token economics:** explicit ERC-20 balance deltas, ERC-4626 per-account `previewRedeem` valuation using an underlying-asset `asset_oracle`, pinned USD Chainlink rounds, actual decimals, code/source prestate and post-state consistency checks, and native gas/setup-cost conversion are implemented behind `lk reprove --portfolio-manifest`. The installed-CLI Anvil portfolio acceptance passed on head `c16429a99e4c1c07fcb572fd2075802d35b93311` in [run 43835110172](https://github.com/Toji254/foundry-lowkey/actions/runs/43835110172): both mock token types were measured, costs deducted, and verdict remained local-only. The retained artifact was `token-portfolio-acceptance-8359`. This is not independent archive-RPC profitability against a real deployment; feed suitability and explicit-asset coverage remain auditor assumptions.
- **Protocol graphs:** compiler build-info AST ingestion now records contracts, functions, modifiers, inheritance, state variables, structs, enums, events, errors, user-defined value types and using-for directives. Source spans, static call candidates, modifier use and AST-derived state reads/writes/dependency candidates are retained. Runtime call edges come separately from validated canonical trace artifacts. Foundry `--build-info --ast` installed-CLI acceptance passed on head `c16429a99e4c1c07fcb572fd2075802d35b93311` in [run 43835110172](https://github.com/Toji254/foundry-lowkey/actions/runs/43835110172). This is not full SSA/path-sensitive data flow, storage-layout slot mapping, or verified proxy/diamond resolution.
- **Attack-chain synthesis:** new `lk attack synthesize` revalidates research source hashes/quotes, maps hypothesis source spans to compiler AST functions, and composes only compiler-call or state-dependency candidate edges. The real Foundry fixture on head `c16429a99e4c1c07fcb572fd2075802d35b93311` produced a two-stage deposit/withdraw chain using a real AST state-dependency edge; CI retained `attack-chain-synthesis-acceptance-8359`. It was correctly marked `BLOCKED_ADAPTER_REQUIRED` for accounting; no test or transaction was run. Automatic chain synthesis is therefore a review-candidate planner, not an executable chain adapter.
- **AI research:** `lk attack research --contract NAME --function NAME` asks the configured model for a small set of candidate hypotheses and validates current source hashes and exact quotes confined to the excerpt sent to the model. Results carry context hash, provider/model, source revision, controls, test plans and mutations; they remain `CANDIDATE_ONLY`. No live provider-driven discovery or model-proposed hypothesis has yet passed attack/control, mutation and independent reproof acceptance.
- **Test generation:** a narrow WETH round-trip recognizer was added for a source pattern requiring ERC20 inheritance, deposit minting exactly `msg.value`, and withdrawal burning before a value-bearing callback. It emits unit and fuzz wrap/unwrap conservation tests. Synthetic positive/negative fixtures exist; the latest full Solady corpus run has not yet completed on the current head, so real-project behavioral acceptance is not claimed.
- **Certora:** the CLI adapter now requires `CERTORAKEY` before selecting or launching a remote proof, parses native PASS/FAIL outputs and retains remote job/report references. A small MiniToken CVL fixture and manually triggered workflow were added; no authenticated remote proof has been executed. The manual workflow file is on this branch only and will be available in GitHub Actions only after reviewed promotion to the repository default branch. Do not claim Certora remote validation from CLI installation.
- **Attack-family adapters:** only the existing reentrancy strategy remains fixture-accepted. All fourteen other strategy families remain `adapter_required`; changing labels without target-specific paired attack/control, mutation kill, traces and independent reproof is prohibited.
- **Isolated branch:** all changes remain on `integration-upgrades-lab-20261116`. PR #76 stays draft against `integration-test-drive`. Do not retarget or merge PR #76 without reviewing the exact final head, CI results and retained evidence artifacts.

## Isolation contract

This branch was created from `integration-test-drive` at
`37ee1be2b239037f9f4971911500cecb5d55fc86`. All implementation work in this
track stays on `integration-upgrades-lab-20261116`. Do not modify, reset,
force-push, retarget, or otherwise interfere with the integration branch or its
in-flight pull requests.

Before importing later integration work, inspect both heads and their merge
base. Never overwrite either branch's commits. Preserve all existing work.

## Acceptance policy

A feature is complete only when all of the following exist:

1. A real implementation on the isolated branch.
2. A target-specific positive fixture and a matched negative/control fixture.
3. A mutation or fault-injection test proving the acceptance test detects the
   relevant defect.
4. An executable end-to-end acceptance job, not just unit tests or compilation.
5. A retained evidence artifact with pinned source/target revisions.
6. Explicit unsupported/inconclusive outcomes where evidence is unavailable.

A registry entry, prompt, documentation claim, synthetic-only test, compile
pass, or green test that never invokes the relevant engine is not completion.

## Capability backlog

### 1. Attack-family adapters

- [ ] Replay
- [ ] Access control
- [ ] Accounting
- [ ] Boundary conditions
- [ ] Time/block dependence
- [ ] Upgrade and initializer safety
- [ ] Callback and hook behavior
- [ ] Oracle integrity
- [ ] Economic/compositional attacks
- [ ] ERC-20 behavior
- [ ] Proxy behavior
- [ ] Storage manipulation/collision
- [ ] Signature validation
- [ ] DoS and liveness

Each adapter must declare threat model, prerequisites, security property,
attacker/authorized control, setup and prestate anchors, attack and control
entrypoints, canonical trace requirements, impact evidence, mutation(s), and
reason-coded failure outcomes. Reentrancy remains the regression baseline.
Do not claim family-wide support from one unrelated fixture.

### 2. Protocol-specific attack-chain synthesis

- [ ] Build a protocol dependency model from source and verified runtime
      observations.
- [ ] Generate candidate multi-stage chains only from supported primitives.
- [ ] Require each edge to have provenance and a validated precondition.
- [ ] Execute paired attack/control chains and injected-failure cases.
- [ ] Validate intermediate state, asset flow, approvals, callbacks, and
      rollback/recovery behavior.
- [ ] Require mutation killing and independent replay/reproof.
- [ ] Label unsynthesizable or unsupported chains explicitly.

### 3. Protocol graphs

- [ ] Compiler-AST-backed contract, function, modifier, inheritance, and
      storage declarations.
- [ ] Static call and data-dependency edges with source spans.
- [ ] Runtime call graph from normalized traces, retaining caller/callee,
      selector, depth, and execution outcome.
- [ ] Storage read/write links with backend fidelity labels.
- [ ] Proxy, beacon, diamond/facet, and implementation relationships with
      verification provenance.
- [ ] Confidence, evidence origin, revision pinning, and explicit unknowns.
- [ ] Cross-check static candidates against runtime observations without
      treating either as complete proof of reachability.

### 4. Token economics

- [ ] ERC-20 decimals and balance/transfer measurement.
- [ ] Fee-on-transfer, rebasing, non-standard return values, and callback
      token behavior.
- [ ] ERC-4626 convert/deposit/redeem previews and rounding/slippage bounds.
- [ ] Oracle source, decimals, freshness, round completeness, and manipulation
      assumptions.
- [ ] Cross-token valuation and portfolio accounting with pinned price sources.
- [ ] Native/token-denominated profit, setup costs, gas, and repayment costs.
- [ ] Refuse economic verdicts when prices, decimals, liquidity, or conversion
      semantics cannot be established.

### 5. Real-project test generation

- [ ] Generate executable unit, fuzz, invariant, integration, regression, and
      exploit/PoC candidates from explicit properties and protocol models.
- [ ] Use project-specific setup/deployment/initialization and dependency
      discovery; never guess unsafe constructor arguments.
- [ ] Compile and execute generated tests against the untouched baseline.
- [ ] Require a paired control and mutation-killing evidence.
- [ ] Expand the pinned ecosystem corpus and report per-project/per-category
      outcomes; evidence gaps are not passes.
- [ ] Preserve explicit unsupported categories and nonzero strict-mode exits.

### 6. Certora remote verification

- [ ] Credential discovery without logging or persisting secrets.
- [ ] Validate project-relative configuration and rule/spec selection.
- [ ] Submit remote jobs only with explicit user-configured credentials.
- [ ] Poll and normalize completed proof/counterexample outcomes.
- [ ] Retain job IDs, target revision, config/spec hashes, and output artifacts.
- [ ] Distinguish CLI-installed, submitted, running, proved, counterexample,
      timeout, resource-limit, and credential/configuration failure.
- [ ] Live authenticated acceptance is conditional on a secure CI secret; do
      not claim remote proof execution from CLI startup.

### 7. AI-assisted security research

- [ ] Generate hypotheses grounded in source spans, protocol graph edges, and
      prior evidence.
- [ ] Store model/provider/version, prompt/context hashes, and source revision.
- [ ] Require explicit schemas and provenance for proposed hypotheses/tests.
- [ ] Route all execution through the deterministic, sandboxed tool boundary.
- [ ] Run attack/control, mutation, trace, and impact validation before
      promoting a hypothesis.
- [ ] Treat model output as untrusted candidate material; never as a verdict.
- [ ] Add adversarial tests for prompt injection in source comments, docs, and
      tool output, plus secret redaction and resource limits.

### 8. Forge/Anvil storage evidence parity

- [ ] Inventory actual storage observability for both backends and supported
      tracer/client versions.
- [ ] Attribute storage reads/writes to call frames wherever the backend
      genuinely exposes that relationship.
- [ ] Preserve slot, before/after value, access type, frame identity, and order.
- [ ] Compare exact common evidence; separately report unsupported/partial
      dimensions.
- [ ] Add nested-call, delegatecall, reverted-frame, same-slot multi-frame,
      transient-storage, and proxy fixtures.
- [ ] Never synthesize frame attribution from transaction-level changed slots.
- [ ] If exact parity is impossible for a backend, expose a truthful degraded
      contract and keep strict consumers from accepting it as exact.

## Current baseline facts

The starting branch contains a 15-family strategy registry, but only the
reentrancy family is currently marked fixture-accepted. The other fourteen
families are adapter-required. Existing generic test generation recognizes a
narrow setter/getter property. The current P2 real-fork acceptance matches the
call tree for a read-only EntryPoint call while reporting Anvil storage
evidence as partial and storage parity as degraded. The ecosystem benchmark
currently reports zero projects fully generated and behaviorally validated.
Certora's CLI startup is not remote proof execution.

These are baseline facts, not acceptance claims for this upgrade track.
