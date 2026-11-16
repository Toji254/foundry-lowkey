# Isolated LK capability-completion track

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
