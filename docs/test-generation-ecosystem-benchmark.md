# Test-generation ecosystem benchmark

## Why this exists

The generator must work from evidence in an unfamiliar project, not from repository names or a list of protocol-specific branches. This corpus samples materially different EVM architectures: inherited standards, libraries and assembly, AMMs, lending markets, singleton/hook systems, cross-chain messaging, proxy patterns, and a non-protocol test framework.

The manifest is a benchmark plan, not evidence that these repositories have already passed. Results must only be described as completed after the pinned repository revision has actually been checked and the report retained.

## Running the corpus

From a checkout with LowkeyCast and Foundry installed, run:

```bash
python3 scripts/test-gen-ecosystem-benchmark.py
```

The runner shallow-clones each manifest repository into an isolated temporary workspace, records each immutable checkout SHA, discovers candidate declarations, records the baseline Foundry build, generates all eight artifact families, and separately invokes validation for the seven Solidity families. It writes a machine-readable report to `.audit/test-gen-ecosystem-benchmark.json`. Use `--limit-projects 1` for a smoke run, `--targets-per-project 1` to reduce work, and `--work-dir PATH --keep-workspaces` to retain cloned repositories for investigation. The runner exits nonzero if any project could not be evaluated; inspect per-project statuses instead of treating a partial run as a pass.

The current runner does not implement mutation campaigns yet. A green run is therefore evidence about repository discovery, generation, and the generator's available validation path—not proof that generated tests kill deliberate faults. Mutation testing remains a separate release gate.

## Required evaluation protocol

1. Record the exact repository URL, commit SHA, tool versions, compiler profile, remappings, dependencies, and target contract.
2. Discover source, inherited declarations, interfaces, imports, configuration, existing tests, deployment scripts, and available specifications. Do not use repository identity to select generator logic.
3. Generate all seven Solidity categories plus formal-verification artifacts.
4. Preserve a per-category evidence trail: source/specification citations, assumptions, unresolved questions, generated test assertions, and setup dependencies.
5. Build the untouched project first; report baseline failures separately.
6. Compile generated Solidity tests in an isolated working copy and execute tests that have a complete local harness. Do not count a successful build as a passing test.
7. Run bounded, semantics-aware mutation testing in an isolated copy. Record mutants attempted, equivalent/unreachable mutants, killed mutants, surviving mutants, and execution failures. Never mutate the user's working tree.
8. For fork tests, pin the chain and block where possible, verify the target runtime code and expected deployment identity, and label unavailable RPC credentials as unavailable rather than passed.
9. For exploit reproduction and regression, require a concrete defect, precondition, and expected security impact from supplied evidence or a reviewed finding. A recorded transaction replay alone is not an exploit test.
10. For formal verification, run the configured verifier only when available, record the exact assumptions and result, and distinguish a candidate specification from a completed proof.
11. Save machine-readable results and a human-readable summary. Every category must end in a truthful status: generated, executed, behaviorally validated, blocked by missing evidence, unsupported by the selected backend, or failed.

## Genericity gate

A change fails this benchmark if the implementation checks a repository name, target name, hard-coded path, or project-specific constant to decide what tests to emit. The manifest can name known benchmark targets; the generator itself must discover behavior from each checked-out project's evidence and general language/build metadata.

Protocol profiles may suggest questions to investigate, but must not directly become asserted truths. For example, detecting a borrow function does not establish a solvency invariant; detecting an oracle call does not establish the correct freshness bound. Assertions must be backed by tests, explicit specifications, documented protocol semantics, or user confirmation. If that evidence is absent, the generator should request it and explain why.

## Release gates

A release is not production-ready merely because all eight output types have files or compile.

- **Substantive generation:** each requested category contains project-specific assertions, or a precise evidence gap with a targeted question; empty boilerplate does not count.
- **Execution:** runnable generated tests execute against the original implementation and report per-test results.
- **Mutation validation:** where a safe, relevant mutant can be generated, at least one test must kill it; surviving mutants and mutation limitations remain visible.
- **No false confidence:** no inferred property, skipped test, compile-only result, or unrun formal specification is reported as proven.
- **Isolation:** baseline source, user tests, dependencies, and deployment state are unchanged by validation.
- **Regression safety:** all existing Lowkey tests and integration checks remain green.
- **Corpus diversity:** run the manifest across the listed project families and add new cases whenever a materially different architecture fails. Do not claim universal compatibility from this finite corpus.

## Interpreting outcomes

This is a coverage and capability benchmark, not a security certification of the sampled protocols. Public repositories change; benchmark runs must pin immutable commit SHAs. Missing RPC endpoints, unavailable paid verification services, dependency failures, and projects requiring private configuration must be reported as blocked/unavailable, not as generator failures or passes without context.
