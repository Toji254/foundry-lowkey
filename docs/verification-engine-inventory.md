# Verification engine inventory and adapter contract

Status: initial architecture inventory; capability claims must be verified per checkout and execution environment.

## Existing architecture observed on `integration-test-drive`

- `lowkey/generator.py`: Foundry-artifact/ABI-driven deployment, PoC, and test scaffolding. Generated test artifacts are intentionally scaffolds; the generator does not yet establish that every intended security property is encoded correctly or that the test detects a bug.
- `lowkey/forge_tools.py` and command dispatch in `lowkey/lk.py`: wrappers for native Forge workflows, including build/test, fuzz, invariant, mutation, and symbolic commands.
- `lowkey/analysis_adapters.py`: repository/language/build detection and optional security-analysis command planning. Its current adapters are analysis-plan entries, not a universal test-execution plugin interface.
- `lowkey/audit_context.py`: project-scoped shared context/evidence used to connect findings, traces, state changes, and generated PoCs.
- `lowkey/benchmark.py`, walkthrough benchmarks, finding patterns, and CI: useful regression/triage assets, but source-triage benchmarks do not establish vulnerability recall, mutation score, or generated-test quality.
- `tests/test_generator.py`, `tests/test_analysis_adapters.py`, and related suites: substantial regression coverage for existing behavior. This branch inventory is based on repository source inspection; tests have not been executed by this document.

## First adapter contract

The first implementation lives in `lowkey/verification_adapters.py`:

- `EngineCapability` declares test kinds, language/build support, project markers, RPC needs, and resource class.
- `ToolAdapter` defines `available()`, `supports(project, test_kind)`, and bounded `run(project, request, budget)`.
- `EngineResult` normalizes status/exit code/summary/artifacts while retaining raw stdout, stderr, raw evidence, and metadata.
- `CapabilityRegistry` inventories adapters and selects only available, compatible tools under `light`, `balanced`, or `deep` profiles.
- `default_registry()` is a capability catalogue, not a guarantee that any executable is installed or that every advertised workflow has an execution adapter.

## Initial engine map

| Engine | Potential role | Important boundary |
|---|---|---|
| Forge | Unit, integration, fuzz, invariant, exploit/regression tests | Executable test behavior depends on generated properties and fixtures |
| Echidna | Stateful property-based fuzzing | Requires compatible harness/properties and EVM project support |
| Medusa | Coverage-guided EVM fuzzing | Requires compatible setup and properties/harness |
| Halmos | Symbolic tests | Solver/model bounds apply; not an unqualified proof of all behavior |
| Certora | Specification-driven formal verification | Requires meaningful rules/specifications and configured tool/service |
| Slither | Static analysis | Not a test executor and not a formal proof engine |

This catalogue is deliberately honest: the registry describes candidate capabilities; it does not claim integrations are production-ready merely because an executable name is known.

## Required seven artifact classes

1. **Unit** — isolated function behavior with concrete assertions.
2. **Integration** — cross-contract/component behavior and deployment/configuration assumptions.
3. **Invariant** — state properties that must hold across sequences of actions.
4. **Exploit** — executable reproduction of a concrete attack condition.
5. **Regression** — a previously failing behavior that remains failing after a fix.
6. **Fuzz** — generated inputs/sequences with preserved properties and replayable seeds.
7. **Formal verification** — explicit specifications, assumptions, proof/solver status, and limitations; never relabel a passing test as a proof.

Every generated artifact should record: intended property, preconditions, actors/roles, actions, expected behavior, assertion/oracle, setup assumptions, source/finding provenance, engine, execution status, and evidence links.

## Resource profiles

- `light`: low-memory engines only; intended for an 8 GB machine.
- `balanced`: low and medium memory engines.
- `deep`: includes high-memory engines, still selected serially by default.
- Never launch every fuzzer/solver concurrently by default. A future planner must account for RAM, CPU, project size, timeout, and explicit user budgets.

## Gaps still open

- The common interface exists, but concrete execution adapters beyond the declarative executable adapter are not implemented by this first change.
- The generator still needs property-preserving, project-specific generation for all seven categories.
- Mutation/buggy-fixture validation and mutation-score gates remain to be built.
- Real-project benchmark matrix and reproducible campaign reports remain incomplete.
- Capability claims need per-tool version checks, supported-project checks, integration tests, and evidence provenance.
