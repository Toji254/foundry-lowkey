# Verification engine inventory and adapter contract

Status: initial architecture inventory; capability claims must be verified per checkout and execution environment.

## Existing architecture observed on `integration-test-drive`

- `lowkey/generator.py`: Foundry-artifact/ABI-driven deployment, PoC, and test scaffolding. Generated test artifacts are intentionally scaffolds; the generator does not yet establish that every intended security property is encoded correctly or that the test detects a bug.
- `lowkey/forge_tools.py` and command dispatch in `lowkey/lk.py`: wrappers for native Forge workflows, including build/test, fuzz, invariant, mutation, and symbolic commands.
- `lowkey/analysis_adapters.py`: repository/language/build detection and optional security-analysis command planning. Its current adapters are analysis-plan entries, not a universal test-execution plugin interface.
- `lowkey/audit_context.py`: project-scoped shared context/evidence used to connect findings, traces, state changes, and generated PoCs.
- `lowkey/benchmark.py`, walkthrough benchmarks, finding patterns, and CI: useful regression/triage assets, but source-triage benchmarks do not establish vulnerability recall, mutation score, or generated-test quality.
- `tests/test_generator.py`, `tests/test_analysis_adapters.py`, and related suites: substantial regression coverage for existing behavior. The current implementation is covered by the repository CI suite; a green CI run validates these tested paths, not every external engine or arbitrary project.

## First adapter contract

The first implementation lives in `lowkey/verification_adapters.py`:

- `EngineCapability` declares test kinds, language/build support, project markers, RPC needs, and resource class.
- `ToolAdapter` defines `available()`, `supports(project, test_kind)`, and bounded `run(project, request, budget)`.
- Third-party Python packages may register an entry point in the `lowkey.verification_adapters` group. Each entry point is a zero-argument factory returning one adapter or a list/tuple; required members are `capability`, `available()`, `supports()`, and `run()`. Discovery/registration failures are visible in `lk verification engines` output and JSON rather than silently swallowed.
- `EngineResult` normalizes status/exit code/summary/artifacts and monotonic elapsed duration while retaining raw stdout, stderr, raw evidence, and metadata. Duration is evidence for comparing campaigns, not a correctness score.
- `CapabilityRegistry` inventories adapters, selects available compatible tools under `light`, `balanced`, or `deep` profiles, and runs selected engines serially through `run_campaign()`.
- Campaign reports include total wall-clock duration and the sum of measured engine durations, making runtime comparisons reproducible alongside each engine's raw evidence.
- Adapter exceptions are normalized as per-engine `error` results, so one faulty plugin does not discard later engine evidence from the same serial campaign.
- Exceptions from plugin `available()` and `supports()` checks are isolated too: the affected engine is reported as unavailable or `adapter_error`, the reason is retained in `plugin_errors`, and healthy engines can still be planned and run.
- Native command arguments can be explicit (`argv` or `argv_by_engine`) or built by conservative engine-specific adapters. Echidna requires an existing harness file, Medusa requires an existing JSON config (defaults to `medusa.json`), Halmos defaults to a `--function test` filter, and Certora requires an existing `.conf`. Config/target paths must stay inside the project root. These builders validate inputs; they do not synthesize missing harnesses or specifications.
- Certora CLI exit code zero is reported as `submitted`, not `passed`, because a successful CLI invocation alone does not establish that every proof rule passed.
- `default_registry()` is a candidate catalogue, not a guarantee that an executable is installed or that every advertised workflow has an engine-specific integration.
- `lowkey/test_generation.py` adds project-aware Solidity/Foundry drafts for unit, integration, invariant, exploit, regression, fuzz, and formal categories, plus fork/PoC variants. It recognizes only a narrow direct integer setter/getter property; unsupported constructor types are skipped rather than guessed.
- `lk test-gen <ContractName> --types ...` routes to the project-aware generator. Bare `lk test-gen` retains the existing last-send reproduction workflow for backward compatibility.

## Generation plugins and behavioral validation

- `lowkey/generation_plugins.py` defines `GenerationCapability`, `GeneratedArtifact`, `GenerationRun`, the `GenerationAdapter` protocol, and `GenerationRegistry`.
- The current `SolidityFoundryGenerationAdapter` routes project-aware generation for Solidity + Foundry through the existing test generator. Each artifact carries a status, recognized property when one is actually inferred, assumptions, source provenance, and a review-required marker.
- `lk test-gen Contract --types unit,integration,invariant,exploit,regression,fuzz,formal` routes through that registry. Bare `lk test-gen` preserves the legacy last-send workflow.
- `lowkey/behavioral_validation.py` adds a baseline-first mutation runner. It executes commands without a shell in isolated project copies, requires exact unique source replacements, records hashes and raw output, separates killed/survived/invalid/timeout/error outcomes, and writes reproducible JSON.
- `lk mutation-check manifest.json` exposes the mutation runner. The manifest supplies a native argv array and mutation definitions. A failed baseline produces no mutation score; compile/setup failures are not automatically counted as killed behavioral bugs.

- `lowkey/verification_benchmark.py` adds manifest-driven benchmark runs with per-case project labels, manifest hashes, git revision, aggregate killed/survived/invalid/timeout counts, and an optional mutation-score gate. Use `lk verification-benchmark manifest.json --min-mutation-score 0.80` to enforce the gate.

- `lowkey/verification_cli.py` exposes `lk verification engines [--json]` and `lk verification run manifest.json --profile light|balanced|deep`. Campaign manifests provide the test kind, per-engine native argv, and time budget; execution stays serial and writes raw results to a JSON report. The planner records both selected engines and rejected engines with explicit compatibility or profile-exclusion reasons.

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
- Campaign execution is serial; each process has a bounded timeout. Stdout/stderr are drained concurrently but only a bounded prefix is retained in memory (default 256 KiB per stream; configurable with `budget.max_output_bytes`, clamped to 1 KiB–4 MiB). Reports explicitly mark truncated streams, while the retained raw evidence remains directly inspectable. This limits Python-side capture memory, not the child process's own memory or total CPU/disk/network use. Forge fuzz/invariant runs scale with the profile (light: 32 fuzz runs / 16 invariant runs at depth 10; balanced: 256 / 64 at depth 20; deep: 1,024 / 256 at depth 50). These are execution budgets, not measured live RAM/CPU limits.
- On POSIX, if an engine exits but a spawned descendant keeps inherited output pipes open, Lowkey attempts to terminate the remaining process group and records cleanup evidence. This is best-effort process cleanup, not a security sandbox or a hard resource limit.
- Never launch every fuzzer/solver concurrently by default. Current selection uses declared memory classes and per-engine timeouts; live RAM/CPU sampling, project-size estimates, and adaptive budget adjustment remain open.

## Gaps still open

- Initial native command builders now exist for Echidna, Medusa, Halmos, and Certora, with explicit config/harness requirements and conservative defaults. Live execution against installed versions, version-specific CLI compatibility, native result parsing, and pinned real-project integration fixtures remain open. In particular, Certora's remote proof status is not yet fetched or parsed by Lowkey.
- The generation plugin contract exists, but project-aware generation is currently Solidity/Foundry-specific. Other language/build-system generators remain open.
- Integration, exploit, and regression outputs are honest starters unless concrete setup/bug evidence is supplied; they are not automatically meaningful tests yet.
- The recognized setter/getter fuzz/invariant/formal path needs compilation and real engine validation, including checking for vacuous or invalid specifications.
- Mutation execution and optional mutation-score gates exist, but broad buggy-fixture validation and trustworthy mutation-score measurements across project families remain open.
- Reproducible campaign and benchmark report formats exist. The real-project matrix is still a plan until pinned project revisions have actually been run and results retained.
- Capability claims need per-tool version checks, supported-project checks, integration tests, and evidence provenance.
