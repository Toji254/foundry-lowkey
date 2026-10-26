# Verification engine inventory and adapter contract

Status: validated first-release integration for the pinned tools and fixtures below. Capability claims remain project- and environment-specific; smoke tests are not security certification.

## Current architecture and implementation boundaries

- `lowkey/generator.py`: Foundry-artifact/ABI-driven deployment and recorded-call reproduction. A replay is evidence of reproduced execution, not an exploit proof unless a measurable impact assertion is validated.
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
- Native command arguments can be explicit (`argv` or `argv_by_engine`) or built by conservative engine-specific adapters. Use `request.engine_config_by_engine` to provide distinct harness/configuration options for multiple engines in the same campaign; per-engine `argv_by_engine` takes precedence. Echidna requires an existing harness file, Medusa requires an existing JSON config (defaults to `medusa.json`), Halmos defaults to a `--function check_` filter (Halmos symbolic tests use the `check_*` naming convention), and Certora requires an existing `.conf`. Config/target paths must stay inside the project root. These builders validate inputs; they do not synthesize missing harnesses or specifications.
- Certora results are classified conservatively: explicit completed output with passing rule markers is `passed`; explicit violation output is `failed`; an identifiable submission without completed proof output is `submitted`; unrecognized output is `inconclusive`; nonzero CLI exits without violation evidence are `error`. The adapter requests the official CLI's `--wait_for_results` behavior by default; callers can explicitly opt into submission-only mode with `wait_for_results: false`. This is CLI-native waiting and output parsing, not a separately implemented Certora REST poller. CI smoke-tests the CLI but does not submit a remote proof without authorized credentials.
- Halmos output is normalized using its `[PASS]`/`[FAIL]` test markers. A zero exit with no recognized result marker is `inconclusive`, not a pass; the CLI exits nonzero for inconclusive campaigns.
- Echidna's native builder requests JSON campaign output and reads the documented `success` field. Missing/malformed JSON is `inconclusive`; a campaign-level error is `error`, and `success: false` is `failed`. Raw process evidence and parsed native JSON are retained together.
- Medusa exit code `7` is normalized as a native fuzz-test failure; documented general/handled error codes `1` and `6` are reported as execution `error`, not a discovered contract failure. Other outcomes retain raw process evidence. The live CI fixture exercises Echidna 2.3.3, Medusa 1.5.1, and Halmos 0.3.3 via actual Lowkey campaigns, and separately invokes Slither on the same Foundry fixture. These are compatibility smoke tests for the pinned fixture, not a guarantee across every version or arbitrary project.
- A campaign containing a Certora `submitted` result exits nonzero until the remote proof outcome is available; a submitted job is not a completed verification.
- `default_registry()` is a candidate catalogue, not a guarantee that an executable is installed or that every advertised workflow has an engine-specific integration.
- `lowkey/test_generation.py` emits only Solidity/Foundry artifacts that pass a completeness gate: no TODO/worksheet/scaffold content, executable test functions and assertions for local candidates, and explicit constructor values where required. The generation plugin registry additionally supports a Vyper/Titanoboa backend for a narrow public-integer getter/direct-setter property, with real pytest/Hypothesis execution under `--validate`. Complex integration, exploit, regression, PoC and formal requests without the required scenario/property/verifier evidence are not generated and make the command exit nonzero.
- `lk test-gen <ContractName> --types ...` routes to the project-aware generator. Bare `lk test-gen` retains the existing last-send reproduction workflow for backward compatibility.

## Generation plugins and behavioral validation

- `lowkey/generation_plugins.py` defines `GenerationCapability`, `GeneratedArtifact`, `GenerationRun`, the `GenerationAdapter` protocol, and `GenerationRegistry`.
- The current `SolidityFoundryGenerationAdapter` routes project-aware generation for Solidity + Foundry through the existing test generator. It carries status, recognized property, assumptions, source provenance, and a review-required marker; incomplete templates are rejected rather than emitted as runnable-looking tests.
- `lk test-gen Contract --types unit,integration,invariant,exploit,regression,fuzz,formal` routes through that registry. Bare `lk test-gen` preserves the legacy last-send workflow.
- `lowkey/behavioral_validation.py` adds a baseline-first mutation runner. It executes commands without a shell in isolated project copies, requires exact unique source replacements, records hashes and raw output, separates killed/survived/invalid/timeout/error outcomes, and writes reproducible JSON.
- `lk mutation-check manifest.json` exposes the mutation runner. The manifest supplies a native argv array and mutation definitions. A failed baseline produces no mutation score; compile/setup failures are not automatically counted as killed behavioral bugs.

- `lowkey/verification_benchmark.py` adds manifest-driven benchmark runs with per-case project labels, manifest hashes, git revision, aggregate killed/survived/invalid/timeout counts, and an optional mutation-score gate. Use `lk verification-benchmark manifest.json --min-mutation-score 0.80` to enforce the gate.

- `lowkey/verification_cli.py` exposes `lk verification engines [--json]` and `lk verification run manifest.json --profile light|balanced|deep`. Campaign manifests provide the test kind, per-engine native argv, and time budget; execution stays serial and writes raw results to a JSON report. The planner records both selected engines and rejected engines with explicit compatibility or profile-exclusion reasons.

- `lk verification correlate <campaign-report.json> [--signal SIGNAL_ID ...]` joins normalized results from a saved campaign into one correlation report. A campaign manifest may include an `investigation` object with explicit `signal_ids` (or one `signal_id`) and a stable `property_id`; an exact `source_file` + `function` may attach automatically only when it resolves to one existing signal. Correlation preserves the native report by hash/reference, attaches one repeat-safe evidence record to each matched signal, and never creates a missing signal or promotes a failure into a confirmed vulnerability. A failing test/property is a review lead; a passing engine is not a protocol-wide security verdict. The finding renderer shows correlated per-engine statuses and selected-but-skipped tools. If zero engines produced results, correlation returns a coverage-gap report and exits nonzero rather than presenting an empty campaign as a successful check.

- `lk verification investigate <SIGNAL_ID> [--constructor-args JSON_ARRAY]` supports two narrowly constrained families: (1) a unique `onlyOwner`/`onlyRole` method with a simple state-changing body, and (2) a simple ETH reentrancy pattern where a zero-argument withdrawal reads `mapping[address]` credit, sends ETH to `msg.sender`, and clears that credit only after the call, paired with a unique payable deposit that credits `msg.value`. The reentrancy probe is generated only when constructor setup can be supplied explicitly and no recognized/custom guard blocks the path. Both families execute through Forge and attach source/test hashes to the existing signal. A reproduced overpayment is a review lead, not an automatic verdict. Complex, inherited, ambiguous, token-based, cross-contract or otherwise unsupported patterns remain explicit gaps.

## Initial engine map

| Engine | Potential role | Important boundary |
|---|---|---|
| Forge | Unit, integration, fuzz, invariant, exploit/regression tests | Executable test behavior depends on generated properties and fixtures |
| Echidna | Stateful property-based fuzzing | Requires compatible harness/properties and EVM project support |
| Medusa | Coverage-guided EVM fuzzing | Requires compatible setup and properties/harness; exit code 7 means test failure, codes 1/6 mean execution error |
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
- Reports preserve the effective per-campaign budget and profile defaults alongside process-level timeout, output-truncation, and optional RSS evidence, so later reviewers can reconstruct the configured limits.
- Campaign reports include separate engine-selection counts (`selected`, `unsupported`, `missing_configuration`, `profile_excluded`, and `adapter_error`) alongside execution-result counts, so a skipped engine is not confused with a test that ran and passed or failed.
- Campaign execution is serial; each process has a bounded timeout. On Linux, a campaign may set `budget.max_memory_mb` to sample and cap aggregate resident memory for the engine's process group; exceeding the cap terminates that process group and yields `resource_limit`. This is opt-in, sampled rather than instantaneous, and unsupported outside Linux `/proc`; it is not a sandbox. Stdout/stderr are drained concurrently but only a bounded prefix is retained in memory (default 256 KiB per stream; configurable with `budget.max_output_bytes`, clamped to 1 KiB–4 MiB). Reports explicitly mark truncated streams, while the retained raw evidence remains directly inspectable. This limits Python-side capture memory, not the child process's own memory or total CPU/disk/network use. Forge fuzz/invariant runs scale with the profile (light: 32 fuzz runs / 16 invariant runs at depth 10; balanced: 256 / 64 at depth 20; deep: 1,024 / 256 at depth 50). These are execution budgets, not measured live RAM/CPU limits.
- On POSIX, if an engine exits but a spawned descendant keeps inherited output pipes open, Lowkey attempts to terminate the remaining process group and records cleanup evidence. This is best-effort process cleanup, not a security sandbox or a hard resource limit.
- Never launch every fuzzer/solver concurrently by default. Linux process-group RSS sampling is now available when an explicit `max_memory_mb` budget is supplied; automatic per-profile RAM caps, CPU sampling, project-size estimates, and adaptive budget adjustment remain open.

## Validation evidence and remaining release blockers

### Live CI evidence (25–26 October 2026)
- **Targeted finding investigation:** live Foundry fixtures exercise a deliberately broken `onlyOwner` modifier, a working `onlyRole` guard, and an ETH reentrancy vault that pays a caller twice before clearing their credit. CI invokes the installed CLI and real generator/probe, executes the generated tests with Forge, and checks attached hash-backed evidence. Unsupported/inherited policy setups remain unsupported rather than guessed.
- **Campaign-to-finding correlation:** CI runs a real Forge campaign with a deliberately failing unauthorized-withdraw assertion, then invokes `lk verification correlate` on the saved native report. It checks report hashes, engine status, original signal linkage, and repeat-safe evidence attachment while verifying the failure remains a review lead rather than an automatic verdict.

The [CI workflow](../.github/workflows/ci.yml) has separate real-project smoke gates:

- **Forge:** a fresh Foundry fixture is detected as Solidity + Foundry; Lowkey executes a real Forge unit test through `lk verification run`, checks the normalized `passed` result, and verifies native output is preserved in the campaign report.
- **Echidna 2.3.3 and Medusa 1.5.1:** Lowkey runs live fuzz campaigns against the same small Solidity fixture and the workflow asserts both campaign results are `passed`.
- **Halmos 0.3.3:** Lowkey runs a `check_*` symbolic test and checks native PASS evidence is normalized as `passed`.
- **Slither 0.11.6:** Slither compiles and analyzes the fixture. The deliberately simple fixture emits a compiler-version detector finding; successful analysis means the tool ran, not that the fixture is security-clean.
- **Certora CLI 8.20.2:** installation and CLI startup are checked, but CI does not submit a remote proof because that requires authorized credentials and may invoke a paid service. Therefore remote proof submission/completion is not marked live-validated.
- **Generation/mutation:** CI generates and executes the supported direct-setter/getter unit/fuzz/invariant tests and runs the mutation harness against a seeded setter mutant. It separately asserts that unsupported integration/exploit/regression/formal requests emit no files and return nonzero. A pinned OpenZeppelin corpus smoke test confirms that the current generic generator refuses a complex inherited contract when it cannot establish a real property; this is an explicit coverage gap, not a successful generation benchmark. The mutation gate requires the unmodified unit baseline to pass and the known setter mutant to be killed.

The live checks are run by the [CI workflow](../.github/workflows/ci.yml); each successful run validates pinned fixtures and exact tool versions, not every user project. The workflow pins observed external-tool versions and asserts Python package versions rather than relying on an unpinned latest install.

### Remaining work

- **Certora remote proof:** the adapter requests native CLI wait-for-results behavior by default and parses CLI output conservatively, but no authenticated remote proof run has been performed and no separate Certora REST polling client is implemented. A real authorized proof run is still required before claiming end-to-end Certora proof validation.
- **Generator scope:** executable test generation now supports Solidity + Foundry and a narrow Vyper + Titanoboa path. Rust, Move, Cairo and other language/build-system generators are still not implemented; detection of a language is not test-generation support.
- **Test substance:** the direct integer setter/getter path can generate executable candidate properties. Integration, exploit, regression, and protocol-specific test cases need concrete dependencies, attack conditions, expected outcomes, and assertion oracles; the generator now refuses to emit incomplete templates. Compilation alone is not behavioral validation.
- **Language coverage:** project-aware generation currently supports Solidity + Foundry and the narrow Vyper + Titanoboa property described in the test-generation guide. Other languages are not reported as supported until they have a native generator plus compile/run gates.
- **Protocol coverage:** comprehensive multi-protocol security verification has not been established. The pinned multi-repository benchmark is a release gate that must be expanded and pass with meaningful, evidence-backed properties before making a broad coverage claim.
- **PoC generation:** exact-call replay is not an exploit proof. PoC creation requires exact calldata and an explicit impact assertion, and generated candidates are labelled unvalidated until a subsequent run records outcome evidence.
- **Mutation generality:** CI demonstrates one meaningful mutant is killed. That is a regression gate for this fixture, not a trustworthy mutation score across protocol families or arbitrary projects.
- **Real-project corpus:** CI now runs the complete pinned multi-repository manifest, targets up to two contracts per project, and uploads `.audit/test-gen-ecosystem-full.json` even when target evaluations fail. Review the artifact's exact revisions, baseline-build failures, generator reports, unsupported categories, and execution results. A completed run means evaluation evidence was retained—not that all categories were generated successfully or that sampled protocols are secure.
- **Formal-specification quality:** generated CVL is a candidate specification for a narrow recognized property. A real Certora proof and review of assumptions/vacuity are still outstanding.
- **Resource isolation:** campaigns use serial execution, timeouts, bounded output capture, and optional sampled Linux process-group RSS limits. This is not an OS sandbox and does not yet impose hard CPU, disk, or network limits.

The full corpus benchmark is an evidence-collection job with `continue-on-error` so its first complete run can expose unsupported architectures without concealing the per-project report. Do not treat the job's non-blocking status as a release pass; any baseline/build/tool failures and the recorded gaps still require triage.

These boundaries are release constraints, not hidden successes. The live tests prove compatibility for the specific fixture and tool versions above; they do not establish universal support, broad vulnerability recall, or security certification.
