# Lowkey architecture and validation baseline

**Snapshot date:** 2026-11-27  
**Repository:** [Toji254/foundry-lowkey](https://github.com/Toji254/foundry-lowkey)  
**Branch:** `integration-test-drive`  
**Baseline commit before this documentation slice:** [`3937556f73d7649711a2fa313888f596518fcac7`](https://github.com/Toji254/foundry-lowkey/commit/3937556f73d7649711a2fa313888f596518fcac7)  
**Baseline tree:** `e57328b1bc6e36cf3f49a250e50d37a71d88548a`

This is an engineering inventory and validation snapshot, not a security certification or a claim that every registered capability is complete. Runtime evidence, adapter availability, project compatibility, and historical reproduction must continue to be assessed separately.

## 1. Repository shape

At the baseline tree, the repository contains 341 tracked tree entries, including:

- 89 Python modules under `lowkey/`
- 130 Python files under `tests/` (test modules and support code)
- 21 files under `scripts/`
- 29 files under `docs/`
- 4 GitHub Actions workflows

The main integration points are `bin/lk`, `lowkey/lk.py`, `lowkey/command_wrapper.py`, and `install.sh`. The installed CLI copies the Python runtime into the user's Lowkey home and exposes the `lk` launcher under the Foundry bin directory. The Bash launcher routes specialized commands such as `ast`, `hardhat`, `attack`, Godmode capabilities, block inspection, and coverage before falling back to the native Lowkey router.

The command router and its generated help catalog are large central integration points. Preserve existing command spellings, aliases, defaults, and native Foundry behavior when changing them. The maintained command/help tests include `test_command_help.py`, `test_cli_consistency.py`, `test_integrated_command_surface.py`, and `test_native_command_routing.py`.

## 2. Architecture map

| Layer | Main implementation | Responsibility and boundary |
|---|---|---|
| CLI and installation | `bin/lk`, `lowkey/lk.py`, `lowkey/command_wrapper.py`, `install.sh` | Command routing, contextual help, compatibility aliases, installed runtime and native-tool delegation |
| Project and workspace context | `project_detection.py`, `workspace_tools.py`, `shared_context.py`, `lab_target_scope.py`, `audit_context.py` | Detect build/language markers, select package-local workspace members, scope targets and share audit context |
| Source understanding | `source_index.py`, `source_ast.py`, `source_graph.py`, `source_link.py`, `source_explorer.py`, `protocol_graph.py`, `archetypes/` | Index declarations, inspect compiler AST/build-info, derive source relationships and keep static candidates distinct from runtime observations |
| Security reasoning | `attack_catalog.py`, `attack_library.py`, `attack_research.py`, `attack_synthesis.py`, `attack_engine.py`, `proxy_engine.py`, `source_risk.py` | Read-only learning catalogue, source-cited hypotheses, graph-constrained candidate chains, target-specific experiments and conservative proxy/source analysis |
| Test generation and execution | `test_generation.py`, `generation_plugins.py`, `generator.py`, `forge_tools.py`, `hardhat_tools.py`, `test_planner.py`, `test_repair.py`, `behavioral_validation.py` | Generate reviewable artifacts, invoke native build/test tools, run controlled local experiments and classify mutation outcomes |
| Verification adapters | `verification_adapters.py`, `verification_cli.py`, `analysis_adapters.py` | Declare language/build/test-kind support, preflight tools, execute bounded campaigns, retain raw output and correlate results to existing signals |
| Evidence and accounting | `proof_evidence.py`, `evidence_ledger.py`, `trace_schema.py`, `trace_evidence.py`, `trace_parity.py`, `storage_trace.py`, `forge_state_diff.py`, `token_economics.py` | Normalize trace evidence, compare state, record provenance/fidelity, reconcile measured costs and preserve unknown or partial results |
| Orchestration and reporting | `godmode.py`, `audit_engine.py`, `multiwave_audit.py`, `workflow_engine.py`, `walkthrough.py`, `finding_explainer.py` | Coordinate staged review, bounded AI roles, explicit skips, evidence collection and beginner-readable explanations |
| Networks and deployment | `network_manager.py`, `library_linker.py`, `project_tools.py`, `abi_support.py`, `runtime_verification.py` | Manage Lowkey-owned Anvil sessions, session-scoped actors/deployments, library linking and read-only runtime identity checks |

The architecture is integrated through the existing CLI, shared project context, and evidence artifacts. New functionality should extend these contracts rather than create a parallel command framework.

## 3. Capability inventory and actual attack-family status

`lowkey/capability_registry.py` is the canonical machine-readable 44-capability inventory at this snapshot:

- **10 `implemented`:** `control`, `mutation-score`, `target-coverage`, `sandbox`, `fallback-map`, `fidelity`, `economic`, `questions`, `learn`, `report`
- **28 `partial`:** `cheat-fingerprint`, `provenance`, `storage-infer`, `proxy-resolve`, `selectors-full`, `cfg`, `reentrancy-graph`, `calldata-mine`, `attack-forge`, `invariant-forge`, `archetype`, `token-weird`, `oracle-map`, `time`, `sig-matrix`, `init-frontrun`, `compose`, `reprove`, `gas-ladder`, `state-diff`, `watch`, `godmode`, `custody`, `agent-split`, `unravel`, `fork-cache`, `upgrade-diff`, `cross-vm`
- **6 `adapter-required`:** `decompile`, `flashmax`, `path`, `verify-hack`, `bundle`, `sandwich`

These are declared implementation states, not independent proof that a tool is installed, compatible with every project, or capable of establishing a vulnerability. Each command must still preflight its dependencies and report its own evidence and limitations. The existing [capability ledger](capability-ledger.md) is a dated 2026-11-25 snapshot; use the code registry and this dated baseline for the state recorded here rather than treating its older reviewed SHA as current.

The attack experiment strategy registry in `lowkey/attack_engine.py` contains 15 families: reentrancy, replay, access, accounting, boundary, time, upgrade, callback, oracle, economic, erc20, proxy, storage, signature, and dos. Only **reentrancy** is marked `fixture_accepted`; the other 14 are `adapter_required`. A family name, heuristic source signal, or generated plan is not an executable family implementation.

## 4. Attack reasoning and corpus boundary

The current pieces serve different purposes and must not be conflated:

1. `attack_catalog.py` contains 29 read-only teaching/reference patterns. `attack_library.py` exposes learning, search, local-lab plans, and historical-example references. It is not a reproducible incident corpus with pinned source revisions and per-case evidence.
2. `attack_research.py` produces bounded, redacted, source-cited `CANDIDATES_ONLY` hypotheses. It validates cited lines and source hashes; it does not generate or execute tests.
3. `attack_synthesis.py` maps those candidates to compiler-AST functions and joins them only across validated static candidate edges. Its output remains a chain proposal, not a finding or exploit.
4. `attack_engine.py` validates target-specific experiment manifests and paired attack/control evidence. The accepted family fixture is currently reentrancy; other family strategies remain adapter-required until they have their own executable acceptance.
5. `docs/test-generation-ecosystem-benchmark.md` and `scripts/test-gen-ecosystem-benchmark.py` evaluate test generation across real projects. That is a project/build diversity benchmark, not a historical exploit reproduction corpus.
6. `calldata-mine` is a partial historical-calldata capability, not a provenance-complete exploit case format or deterministic reproduction runner.

No dedicated versioned historical exploit-case corpus or corpus loader appears in the baseline repository tree. In particular, the current catalogue does not provide, for every historical case, a verified upstream URL and exact revision, license/attribution, affected version, chain/deployment/incident block, fork block, dependency pins, expected observable effect, mitigation reference, paired negative control, and reproduction status.

**Decision:** keep historical corpus records separate from the current attack catalogue, target experiment manifest, and test-generation ecosystem benchmark. Do not copy or execute upstream research code until its exact revision, license, attribution, scripts, and dependencies have been reviewed.

## 5. Project and backend support boundaries

- **Solidity + Foundry** is the broadest native generation and execution path. The generator requires a supported project/configuration and emits reviewable artifacts with explicit assumptions and validation status.
- **Vyper + Titanoboa** has a narrower generation path for a public-integer getter/direct-setter property, with pytest/Hypothesis validation. The live Vyper workflow is a compatibility test for that supported fixture, not universal Vyper coverage.
- **Hardhat** is handled through project-local tooling. The pinned GMX workflow validates one real project revision and its compile/link/deploy/verify path; it does not prove every Hardhat workspace works.
- **Echidna, Medusa, Halmos, and Slither** have pinned live fixture coverage through the verification/analysis adapters. Certora CI confirms CLI installation without submitting a paid remote proof. Adapter presence does not imply every version or project configuration is supported.
- **Cairo, Move, Solana/Anchor, and other cross-VM routes** are represented in the broader routing/analysis surface, but the registry marks `cross-vm` partial. Do not claim universal native exploit generation or equivalent evidence quality across those ecosystems.
- **Mixed-language and monorepo workspaces** are handled through project/workspace discovery and package-local context. A green fixture proves only the tested package/configuration path.

## 6. Evidence, network, deployment, and proxy safety

- Static source patterns, compiler-AST edges, AI hypotheses, and archetype classifications are leads. They do not prove runtime reachability, deployed target identity, or exploitability.
- AI source research and multi-agent review are explicit provider-assisted, redacted-source workflows. Their outputs remain candidates; they do not independently run attacks or establish findings.
- Executable experiments require an isolated local Anvil or explicitly configured local fork path. Paired attack/control, matched prestate/entry call, trace/state evidence, rollback, mutation, and independent reproof remain separate gates.
- Provenance hashes/signatures establish integrity relative to a separately trusted public key; they do not prove that the experiment or its interpretation is correct.
- `NetworkManager` scopes sessions by project and session identity and records process identity, chain ID, genesis hash, actors, and deployments. Process stop checks are designed to avoid signalling an unmanaged process. Ambiguous multiple-session selection fails closed; an explicit RPC override must not inherit another session's actor/target context.
- Deployment records are session-scoped. Proxy inspection is read-only and must preserve `ZERO`, `NONZERO`, `MALFORMED`, and `UNREADABLE` distinctions rather than turning RPC failure into a negative proxy finding.
- The P0 acceptance exercises UUPS, ProxyAdmin/Transparent routing, Beacon, and Diamond fixture controls. Those are accepted fixture paths, not universal support for every proxy implementation or production deployment.

## 7. Exact-SHA validation baseline

The pre-documentation baseline commit `3937556f73d7649711a2fa313888f596518fcac7` had the following completed GitHub checks:

| Workflow / check | Run | Result |
|---|---:|---|
| Validate LowkeyCast — 13 jobs | [45991822176](https://github.com/Toji254/foundry-lowkey/actions/runs/45991822176) | 13/13 jobs successful |
| Live two-session Anvil isolation | [45991821902](https://github.com/Toji254/foundry-lowkey/actions/runs/45991821902) | 1/1 job successful |
| Pinned GMX PositionUtils → PositionManager compile/link/deploy/verify | [45991821913](https://github.com/Toji254/foundry-lowkey/actions/runs/45991821913) | 1/1 job successful |
| GitGuardian Security Checks | [check run](https://github.com/Toji254/foundry-lowkey/runs/140481286542) | successful |

GitHub returned 16 check-run records for this SHA; all 16 were completed with `success`. The three Actions workflows above contained 15 successful jobs in total. The legacy combined commit-status endpoint returned `pending` with an empty legacy-status list; it exposed no named pending context. The branch API reported `protected: false` with no required status checks, so this validation was manually inspected rather than enforced by branch protection.

The main Python job ran:

- `python -m py_compile` over the maintained runtime modules and acceptance scripts listed in `.github/workflows/ci.yml`
- `python -m unittest tests/test_solidity_cheatsheet.py -v`
- `python -m unittest tests/test_benchmark.py -v`
- `python -m unittest discover -s tests -v` — **2,566 tests, OK (skipped=3)**
- `bash -n bin/lk install.sh scripts/install-verification-engines.sh scripts/install-lh-jev-shortcuts.sh`

The same exact SHA also passed the P0 break/proxy acceptance, P1 Step and paired reentrancy acceptance, P2 portfolio/first-fork acceptance, P3 genericity acceptance, compiler-graph/attack-synthesis acceptance, live external-engine campaigns, Foundry integration, Vyper integration, test-generation smoke and full ecosystem checks, live Foundry verification/correlation, two-session Anvil isolation, and the pinned GMX project workflow. Foundry v1.9.0 was verified. The multi-Anvil workflow used isolated local Anvil processes; the GMX workflow checked out the pinned upstream revision `fe55c4ba8911ae2378b50bfb9bece5ee50cf2af8`.

Three unittest skips were reported by the Python suite. The Godmode plan-only test output explicitly states that mutation execution and source coverage execution were disabled in that plan-only invocation; those messages are not evidence that those stages ran there. Dedicated Tier 0/P0/P1 acceptance and unit tests remain the relevant evidence for those paths.

**Execution limitation for this automation run:** the connected GitHub repository API and Actions logs were available, but no local `foundry-lowkey` checkout was mounted in the execution container. Therefore no local test command was rerun by this automation; the test results above are the exact-SHA hosted Actions results, not a claimed local run.

## 8. Recent regressions reviewed

Two short-lived regressions on earlier integration commits were traced to concrete causes and are fixed on the baseline SHA:

- [Run 45991484906](https://github.com/Toji254/foundry-lowkey/actions/runs/45991484906) failed one Python test because the managed-network help example rendered `lk actor Alice` while the test correctly expected the registration form `lk actor 1 Alice`. The example was corrected in [`3937556f73d7649711a2fa313888f596518fcac7`](https://github.com/Toji254/foundry-lowkey/commit/3937556f73d7649711a2fa313888f596518fcac7); the exact-SHA Python job now passes.
- [Run 45991343916](https://github.com/Toji254/foundry-lowkey/actions/runs/45991343916) failed the live multi-Anvil acceptance with `KeyError: 'Alice'`. The acceptance had captured the managed-session actor record before registering the alias. The record is now refreshed after registration, and the exact-SHA live multi-Anvil job passes.

These were code/test-sequencing and help-content defects, not external infrastructure failures. Their failed logs were inspected; no assertions or acceptance thresholds were weakened.

## 9. Ordered next work

Do not start more than one slice at a time. The next gated work after this architecture snapshot is:

1. **Historical corpus schema and read-only loader.** Define a separately versioned manifest with upstream URL, exact revision, license and attribution, affected contract/version, chain and deployment/incident references, fork block, dependency pins, root cause, violated invariant, attacker preconditions, reachable entrypoint, attack sequence, expected evidence/effect, control case, mitigation/patched variant, reproduction command, and limitations. Validate strict positive and negative cases. Loader must not execute upstream code.
2. **One documented pilot case.** Select only after upstream revision, license, attribution, and reproduction prerequisites are independently reviewed. Keep it `DOCUMENTED` until a pinned isolated test has run and matched independently defined evidence.
3. **Isolated reproduction runner.** Add deterministic local-fixture execution, paired control/attack, patched variant, bounded resources, rollback, and retained raw evidence. Historical forks must be explicit, pinned, read-only at the provider boundary, and executed only through a local isolated Anvil.
4. **Generic hypothesis mapping.** Map case root-cause patterns to target-specific source/AST/runtime hypotheses with explicit preconditions, falsification conditions, and assumption gaps.
5. **Beginner-guided orchestration.** Compose the existing project, source, test-generation, verification, and evidence layers without inventing a parallel CLI.

Acceptance for the first corpus slice: one valid manifest loads; malformed/missing provenance, unsupported states, invalid hashes/revisions, path traversal, missing control metadata, and unreviewed license data are rejected or explicitly marked incomplete; no network fetch or test execution occurs during loading. A documentation-only historical account remains `DOCUMENTED`, never `REPRODUCED`.

