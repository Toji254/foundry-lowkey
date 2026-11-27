# Lowkey protocol graph upgrade — reconnaissance

**Repository:** Toji254/foundry-lowkey  
**Branch examined:** integration-test-drive  
**Baseline examined:** 1f7714aa1a5f7a8c47aa348681693c5ebd8584cb  
**Report updated:** 2026-11-27

## Evidence boundary

This report combines committed source inspection, test/CI records, and static CLI registration analysis. The connected GitHub repository view does not expose uncommitted files in a developer's laptop checkout, and this session did not execute the user's installed lk binary. Therefore the complete command runtime matrix described in the project mission remains open. Do not interpret the static inventory below as proof that every route, flag combination, exit code, side effect, or failure path was executed.

## Command architecture

The command surface is distributed across several layers:

- lowkey/lk.py contains the primary Python router and assembled COMMAND_HELP metadata.
- bin/lk intercepts selected commands and routes them to specialised modules before the normal Python router.
- lowkey/command_wrapper.py applies contextual execution/configuration behaviour around selected backends.
- lowkey/godmode.py and specialist modules implement further workflows.
- lowkey/forge_tools.py preserves native Forge subcommands and adapters.

### Static root help inventory

The current inspected CLI metadata contains **161 unique root help keys** and **28 aliases**. This is a count of assembled static help metadata, not a runtime command matrix.

Root keys (alphabetical):

4byte, 4byte-calldata, 4byte-event, abi, abi-encode, access-list, actor, actors, admin, array, as, audit, audit--checks, audit-checks, balance, batch, benchmark, bind, bind-json, break, brutalize, build, c, cache, calldata, chain, changes, cheat, cheatcode, cheatcodes, checklist, chisel, clean, clone, compare, compiler, completions, config, confused, connect, constructor-args, context, coverage, create, creation-code, decode, decode-calldata, decode-error, deploy, deployments, deps, detect, detect-project, disasm, doc, doctor, eip712, encode, ens, event, export, expression, finding, findings, flatten, fmt, fn, focus, forge, fork, functions, fuzz, gas, geiger, generate, id, ids, impersonate, impersonate-actor, implementation, info, init, inspect, install, interface, invariant, lab, label, last, layout, link, lint, logs, lsp, mapping, matrix, mutate, mutation-check, namespace, note, opcodes, patterns, poc, practice, probe, project, projects, proof, proxy, q, questions, raw, read, receipt, recon, remappings, remove, replay, risk, rpc, s, scan, script, seams, selectors, self-test, send, session, sig, slither, slots, snapshot, soldeer, st, state-diff, status, storage, symbolic, system, target, targets, test, test-gen, todo, token, trace, tree, tx, txpool, update, use, verification, verification-benchmark, verify-bytecode, verify-check, verify-contract, version, walkthrough, wallet, wizard, workspace.

Aliases (28):

cheats → cheat; cheatsheet → cheat; walk → walkthrough; graph → project; signals → findings; signal → findings; investigate → focus; gen → generate; deployment → deploy; verify → verification; vbench → verification-benchmark; mcheck → mutation-check; cov → coverage; investigation → focus; try → probe; statediff → state-diff; state_diff → state-diff; map → mapping; hotspots → seams; target-list → targets; actor-list → actors; erc20 → token; resolve → ens; lookup → ens; decode-event → event; decode-calldata → calldata; returns → decode; error → decode-error.

### Special launcher routes

The launcher has additional dispatch behaviour that should be tested independently from the static help dictionary. The inspected bin/lk source includes:

- Dedicated routes: ast, hardhat, clean, attack/attacks, cheat fingerprint.
- Godmode/offensive catalogue routes: capabilities, godmode, control, trace-parity, steps, mutation-score, target-coverage, provenance, fidelity, sandbox, cheat-fingerprint, decompile, storage-infer, proxy-resolve, selectors-full, cfg, reentrancy-graph, fallback-map, calldata-mine, attack-forge, invariant-forge, archetype, assumptions, capability, token-weird, oracle-map, skew, flashmax, time, sig-matrix, init-frontrun, path, compose, reprove, economic, gas-ladder, watch, custody, agent-split, verify-hack, unravel, bundle, sandwich, jit, fork-cache, upgrade-diff, cross-vm, learn, report, and questions.
- Other special routes: state-diff with block/slot flags; block/blocks; coverage; Forge debug; workspace-root project overview; workspace select/list/status; workflow; project-aware build; risk; scoped AI routes; flow eth; trace source; link; fn --flow; memory; test/Hardhat preparation; forge; slither; import; native Forge passthrough; generate/gen; cov.

The source comments in bin/lk describe some safety boundaries, but a command's comment or help text is not a substitute for exercising its runtime behaviour and observing its effects.

### lk link options verified statically

| Input | Static parser contract |
| --- | --- |
| Target | Optional positional target |
| --root | Project root |
| --depth | 1–10; default 1 (function source tracing has a distinct default) |
| --only | calls, storage, reads, writes, imports, assets, all |
| --detail | summary, calls, storage, external, all |
| --limit | 1–500; default 24 |
| --format | terminal, html, json |
| --output | HTML output path |
| --include-third-party | Include vendor dependencies |
| --serve | Loopback local workspace server |
| --github / --archive | Mutually exclusive remote repository or ZIP import modes |
| --ref | Used with --github |
| --port | 1–65535; default 8765 |
| Listing/search | --list, --search, --type contract/interface/library, --page, --all, --json |

### Runtime matrix status

The full mission asks for help/default/valid/invalid/flag-combination/configuration/side-effect testing for every root and nested command. That work has **not** been completed in this session because the local checkout and installed CLI are not exposed through the GitHub connector. The safe way to complete it is a disposable checkout or temporary fixture workspace, with each command classified as read-only, file mutation, configuration mutation, build/test, local server, RPC/network, or transaction-capable. Real broadcasts and production RPC calls must remain excluded. The command matrix is still an explicit acceptance item, not a checked box.

## Architecture and data flow

Primary source-explorer path:

source_index → source_ast → source_graph → source_explorer

- source_index.py builds a bounded local lexical index of contracts, functions/modifiers, storage, imports, type declarations, call sites, assets, and unresolved relationships. It retains stable declaration IDs, source locations, and evidence/resolution metadata.
- source_ast.py enriches the source index from fresh Foundry build-info AST. Compiler declaration references can resolve static calls/modifiers and storage references. Stale build-info is rejected; this path does not claim a call executed at runtime.
- source_graph.py provides graph projection/serialization over source-index facts.
- source_explorer.py builds the embedded HTML/CSS/JavaScript/SVG graph workspace and local source-serving endpoints.
- source_link.py backs CLI source tracing and related source navigation.
- protocol_graph.py builds a compiler-AST graph and a separate canonical validated runtime-trace graph. Its compiler-AST facts are now joined into the source explorer for C3 linearization and override metadata. Runtime graph output is not yet unified into the main source-explorer canvas.
- Deployment/proxy intelligence lives in separate deployment modules and remains a distinct source of deployment identity and proxy resolution evidence.

## Existing graph model and evidence contracts

The source explorer represents contract/declaration nodes, functions and modifiers, state declarations, assets, external/unresolved targets, synthetic folder groups, and typed edges. Edges retain source file/line, evidence kind, resolution state, and optional details. Synthetic CONTAINS edges are declaration-ownership navigation, not executable calls.

Keep evidence categories separate:

1. Lexical source observations.
2. Fresh compiler AST/build-info observations.
3. Storage and asset relationships.
4. Validated canonical runtime trace events.
5. Manually asserted interface bindings.
6. Unresolved or ambiguous relationships.

An AST-derived static relationship is not proof of runtime execution. A trace proves only that a validated event was observed in that trace context, not all possible execution paths. Manual interface bindings are user assumptions, not deployed implementation evidence.

## Baseline and subsequent validation

The pre-upgrade remote baseline snapshot at commit 1f7714aa reported:

- python -m unittest discover -s tests -v: 2,619 passed.
- python -m pytest tests/test_network_rpc_enforcement.py -q: 32 passed.
- Python compilation and shell syntax checks passed.
- Latest baseline Actions snapshot: 14 successful checks, one skipped live-Foundry verification job, one failed Foundry integration job.

The Foundry acceptance failure was traced to an over-escaped raw regex in scripts/project-native-foundry-deployment-e2e.py. It failed to recognise a valid printed .audit/deployment-reviews/<64-hex-id>.json path. That regex was corrected.

The first graph implementation validation reported 2,621 Python tests passing and 32 RPC checks passing. Later feature additions increased the suite to 2,626 tests. The last completed Python run on commit b7062037 reported 2 failures: one nested-type fixture could not locate the struct parent field in the explorer model; one compiler-backed override fact was merged into a lexical edge without upgrading its evidence metadata. Both defects were corrected in subsequent commits (model now carries struct/enum field-parent metadata; merged compiler-confirmed edges carry COMPILER_AST evidence and compiler location). The follow-up validation is queued behind in-progress integration/corpus jobs at the time this report was written; its result must be checked before treating the branch as green.

Remote multi-Anvil isolation and P3 genericity acceptances have passed in the recent runs. The pinned GMX deployment acceptance has passed on an earlier graph-stage commit; a later run remained in progress at the time of reporting.

## Known test and acceptance gaps

- The full command/default/flag/side-effect matrix has not been executed from the installed CLI.
- Existing graph tests assert model/HTML content; a real browser E2E harness and viewport/pointer/console/accessibility acceptance have not been demonstrated.
- Large-protocol performance has not been benchmarked with hundreds/thousands of declarations and dense edges in a real browser.
- The user's laptop working tree and uncommitted modifications are not visible through the GitHub integration.
- Figma's shared file was identified, but the design-context and screenshot endpoints were rate-limited during this session. The reference frame has not been visually inspected here.
- Runtime trace address-to-source/deployment joins remain incomplete and must require strict project/network session/chain/genesis/deployment/proxy identity.

## Security and compatibility requirements

- No audited source is uploaded to external services.
- Keep the local source server loopback-only and preserve path containment, symlink and file-size checks.
- Do not install Slither or other optional tools automatically.
- Do not edit target project configuration as a side effect of graph generation.
- Do not infer deployed implementation identity from interface names or a source-level binding.
- Preserve existing CLI routes, deployment/proxy evidence, trace schemas, and project audit context.
