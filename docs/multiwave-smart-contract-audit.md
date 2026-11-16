# Multi-wave smart-contract audit

Lowkey's multi-wave auditor applies a coverage-led orchestration pattern to Solidity/EVM repositories while retaining Lowkey's existing proof and evidence gates.

## Run it

From a Foundry/Solidity project:

~~~bash
lk godmode --root . --multi-agent --profile standard
~~~

Optional bounded profiles and call budgets:

~~~bash
lk godmode --root . --multi-agent --profile quick --agent-budget 8
lk godmode --root . --multi-agent --profile deep --agent-budget 24
~~~

The existing light, balanced and deep Godmode profile names remain supported. For the multi-agent stage, light maps to quick and balanced maps to standard.

## How orchestration works

1. **Protocol reconnaissance** maps contract roles, assets, privileged actors, entrypoints, dependencies, invariants and unresolved assumptions.
2. **Coverage-led hunting** assigns distinct model invocations to groups of EVM attack families. The coverage unit is source path × public/external entrypoint × attack family. A wildcard business-logic unit remains in scope so pattern matching does not define the whole audit.
3. **Post-wave coverage criticism** uses a fresh invocation to identify missing paths and attack classes. New source-backed units are added to the ledger and become work for a later hunting wave.
4. **Repeated waves** continue until the critic reports no new material coverage, the separate final-clean review finds no new work, or a profile/budget limit forces an explicit incomplete result.
5. **Independent candidate challenge** gives each candidate to a fresh verifier that did not discover it. The verifier may reject it, retain it as a source-level candidate, or mark it as needing validation.
6. **Reporting** writes the full coverage ledger, candidate records, agent-call log, architecture context and report.

Quick runs one hunter wave and one final critic pass. Newly discovered units are deferred rather than silently treated as covered. Standard supports up to three waves and a distinct final-clean critic. Deep supports up to five waves and more hunters. These are bounded defaults, not promises that every possible vulnerability can be found.

Remote model providers may run up to two hunter calls concurrently. Ollama and guarded free-tier mode are sequential to limit local memory pressure and avoid quota races. All roles use the configured provider; separate invocations provide role separation, not a guarantee that different underlying model families are used.

## Outputs

Each run is stored under:

- .audit/godmode/multiwave/run-<id>/run-metadata.json
- .audit/godmode/multiwave/run-<id>/coverage-ledger.json
- .audit/godmode/multiwave/run-<id>/findings.json
- .audit/godmode/multiwave/run-<id>/agents.json
- .audit/godmode/multiwave/run-<id>/architecture.json
- .audit/godmode/multiwave/run-<id>/REPORT.md
- .audit/godmode/multiwave/latest.json

Coverage units have stable IDs derived from source path, entrypoint and attack family. Prior units are carried as reviewed only when their current source hash matches the prior run. Changed-source units are investigated again. Prior candidates are re-challenged when the exact source hash still matches.

## Safety and proof boundaries

This is a source-review orchestrator. It does not run target builds or tests, access RPC endpoints, select deployments, sign transactions or broadcast transactions. Contract source, comments and repository text are untrusted data and are not instructions to agents.

AI-generated records remain candidates. An independent source challenge cannot set a finding to confirmed. It cannot grant FORK_REPRODUCED, PROFITABLE or HUMAN_CONFIRMED, and it cannot bypass Lowkey's native Foundry/Anvil reproduction, sequential-control, fidelity, provenance, mutation, economics or human-disposition requirements.

A coverage_complete status means the recorded in-scope units were reviewed and the configured critics found no remaining material gaps. It is not a security clearance, proof of complete coverage, or proof that the protocol has no vulnerabilities. Deferred, blocked, failed and needs-validation units prevent coverage completion. Insufficient provider quota or call budget produces an explicit blocked/incomplete result.

## Current scope

The initial orchestrator targets Solidity/EVM source exposed by Lowkey's bounded protocol-review context. The coverage taxonomy includes authorization, reentrancy/callbacks, accounting, oracles, signatures/replay, initialization, upgradeability, governance, token integration, ordering/MEV, denial of service, external calls, cross-contract assumptions, state machines, invariants and wildcard business logic.

The coverage ledger is an investigation plan and record, not a vulnerability detector. Pattern matches select where to look; they do not establish a defect.
