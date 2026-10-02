# Lowkey auditor-question engine

The auditor-question engine is the reasoning layer that connects Lowkey's commands into one project-scoped learning path.

It is deterministic and evidence-first. It does not need an LLM to decide what is true, and it does not turn a heuristic, analyzer warning, or test observation into a vulnerability verdict.

## Architecture

Four layers work together:

1. Stable question universe: the catalog in lowkey/question_engine.py is versioned and inspectable. The question universe does not randomly change between runs.
2. Contextual rule packs: core questions apply to ordinary software. Blockchain/EVM, web/API, native/runtime, and data/database questions activate only when project evidence indicates the relevant behavior.
3. Shared evidence frontier: the engine reads the existing .audit/context.json and .audit/events.jsonl bus instead of creating a second isolated audit world.
4. Learner state: .audit/questions/state.json records explicit progress and .audit/questions/history.jsonl records the visible question path. Resetting question state does not delete audit evidence.

## Command model

lk q shows the single current question.

lk questions shows the compact frontier map. lk questions --all exposes every applicable question so the knowledge base remains inspectable.

Focused controls:

- lk q current
- lk q why
- lk q evidence
- lk q path
- lk q done
- lk q note "..."
- lk q skip "..."
- lk q source QUESTION_ID
- lk q reset

The auditor remains responsible for answering. lk q done records an explicit human decision; Lowkey does not infer that answer merely because another command succeeded.

## Progressive narrowing

A fresh project starts broad: purpose, protected assets/data, trust boundaries, entry points, dependencies, and failure model. As the auditor settles those questions and Lowkey accumulates evidence, state, authorization, interaction, attack, and proof questions become more relevant.

```text
project / system
       |
       v
purpose + trust + entry points
       |
       v
state + dependencies + invariants
       |
       v
trace / changes / probe / findings
       |
       v
focused question
       |
       v
reproduction / test / proof
```

A live observation does not become a finding. It changes what can be asked next.

## Command-to-evidence model

Every major Lowkey command can contribute to the frontier through a stable evidence map. This prevents q from becoming a special command that ignores the rest of the audit.

| Lowkey activity | Question concepts advanced |
| --- | --- |
| project, projects, system | purpose, architecture, dependencies, roles, lifecycle |
| functions, fn, ask, abi | entry points, inputs, trust boundaries |
| read, recon | observable state, configuration, assets |
| deps, layout, mapping, namespace, proof | state and component relationships |
| send, probe, changes, state-diff, trace | real execution, call flow, state transitions |
| logs, receipt, tx | execution history, ordering, observability |
| findings, focus, slither, scan, risk, seams, rg | security signals and manual validation threads |
| walkthrough, walkthrough test, matrix | stateful behavior and adversarial sequences |
| test, generate, test-gen, fuzz, invariant, mutate, symbolic, brutalize | reproducibility, properties, proof strength |
| build, script, lab, fork, rpc, doctor | build integrity, deployment/runtime assumptions, environment evidence |

## Question states

Question state is separate from finding severity or impact.

- UNKNOWN: prerequisites are not established.
- ANSWERABLE: the branch is ready to investigate.
- NEEDS PROOF: useful evidence exists, but the security claim still needs proof.
- CONTRADICTED: current evidence conflicts with the current model and needs reconciliation.
- ANSWERED: the auditor explicitly recorded the answer.
- NOT APPLICABLE: the auditor explicitly recorded that the branch is irrelevant.
- SKIPPED: intentionally deferred.

## Auditor mindset encoded in the catalog

Threat modeling and assumptions are first-class questions, not background notes. Lowkey asks who the realistic attacker is, what they can control, which assumptions are trusted rather than enforced, whether important assumptions remain unproven, and whether different parts of the evidence disagree about the same fact.

That gives the frontier a useful progression after basic architecture: establish the threat model, identify assumptions, locate exact enforcement, search alternative paths, then move the surviving hypothesis into proof and reproduction.


The catalog repeatedly enforces these distinctions:

- An intended rule is not the same as proof of enforcement.
- Protecting one entry point does not prove every route to the same state transition is protected.
- A successful call is an observation, not a vulnerability verdict.
- A static-analysis warning is a review lead, not a finding by itself.
- A reverted call proves that attempt reverted; it does not prove the property globally.
- A passing test proves what that test asserts, not every possible behavior.
- Fixes should be checked in context because alternate paths and original assumptions can survive the patch.
- Unknowns and unresolved assumptions are useful audit output rather than failures.

For smart contracts, the blockchain pack includes value flow, token semantics, accounting, rounding, oracles, flash-loan manipulation, reentrancy and callbacks, cross-function and read-only reentrancy, MEV and ordering, signatures/nonces/replay, upgradeability and initialization, storage, delegate execution, forced native value, time boundaries, chain context, gas/DoS, randomness, governance, and cross-contract invariants.

For other software, the same core reasoning extends into web/API authorization and injection, native process/filesystem/memory/privilege/concurrency boundaries, and data integrity/migration/tenant isolation. New ecosystems should be added as packs rather than turning the core into a language-specific checklist.

## Provenance

Each question may carry source metadata. The initial corpus is informed by Trail of Bits audit-context and secure-development material, Ethereum and Solidity security guidance, OWASP SCSVS/SCSTG, OpenZeppelin audit guidance, Foundry/Echidna property-testing material, and public competitive-audit and bug-fix research from Code4rena and Immunefi.

Use lk q source QUESTION_ID to inspect the references attached to a question.

## No hidden reasoning

lk q path exposes the question history Lowkey has actually recorded. It is an audit-learning artifact, not hidden model reasoning.

lk q why reports concrete selection inputs: applicability, question state, recent command evidence, focused findings, and available execution evidence. That makes the frontier explainable without pretending that Lowkey has a secret proof of the result.

## Extension contract

A new project ecosystem should provide a rule pack with:

- applicability tags;
- explicit prerequisites;
- reusable evidence keys;
- proof and contradiction follow-ups;
- provenance/source references;
- deterministic behavior;
- no requirement for an AI model.

This keeps the architecture broad while allowing specialized adapters to remain specific to their actual toolchains.
