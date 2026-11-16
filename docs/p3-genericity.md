# P3 — Genericity stack: protocol intelligence

This phase extends the existing Godmode archetype and invariant surfaces. It does not replace the P0–P11 roadmap and does not pull P6 composition or P9 model-driven research forward.

## Existing work reused

- The existing **lk archetype** command still generates starter checklists. The new **lk archetype classify** subcommand adds deterministic source classification.
- **lk capabilities** and the 44-entry Godmode capability inventory remain the source of capability states. The new singular **lk capability** view negotiates requirements for the selected archetype.
- The configured, replaceable provider layer already lives in **lowkey/ai_harness.py**. P3 does not create another AI provider.
- PR #66 contains a separate multi-wave audit proposal with reconnaissance, coverage hunters, critics and independent source-level candidate challenge. It remains a separate open PR and is not silently assumed to be integrated.
- Existing source maps (oracle-map, custody, reentrancy-graph, cfg, proxy-resolve, and related commands) remain reusable evidence sources.

## Current P3.1 implementation

Ten data-driven archetype packs live under **lowkey/archetypes/**:

- **vault4626**
- **lending**
- **amm_cp**
- **amm_concentrated**
- **staking**
- **bridge**
- **governance**
- **nft**
- **escrow**
- **proxy**

Each pack uses the canonical **ArchetypePack** fields: **name**, **detect_signals**, **invariants**, **required_capabilities**, **forbidden_capabilities**, **attack_families**, and **assumption_classes**.

The classifier:
1. scans bounded Solidity/Vyper source trees without contacting RPC or an AI provider;
2. scores the declared signals using a fixed deterministic weighted rule;
3. requires at least two distinct signal kinds and a 0.35 confidence floor;
4. returns **UNCLASSIFIED** when the floor is missed or the top candidates are too close;
5. emits source-file fingerprints, source-linked evidence, a conservative import/typed-call-candidate relationship graph, and the selected pack's invariant candidates;
6. extracts **Assumption** records only where a matching signal exists, with **verification_status: unverified**;
7. checks required capabilities against the existing Godmode inventory and publishes an explicit generic-mode skip list.

The confidence number is a deterministic ranking score, not a calibrated probability. **OBSERVED** means the source classifier selected an archetype; it does not authenticate a deployment or prove protocol behavior.

The relationship graph is intentionally conservative. **import** edges are source references; **typed_call_candidate** edges are source-level leads. Neither establishes runtime reachability. Compiler AST, full call-graph and data-flow extraction through Slither/solc remain follow-on P3 work and must preserve file/line citations.

## Commands

~~~bash
# Produce a source classification and save a fingerprinted report
lk archetype classify --root . --json

# Re-read the saved ledger citations and verify file/line content
lk assumptions --root .

# Inspect capability availability and generic-mode skips for the report
lk capability --root .
~~~

The default report is **.audit/godmode/archetype-classification.json**. It is generated locally and is not a committed artifact. Re-run classification after source changes. **lk assumptions** re-reads the saved source hashes and cited lines; changed source is **UNRESOLVED**, not a clean pass.

## Explicit boundaries

- Source-only discovery does not prove that the inspected source matches a deployed address.
- A classified archetype is not a finding, attack family acceptance, or capability promotion.
- The initial packs link to existing family names; they do not register novel exploit families.
- No AI model is called in P3. P9 may propose steps, rerank deterministic candidates, extract assumption proposals, triage failures and draft reports from frozen evidence.
- AI proposals must remain **PROPOSED**; deterministic checks and execution remain authoritative.
- No attack sequence is synthesized or executed by this classifier.
- Generic mode publishes its skip list and is not a claim of comprehensive coverage.

## Proposed additions requiring explicit schema review

The original mission defines **ArchetypePack** and **Assumption**, but not a protocol relationship graph or a complete classification-report schema. This implementation uses a local report shape with **protocol_graph.nodes**, **protocol_graph.edges**, **ranked_candidates**, **source_hashes**, **citation_fingerprints**, **capabilities**, and **generic_mode**. These are report-level additions, not replacements for the canonical **Assumption** or **ArchetypePack** schemas. They should be promoted into versioned schemas only after review.

The mission also does not define a calibrated confidence methodology. This first version uses a fixed deterministic weighted score with a conservative floor and ambiguity margin; no score is represented as a probability.

## P3.1 acceptance boundary

The committed fixture set covers a vault, a constant-product AMM and an unknown contract. The acceptance gate must establish:
- the vault and AMM classify using distinct source signals;
- the unknown contract stays **UNCLASSIFIED**;
- assumption citations resolve on re-read and fail after source tampering;
- generic mode publishes skips;
- the relationship graph cites the source lines from which each edge was derived;
- the installed CLI routes the new commands and the installer fingerprints every new runtime/data file.

This is classification acceptance only. The archetype packs are not entered as attack-family evaluation successes, and no P4–P11 capability is promoted.

The integration candidate is based on `integration-test-drive`; its combined P0/P1/P2/attack-engine/P3 tree is validated by the exact-head CI attached to PR #72.
