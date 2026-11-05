# Lowkey capability ledger

This ledger records current implementation claims separately from the full roadmap. A registered command or inventory entry is not, by itself, a shipped capability.

## Status meanings

- **implemented** — a local workflow exists and has focused regression coverage; this label does not imply broad target coverage or security certification.
- **partial** — the workflow produces bounded evidence, a lead, a starter or requires protocol-specific input.
- **adapter-required** — execution depends on an external runtime/provider/adapter that is not currently available as a complete Lowkey workflow.
- **telemetry-only** — recorded for visibility and learning; not eligible for security verdicts.

A capability may be promoted only when it has executable positive, control, rejection and mutation acceptance cases, trace-backed evidence, and a reproducible CI run for the exact commit.

## Current Godmode inventory (baseline before P0 acceptance)

| capability | baseline status | limitation |
|---|---|---|
| cheat-fingerprint | partial | Static source patterns; aliases and dynamic dispatch may be missed. |
| control | implemented | Family-specific manifests and metrics still constrain proof strength. |
| mutation-score | implemented | Quality is only as good as the mutation set and test property. |
| target-coverage | implemented | Coverage is not security correctness. |
| provenance | partial | Hashing/signing does not establish truth of inputs. |
| sandbox | partial | Not every external build/test path is isolated. |
| decompile | adapter-required | Requires a supported decompiler. |
| storage-infer | partial | Probabilistic layout inference needs corroboration. |
| proxy-resolve | partial | Proxy families and custom dispatch remain incomplete. |
| selectors-full | partial | Unknown selectors may remain unresolved. |
| cfg | partial | Static outline, not complete execution semantics. |
| reentrancy-graph | partial | Pattern-based read/call/write signal, not a complete storage dependency graph. |
| fallback-map | implemented | Source-level callback inventory; does not prove callback reachability. |
| calldata-mine | partial | Requires historical data source and bounded scope. |
| attack-forge | partial | Produces a starter requiring protocol-specific predicates. |
| invariant-forge | partial | Candidate templates require real handlers and ghost accounting. |
| archetype | partial | Current profile templates are not a complete target classifier. |
| token-weird | partial | Hostile fixtures are not a proof that the target handles them safely. |
| oracle-map | partial | Maps reads and cues; does not infer profitable manipulation. |
| flashmax | adapter-required | Venue callbacks, liquidity and fee verification not complete. |
| time | partial | Bounded timestamp/block probes. |
| sig-matrix | partial | Candidate replay/validation grid needs a target-specific signer and domain. |
| init-frontrun | partial | Static exposure map; no live takeover claim. |
| path | adapter-required | Requires a configured symbolic engine and useful harness. |
| compose | partial | Candidate chain planner; not exhaustive multi-contract attack search. |
| fidelity | implemented | Static checks are signals and can miss wrappers/aliases. |
| reprove | partial | Limited fork and family support. |
| economic | implemented | Input-driven native-ETH arithmetic; not a universal token/share model. |
| gas-ladder | partial | Bounded gas measurements, not general DoS proof. |
| state-diff | partial | Backend and trace coverage limitations apply. |
| watch | partial | Depends on RPC/provider and monitoring scope. |
| godmode | partial | Orchestrator; reports stages but does not autonomously discover every exploit. |
| custody | partial | Static/source and bounded on-chain maps. |
| questions | implemented | Question workflow does not itself establish exploitability. |
| agent-split | partial | Role orchestration is not independent verification. |
| verify-hack | adapter-required | Historical incident replay corpus and fixtures are incomplete. |
| unravel | partial | Trace/call-tree support depends on backend. |
| bundle | adapter-required | Requires relay authentication and bundle simulation. |
| sandwich | adapter-required | Requires ordering/venue simulation and realistic state. |
| fork-cache | partial | Cache integrity and reorg handling are bounded. |
| upgrade-diff | partial | Implementation-specific comparison. |
| cross-vm | partial | Detector routing is not per-VM exploit proof. |
| learn | implemented | Experience memory stores reviewed evidence; it is not a verdict engine. |
| report | implemented | Report output depends on validated records and human disposition. |

## P0 — ABI and asset setup compatibility

P0 adds or improves:
- ABI-driven scalar and one-dimensional address/integer argument construction.
- Explicit refusal for nested arrays, tuples and unsupported setup ABI types.
- Decimal-aware token funding with an observable 18-decimal fallback.
- Low-level optional-return approval calls with allowance reset support.
- ERC-777, ERC-721 and ERC-1155 receiver hooks and corrected ERC-777 source detection.
- Standards references and compatibility acceptance fixtures.

These are compatibility improvements, not new exploit families. P0 does **not** promote any attack family or claim token-share profitability proof.

## Promotion evidence

Every future ledger update must link:
1. The exact commit SHA.
2. The relevant acceptance fixture and its positive/control/reject/mutation cases.
3. The CI run URL and result.
4. The frozen spec hash, where applicable.
5. Any known fidelity, target-authenticity, adapter or protocol-specific limitations.

A missing evidence link means the capability remains partial or telemetry-only.
