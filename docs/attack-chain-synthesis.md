# Graph-backed attack-chain synthesis

Run `lk attack research --contract Vault --function withdraw` first. This asks the configured Lowkey AI provider for bounded, source-cited hypotheses for the selected contract/function. Every accepted candidate is hash-pinned and exact-quote checked; no tests are generated or executed.

Then run `lk attack synthesize --max-stages 4`. The synthesizer re-reads the research artifact, verifies the current source hashes and revision, builds the compiler AST graph, and maps each candidate's cited source lines to compiler function spans.

A stage transition is emitted only when a compiler AST call-candidate or state-dependency-candidate edge connects the two mapped functions. The report records the exact edge kind and function IDs. It does not infer a transition from shared names, a model claim, or a repository comment.

## Output and acceptance boundary

The output is `.audit/lowkey/attack-chains/synthesis.json`.

- `CANDIDATE_CHAINS_ONLY` means one or more source/graph-connected chain proposals were derived. It is not an exploit result.
- `NO_SUPPORTED_CHAIN` means no validated graph path joined the cited hypotheses.
- `BLOCKED_ADAPTER_REQUIRED` means at least one stage's family still lacks an accepted target-specific adapter.
- `DRAFT_NEEDS_CHAIN_ADAPTER` means the stage families have an accepted family fixture, but this chain still needs its own explicit adapter and paired acceptance.

Every chain includes source-cited stages, graph-backed transitions, per-stage preconditions, attack/control plans and mutation ideas. Nothing is signed, deployed, executed or promoted. Before `lk attack chain run`, each proposed chain must be converted into a target-specific manifest and pass its own attack/control, rollback, mutation and independent replay/reproof acceptance.

Compiler AST edges remain static candidates. Runtime-observed calls are retained separately in the protocol graph and are not silently substituted for static edges. If build-info is missing or source changed, synthesis refuses.
