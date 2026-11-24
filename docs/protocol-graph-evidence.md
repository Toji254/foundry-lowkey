# Compiler and runtime protocol graph evidence

Lowkey emits three separate evidence layers. They must not be collapsed into one claim that the protocol graph is complete.

## 1. Compiler AST

Run `forge build --build-info` in the target project, then run `lk archetype classify --root . --json`. The classifier reads existing `out/build-info/*.json`; it does not silently rebuild or change compiler settings.

Each build-info source is accepted only when its literal source content still matches the current project file. The graph then records contract and function declarations, inheritance candidates, compiler-resolved call candidates, state-variable reads/writes, and writer-to-reader dependency candidates. Source SHA-256 values pin each accepted compiler source.

An AST entry with a stale source is rejected. If build info is absent, the report says `AST_UNAVAILABLE` and preserves the simpler import/typed-call candidate graph as a separate field.

## 2. Runtime call graph

Saved Lowkey audit artifacts under `.audit/` are scanned for canonical TraceEvent v2 streams. Events are revalidated through the trace schema before a call edge is emitted. Edges retain the accessor, destination, depth, selector, backend, revert status, source artifact, and run/transaction identifier when available.

This graph is observational: it shows calls present in the saved executions only. It does not prove all paths are reachable or enumerate calls across untested states. Missing caller/target fields are never inferred.

## 3. State dependency candidates

Compiler AST identifiers are associated with state declarations and function read/write contexts. Lowkey emits state-variable read/write edges and candidate writer-to-reader function dependencies. These are static AST-derived candidates, not a path-sensitive SSA or full data-flow proof. In particular, assembly, delegatecall storage layout, aliasing, dynamic dispatch and control-flow feasibility require additional analysis.

## 4. Current limitations

- Compiler AST graph only consumes existing Foundry build-info. It does not currently compile arbitrary multi-language projects itself.
- Static function-call resolution depends on Solidity AST referencedDeclaration values; low-level calls, function pointers and dynamic dispatch may remain unresolved.
- The runtime graph is only as complete as the saved canonical trace artifacts.
- Storage read/write evidence remains separately labeled by Forge/Anvil trace fidelity; this graph does not upgrade partial storage observations to exact.
- Proxy/beacon/diamond implementation resolution and verified deployment identity remain separate gates.
- AST dependency candidates are not a vulnerability finding or exploit proof.

The classifier reports these distinctions in `compiler_protocol_graph.compiler_ast`, `runtime_call_graph`, and `state_dependency_graph`.
