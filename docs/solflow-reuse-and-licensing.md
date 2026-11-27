# SolFlow reuse and licensing record

**Upstream:** norah1499/solidity-flow-navigator  
**Branch examined:** main  
**Inspected upstream revision:** b4a697affb6647fd79d09ecbf954857761cb84e8  
**Upstream licence declaration:** GNU AGPL-3.0-only  
**Report date:** 2026-11-27

## Licensing decision

The inspected SolFlow revision declares AGPL-3.0-only. The Lowkey repository snapshot inspected for this work has no visible root LICENSE file and no confirmed Lowkey licensing or distribution policy in repository metadata. That is insufficient to establish whether direct copying, adaptation, or linking is compatible with Lowkey's intended distribution model.

Accordingly, this work does **not** vendor, copy, import, or adapt SolFlow source files. No SolFlow copyright notices have been removed or republished. Lowkey-native implementations below use the concepts and the independently inspected behaviour as design inputs. This is a conservative engineering decision, not a legal opinion or a conclusion that future reuse is impossible.

Before direct reuse is approved, Lowkey maintainers must decide Lowkey's own license/distribution model and review the AGPL source-distribution and network-interaction obligations with qualified counsel.

## Upstream areas inspected

The investigation covered the repository's declared licence/dependencies and the relevant analysis, flow, scope, dispatch and browser implementation areas, including:

- analysis/slither_facts.py
- flow/builder.py
- flow/types.py
- flow/scope.py
- flow/virtual_dispatch.py
- serve/static/js/flow-progressive.js
- serve/templates/flow.html
- Their related unit/fixture coverage.

SolFlow combines Slither/CryticCompile-derived facts with entrypoint-oriented flow construction and progressive browser exploration. Its Slither/CryticCompile dependency surface is not equivalent to a drop-in renderer-only component. Importing the application wholesale would introduce a second analysis pipeline and dependency surface.

## Reuse matrix

| SolFlow component / concept | Decision in this integration | Lowkey destination | Licence implications | Required follow-up |
| --- | --- | --- | --- | --- |
| analysis/slither_facts.py | No source copied | Existing optional Lowkey analysis adapters and source/AST pipeline | AGPL code not included | Evaluate a future adapter only after license review |
| flow/builder.py | Behavioural concept independently implemented | source_explorer.py function focus and entrypoint overlay | No upstream implementation copied | Continue expanding progressive navigation and execution context |
| flow/types.py | Keep Lowkey graph/evidence model | source_index.py and source_explorer.py | No upstream types copied | Keep stable IDs and typed evidence in shared Lowkey model |
| flow/scope.py | Scope concepts implemented against Lowkey project state | source_explorer.py plus .audit/context.json workspace preferences | No upstream implementation copied | Expand scope options only when they have real semantics |
| flow/virtual_dispatch.py | No source copied; compiler-native facts used | protocol_graph.py and source_explorer.py | No upstream implementation copied | Use fresh compiler linearization; do not guess super/deployment targets |
| flow-progressive.js | Interaction concept independently implemented | existing SVG renderer in source_explorer.py | No upstream JavaScript copied | Add browser-level acceptance |
| flow.html | No template copied | existing Lowkey graph HTML | No upstream template copied | Continue Figma-informed UX refinement after screenshot inspection |

## Lowkey-native capabilities added

- Entry-point indexing retains special function identity for fallback, receive and constructor. Public/external functions plus fallback/receive are presented as entrypoints; constructors are not.
- Entry points appear in a contract-grouped explorer with mutability and unresolved relationship hints.
- Function focus overlays reachable function/modifier/effect paths on the existing folder-level protocol overview and dims unrelated regions. It does not replace the network with a call tree.
- Node coordinates survive graph renders; the camera is no longer refitted on every selection. Manual node positions, camera, mode, selected node, inspector tab and filter state are persisted locally.
- Edge anchors use node-rectangle intersections and direction-aware cubic curves. Drag operations update incident edges using an adjacency index.
- The source graph embeds bounded project-relative Solidity files for offline inspection and opens a line-numbered, syntax-highlighted source drawer. The bundle is capped at 8 MiB total and 2 MiB per file. The loopback API serves larger files only after path-containment/symlink/file-size checks.
- Compiler AST C3 linearization and base-function override references are exposed in the inspector when current Foundry build-info is available. Compiler facts are kept distinct from lexical relationships.
- Manual interface bindings create a separate dashed overlay with evidence **ASSERTED ASSUMPTION** only for unique exact function signature matches. The original EXTERNAL_CALL source edge remains unresolved.
- Bookmarks and entrypoint investigation status are stored in browser-local storage under a key derived from the project path hash.
- Project-scoped interface bindings and graph scope preferences are saved through the loopback workspace endpoint into the existing .audit/context.json merge path.
- Nested structs, enums, user-defined value types, state/parameter/return type references are indexed and exposed for one-step navigation. The type panel does not recursively auto-expand cycles.
- Scope controls support hiding support sources, excluding contract declarations and project-relative path prefixes, and controlling whether a function-flow investigation expands library internals while keeping the library boundary relationship.

## Remaining integration items

- No SolFlow source is directly reused.
- C3 facts are compiler-backed when fresh Foundry AST is available, but complete Solidity super-dispatch execution modelling is still incomplete.
- Interface associations remain manual assumptions; they do not prove implementation deployed at an address or resolve a proxy.
- Scope "stub" functionality has not been introduced because a safe, evidence-preserving stub contract has not been designed.
- Runtime trace graphs are still separate from the main source-explorer graph; they have not been joined through strict deployment/network identity.
- Source syntax highlighting is intentionally lightweight rather than a full language-server implementation.
- Browser-level E2E interaction tests have not yet been demonstrated.

