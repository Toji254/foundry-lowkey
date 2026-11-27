# Protocol graph workspace — implementation and usage notes

## Product direction

Lowkey remains a local-first, evidence-driven protocol explorer. The graph stays central: a compact project explorer and entrypoint list on the left, the SVG protocol network in the centre, contextual node/edge inspection on the right, and a collapsible/resizable source drawer below. Function focus is an overlay on the overview graph, not a separate call-tree application.

The intended visual direction follows the user's dark hybrid Figma reference. The Figma design-context and screenshot endpoints were rate-limited while this integration was made, so the specific prototype frame was not visually verified in this session. The implementation is based on the supplied layout/product requirements and should be visually reviewed against the frame when Figma inspection is available.

## Implemented workflows

### Contract and entrypoint exploration

- Public and external functions appear in the entrypoint list, grouped by contract.
- Solidity receive and fallback functions are preserved as special entrypoints; constructors are excluded.
- Each entrypoint row shows callable kind, a conservative read-only versus may-mutate label, and an unresolved/ambiguous outgoing edge count when present.
- Selecting an entrypoint keeps the folder-level protocol network visible, adds its reachable function/modifier/effect neighbourhood, and dims unrelated nodes/edges.
- The left entrypoint search reuses the sidebar search string.

### Graph layout and interaction

- Existing positions are retained across focus, mode and selection changes. Newly visible nodes get an initial layout position only if they do not already have one.
- Selecting a node no longer calls fitGraph automatically. The existing Fit control and F shortcut remain available.
- New graph import resets the graph layout/camera. Browser workspace state may then restore selected node, mode, filters, viewport and saved manual positions.
- Edge endpoints are anchored at the intersection of node rectangles along the edge direction. Curves follow reverse, vertical and diagonal directions.
- Node dragging redraws only incident edges and their labels through an adjacency index.
- The graph remains progressively scoped around folder/declaration groups rather than rendering every declaration in a huge protocol simultaneously.

### Source inspection

- The graph model embeds source files using project-relative paths, SHA-256 hashes, byte size and line count.
- Offline source embedding is limited to 8 MiB total and 2 MiB per file. Files outside the offline budget show an explicit unavailable state; they are not silently omitted.
- In loopback serve mode, the source drawer may request a non-embedded .sol file from /api/source. The server rejects absolute/traversal/backslash paths, symlink escapes, non-Solidity paths and oversized reads.
- The drawer uses 500-line windows, line numbers, a selected line, lightweight Solidity token colouring, and earlier/later/selected-line navigation. Its height can be adjusted vertically or the drawer closed.
- Selecting a source-anchored edge opens the call-site file/line. The drawer identifies the source file hash.
- This is a useful source viewer, not a full IDE: call-token precision highlighting, compiler diagnostics, language-server navigation and complete semantic syntax highlighting remain out of scope.

### Compiler inheritance and types

- Fresh Foundry compiler AST facts provide C3 linearized base order and base-function references.
- The inspector surfaces compiler C3 order, virtual/override facts and override relationships. If fresh compiler AST is unavailable, the UI says so rather than guessing.
- Struct fields, enum members and file-level user-defined value types are navigable. Function parameters/return values and state/struct fields link to unique local type declarations when the source index can establish an unambiguous match.
- Type expansion is one level at a time, preventing automatic recursive cycles.

### Interface assumptions

- The interface inspector offers a contract candidate selector.
- Saving requires at least one unique exact function name-and-signature match.
- A saved manual association creates a separate dashed ASSERTED ASSUMPTION overlay. It does not rewrite the original EXTERNAL_CALL edge or change that edge's unresolved implementation-resolution status.
- The UI and inspector explain that the binding is not compiler proof, runtime evidence, a proxy implementation resolution, or proof of deployed code.
- Project loopback mode persists the binding through the existing audit context. Imported/offline graph bundles use browser-local persistence only.

### Bookmarks, progress and scope

- Contracts/functions can be bookmarked and revisited from the left panel.
- Entrypoints can be marked investigated/uninvestigated.
- Browser-local preferences are namespaced using a hash derived from the canonical project root and are not uploaded.
- Project loopback mode persists interface assumptions and scope preferences under .audit/context.json, preserving unrelated audit fields.
- Scope controls can exclude support/test paths, contract declarations and relative source-path prefixes. Library internals can be left collapsed in function-flow traversal while the boundary edge remains visible.
- Scope changes are investigation filters; they do not delete indexed facts or rewrite source files. There is no stub-mode claim.

## Evidence interpretation

- LEXICAL_SOURCE: local source parser observation.
- COMPILER_AST: fresh compiler AST declaration/source relationship.
- ASSERTED ASSUMPTION: user-supplied association; never a proof claim.
- Runtime trace evidence remains separately validated and is not merged into the source explorer as if it were static call-graph truth.
- Unresolved relationships remain unresolved unless an evidence-backed resolution exists.

Static graph relationships show possible source-level relationships, not that the path executed. A validated runtime trace shows an observed event in that trace only. Deployment/proxy resolution remains a separate deployment evidence path.

## Copy-ready usage

~~~bash
# Open the protocol overview in the terminal
lk link

# Generate the offline graph HTML with bounded embedded source
lk link --format html

# Serve the project locally for on-demand source reads and project preferences
lk link --serve

# Focus the graph on calls while retaining detailed edge evidence
lk link --only calls --detail all --format html

# Inspect storage relationships
lk link --only storage --detail all --format html

# Browse and search the declaration inventory
lk link --list --search withdraw
~~~

Use ordinary Foundry project build-info for C3/override enrichment; graph generation does not force a new compilation. A source graph without fresh build-info will still show the lexical facts and explicitly mark compiler inheritance facts unavailable.

## Remaining UX acceptance

- Run browser E2E tests at practical desktop and narrower viewport sizes.
- Check node/edge overlap, pointer coordinate transformations, drawer resizing, inspector reflow, focus visibility, keyboard-only navigation and console/network failures.
- Benchmark hundreds of contracts/thousands of functions/dense edges with real browser timings.
- Add robust expand/collapse controls, richer entrypoint filters, full caller-path navigation and source call-token selection/highlighting.
- Visually compare the actual target Figma frame after the current Figma MCP rate limit is lifted.
