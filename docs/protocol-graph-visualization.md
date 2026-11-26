# Lowkey protocol graph and source workspace

Lowkey's protocol graph is built from the shared Solidity source index. The graph
model preserves the original declarations, function-level relationships,
storage effects, interface/library boundaries, source locations, resolution
states and inspection coverage. The UI renders focused projections of that
model; it does not replace source evidence with guessed runtime connections.

## Quick start

- `lk link` — terminal project architecture overview.
- `lk link OrderBook --format html` — generate a focused interactive graph
  centred on a named declaration.
- `lk link --format html` — generate the graph-first offline explorer at
  `.lowkey/link-graph.html`.
- `lk link --format html --output /tmp/protocol.html` — choose an output path.
- `lk link --serve` — start the loopback-only live workspace at
  `http://127.0.0.1:8765`.
- `lk link --serve --port 8766` — choose another local port.
- `lk link --include-third-party --format html` — include third-party source
  declarations in the initial view; vendor filters remain available.
- `lk link --only calls --format html` — focus the graph on call relationships.
- `lk link --only storage --format html` — focus on function/state interactions.
- `lk link --only assets --format html` — focus on source-level asset paths.
- `lk link --github https://github.com/gmx-io/gmx-contracts --ref master --format html`
  — shallow-clone a GitHub repository and export its graph.
- `lk link --archive ./protocol.zip --format html` — safely extract and graph a
  Solidity project archive.
- `lk link --root ./src/SomeContract.sol --format html` — inspect a Solidity
  source file using the same source index.
- `lk link --list` — open the existing searchable, paginated declaration
  inventory. Existing function and transaction trace commands remain available.

The `--github` and `--archive` paths create a temporary imported workspace and
remove the checkout/extraction after the graph has been generated. The exported
HTML contains the graph model and retained source excerpts needed for offline
inspection. The live `--serve` workspace is the option for importing from the
browser and switching between multiple uploaded workspaces.

## Graph navigation

The primary view is an interactive node-and-edge graph, not a declaration-card
list. The project overview groups declarations by source directory. Select a
folder to expand its declarations; select a declaration to reveal its
function-level relationships, peer contracts, interfaces, libraries, storage
and asset endpoints. Select a function to follow its reachable call path and
attached state/asset effects.

- Drag nodes to arrange the current view; drag the canvas to pan.
- Use the wheel or zoom buttons to zoom and Fit to frame the current graph.
- Select a node to inspect it; select an edge to inspect its source evidence.
- The left explorer searches declarations and groups them by source directory.
  The global search also matches function and state declaration names.
- The right inspector exposes overview, functions, state, calls, assets and
  review-lead context.
- The lower flow strip follows a selected function's statically identified
  call/effect path. Branch conditions and runtime execution still require review.

## Filters

Filters are visibility controls over the unified graph model. They do not
rewrite the underlying source evidence.

- **Declaration types:** contracts, abstract contracts, interfaces and
  libraries.
- **Source scope:** first-party, third-party, test/mock/support and unresolved.
- **Vendors:** hide individual recognised vendor groups, including OpenZeppelin,
  Chainlink, Uniswap, Solmate and other third-party dependencies when their
  source paths/provenance can be identified.
- **Relationship layers:** internal calls, interface/external calls, modifiers,
  inheritance, reads, writes, deletes, asset flows, library relationships and
  imports.
- **Resolution:** unresolved and ambiguous relationships can be hidden or
  restored separately.

Hiding an interface declaration also hides its function nodes in the visible
projection; the underlying interface-call edge remains in the model and is
available again when the interface filter is restored. Unresolved external
receivers remain explicit rather than being assigned a guessed contract.

## Source coverage and missing declarations

The project overview reports the indexed Solidity-file count and declaration,
function and storage totals. The coverage inspector exposes discovered versus
inspected files, uninspected source paths with phase/error details, and
directories intentionally excluded by the project source inventory.

The explorer displays every declaration node delivered by the source index;
it does not apply a hidden relationship-edge limit to the declaration browser.
If a declaration such as `OrderBook` is absent, inspect the coverage and source
inventory first: a parse/read/exclusion issue should be visible rather than
silently interpreted as a graph-rendering limit.

The source index uses its existing bounded inventory and dependency traversal.
A complete first-party inventory does not imply every transitive dependency
has been indexed; third-party imports have separate limits and are identified
by provenance.

## Importing source projects

The live workspace provides **Choose files**, **Choose folder**, **Choose ZIP**
and **GitHub repository** imports. All source imports run through
`build_source_index`, the same local Python analysis path used for a local
project. The interface does not use a weaker browser-only Solidity parser.

- File/folder uploads accept Solidity files and recognised root configuration
  files (`foundry.toml`, `remappings.txt`, `soldeer.lock`,
  `.gitmodules`, `.gitignore`).
- ZIP imports skip normal non-source files such as README/docs and common build
  or VCS directories. Unsafe relative paths, symbolic links, duplicate paths,
  over-budget archives and oversized Solidity files are rejected.
- GitHub imports accept HTTPS repository URLs on `github.com`, with an optional
  branch or tag. Git must be installed. Credentials must not be embedded in the
  URL; locally configured Git credential helpers may be used by Git itself.

The live import service binds only to loopback (`127.0.0.1` or `::1`), checks
the local Host/Origin, limits request/source/archive sizes and processes imports
in temporary directories. It is not a remote upload service and should not be
exposed through a reverse proxy or public network interface.

## Auditor review leads

The review-lead overlay highlights source patterns worth investigating, such as
external calls combined with state effects, payable entry points, asset exits,
unresolved receivers and oracle/price-related dependencies. Each lead points
back to the indexed function and source evidence.

These are deterministic triage signals, not vulnerability findings, severity
ratings or proofs of exploitability. An auditor must still inspect the exact
source, conditions, authorization model, protocol invariants and runtime
behaviour.

## Evidence boundaries

- A static call edge does not prove a path executed, succeeded or was reachable
  in a particular state.
- A resolved interface method identifies the declared interface function; it
  does not establish the implementation selected at a deployed address.
- Inferred helper effects preserve the indexed call path but need branch and
  execution-context review.
- Storage read/write and asset-flow edges describe source-level effects or
  candidates. Validate actual transfers, balances and state changes with
  transaction traces, state diffs and deployment identity.
- The graph reports unresolved or ambiguous edges rather than manufacturing
  targets. A hidden filter is not evidence that a dependency is absent.
