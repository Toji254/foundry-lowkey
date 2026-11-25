# Lowkey protocol relationship graph

\`lk link\` opens the project architecture graph by default. It uses the existing
read-only Solidity source index and collapses function/declaration relationships
onto contract nodes so the first view stays navigable on large protocols.

## Quick start

- \`lk link\` — terminal protocol architecture graph.
- \`lk link OrderBook --depth 2\` — focus the graph on a contract and show its
  relationship overview.
- \`lk link --only calls\` — cross-contract call relationships.
- \`lk link --only storage\` — state variables and their source-level readers and
  writers.
- \`lk link --only imports\` — imports, inheritance, libraries and typed
  dependencies.
- \`lk link --only assets\` — source-level asset-flow candidates and external
  call boundaries.
- \`lk link --format html\` — write an offline interactive graph to
  \`.lowkey/link-graph.html\`.
- \`lk link --format html --output /tmp/protocol.html\` — choose another HTML path.
- \`lk link --format json\` — emit the graph model for scripts.
- \`lk link --list\` — open the previous searchable declaration inventory.

\`--search\`, \`--type\`, \`--page\`, and \`--all\` also select inventory mode, so
existing source-map workflows remain available.

## Reading the graph

Nodes represent source declarations or aggregated dependencies. Terminal and
HTML architecture views group contracts by source directory. Directed edges
retain their relationship kind and resolution state; repeated source edges are
aggregated and shown with a count.

The offline HTML view embeds its graph data and renderer. It has no CDN or
runtime network dependency. Search, relationship-kind filtering, zoom, fit,
node selection, and connection details work locally in the browser.

Third-party dependencies are hidden from the default graph to keep protocol
architecture readable. Use \`--include-third-party\` to include declarations
classified as third-party or located under common vendored/dependency paths.

## Evidence boundaries

The graph is a visualization of Lowkey's static source-index edges. It does not
prove that a call executed, succeeded, was reachable in a particular state, or
resolved to a particular deployed implementation.

Storage reads/writes and asset-flow links are potential source effects.
Unresolved external calls remain unresolved; the graph does not guess addresses
or proxy implementations. Use transaction traces, state diffs, verified target
identity and runtime evidence to validate execution claims.
