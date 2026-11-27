# Lowkey Protocol Graph — Figma frame 9:2

This folder captures the working design reference for the Lowkey protocol graph.

## Source of truth

- Figma file: [Lowkey — Protocol Graph UI Explorations (Copy)](https://www.figma.com/design/hCgJTS44y4ErF1AIhiQczB/Lowkey-%E2%80%94-Protocol-Graph-UI-Explorations--Copy-?node-id=9-2)
- Frame: \`9:2\`
- Frame dimensions: **1440 × 900**
- Working reference: [Open the standalone HTML](./protocol-graph-frame-9-2.html)

## Frame geometry recorded from Figma

| Region | Position | Size |
|---|---:|---:|
| Header | x=0, y=0 | 1440 × 58 |
| Activity rail | x=0, y=58 | 58 × 842 |
| Explorer column | x=58, y=58 | approx. 252px wide |
| Main graph canvas | x=310, y=58 | 835px wide |
| Inspector | x=1145, y=58 | 295 × 798 |
| Source preview | x=310, y=685 | 818 × 154 |
| Footer | x=58, y=856 | 1382 × 44 |

## Graph nodes

The frame's layer names and coordinates identify these principal graph nodes:

\`whenNotPaused\`, \`collectFees\`, \`marginFee\`, \`deposit\`, \`executeDeposit\`,
\`positionManager\`, \`validateDeposit\`, \`increase\`, \`priceMin\`, \`priceMax\`,
\`oracle\`, \`transferIn\`, \`feeReserves\`, \`positions\`, \`globalShort\`,
\`weth\`, \`token\`, \`priceFeed\`, \`vaultContract\`, and \`storageUtils\`.

The HTML preserves the known node positions, circular node treatment, selected
\`deposit\` focus, side inspector, graph controls, relationship legend, source
preview, and footer arrangement as a working baseline.

## Fidelity note

This is a **Figma-derived structural reconstruction**, not a verified pixel-perfect
export. The Figma MCP screenshot/vector export quota was exhausted after the
frame's layer metadata was read, so original text contents, fills, strokes,
typography, and vector edge paths could not all be recovered. The HTML labels
and some relationship paths are therefore illustrative. Do not treat those
illustrative edges or source preview text as audit evidence.

When the Figma export is available, replace the illustrative values with the
original export or use it as the visual acceptance reference. Keep this copy
separate from \`lowkey/source_explorer.py\` until visual comparison and browser
acceptance pass.
