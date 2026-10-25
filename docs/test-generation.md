# Evidence-backed Solidity test generation

Lowkey exposes `lk test-gen` for generating test drafts and an evidence-linked test plan for a contract. The generator makes conservative inferences; it must not imply that a heuristic, a generated file, or a passing smoke test proves security.

## Usage

```bash
lk test-gen Counter
lk test-gen Counter --types unit,fuzz,invariant
lk test-gen Counter --types fork,poc --output-dir .audit/drafts
lk test-gen Counter --types all --force
lk test-gen Counter --types unit,fuzz,invariant --validate
lk test-gen Counter --types formal
```

If no contract name is supplied, Lowkey uses the active configured contract name. Run this command from the root of a Foundry project.

## What it creates

By default, files are written to `.audit/test-gen/<ContractName>/`. This is intentional: drafts do not enter Foundry's regular test discovery and therefore cannot silently change the project's normal test result. `--validate` first builds the untouched project, then stages uniquely named temporary copies under the active Foundry test directory and runs `forge build` again. It never executes test functions, removes the temporary files afterward, and records both build results in `report.json`. A JSON report lists generated/skipped types and a source-analysis summary. It also includes `generation_assessment` for each selected type, with a readiness level and a note explaining what the artifact actually tests; every entry explicitly records that protocol security has not been established. Treat `executable-candidate` as a narrow runnable candidate, not as proof of broad coverage. A test-plan.md records recognized protocol shapes, security-relevant source cues, dependency imports, existing test inventory, reusable .audit/evidence files, and a plan for all seven test families plus formal verification. For recognized ERC-20, ERC-721, ERC-4626, ERC-1155, proxy/upgradeable, escrow, lending, staking, bridge, oracle, governance, AMM/DEX, ERC-4337, flash-loan, Merkle-claim, and NFT-marketplace shapes, it also adds profile-specific candidate test obligations (rounding, replay, state transitions, callbacks, oracle edges, and similar risks). These are checklists, not automatically asserted properties; confirm each against the actual specification.

| Type | Starter contents | What still needs human/project input |
|---|---|---|
| Unit | Deployment smoke test plus a deterministic setter/getter assertion when a safe direct setter is recognized | Authorization, revert behavior, events, accounting and additional business cases |
| Fuzz | For a simple public integer state variable with a direct one-statement setter, generates an executable round-trip fuzz property; otherwise leaves a TODO scaffold | Other properties, valid input bounds, actors, approvals and expected result |
| Invariant | For a recognized direct setter, emits a Foundry handler and an executable invariant comparing the public getter with the handler's last successful write; otherwise leaves a TODO | Broader protocol invariants, valid action sequences and multi-actor accounting |
| Integration | Local deployment and dependency-wiring guidance | Peer contracts, dependency addresses and cross-contract expectations |
| Fork | Fork setup, chain-ID pinning via LOWKEY_EXPECTED_CHAIN_ID, optional block pinning via LOWKEY_FORK_BLOCK, target-code check, and read-only calls to recognized public scalar getters | Correct RPC, target, implementation/deployment match, and explicit expected values for deployment-specific properties |
| PoC | Fork setup and reproduction guidance | Exploit calldata/preconditions and a security-impact assertion |
| Regression | Starter for an already fixed bug | Original preconditions, trigger and expected post-fix assertion |
| Formal | Certora CVL `.spec` rule for a recognized setter/getter property, otherwise a formal-specification worksheet | Verifier setup, complete security properties, assumptions, and proof/counterexample review |

The local-deployment styles (unit, fuzz, invariant, integration and regression) support zero-argument constructors and simple constructor parameters with conservative placeholders for integer, address, boolean, string and bytes types. For example, `constructor(uint256 initial)` is scaffolded as `new ContractName(0)`, with a TODO to review the placeholder. These values are compile-oriented defaults, not evidence of valid protocol setup. Unknown or user-defined parameter types are skipped rather than guessed. For unit and fuzz tests, Lowkey currently emits an executable setter/getter assertion only when source inspection identifies a public integer state variable and a one-statement public/external setter assigning its sole parameter directly to that variable. It deliberately declines to infer through custom modifiers such as `onlyOwner`. For invariants, the same narrow pattern enables a handler that tracks the last successful write and an executable invariant checking the getter against that tracked value. These are narrow starter properties, not a substitute for protocol-specific accounting or authorization invariants. The `formal` option emits a Certora CVL `.spec` rule only for that recognized property; otherwise it emits a Markdown worksheet rather than an invented or vacuous proof. A generated spec has not been verified automatically. Fork and PoC drafts still need a configured target address and a valid `LOWKEY_RPC_URL` before execution.

The import paths assume generated Solidity files are eventually moved to `lowkey-generated/` under the active Foundry test directory (default: `test/`). Generated test files reuse the target source's Solidity pragma when one is present. Review drafts before moving or running them. `--force` allows replacing existing drafts; without it Lowkey preserves existing files. If the baseline project build fails, `--validate` reports `baseline-failed` and does not blame the generated drafts; if Forge is missing, it reports `unavailable` and exits nonzero. Validation compiles only Solidity drafts generated by the current invocation; it ignores unrelated stale drafts in the output folder. If a request includes `formal` alongside Solidity test types, the report is `partial` and the command exits nonzero because Forge does not validate CVL or the formal worksheet. The report includes `source_sha256` so you can identify the exact source text used for generation.

## Evidence boundary

These are starter drafts, not automatic claims of test coverage. An ABI and function names alone do not establish intended business behavior, valid protocol states, or invariants. Lowkey leaves assertions and setup that depend on those assumptions as TODOs. For a call-specific reproduction based on recorded evidence, the existing `lk generate test` flow remains available. Running tests is separate from generating the drafts.


## Evidence-aware generation and validation boundaries

The analysis is deliberately syntax-aware about comments and string literals. It summarizes public/external functions, simple state variables, events, inheritance names, locally resolvable imports, existing Solidity test functions, recognized protocol profiles, security-surface cues, and saved audit-evidence files. These are search signals and test-planning inputs, not findings.

Unit drafts may add an unauthenticated-caller test only when an explicit onlyOwner modifier protects an uncomplicated state-mutating function body. The test remains a candidate and should be reviewed for project semantics. Fork drafts are read-only by default; Lowkey no longer infers a write against a deployed address merely because the local source contains a simple setter. Configure LOWKEY_RPC_URL, and optionally LOWKEY_FORK_BLOCK and LOWKEY_EXPECTED_CHAIN_ID, to make the fork reproducible.

The generator does not claim to automatically reconstruct every protocol's economic rules. Invariant handlers, realistic integration fixtures, exploit preconditions, and formal assumptions require the specific properties and environmental model to be established. See the generated test plan for recognized evidence and prioritized test families.


Validation is a compiler check only. It does not execute assertions, verify a fork against live RPC state, or prove security. Formal specifications require their configured verifier and assumptions to be reviewed separately.


The generated fork template is read-only by default. It does not infer writes from a local setter because a deployed proxy, implementation, permissions, or live state may differ. A missing target address intentionally leaves an explicit setup failure in the draft rather than pretending the test has checked a deployment.
