# Multi-type test scaffolding

Lowkey exposes `lk test-gen` for generating starter files for several Solidity test styles.

## Usage

```bash
lk test-gen Counter
lk test-gen Counter --types unit,fuzz,invariant
lk test-gen Counter --types fork,poc --output-dir .audit/drafts
lk test-gen Counter --types all --force
lk test-gen Counter --types formal
```

If no contract name is supplied, Lowkey uses the active configured contract name. Run this command from the root of a Foundry project.

## What it creates

By default, files are written to `.audit/test-gen/<ContractName>/`. This is intentional: drafts do not enter Foundry's regular test discovery and therefore cannot silently change the project's normal test result. A JSON report lists generated and skipped types.

| Type | Starter contents | What still needs human/project input |
|---|---|---|
| Unit | Deployment smoke test plus a deterministic setter/getter assertion when a safe direct setter is recognized | Authorization, revert behavior, events, accounting and additional business cases |
| Fuzz | For a simple public integer state variable with a direct one-statement setter, generates an executable round-trip fuzz property; otherwise leaves a TODO scaffold | Other properties, valid input bounds, actors, approvals and expected result |
| Invariant | For a recognized direct setter, emits a Foundry handler and an executable invariant comparing the public getter with the handler's last successful write; otherwise leaves a TODO | Broader protocol invariants, valid action sequences and multi-actor accounting |
| Integration | Local deployment and dependency-wiring guidance | Peer contracts, dependency addresses and cross-contract expectations |
| Fork | Fork setup and target-code smoke test | Correct archive RPC, chain/target and behavioral assertion |
| PoC | Fork setup and reproduction guidance | Exploit calldata/preconditions and a security-impact assertion |
| Regression | Starter for an already fixed bug | Original preconditions, trigger and expected post-fix assertion |
| Formal | Certora CVL `.spec` rule for a recognized setter/getter property, otherwise a formal-specification worksheet | Verifier setup, complete security properties, assumptions, and proof/counterexample review |

The local-deployment styles (unit, fuzz, invariant, integration and regression) support zero-argument constructors and simple constructor parameters with conservative placeholders for integer, address, boolean, string and bytes types. For example, `constructor(uint256 initial)` is scaffolded as `new ContractName(0)`, with a TODO to review the placeholder. These values are compile-oriented defaults, not evidence of valid protocol setup. Unknown or user-defined parameter types are skipped rather than guessed. For unit and fuzz tests, Lowkey currently emits an executable setter/getter assertion only when source inspection identifies a public integer state variable and a one-statement public/external setter assigning its sole parameter directly to that variable. It deliberately declines to infer through custom modifiers such as `onlyOwner`. For invariants, the same narrow pattern enables a handler that tracks the last successful write and an executable invariant checking the getter against that tracked value. These are narrow starter properties, not a substitute for protocol-specific accounting or authorization invariants. The `formal` option emits a Certora CVL `.spec` rule only for that recognized property; otherwise it emits a Markdown worksheet rather than an invented or vacuous proof. A generated spec has not been verified automatically. Fork and PoC drafts still need a configured target address and a valid `LOWKEY_RPC_URL` before execution.

The import paths assume the generated Solidity files are eventually moved to `test/lowkey-generated/`. Review them before moving or running them. `--force` allows replacing existing drafts; without it Lowkey preserves existing files.

## Evidence boundary

These are starter drafts, not automatic claims of test coverage. An ABI and function names alone do not establish intended business behavior, valid protocol states, or invariants. Lowkey leaves assertions and setup that depend on those assumptions as TODOs. For a call-specific reproduction based on recorded evidence, the existing `lk generate test` flow remains available. Running tests is separate from generating the drafts.
