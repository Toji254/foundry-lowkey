# Multi-type test scaffolding

Lowkey exposes `lk test-gen` for generating starter files for several Solidity test styles.

## Usage

```bash
lk test-gen Counter
lk test-gen Counter --types unit,fuzz,invariant
lk test-gen Counter --types fork,poc --output-dir .audit/drafts
lk test-gen Counter --types all --force
```

If no contract name is supplied, Lowkey uses the active configured contract name. Run this command from the root of a Foundry project.

## What it creates

By default, files are written to `.audit/test-gen/<ContractName>/`. This is intentional: drafts do not enter Foundry's regular test discovery and therefore cannot silently change the project's normal test result. A JSON report lists generated and skipped types.

| Type | Starter contents | What still needs human/project input |
|---|---|---|
| Unit | Local deployment smoke test | Expected state changes, authorization, revert behavior, events and accounting |
| Fuzz | Local deployment and fuzz-test shape | Property, valid input bounds, actors, approvals and expected result |
| Invariant | Local deployment and handler/property guidance | Valid action handler and protocol-level invariant |
| Integration | Local deployment and dependency-wiring guidance | Peer contracts, dependency addresses and cross-contract expectations |
| Fork | Fork setup and target-code smoke test | Correct archive RPC, chain/target and behavioral assertion |
| PoC | Fork setup and reproduction guidance | Exploit calldata/preconditions and a security-impact assertion |
| Regression | Starter for an already fixed bug | Original preconditions, trigger and expected post-fix assertion |

The local-deployment styles (unit, fuzz, invariant, integration and regression) support zero-argument constructors and simple constructor parameters with conservative placeholders for integer, address, boolean, string and bytes types. For example, `constructor(uint256 initial)` is scaffolded as `new ContractName(0)`, with a TODO to review the placeholder. These values are compile-oriented defaults, not evidence of valid protocol setup. Unknown or user-defined parameter types are skipped rather than guessed. Fork and PoC drafts still need a configured target address and a valid `LOWKEY_RPC_URL` before execution.

The import paths assume the generated Solidity files are eventually moved to `test/lowkey-generated/`. Review them before moving or running them. `--force` allows replacing existing drafts; without it Lowkey preserves existing files.

## Evidence boundary

These are starter drafts, not automatic claims of test coverage. An ABI and function names alone do not establish intended business behavior, valid protocol states, or invariants. Lowkey leaves assertions and setup that depend on those assumptions as TODOs. For a call-specific reproduction based on recorded evidence, the existing `lk generate test` flow remains available. Running tests is separate from generating the drafts.
