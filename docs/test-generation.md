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

The local-deployment styles are currently generated only when Lowkey can see a zero-argument constructor. If construction requires arguments, those types are skipped with a reason rather than emitting a likely-invalid deployment expression. Fork and PoC drafts still need a configured target address and a valid `LOWKEY_RPC_URL` before execution.

The import paths assume the generated Solidity files are eventually moved to `test/lowkey-generated/`. Review them before moving or running them. `--force` allows replacing existing drafts; without it Lowkey preserves existing files.

## Evidence boundary

These are starter drafts, not automatic claims of test coverage. An ABI and function names alone do not establish intended business behavior, valid protocol states, or invariants. Lowkey leaves assertions and setup that depend on those assumptions as TODOs. For a call-specific reproduction based on recorded evidence, the existing `lk generate test` flow remains available. Running tests is separate from generating the drafts.
