# Evidence-backed test generation

Lowkey must not call a file a test merely because it compiles. A generated test is useful only when it contains a concrete executable assertion, uses an explicit/verified setup, and records what was actually validated.

## Commands

```bash
# Generate tests for source properties Lowkey can safely establish.
lk test-gen Counter --types unit,fuzz,invariant

# A constructor with arguments needs explicit Solidity expressions.
lk test-gen Vault --types unit,fuzz,invariant \
  --constructor-args '["address(0x0000000000000000000000000000000000000001)", "1000"]' \
  --validate

# Ask for the full category set. Unsupported or under-specified categories are
# reported as not generated and the command exits nonzero rather than writing
# a TODO-filled Solidity file.
lk test-gen Vault --types all --strict --validate

# Inspect the machine-readable result.
cat .audit/test-gen/Vault/report.json
```

`--constructor-args` accepts a JSON array of non-empty Solidity expression strings. The item count must match the parsed constructor parameter count. Lowkey does not assume zero addresses, zero amounts, empty strings, or false values are valid protocol configuration.

## What the automatic generator can currently implement

For Solidity projects built with Foundry, Lowkey recognizes a deliberately narrow property when a contract has a public integer state variable and a simple public/external setter that directly assigns its sole integer parameter:

- **Unit:** invokes the setter and asserts that the public getter returns the written value.
- **Fuzz:** fuzzes the setter input and asserts the same relation for each generated input.
- **Invariant:** uses a handler and checks that the public getter agrees with the handler's last successful setter call.

These are executable properties, not comprehensive protocol tests. They do not prove authorization, accounting, upgrade safety, economic correctness, or other behavior that the property does not encode. Lowkey declines to infer through custom modifiers or more complicated function bodies.

Lowkey may also generate read-only fork diagnostics when a deployed target and executable checks can be identified. A diagnostic verifies the limited checks it encodes; it is not a security verdict.

## Categories that require more evidence

Lowkey does not emit fake files for the following categories simply to satisfy a requested type:

| Category | Required evidence before an artifact can be produced |
|---|---|
| Integration | Peer contracts/dependencies, valid deployment and initialization, scenario, expected results and assertions |
| Exploit / PoC | Concrete preconditions, trigger, attacker model and measurable security-impact assertion |
| Regression | Known bug trigger and an assertion that distinguishes the fixed behavior |
| Formal | A configured verifier, an explicit property/specification, and a completed proof/counterexample result |

A recorded transaction can be replayed, but replay alone does not show exploitability. A formal specification file is not a completed proof. A generated artifact without an assertion is not a test. Requests that lack the necessary evidence are listed under `skipped` in `report.json`, and the command exits nonzero.

## Validation and exit status

`--validate` first builds the untouched project, stages only the artifacts created by the current invocation into a temporary Foundry test location, builds again, and executes eligible local unit/fuzz/invariant tests. Temporary files are removed after validation. Baseline failure, missing Forge, compilation failure, execution failure, and partial validation remain distinct results.

- Exit `0`: every requested type was generated without incomplete-template content, and any requested validation succeeded.
- Exit `1`: one or more requested types could not be generated, validation failed/was partial, or strict readiness conditions were not met.
- Exit `2`: invalid command input, project configuration or contract selection.

Without `--validate`, successful generation only means that a complete candidate artifact was written; it does not claim that the file compiles or that the property is true. Use `--strict --validate` for an explicit generation/readiness gate.

## Native generator backends and scope boundary

### Solidity + Foundry

The Solidity backend recognizes a public integer state variable and a simple public/external setter whose sole integer parameter is assigned directly to that variable. It generates executable unit, fuzz, and invariant tests for that relation. It does not infer broader protocol properties from the ABI or function names.

### Vyper + Titanoboa

The Vyper backend recognizes a Vyper `public(uintN/intN)` integer state variable and an `@external` function whose single integer argument is assigned directly to `self.<state>`. It emits native Python tests using Titanoboa, pytest, and Hypothesis:

- **Unit:** calls the setter with a concrete value and checks the public getter.
- **Fuzz:** fuzzes values across the integer type's range and checks the getter after each call.
- **Invariant / sequence property:** generates sequences of setter inputs and checks the getter after each state transition.

Run it with:

```bash
python -m pip install "vyper>=0.4,<0.5" titanoboa pytest hypothesis
lk test-gen Counter --language vyper --types unit,fuzz,invariant --validate --strict
```

Vyper artifacts and reports are isolated under `.audit/test-gen/vyper/<ContractName>/` so they cannot overwrite Solidity output when both backends contain a same-named contract. In a mixed-language repository, use `--language solidity` or `--language vyper` to select a backend; when the requested name matches both, Lowkey runs both and returns a result for each.

When the Vyper constructor needs parameters, provide a JSON array of Python literals through `--constructor-args`, such as `'["100", "\"TOKEN\""]'`. Calls, names, attribute access, and other executable expressions are rejected; only literal values are accepted. If the constructor arguments do not match the constructor, Lowkey does not write a test file.

### Unsupported languages and categories

Rust, Move, Cairo, and other language/build-system generators are not implemented yet. Language detection or native command execution alone is not test-generation support. Lowkey must return an unsupported/failed result rather than emit a generic TODO file. Integration, exploit, regression, and formal categories are also refused unless the request contains the real scenario/property and setup needed to generate a meaningful, runnable artifact.

## Evidence boundary

A generated assertion establishes evidence only for the encoded property, the tested inputs/states and the assumptions of the run. It is not protocol-wide security certification. Lowkey retains source provenance, source hash, requested types, generated/skipped categories and validation details in `report.json`; raw execution evidence remains available for review.
