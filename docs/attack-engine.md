# Attack-family strategy engine and attack-chain composition

This module turns the attack catalogue into a strict execution and evidence contract. It does **not** turn catalogue text or a static source match into an exploit. Each family needs a target-specific Foundry adapter that asserts its real preconditions and impact.

## Commands

```bash
# See all strategy contracts and their current adapter status
lk attack engines --json

# Find source-level candidates. Output is always a lead, never a finding verdict.
lk attack discover --root . --json
lk attack discover --root . --family oracle

# Execute a paired attack/control adapter, independently validate the fork reproof,
# and run the explicit mutation campaign.
lk attack verify .audit/lowkey/experiments/vault-withdraw.json --root .

# Validate a multi-stage chain without running anything
lk attack chain validate .audit/lowkey/chains/flash-price-borrow.json --root .

# Execute the chain's attack, control and failure-injection Foundry adapters
lk attack chain run .audit/lowkey/chains/flash-price-borrow.json --root .
```

`lk attack`, `lk attack search`, `learn`, `lab`, and the existing library commands remain the read-only learning/reference surface. The executable strategy engine is routed only for `engines`, `discover`, `verify`, and `chain`.

## Family contract

The registry currently names 15 EVM families: reentrancy, replay, access control, accounting, boundary, time, upgrade, callback, oracle, economic, ERC-20, proxy, storage, signature, and DoS/liveness.

For each family, the strategy contract declares:
- the attack shape it is meant to test;
- family-specific source signals and target preconditions;
- the required security-property identifier;
- minimum trace-event count and call depth;
- whether exact Forge per-access storage evidence is required; and
- whether the default impact policy expects economic proof.

Only the existing reentrancy fixture is marked `fixture_accepted`. The other 14 are `adapter_required`: the strategy contract exists, but there is no automatic claim that a general exploit implementation exists. They are not eligible for a verified family verdict until a target-specific adapter and acceptance suite pass.

### Target-specific discovery

An experiment pins:
- a project-relative Solidity/Vyper source file;
- its exact SHA-256 digest;
- the source line of the selected entrypoint; and
- the explicit function signature.

The file digest must still match at validation time, the entrypoint must exist at the selected line, and at least one family-specific source signal must be present. Source matches remain candidates; they are not proof of exploitability.

### Paired experiment manifest

A minimal manifest has this shape:

```json
{
  "schema_version": 1,
  "id": "vault-withdraw-001",
  "family": "reentrancy",
  "impact_mode": "semantic",
  "target": {
    "address": "0x1111111111111111111111111111111111111111",
    "code_sha256": "0x2222222222222222222222222222222222222222222222222222222222222222",
    "chain_id": 1,
    "block_number": 21000000
  },
  "discovery": {
    "source_file": "src/Vault.sol",
    "source_sha256": "<64 lowercase hex characters>",
    "source_line": 48,
    "entrypoint": "withdraw(uint256)"
  },
  "property_id": "reentrancy-invariant-violation",
  "attack": {
    "test_file": "test/AttackAdapter.t.sol",
    "test_name": "testAttack",
    "evidence_file": ".audit/lowkey/attack.json"
  },
  "control": {
    "test_file": "test/AttackAdapter.t.sol",
    "test_name": "testControl",
    "evidence_file": ".audit/lowkey/control.json"
  },
  "reproof": {
    "reproof_file": ".audit/godmode/reprove.json"
  },
  "mutation": {
    "mutants": [
      {
        "id": "restore-effects-before-interaction",
        "file": "src/Vault.sol",
        "before": "<one exact vulnerable source fragment>",
        "after": "<one exact safe replacement>"
      }
    ]
  },
  "timeout_seconds": 300
}
```

`code_sha256` is SHA-256 of the deployed runtime bytecode, not the EVM Keccak code hash. `block_number` pins the fork parent block. The source file digest is separate from deployment bytecode identity.

The test runner sets:
- `LOWKEY_EXPERIMENT_ID` (stable manifest identifier)
- `LOWKEY_EXPERIMENT_RUN_ID` (unique execution identifier)
- `LOWKEY_EXPERIMENT_ROLE` (`attack` or `control`)
- `LOWKEY_EVIDENCE_PATH`

The target-specific Foundry tests must write their evidence JSON to that exact path. Each JSON document must include the matching experiment/family/role, pinned target, discovery digest, every required precondition as a boolean, the canonical TraceEvent v2 rows, the declared property result, and a pair anchor containing the same entry selector, calldata digest, prestate digest, and setup digest on both sides.

For every paired run:
- attack predicate must be `true`;
- control predicate must be `false`;
- target, source digest, entry call, setup and prestate must match;
- exact-storage families require a non-empty `forge-state-diff` event with `storage_support: "exact"`;
- the mutation baseline must pass, and every declared mutant must be killed; survived, invalid, timeout, or infrastructure-error mutants block acceptance.

The engine invokes the attack and control tests independently with the same run ID and role-specific evidence path. It does not manufacture trace evidence or fill unknown fields.

### Independent reproof and impact mode

A paired Forge experiment is not enough to prove a real deployment exploit. The manifest must reference a completed `lk reprove` artifact. The engine checks the reproof's source-RPC verification, target address, runtime-code SHA-256, chain ID, fork block, successful mined receipt, call trace, and (for exact-storage families) trace-derived storage slots.

Use `impact_mode: "economic"` when the attack is required to realize positive value. The reproof must be independently classified `PROFITABLE`, and its measured native-ETH gas/setup costs must reconcile. The current generic reproof accounting does not value arbitrary ERC-20s, ERC-4626 shares, rebasing assets, or cross-token portfolios; those need a separately reviewed valuation adapter.

Use `impact_mode: "semantic"` for a concrete security-property violation where profit is not the correct acceptance criterion. Run `lk reprove` with `--non-economic` and a separately executed `--semantic-check-argv-json` / `--semantic-test`; a source match or passing test command without the semantic assertion is insufficient.

A `SIMULATED_BREAK` or local observation does not become `FORK_REPRODUCED`, `PROFITABLE`, or `HUMAN_CONFIRMED` automatically. The target authenticity and fidelity axes remain independent.

## Chain composition

A chain is not just a list of unrelated calls. Each stage carries:
- a family and its own target source/entrypoint discovery;
- the complete family precondition list;
- explicit stage dependencies;
- named artifacts it consumes and produces;
- a failure policy (`abort`, `revert`, or `restore`); and
- an explicit rollback strategy.

The manifest is limited to 32 stages and must already be in topological order. A stage cannot consume an artifact before its producer succeeds, and it must explicitly depend on the producer. Single-transaction chains must use EVM transaction revert; stateful-fork chains must use Anvil snapshot revert or a verified compensating action.

The three target-specific Foundry adapters provide:
1. attack-chain evidence;
2. matched control-chain evidence; and
3. a failure-injection test proving the declared rollback behavior.

Each stage result must record the source digest, every satisfied precondition, its family-specific predicate, consumed/produced artifacts, pre/post-state hashes, transaction hash/block, and canonical trace events. State hashes must form a continuous chain. For a single-transaction chain, every stage must refer to the same transaction and block.

The failure-injection evidence names the failed stage and repeats that stage's exact failure policy and rollback strategy. EVM/snapshot rollback must restore the exact prestate hash; compensating actions must prove zero residual delta.

### Example stage sequence

```json
{
  "id": "flash-liquidity",
  "family": "economic",
  "discovery": {
    "source_file": "src/FlashAdapter.sol",
    "source_sha256": "<source digest>",
    "source_line": 22,
    "entrypoint": "execute()"
  },
  "preconditions": [
    "complete action sequence",
    "same-unit balance measurement",
    "all costs and repayment obligations measured"
  ],
  "depends_on": [],
  "consumes": [],
  "produces": ["borrowed-liquidity"],
  "on_failure": "abort",
  "rollback": "evm_transaction_revert"
}
```

A later price-manipulation stage might consume `borrowed-liquidity` and produce `manipulated-price-window`; a collateral-borrow stage consumes that artifact and produces `borrowed-collateral`; the final repayment/unwind stage consumes both outstanding liabilities and borrowed collateral. Those are protocol-specific adapter steps, not built-in universal calldata recipes.

## Status meanings

- `VALIDATED_NOT_EXECUTED`: manifest structure and dependency rules passed; no command or transaction ran.
- `PAIRED_OBSERVATION`: local attack/control evidence matched and the declared property differed as expected.
- `VERIFIED_LOCAL_EXPERIMENT`: paired Forge run plus mutation gate passed; the report remains local scope.
- `VERIFIED_LOCAL_ATTACK_CHAIN`: attack/control chain, stage continuity, failure rollback, and mutation gate passed; still local scope.
- `REFUSED`: a precondition, evidence, identity, dependency, storage, backend, or policy requirement was not met.

The status never upgrades a finding to human-confirmed. No command in this module broadcasts a production transaction. Actual transaction execution is limited to an explicitly configured local Anvil fork through the separate reproof workflow.

## What is not claimed yet

- The 14 non-reentrancy strategy adapters are not universally implemented or accepted.
- The chain schema/orchestrator does not automatically synthesize a target-specific flash-loan callback, oracle attack, lending borrow, or repayment contract.
- Generic token valuation and cross-token profit accounting are not complete.
- A successful read-only fork or local fixture run is not proof of a profitable deployed exploit.
