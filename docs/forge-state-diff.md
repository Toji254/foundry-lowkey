# Forge state-diff evidence backend

Lowkey's Anvil backend observes mined transactions, receipts and (where the node
supports them) RPC tracers. Forge's state-diff backend is different: it records
the ordered call contexts and storage accesses inside a Foundry test execution.
It is useful for pinned-fork PoCs where JSON-RPC `debug_traceTransaction` is not
available, but it is **not** a mined EOA transaction and cannot prove EOA gas
cost or net profitability.

## Recorder

Copy or import `docs/LowkeyForgeStateDiffRecorder.sol` into the test project.
Inherit `LowkeyForgeStateDiffRecorder`, configure and pin the fork, deploy or
prepare test-only actors, and start recording immediately before the exact target
call. Stop and write immediately after it:

```solidity
contract VaultForkPoC is LowkeyForgeStateDiffRecorder {
    function test_attack() external {
        // Select a pinned fork and prepare the real target/attacker first.
        // Do not use vm.deal, vm.store, vm.etch, mocks or time overrides.
        _lowkeyStartTrace(address(vault));
        attacker.execute();
        _lowkeyWriteTrace(".audit/godmode/attack-state-diff.json");
    }
}
```

The sequential control test should use the same recorder calls and same target
entrypoint. Its artifact path should be different.

The recorder stores the fork chain ID, block number, parent hash and target runtime
code hash **before** the tested call. It then stores the full ordered
`AccountAccess[]` sequence, with each account access's nested `StorageAccess[]`.
Storage slots are therefore derived from the executed test rather than being
limited to a hand-written slot list.

Foundry filesystem permissions must allow writes to the output directory. Add
the following to the project's `foundry.toml` (preserving any existing entries):

```toml
fs_permissions = [
  { access = "read-write", path = "./.audit/godmode" }
]
```

## Manifest shape

Select `trace_backend = "forge-state-diff"`. Each scenario provides its own
Foundry command, recorder harness path and recorder artifact path:

```json
{
  "trace_backend": "forge-state-diff",
  "target_authenticity": "forked_deployment",
  "family": "reentrancy",
  "target_address": "0x...",
  "source_addresses": ["0x..."],
  "same_calls_id": "vault-withdraw-v1",
  "metric_addresses": ["0x..."],
  "trace_expectations": [
    {
      "address": "0x...",
      "control_min_calls": 1,
      "control_max_calls": 1,
      "attack_min_calls": 2,
      "attack_max_calls": 2
    }
  ],
  "control": {
    "harness": "test/VaultControl.t.sol",
    "state_diff_file": ".audit/godmode/control-state-diff.json",
    "argv": ["forge", "test", "--match-path", "test/VaultControl.t.sol", "--match-test", "test_control", "-vv"]
  },
  "attack": {
    "harness": "test/VaultAttack.t.sol",
    "state_diff_file": ".audit/godmode/attack-state-diff.json",
    "argv": ["forge", "test", "--match-path", "test/VaultAttack.t.sol", "--match-test", "test_attack", "-vv"]
  }
}
```

Run `lk control <manifest> --rpc-url <fork-rpc> --source-rpc-url <independent-archive-rpc>`.
The independent source RPC is used to check the fork anchor, target code hash,
source-address code hashes (via `eth_getProof`) and every trace-derived slot's
prestate. If the archive endpoint does not support `eth_getProof`, Lowkey will
not mark the target authenticity as independently verified.

## Interpretation limits

- Forge state-diff is an ordered execution record, not geth callTracer; the two
  backends are normalized into a common call/storage evidence shape but retain
  their original source and limitations.
- The Forge test caller is simulated. A verified fork with test-simulated callers
  is `FORK_OBSERVED`, never `PROFITABLE`.
- Forge state-diff does not provide a signed EOA transaction envelope, mined
  receipt, effective gas price or complete gas accounting.
- `newBalance` is documented by Foundry as a potential balance change even when
  reverts occurred. Lowkey keeps the raw record and excludes reverted accesses
  from the simple aggregate delta.
- A slot that was only read appears in Forge's access records. A storage read-set
  is not equivalent to a complete snapshot of all protocol state.
- A proxy target's runtime code hash identifies the proxy bytecode, not its
  implementation. Include implementation addresses in `source_addresses` and
  rely on trace-derived EIP-1967 slot checks when the test path reads those slots.
