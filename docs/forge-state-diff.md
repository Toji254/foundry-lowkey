# Forge state-diff evidence backend

Lowkey's Anvil backend observes mined transactions, receipts and (where the node
supports them) RPC tracers. Forge's state-diff backend is different: it records
the ordered call contexts and storage accesses inside a Foundry test execution.
It is useful for pinned-fork PoCs where JSON-RPC `debug_traceTransaction` is not
available, but it is **not** a mined EOA transaction and cannot prove EOA gas
cost or net profitability.

## Recorder

Copy the recorder into the Foundry source tree so Forge's isolated test modes
can resolve the same import (the `docs/` folder is not guaranteed to be copied
into generated workspaces):

```bash
mkdir -p src
cp /path/to/foundry-lowkey/docs/LowkeyForgeStateDiffRecorder.sol src/
```

Import it from `../src/LowkeyForgeStateDiffRecorder.sol` in the test file.
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
entrypoint. Its artifact path should be different. For callback/reentrancy
fixtures, also assert the exact target-call count with vm.expectCall (one in the
sequential control and two in the callback attack), and emit fixture domain events
such as Deposited and Withdrawn where useful. Those semantic assertions complement
the parsed trace; they do not replace it. Keep setup and any zero-value mode switch
outside the measured window. Stop recording immediately after the target path.
The normalizer rejects an empty AccountAccess array rather than treating it as a
successful trace. The recorder emits ordinary JSON directly (it does not rely on
Foundry's keyed JSON serializer), with a top-level `accesses` array and nested
`storage_accesses` arrays.

## Shared normalized trace schema

Both evidence backends emit TraceEvent schema version 1 with index, kind, accessor,
account, depth, value, reverted, selector, input, storage, error and source_backend.
A missing field remains null; it is not inferred as zero or an empty list.

Forge obtains calldata from AccountAccess.data and includes the storage accesses
captured in the same state-diff window. Anvil callTracer supplies call frames and
calldata but no storage read/write set, so its TraceEvent.storage is null. The
backend is explicit on every event. The selector is derived from the first four
calldata bytes only; no external selector database is silently consulted.

The recorder stores the fork chain ID, block number, parent hash and target runtime
code hash **before** the tested call. The normalized artifact must preserve the
32-byte fork_parent_hash; source verification rejects artifacts without it. It
then stores the full ordered
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
  "expected_chain_id": 1,
  "expected_fork_block": 20000000,
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
    "support_files": ["test/helpers/ActorSetup.sol"],
    "state_diff_file": ".audit/godmode/control-state-diff.json",
    "argv": ["forge", "test", "--match-path", "test/VaultControl.t.sol", "--match-test", "test_control", "-vv"]
  },
  "attack": {
    "harness": "test/VaultAttack.t.sol",
    "support_files": ["test/helpers/ActorSetup.sol"],
    "state_diff_file": ".audit/godmode/attack-state-diff.json",
    "argv": ["forge", "test", "--match-path", "test/VaultAttack.t.sol", "--match-test", "test_attack", "-vv"]
  }
}
```

First freeze the experiment, then execute it:

```bash
lk control .audit/control.json --root . --rpc-url http://127.0.0.1:8545 --freeze
lk control .audit/control.json --root . --rpc-url http://127.0.0.1:8545 \
  --source-rpc-url "$ARCHIVE_RPC" --require-frozen
```

The freeze binds the manifest, trace expectations, commands, explicit harnesses,
support files, the active Lowkey gate/policy source hashes, and any project-local
generator files named in the manifest's generator_files array. Any change to those
inputs invalidates the freeze and requires a new freeze before rerunning. Freeze
schema-v1 artifacts must be recreated with lk control --freeze.

The independent source RPC is used alongside the fork RPC to check chain ID,
the fork parent hash, the pinned block header, code, balances and nonces for
declared `source_addresses`, and trace-derived storage slots for those same
accounts. Include the target and actual protocol dependencies (for example, a
proxy implementation or oracle) in `source_addresses`; do not list test actors
or helper contracts as deployed dependencies. A dependency that was not touched
in the state-diff must not be claimed as source-verified. If the archive endpoint
does not support the required state queries, Lowkey will leave authenticity
unverified and will not promote the result to deployment proof.

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


## Non-economic and negative controls

For liveness/DoS, signature-replay, authorization, or other non-economic
families, use a separate semantic assertion command. A non-economic result
requires that command to pass and is capped at `SIMULATED_BREAK`; it is never
labelled profitable. An intentional revert can be used as a negative-control
scenario:

```json
{
  "require_negative_control": true,
  "negative_control": {
    "harness": "test/VaultNoEntitlement.t.sol",
    "state_diff_file": ".audit/godmode/no-entitlement-state-diff.json",
    "expected_receipt_status": "0x0",
    "argv": ["forge", "test", "--match-path", "test/VaultNoEntitlement.t.sol", "-vv"]
  }
}
```

The trace expectation must also declare the negative control's expected call
count range. The expected revert is recorded as a control result, not treated
as a successful exploit or a tooling failure. Use the Anvil backend when a
mined transaction/receipt is needed; Forge state diffs remain test-execution
evidence and do not contain signed EOA gas accounting.
