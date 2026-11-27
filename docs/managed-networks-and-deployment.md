# Managed networks and generic deployment

Lowkey's managed EVM labs are project-scoped. Network sessions are persisted in the existing `.audit/anvil.json` state file so legacy project fixture state and managed sessions share one lifecycle store rather than competing registries.

## Managed Anvil sessions

Create and select separate local chains:

```bash
lk lab network create --name local-dev
lk lab network create --name attack-lab
lk lab network list
lk lab network status local-dev
lk lab network use attack-lab
lk lab network stop attack-lab
```

Creation starts Anvil on a loopback address with a separate account seed and a generated session UUID. Lowkey records project identity, RPC endpoint, chain ID, genesis hash, process PID, process start ticks, UID, executable, command line/port identity, lifecycle state, actors and deployment evidence. The active session is selected explicitly when more than one healthy managed session exists.

Lowkey does not adopt or terminate arbitrary processes merely because they are listening on an Anvil port. A recorded process is eligible for shutdown only when the live Linux process identity still matches the persisted process record. A stale or unowned record is reported and is not signalled.

### Live two-session acceptance

The CI workflow `.github/workflows/live-multi-anvil-acceptance.yml` runs
`scripts/multi-anvil-network-acceptance-e2e.py` against two real Anvil
processes. It creates two sessions through the installed `lk lab network`
CLI, records their independent process and chain identities, registers
`Alice` separately in both sessions, switches active context, restarts the
manager, removes active selection to assert ambiguity fails closed, and checks
that an explicit RPC override detaches the other session's actor context.

The same run sends value transactions to both networks, checks recipient
balance deltas and cross-network transaction-hash absence, deploys runtime
bytecode only on the first network, and verifies both the EVM code and
supporting-deployment record remain session-local. The script writes
`.audit/network-multi-anvil-acceptance/latest.json` and uploads that evidence
as a CI artifact. The gate has passed on real GitHub-hosted Anvil runners; it
does not replace a repository-wide audit of every RPC-consuming CLI command,
nor does it prove real GMX library reuse or proxy deployment readiness.


An RPC endpoint is not a network identity by itself. An explicit `--rpc-url` that differs from the selected project/session endpoint is treated as unscoped: session-owned actor, target and deployment identity is detached for that invocation. The explicit endpoint still controls the RPC operation, but Lowkey does not borrow the other network's actor or target context.

## Session-scoped actors

Account zero is reserved as `lab-deployer`. Give other unlocked accounts readable aliases in the selected network:

```bash
lk actor 1 Alice
lk actor 2 Bob
lk actor 3 attacker
lk actor Alice
lk actors
```

Aliases are stored in the selected session's actor map, not as global key-bearing wallet records. The same alias can refer to different accounts in two separate sessions without leaking across them. Lowkey does not persist private keys for these unlocked Anvil accounts.

## Compiler-aware library linking

When the selected deployable artifact contains compiler `linkReferences`, `lk lab` resolves source-qualified library identities from the artifact catalogue. The linker uses compiler-provided byte offsets and widths; it does not infer offsets from placeholder strings or contract names. Duplicate/ambiguous identities, invalid offsets/lengths, missing artifacts and unresolved placeholders block deployment.

Libraries are processed dependency-first. Reuse is allowed only for a deployment recorded under the same project and managed-session UUID whose source-qualified artifact hash and dependency-address map match and whose live runtime is verified against the compiler artifact. A newly deployed library must have code, a matching runtime, and a persisted supporting-deployment record before Lowkey links it into the primary creation bytecode. Original compiler artifacts are not edited; linked creation bytecode is derived in memory and link evidence is retained with the deployment record.

Runtime verification distinguishes code presence from artifact matching and fingerprint availability. Solidity-library self-address normalization requires compiler evidence that the artifact is a library, the compiler-generated self-address guard pattern, and proof that the embedded address equals the actual deployed address. Compiler immutable and runtime library-link references are handled only through their corresponding metadata. Differences outside these permitted locations remain mismatches or unverified results.

## Deployment planning and approval

Before a workflow that requires supporting dependencies, Lowkey prints a deployment plan and resolves the primary constructor inputs before the first supporting transaction. Cancelling a constructor prompt or declining the plan stops the workflow before deployment. Non-interactive dependency execution is disabled unless the environment explicitly sets:

```bash
LOWKEY_NONINTERACTIVE_DEPLOY=1
```

Set this only in reviewed automation. It authorizes the displayed plan; it does not bypass artifact, runtime or network identity checks.

Compiler-backed `new Child(...)` relationships retain their execution phase. A `creation_phase=deployment` edge means the child is created inside the selected contract's constructor and is deployed as part of that parent transaction; it is not a separately scheduled prerequisite. A `creation_phase=runtime` edge records a factory/runtime creation effect after deployment and is likewise not a pre-deployment prerequisite. Lowkey traverses both relationships to identify recursive creation cycles without inventing independent deployment transactions. A contract-typed constructor parameter must be supplied explicitly or selected from the available network choices; an ABI type alone does not prove a dependency address.

The generic ABI deployer is a fallback. When the project contains a discoverable Foundry deployment script (for example `script/Deploy.s.sol`), `lk lab` can use the project-native `forge script` route instead of treating the script as an arbitrary shell command. This Foundry path is subject to the explicit review gate below. Hardhat-native deployment script execution is not yet supported by the reviewed adapter. Lowkey does not infer protocol initialization, role grants or operational readiness merely from an `initialize` function or a successful deployment receipt. It reports initialization and protocol readiness as unverified unless supported by explicit evidence.


### Reviewed project-native Foundry deployment

When Lowkey discovers a project-native Foundry script, it prepares a review snapshot before the `forge script --broadcast` invocation. The snapshot binds:

- the script's project-relative path and SHA-256;
- the Forge version;
- the loopback RPC endpoint and managed-session identity (or an explicitly labelled unmanaged local Anvil endpoint);
- required `vm.env(...)` names and Lowkey-supplied safe defaults, without printing secret values;
- hashes of `foundry.toml`, `.env` and configured `env_file` inputs;
- a warning that arbitrary script code may deploy, call contracts, transfer value, mutate storage and write Foundry broadcast files.

Lowkey displays the snapshot and requires the user to type `DEPLOY` before continuing. In non-interactive automation, the exact opt-in is:

```bash
LOWKEY_NONINTERACTIVE_DEPLOY=1 lk lab
```

This opt-in is an approval signal only. It does not bypass unresolved environment checks, loopback-only RPC enforcement or the revalidation step. Immediately before broadcast, Lowkey checks that the selected project, script hash, configuration hashes, RPC origin and network-session identity still match the approved snapshot. A stale review or missing evidence blocks execution before the script broadcast. Lowkey does not silently edit `foundry.toml`, enable FFI or switch to a remote network.

The review is not a static proof of script safety and cannot enumerate every possible side effect. It establishes what was selected and what was approved so the auditor can make an informed local execution decision. The implementation is a Foundry adapter only: project-native Hardhat deployment scripts and protocol-specific post-deployment configuration remain pending. Dedicated end-to-end acceptance of a real project script broadcast, its complete transaction set and registry capture is also still pending.

## Primary and supporting deployment ownership

The active audit target remains the primary target. Solidity libraries and other supporting deployment attempts are recorded separately in the owning network session. A failed supporting deployment, missing runtime, failed verification or failed registry write cannot promote a supporting address to the primary target. Deployments are scoped by project identity, session UUID, chain ID and address; identical addresses on distinct sessions are distinct records.

## Current scope and acceptance boundaries

The current deployment path supports compiler-metadata-based creation linking, verified reuse of session-scoped supporting libraries, primary-target preservation, pre-deployment constructor cancellation, managed Anvil lifecycle and network-aware RPC selection. It also supports a bounded project-native Foundry script route with the review gate below. It does not support arbitrary shell deployment scripts, a reviewed Hardhat `run` adapter, automatic protocol initialization, role grants or general operational-readiness orchestration. Unsupported proxy topologies and unresolved external requirements remain unverified rather than represented as ready.

For exact accepted CLI syntax, use `lk lab --help`, `lk lab network --help`, and `lk actor --help` in the installed runtime.

### Compiler-backed constructor input inventory

Lowkey inventories constructor inputs from source-matched Solidity compiler build-info and the emitted ABI. It preserves the parameter name, ABI type, compiler `internalType`, nested tuple/struct component paths, array dimensions and compiler provenance. Every constructor value is marked as requiring resolution; constructor arguments are never auto-deployed. A plain `address` remains `ADDRESS_SEMANTICS_UNCLASSIFIED`: Lowkey does not guess whether it is an EOA, token, router, Safe or another contract. A contract-typed parameter identifies a source-level type, not a deployed instance address; its concrete instance remains unresolved until explicit configuration or deployment evidence supplies it. Missing ABI evidence is reported as unavailable rather than treated as an empty constructor.

### Auditor-facing compiler dependency summary

The default project map includes a compiler-backed deployment-relationship section when matching build-info is available. It distinguishes Solidity library link references, contract creation expressions, source-level contract-typed constructor references and ABI constructor values. Constructor values are shown as unresolved until supplied; ordinary `address` values remain unclassified. A creation expression is reported as a factory/constructor relationship, not scheduled as an independent predeployment. Missing compiler evidence and incomplete library ordering remain visible rather than being rendered as an empty or successful dependency result.

### Chain and genesis identity

Explicit RPC overrides are resolved against the selected session's persisted identity, including on a fresh CLI invocation without an in-memory session cache. A mismatch detaches implicit project target and actor context; an explicit target address remains usable. If the project has no managed-session identity to compare, a deliberately supplied manual target may be used with the explicit endpoint. A managed network session records its chain ID and its own observed genesis/identity block. Two independent sessions may legitimately share the same chain ID and genesis hash when started with equivalent chain configuration; equality of genesis hashes is not, by itself, evidence that two sessions are the same network process or share state. Live isolation acceptance therefore checks each session's recorded genesis hash against that session's own RPC, while separately requiring distinct session UUIDs, process identities, ports and account sets, and verifying transactions and deployment registries remain isolated. A mismatched per-session RPC/registry genesis identity is a failure; a matching genesis hash across two otherwise independent sessions is permitted.


## Explicit external dependency declarations

Compiler evidence can identify a constructor input without proving whether an address is a Vault, Router, token, WETH, oracle or another contract. A project may declare that meaning in `.audit/dependencies.json`:

```json
{
  "schema": "lowkey.external-dependencies.v1",
  "network_identity": {
    "project_id": "PROJECT_ID_FROM_LK",
    "network_session_id": "SESSION_UUID_FROM_LK",
    "chain_id": 31337,
    "genesis_hash": "0xREPLACE_WITH_32_BYTE_SESSION_GENESIS_HASH",
    "identity_block_hash": "0xREPLACE_WITH_32_BYTE_SESSION_IDENTITY_BLOCK_HASH"
  },
  "dependencies": [
    {
      "id": "positionmanager-vault",
      "consumer": "contracts/core/PositionManager.sol:PositionManager",
      "parameter": "_vault",
      "kind": "vault",
      "address": "0xREPLACE_WITH_LOCAL_VAULT_ADDRESS",
      "description": "Local Vault fixture"
    }
  ]
}
```

Supported kinds include `weth`, `erc20-token`, `chainlink-feed`, `router`, `vault`, `factory`, `oracle`, `bridge`, `proxy-admin`, `beacon`, `diamond-facet`, `multisig`, `timelock`, `governance` and `other-contract`. The `consumer` must be a source-qualified compiler contract and `parameter` must match a compiler-reported constructor input. Duplicate or malformed bindings block the manifest. An address requires a complete managed-session identity including the session's identity-block hash; a declaration from another or incompletely identified session is detached from the active graph.

Run `lk deps --json` to inspect the declaration. Manifest evidence is marked `DECLARED` / `DECLARED_UNVERIFIED`, is never an automatic deployment instruction, and does not prove code presence, runtime identity, token standard, authority, or protocol readiness. The graph remains `REVIEW_REQUIRED` until separate runtime and semantic checks establish the actual dependency.
