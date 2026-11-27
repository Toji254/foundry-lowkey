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

Factory-created contracts (`new Child(...)` in a constructor) are not automatically deployed as separate prerequisites. They are created by the selected contract's constructor. Lowkey traverses these relationships to identify recursive creation cycles, but it does not invent an independent deployment transaction for the child. A contract-typed constructor parameter must be supplied explicitly or selected from the available network choices; an ABI type alone does not prove a dependency address.

The generic ABI deployer is a fallback. Projects with complex deployment topology should use their own reviewed Foundry/Hardhat deployment scripts. Lowkey does not infer protocol initialization, role grants or operational readiness merely from an `initialize` function or a successful deployment receipt. It reports initialization and protocol readiness as unverified unless supported by explicit evidence.

## Primary and supporting deployment ownership

The active audit target remains the primary target. Solidity libraries and other supporting deployment attempts are recorded separately in the owning network session. A failed supporting deployment, missing runtime, failed verification or failed registry write cannot promote a supporting address to the primary target. Deployments are scoped by project identity, session UUID, chain ID and address; identical addresses on distinct sessions are distinct records.

## Current scope and acceptance boundaries

The current generic path supports compiler-metadata-based creation linking, verified reuse of session-scoped supporting libraries, primary-target preservation, pre-deployment constructor cancellation, managed Anvil lifecycle and network-aware RPC selection. It does not automatically initialize arbitrary protocols, grant roles, infer every external contract integration, or execute arbitrary project deployment scripts. Those requirements remain explicit plan items until project-native configuration and evidence are available. Unsupported proxy topologies and unresolved external requirements must remain unverified rather than being represented as ready.

For exact accepted CLI syntax, use `lk lab --help`, `lk lab network --help`, and `lk actor --help` in the installed runtime.
