# Foundry LowkeyCast

> **An auditor-oriented CLI for contract research, storage inspection, transaction forensics, and repeatable audit workflows — built around Foundry instead of replacing it.**

**portfolio:** lowkeycast is an eng/tooling project built alongside my sc audit learning. it reduces repetitive audit workflow while keeping native foundry behavior visible.

**tags:** `sc sec | evm | foundry | cli | audit tooling | security`

LowkeyCast (lk) is a small auditor-oriented command line tool that sits on top of Foundry. It keeps the repetitive parts of contract research, Anvil interaction, storage inspection, transaction forensics, and test reproduction behind one workflow.

The core idea is simple:

RECON → ATTACK → PROVE

Lowkey does not replace Forge or Cast. It orchestrates them and adds the local audit workflow around them.

## Godmode / evidence-first attack engine

The integrated Godmode layer exposes the full 44-capability roadmap through one inventory:

```bash
lk capabilities
lk godmode
lk godmode 0xTarget --rpc-url http://127.0.0.1:8545
lk fallback-map
lk cheat fingerprint
lk oracle-map
lk reentrancy-graph
lk custody
lk sig-matrix
lk init-frontrun
lk proxy-resolve 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk storage-infer 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk selectors-full 0xTarget --rpc-url "$FOUNDRY_ETH_RPC_URL"
lk target-coverage src/Vault.sol --start-line 40 --end-line 95
lk provenance .audit/godmode/latest.json
lk economic --gross-wei 1000000000000000000 --gas-used 180000 --max-fee-wei 20000000000
lk time
lk token-weird
lk invariant-forge vault
lk archetype lending
lk report
```

The capability inventory uses three honest states: `implemented` means the command has a working local workflow; `partial` means it produces a useful lead, starter, bounded measurement, or needs protocol-specific input; `adapter-required` means an external runtime/provider integration is not available and Lowkey will stop rather than fake a result. A registered capability is not automatically an automated exploit.

### Sequential control is mandatory for BREAK

The lk break engine can find candidate behavioral breaks, but a candidate is downgraded to OBSERVED unless a matching trace-backed sequential-control manifest passes. lk control accepts **only a local Anvil RPC** and requires each scenario to execute one real, mined transaction.

Example manifest:

~~~json
{
  "target_address": "0x0000000000000000000000000000000000000001",
  "function": "withdraw()",
  "family": "reentrancy",
  "same_calls_id": "withdraw-same-entrypoint-v1",
  "prestate_addresses": [
    "0x0000000000000000000000000000000000000001",
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003"
  ],
  "prestate_slots": [
    {
      "address": "0x0000000000000000000000000000000000000001",
      "slot": "0x0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "metric_name": "attacker_portfolio_net_eth_delta_wei",
  "metric_addresses": [
    "0x0000000000000000000000000000000000000002",
    "0x0000000000000000000000000000000000000003"
  ],
  "trace_expectations": [
    {
      "address": "0x0000000000000000000000000000000000000001",
      "control_min_calls": 1,
      "control_max_calls": 1,
      "attack_min_calls": 2,
      "attack_max_calls": 2,
      "description": "The attack adds one nested withdrawal call."
    }
  ],
  "scenario_parameters": [
    {
      "name": "attacker_callback_flag",
      "address": "0x0000000000000000000000000000000000000003",
      "slot": "0x0",
      "control_value": "0x0",
      "attack_value": "0x1",
      "description": "The only permitted attacker-side setup difference."
    }
  ],
  "control": {
    "prepare_argv": ["bash", "scripts/prepare-control.sh"],
    "argv": ["bash", "scripts/run-control.sh"]
  },
  "attack": {
    "prepare_argv": ["bash", "scripts/prepare-attack.sh"],
    "argv": ["bash", "scripts/run-attack.sh"]
  }
}
~~~

Each script must execute its scenario against the same local Anvil endpoint (Lowkey supplies ETH_RPC_URL, FOUNDRY_ETH_RPC_URL, and LOWKEY_RPC_URL) and print exactly one line:

~~~text
LOWKEY_TRACE_TX_HASH 0x<32-byte-mined-transaction-hash>
~~~

The tested transaction must be the only transaction in its block and have transaction index zero. Lowkey obtains the transaction and receipt from RPC, runs debug_traceTransaction with callTracer, verifies the trace root matches the mined transaction, checks that the trace reaches target_address, and derives the root-entry-call fingerprint from the real sender, recipient, calldata, value, and chain ID. It also compares the transaction envelope (nonce, gas limit, gas/fee fields, type, and access list), because contracts can observe fee context and gas availability. The nested call traces are retained but are expected to differ at the callback boundary in a reentrancy experiment. The outer invocation and transaction envelope must match exactly; scenario_parameters explicitly declare the only expected setup difference. Each manifest must also include trace_expectations for the execution-path delta that demonstrates the hypothesis (for example, one target call in the control and two in the reentrancy attack). Lowkey counts those calls from the RPC traces and requires the declared ranges to match before returning BREAK.

For pre-state comparison, prestate_addresses must include the transaction sender, root recipient, and target. prestate_slots must include at least one relevant target accounting or authorization slot. Lowkey reads those values at the transaction's parent block. **Only the declared storage slots are compared**; include every target slot that matters to the hypothesis. Parent block hash is retained as provenance but excluded from the state-equivalence digest because a declared attacker setup call can legitimately change that block hash. The digest still compares parent block number, timestamp, base fee, declared addresses' balances/nonces/code hashes, and declared storage slots. Keep the setup call's gas profile and block context equivalent; Lowkey rejects a mismatch in the transaction pre-state fingerprint. The full nested call traces are retained in the evidence, so callback/reentrant execution differences remain visible even when the outer entry call is identical.

Use scenario_parameters to declare the *only* expected attacker-side setup differences (for example, an attacker callback toggle). Each entry names an address, storage slot, control_value, attack_value, and description. When scenario_parameters are present, each run must supply prepare_argv and argv separately. Lowkey runs prepare_argv first, reads the actual slot from the local Anvil node, and verifies the expected value **before** it runs the transaction command. Prepare the scenario through a normal contract call, not an RPC storage override. These scenario slots are not silently treated as identical target pre-state; they are explicitly declared experimental variables. Keep them confined to the attacker fixture, never target accounting or authorization storage.

The attack metric is no longer printed by the scripts. Lowkey calculates the native-ETH balance delta for metric_addresses from the transaction's parent block to its mined block. The transaction sender must be included, so its actual gas spend is included in the portfolio delta. The control and attack are run from Anvil snapshots and reverted independently, then Lowkey compares their measured portfolio deltas. ERC20/token-share profit metrics are not yet supported by this control gate.

Freeze the manifest and every referenced command/support file before execution:

~~~bash
lk control .audit/control.json --root . --rpc-url http://127.0.0.1:8545 --freeze
lk control .audit/control.json --root . --rpc-url http://127.0.0.1:8545 --require-frozen
lk break --family reentrancy --control-manifest .audit/control.json
~~~

The freeze binds the manifest, scenario settings, trace expectations, command arrays, explicit harness/support files and their SHA-256 hashes. Any change invalidates the freeze; freeze again after reviewing the new inputs. A run without a verified freeze remains review-only and cannot be promoted.

same_calls_id is a human-readable experiment label, not evidence. For compatibility, Anvil control retains `legacy_status: BREAK` when the old local break gate passes. The new `status` / `proof_status` are deliberately stricter: a local fixture or local reimplementation is not proof about a deployed target, and the example CI fixture therefore has legacy BREAK but proof status OBSERVED. The report keeps target authenticity, execution fidelity and outcome as separate axes. A local control result is not human confirmation. The transaction scripts must not hard-code results or reuse old transaction hashes; Lowkey verifies that each hash is mined in the current local Anvil run.

The Anvil path attempts to derive a storage read-set with Geth/Anvil `prestateTracer`. Every discovered slot is retained and checked against its own transaction's parent block. Manifest-declared accounts/slots are used for control/attack state equivalence; shared discovered slots are compared for matching prestate values, while control-only and attack-only slots remain visible as path-specific evidence. Set `require_trace_storage: true` to fail closed when the node does not support `prestateTracer`. This read-set is tracer-specific and is not a completeness proof for all dependencies.

### Forge state-diff backend

For Foundry fork tests where the RPC provider does not expose a transaction tracer,
Lowkey supports `trace_backend: "forge-state-diff"`. This backend consumes a
`Vm.startStateDiffRecording()` / `vm.stopAndReturnStateDiff()` artifact generated
inside the test. The reusable recorder is documented in
`docs/forge-state-diff.md` and `docs/LowkeyForgeStateDiffRecorder.sol`.

A Forge manifest must set `expected_chain_id` and `expected_fork_block`, include
`target_address` in `source_addresses`, and give each control/attack run its
own `harness`, `state_diff_file` and `forge test` command. List the protocol
dependencies whose authenticity matters in `source_addresses`; list imported
test helpers in each run's `support_files`. Freeze the manifest after those
files and commands are final. Use an independent archive RPC when running
`lk control` to compare the fork anchor, pinned block, deployed code, balances,
nonces and trace-derived storage for those declared protocol addresses.

Forge state-diff is execution evidence from a test VM, not a signed EOA transaction.
It has no receipt, effective gas price or full transaction envelope. Consequently
it can support `FORK_OBSERVED` (when deployment authenticity is independently
checked) or a capped `SIMULATED_BREAK` for a semantic non-economic result, but it
cannot independently earn `PROFITABLE`. Its state-access list is only what the
recorded execution touched; dependencies not listed and reached slots not covered
remain out of scope.

### Negative controls and non-economic families

A manifest can include `negative_control` and set `require_negative_control:
true`. Each trace expectation then needs `negative_control_min_calls` and
`negative_control_max_calls`. An Anvil negative control may set
`expected_receipt_status: "0x0"` for a deliberately reverting transaction; the
revert is recorded as the expected control result rather than being confused
with a tool failure.

For DoS/liveness, replay, signature or authorization claims where profit is not
the correct measure, set `non_economic: true` or pass `--non-economic` and
provide `semantic_check_argv` for each scenario. A successful command must
execute a concrete assertion about the impact. This path does not claim positive
economics and is capped at `SIMULATED_BREAK` until stronger family-specific
evidence exists. Rejected completed experiments receive machine-readable
`rejection_codes` and are added to Lowkey's private experience-memory feedback
store. Tooling/setup failures remain unproven observations rather than being
misreported as disproven vulnerabilities.

The proof axes are:

- `target_authenticity`: unknown, fixture, local_reimplementation, or independently verified forked_deployment.
- `fidelity`: unknown, synthetic_state, simulated_caller, simulated_dependencies, constrained_inputs, or real_funded.
- `outcome`: not_run, observed, profitable, or rejected.

`PROFITABLE` requires independently verified deployed target authenticity,
real-funded execution and positive measured net economics. A simulated caller
or constrained fuzz input cannot be promoted to that label. `HUMAN_CONFIRMED`
is never assigned automatically; a reviewer must explicitly record a disposition
in the evidence ledger.

### Fidelity promotion ladder

lk fidelity --inspect test/YourPoC.t.sol reports detected test-state modifications. The current fork-reproduction denylist includes synthetic ETH/token balances, caller impersonation, storage writes, code injection, mocked dependencies, and timestamp/block overrides. vm.assume/bounded-input assumptions are disclosed as `constrained_inputs` and cap proof status at `FORK_OBSERVED`; they do not earn `FORK_REPRODUCED` or `PROFITABLE`. A clean static scan is only a fidelity signal and never makes a finding confirmation-eligible. The allowlist and denylist are recorded with the fidelity report.

To run an actual local-fork transaction through the higher proof stages:

~~~bash
lk reprove test/YourPoC.t.sol \\
  --rpc-url http://127.0.0.1:8545 \\
  --source-rpc-url "$ARCHIVE_RPC_URL" \\
  --fork-block 19300000 \\
  --target-address 0x0000000000000000000000000000000000000001 \\
  --prestate-slot 0x0000000000000000000000000000000000000000000000000000000000000001:0x0 \\
  --profit-address 0x0000000000000000000000000000000000000002 \\
  --profit-address 0x0000000000000000000000000000000000000003 \\
  --argv-json '["bash", "scripts/replay-local.sh"]'
~~~

The replay command must execute one transaction on the local Anvil node and print exactly one LOWKEY_TRACE_TX_HASH matching the transaction it just executed. The transaction must be the only transaction in block fork-block + 1. Lowkey scans the Solidity harness, argv text, and local script files explicitly referenced in the replay command for direct RPC state/balance/code/time overrides and account impersonation, and blocks those findings before execution. This is a static scan of referenced files, not a whole-program proof; imported or transitively invoked helpers must also be reviewed. A tx-hash-only inspection is labeled LOCAL_TRACE_ONLY; it cannot be promoted as a reproduction. Without --source-rpc-url, a command-backed local replay reports proof status OBSERVED, while retaining its prior local result (for example `legacy_status: LOCAL_PROFITABLE`) for compatibility. To reach FORK_REPRODUCED or PROFITABLE, --source-rpc-url must be an independent read-only archive endpoint for the same chain, and --prestate-slot must identify the target's relevant accounting/authorization slot(s). Lowkey compares chain ID, parent block hash, target bytecode, declared target storage slots, and the fork-block balances of all measured profit addresses against that source. It also checks the transaction sender had enough source-chain ETH to pay measured gas. The local Anvil endpoint remains the only transaction destination. PROFITABLE requires positive measured native-ETH portfolio delta after actual receipt gas. This does not validate every dependency, hidden storage slot, token/share position, or off-chain assumption. ERC20/ERC4626 share accounting needs a token-specific adapter. No automated result becomes HUMAN_CONFIRMED.

No tool assigns HUMAN_CONFIRMED automatically. A human must review the evidence and record an explicit disposition in the evidence ledger. A successful Forge test alone never establishes realistic profit or confirms a finding.

### Proof support and boundaries

`lk target-coverage` runs Forge LCOV and reports reachability for the requested file/line range. `lk mutation-score <manifest>` delegates to the existing baseline-first mutation runner and enforces a 90% score by default (`--min-score 0.90`); use a separate manifest for each attack family when measuring family-specific harness quality. `lk provenance` hashes selected artifacts and records run metadata; pass `--signing-key /path/to/private-key.pem` to create a detached OpenSSL signature. `lk fidelity` stores declared evidence strength in the append-only ledger; `lk fidelity --inspect path/to/Harness.t.sol` scans a harness for common synthetic-state and cheatcode signals and records its source hash. The scanner is static and can miss aliases/wrappers or custom state manipulation; it is not a proof of realism. `lk break` attaches this scan to each generated harness and will not automatically create a human-confirmed finding. `lk reprove` rejects common state-fabricating cheatcodes and only accepts a local Anvil fork endpoint. `lk report` writes finding sections and a SHA-256 sidecar when the run JSON contains validated finding records.

The source maps classify fallback/callback paths, Chainlink-style aggregators, spot/TWAP reads, timestamps/deadlines, storage declarations, token assumptions, signatures, initializer and custody cues, cross-VM authorization cues, CFG outlines, and read/call/write candidates. These are static signals. The storage/proxy/selector commands need an RPC endpoint. Historical replay needs an archive RPC and a dedicated harness; flash loans need actual venue callbacks and liquidity reads; symbolic path work needs Halmos and an explicit harness; Flashbots bundle simulation needs relay authentication. These are not silently substituted with mocks. No Godmode command submits a production transaction or calls `eth_sendBundle`.

## Integrated test-drive

This branch is the integration candidate for the current Lowkey feature set. It keeps the local attack-lab/walkthrough stack and adds the project graph, reusable system bootstrap manifest, evidence engine, ripgrep evidence capture, and evidence-backed PoC generation.

Useful discovery commands:

~~~bash
lk cheat
lk cheat mapping
lk cheat require
lk cheat fallback
lk cheat receive
lk cheat interface
lk cheat symbols
lk cheat search mapping
lk attack
lk attack categories
lk attack search reentrancy
lk attack learn EVM-001
lk attack list --severity Informational
lk attack map lending
lk -h
lk project
lk system
lk lab
lk walkthrough --auto --steps 8
lk walkthrough test --cases 24
lk walkthrough test --cases 24 --technical
lk audit run
# A PoC request needs exact observed calldata and a measurable impact assertion.
lk audit run --poc --poc-calldata 0x... --poc-impact-assertion 'attackerAfter > attackerBefore'
lk poc --calldata 0x... --impact-assertion 'attackerAfter > attackerBefore'
~~~

### Lowkey Attack Library

`lk attack` opens the source-linked, beginner-first blockchain attack reference. The current catalogue contains 209 entries across EVM execution, authorization and signatures, DeFi accounting/oracles, tokens, governance, MEV, proxies, bridges, denial of service, randomness, Solana, Move, Cosmos/IBC, privacy/ZK, wallets/account abstraction, and operational security.

Start with:

~~~bash
lk attack
lk attack categories
lk attack list --severity Critical
lk attack list --severity High
lk attack list --severity Medium
lk attack list --severity Low
lk attack list --severity Informational
lk attack search "share inflation"
lk attack show EVM-001
lk attack learn single-function-reentrancy
lk attack lab single-function-reentrancy
lk attack quiz single-function-reentrancy
lk attack related single-function-reentrancy
lk attack map lending
lk attack incidents
lk attack sources
lk attack severity
lk attack check
~~~

Each entry includes a plain-English explanation, the vulnerable shape or code pattern, audit signals, a local reproduction idea, mitigation direction, and source cross-references. The learning view adds a beginner-first reproduction sequence and evidence checklist. `lk attack lab` prints a disposable local Foundry exercise; it does not start Anvil, connect to an RPC, or send transactions.

Severity labels are **typical starting estimates**, not guaranteed findings. Final severity depends on reachability, asset impact, attacker capability, preconditions, blast radius, and the applicable contest/client rubric. Informational entries deliberately include documentation, observability, and testing gaps that are not vulnerabilities by themselves. Use `lk attack check` to validate catalogue IDs, severity labels, protocol-map references, and source mappings.

The catalogue is an expandable cross-reference, not a claim that every possible blockchain attack has already been discovered. Protocol-specific modules and new incident research should continue to grow it.

#### Beginner-first walkthrough view

`lk walkthrough test` uses a simple teaching view by default. Each probe is reduced to one of four labels:

- `✅ NORMAL` — Lowkey has an explained reason for the rejection.
- `⚠️ CHECK THIS` — the chain accepted a state-changing action; inspect what changed.
- `❓ UNKNOWN` — Lowkey cannot yet prove why the call failed.
- `🔧 LAB ISSUE` — the local test setup appears broken, so the result should not be treated as a protocol finding.

The output tells you what happened, why it matters, and what source/function to inspect next. The full forensic renderer is still available with `lk walkthrough test --technical`.

The teaching layer is language-neutral: it does not assume the target is Solidity or a particular protocol. It can label Solidity, Vyper, Move, Cairo, Tact, FunC, Clarity, Rust, and unknown source files without changing the underlying audit semantics. Chain execution remains adapter-specific, so a language needs a compatible build/runtime adapter before live probes can run.
### Universal repository analysis
Lowkey first determines the repository scope and available native/security tooling before choosing a command path. A conventional directory name such as `lib/` is not automatically treated as dependency code: Lowkey prunes it only when repository evidence (for example a Git submodule or Foundry remapping) identifies it as external. First-party source under `lib/` remains auditable.\n\n`lk scan` is a coverage-aware source/security triage command. It uses installed native analyzers when they are relevant (for example Slither on EVM projects, or Rust/Move security tooling when installed) and never turns unsupported language heuristics into a clean audit verdict.\n\nScan exit codes are deliberate: `0` means the requested triage completed with full coverage, `1` means an analyzer/tool failed, and `2` means Lowkey could not establish complete coverage and the result requires review. A nonzero scan result is therefore not a vulnerability finding by itself; it means the analysis state needs attention.\n\n### Working inside a multi-project workspace

Lowkey treats a monorepo as a workspace first and an audit target second. From the workspace root or a shared parent directory:

~~~bash
lk project
lk project --workspace
lk project 2
lk projects 2
~~~

At a workspace root, lk project shows the workspace overview until an active project has been selected. After lk projects <number>, plain lk project opens the selected project's full map. lk project <number> also switches directly to that project's map. When you are already inside a package, lk project maps that package even if a different workspace project was previously selected.

The active workspace scope is used by commands such as lk audit and lk lab when they are invoked from a shared workspace directory. Entering another actual project directory uses that project's own scope, so Lowkey does not accidentally mix sibling packages.

## What each layer does

- Project model: detects Foundry/Vyper/Hardhat/Brownie-style project structure and builds an import/dependency graph.
- System model: records contracts, deployments, relationships, roles, initialization, tests, adversarial evidence, and audit targets in .audit/evidence/system_bootstrap.json.
- Audit engine: runs project-aware build/test/coverage evidence, Slither when available, and source triage. PoCs are emitted only when exact calldata and an explicit measurable impact assertion are supplied; otherwise Lowkey records a review gap. Vyper-aware preparation is retained for mixed/non-Foundry projects.
- Protocol walkthrough: uses the richer local Foundry walkthrough/lab engine for actual stateful execution and replayable observations.

lk audit and lk audit run are intentionally separate surfaces: the former is the interactive Lowkey audit console; the latter is the evidence pipeline. Neither should be read as a vulnerability verdict.
## Native-first AI harness

AI is an optional, once-configured reasoning extension for narrowly scoped tasks such as protocol interpretation and proposing test hypotheses. It does not replace Lowkey's native analyzers or run commands, edit files, sign transactions, deploy contracts, or confirm findings. Normal workflows work with AI disabled.

### Universal command guidance

Add `--ai` to a native command to get a separate explanation of its actual output, risks, missing evidence, and a useful next step:

~~~bash
lk status --ai
lk read isAgreementValid --ai
lk send --ai
lk test --ai
~~~

The native command still runs with its normal behavior. In particular, `lk send --ai` is not a transaction safety preview; it can send if the unmodified `lk send` command would send. AI guidance is added afterward, is labeled unverified, and never executes its suggestions.

`lk ai mode auto` opts into guidance after eligible complex workflows or supported failures. It requires AI to be enabled and usable; `lk ai mode manual` turns that automatic behavior off. The independent `lk ai recommendations` and `lk ai errors` settings remain separate.

Jev is integrated as a structured decision model, separate from the existing text-AI helper. It classifies selected Lowkey command outcomes and recommends a safe response category; it does not generate full explanations or execute commands.

~~~bash
lk ai jev setup                    # fresh setup defaults to JevModel's advertised starter-token endpoint
lk ai jev setup --provider typesafe # choose the official TypeSafe API instead
lk ai jev test                     # one source-free connectivity probe; may use tokens
lk ai jev on                       # enable automatic Jev triage on eligible command results
lk ai jev status                   # local-only status and request budget
lk ai jev off                      # pause Jev without changing other AI features
~~~

JevModel advertises five successful free runs per UTC day plus 100,000 starter input tokens after email verification. The daily runs and token balance are separate; JevModel is independent from TypeSafe. The official TypeSafe endpoint has separate published input-token pricing. Lowkey defaults to a conservative local guard of 5 provider attempts per UTC day and applies a smaller request cap for JevModel. The shared guard also covers optional text-AI calls; exact cache hits do not spend another provider request. The existing `lk ai mode`, `lk ai errors`, and `lk ai recommendations` settings stay independent to avoid silently enabling a second model. See [Jev autonomy](docs/jev-autonomy.md).

For a task spanning several checks, `lk ai run` makes a source-grounded plan and shows each proposed command:

~~~bash
lk ai run "investigate why withdrawal reverts" --plan-only
lk ai run "investigate why withdrawal reverts"
~~~

Review the plan before approving execution. The current task runner only accepts a strict allowlist of read-oriented `lk` commands, executes without a shell, stops at the first failed checkpoint, and interprets the captured output. It does not run tests, modify files, switch targets/RPCs/actors, deploy, sign, or send transactions. If source evidence is insufficient, it can return no executable plan.

Start with guided provider/model setup. Save multiple model configurations and switch between them without re-entering their API keys:

~~~bash
lk ai setup
lk ai status
lk ai test
lk ai switch
~~~

See [the native AI harness guide](docs/native-ai-harness.md) for provider setup, privacy boundaries, saved model profiles, and use of the explicit \`lk lab --ai-review\` option.

Preview the exact redacted payload locally before sharing any project context with a provider:

~~~bash
lk ai preview
lk ai preview --contract ConfidencePool --show-context
bash scripts/test-native-ai-harness.sh
~~~

### Focused security review with evidence

The protocol overview and security-finding workflow are separate commands. The focused review records only unverified candidates; source-quote validation checks citation existence, not exploitability. Use native tests and an explicit human disposition for conclusions.

~~~bash
lk ai security-review --contract ConfidencePool
lk ai ledger
lk ai verify F-0123456789ab --test test/unit/ConfidencePool.t.sol --match-test testWithdrawSucceedsInAttackRequested
# Inspect the plan and selected test before explicitly executing:
lk ai verify F-0123456789ab --test test/unit/ConfidencePool.t.sol --match-test testWithdrawSucceedsInAttackRequested --run
lk ai disposition F-0123456789ab --status confirmed --reviewer auditor --reason 'Reviewed the reproduced impact and assertion.' --evidence-id NATIVE_TEST_EVENT_ID
lk ai runtime
~~~
### AI test planning without AI-driven execution,,`lk ai test-plan --contract ConfidencePool` proposes source-cited unit/fuzz/invariant/regression cases, including explicit setup, steps and assertions. It saves a plan and ledger event only: it does not write test code or run tests.,,~~~bash,lk ai test-plan --contract ConfidencePool,lk ai test-plan --contract ConfidencePool --json,~~~,,Review the proposals against current source and tests before implementing them. See `docs/native-ai-harness.md` for the evidence lifecycle and guardrails.,### Error help and provider key failover

`lk ai explain-error --last` diagnoses the most recently captured Lowkey error; use `lk ai explain-error --text '...'` for any copied error. `lk ai errors auto` opts into an AI diagnosis after routed CLI failures (provider requests may incur charges); `lk ai errors manual` disables automatic explanations. AI-suggested commands are never executed.

Add up to three API key slots for one configured provider with hidden input:

~~~bash
lk ai keys add --provider openai-compatible --slot 1
lk ai keys add --provider openai-compatible --slot 2
lk ai keys add --provider openai-compatible --slot 3
lk ai keys list --provider openai-compatible
~~~

Quota/rate-limit/key-auth failures trigger bounded failover across the configured slots. Keys are not printed or logged; model/provider is not silently changed.

## Shared command evidence

Every native command handler receives the same project-scoped context through Lowkey's transient shared context; the dispatcher records bounded output after each command finishes. The context joins recent command outcomes with allowlisted snapshots of the current audit target/signals, system and deployment graph, and evidence-ledger finding status. The command's own bounded output is also passed directly to its immediate AI recommendation footer, so `lk build` guidance can inspect the compiler warnings from that exact build. A later command can reuse those observations—for example, `lk lab` diagnosis can correlate Solidity deployment-script warnings from the preceding `lk build` with target-discovery failure. The same shared context is supplied to automatic error diagnosis, AI next-step recommendations, protocol review, and opt-in `--ai` guidance/planning.

Use `lk context` to inspect the selected target, known contracts/deployments, saved audit signals, ledger findings, and recent command evidence. History is stored outside the audited repository under `$XDG_STATE_HOME/lowkey/projects/` (or `~/.local/state/lowkey/projects/` when `XDG_STATE_HOME` is unset). Lowkey retains at most 30 recent command events per project. It stores bounded diagnostic excerpts and allowlisted project metadata, not full terminal sessions or source files; sensitive assignments, secret flags, URL credentials, and 32-byte hex values are redacted. History files and containing directories are private to the current user. The absolute project path is used only for local history scoping and is not included in the shared context returned to the model. Historical observations and inferred relationships are clues—not proof—and must be checked against the current source and runtime.

## Native experience memory

Lowkey can retain audit feedback and reusable lessons without an AI provider. Feedback and proposed lessons are stored in a private user-data directory keyed to the canonical path of the audited project, not inside the target repository. Only lessons explicitly approved with validation evidence are supplied as relevance-ranked reference context to an explicitly requested AI review; lessons never execute as code or change native security rules.

~~~bash
lk memory status
lk memory feedback --kind false-positive --summary "Lead did not reproduce" --evidence "Regression test confirms the only path is guarded."
lk memory propose --kind test-procedure --title "Check factory registry" --lesson "Assert both the factory event and registry mapping." --tag factory
lk memory list --status proposed
lk memory approve LESSON_ID --validation-kind test --validation "The linked Foundry regression test passes."
~~~

See [the experience memory guide](docs/experience-memory.md) for validation, scope, global promotion, and correction workflows.

## Start here

~~~bash
lk -h
lk doctor

# Clone and prepare a project for auditing
lk clone <repository-url>
~~~

`lk clone` is the project entry point. Give Lowkey the repository; it derives the project directory and handles the audit setup automatically.

Lowkey automatically detects a local Anvil RPC on the common ports. For the default Anvil mnemonic it binds actors to account numbers and derives the corresponding key only when a signed local transaction is needed.

## Everyday audit flow

Primary UX rule: a command name should make its action obvious before you read its description.

The primary commands are deliberately short and self-describing:

~~~bash
lk audit
lk audit auto
lk audit --checks
lk audit auto --checks
lk status
lk findings
lk focus <SIGNAL_ID>

lk recon
lk functions
lk ask withdraw

lk read balanceOf Alice
lk send withdraw 1
lk trace

lk mapping 3 Alice
lk snapshot
lk diff
lk changes withdraw

lk probe withdraw
lk generate test withdraw 1
lk fuzz
lk invariant
~~~

Legacy aliases such as `signals`, `investigate`, `try`, `c`, `s`, and `state-diff` remain supported, but the help menu presents the clearer primary forms.

Plain `lk audit` detects and uses an existing Anvil node but never starts one. `lk audit auto` is the autonomous local mode: it starts a project-owned Anvil when needed, binds a safe local actor, resolves a project target when possible, and may deploy a zero-constructor-argument local artifact without inventing constructor values. Both modes collect audit evidence without inventing PoCs; `--checks` adds Slither and optional lint/geiger checks. When an explicit PoC request lacks calldata or an impact assertion, Lowkey returns a review-required result instead of writing a placeholder.

## Actors

Use actor names so your audit notes read like an attack story instead of a wall of addresses.

~~~bash
lk actor 1 Alice
lk actor 2 Bob
lk actor 3 attacker

lk actor 0
lk actor 1
lk actor
lk as attacker c balances 0x...
lk as attacker s release --preview
lk as Bob read getContribution
~~~

`lk as <actor> <command>` is a temporary execution context: the command runs with that actor as its signer, then Lowkey restores the previously selected actor. Transaction metadata is still retained, but the temporary signer is not saved as the active actor.

For `lk read` / `cast call`, Lowkey defaults `--from` to the active actor so view functions that inspect `msg.sender` return that actor's state. An explicit `--from <address>` overrides this. Sending a `view` or `pure` function is still possible for transaction-context experiments, but Lowkey warns that it mines a transaction and consumes gas; use `lk read` for an ordinary read.

ABI return values keep the decoded integer visible. When the ABI provides a strong payable-inflow clue (for example `getContribution()` alongside `contribute() payable`), Lowkey adds a second-line ETH equivalent. That conversion is explicitly marked as inferred because `uint256` does not encode whether a value is wei, tokens, shares, or another unit. `lk trace` also shows the raw return word, decoded integer, and the inferred human-readable equivalent when available.

"lk actor <index>" selects an actor profile already assigned to that Anvil account. "lk actor <index> <name>" assigns or rebinds a user-facing profile. Anvil account 0 is reserved for Lowkey's internal lab-deployer, so user actors should use account 1 or higher.

The same Anvil account cannot be assigned to two actor names.

On a local fork, you can also impersonate an existing address:

~~~bash
lk impersonate 0x...
lk as whale s transfer ...
~~~

The fork actor uses Anvil's unlocked-account path; no private key is required for the impersonated account.

## ABI and function discovery

Lowkey normally finds the ABI from Foundry's out/ artifacts. It can use deployment records, the configured contract name, proxy implementation discovery, and runtime bytecode matching.

~~~bash
lk abi
lk functions
lk fn withdraw
lk ask withdraw
lk encode withdraw 100
lk calldata 0x...
~~~

Public mapping/struct getters are shown separately from ordinary read functions because an auditor usually cares about them as direct storage exposure.

Manual override is still available:

~~~bash
lk abi out/EthEscrow.sol/EthEscrow.json
~~~

When Lowkey resolves an ABI, it keeps the original Foundry artifact as the source of truth and also materializes a human-readable copy under the project audit workspace:

~~~text
.audit/
└── abi/
    └── <Contract>.json
~~~

The project-local copy is pretty-printed JSON with an `abi` field. This makes the audit workspace easy to inspect or archive without changing the original `out/` artifact.

## Import intelligence

Lowkey’s import browser is a project-aware Solidity dependency and learning navigator. It resolves real symbols from src/ and lib/, or falls back to a verified reference catalog for common OpenZeppelin, Chainlink, forge-std, and related components.

~~~bash
# Interactive browser
lk import

# Look up a component
lk import ERC721
lk import IERC721
lk import IERC721Receiver

# Browse the installed dependency tree
lk import packages

# Global symbol + learning search — includes known reference imports
lk import search ERC20
lk import search token
lk import search nft
lk import search oracle
lk import search access
lk import search reentrancy

# Jump straight to a view
lk import explain ERC721
lk import explain interface
lk import explain abstract
lk import usage ERC721
lk import graph ERC721
lk import related ERC721
lk import audit ERC721

# Safe install workflow
lk import --install ERC721
lk import --install --dry-run ERC721

# Machine/copy-friendly output
lk import --json ERC721
lk import --copy-only ERC721
~~~

The interactive browser keeps `/<term>` scoped to the list on screen. Use `g` from any list to search project source, installed dependencies, and Lowkey's known reference catalog; `r` resets the list. A `REFERENCE ONLY` result means the dependency is not installed. For the full import and install guidance, look up the symbol directly with `lk import ERC20`.

A symbol card shows:

~~~text
TYPE / ROLE
SOURCE + SOURCE KIND
IMPORT PATH
WHY / WHEN / USE CASES
VERSION + COMMIT
FORGE INSTALL COMMAND
HOW TO USE IT
INTERFACE SURFACE (when applicable)
RELATED COMPONENTS / NEXT TO LEARN
DIRECT DEPENDENCIES
PROJECT USAGE
COMPATIBILITY NOTES
COMMON MISTAKES
AUDIT LENS / AUDIT QUESTIONS
COPY-READY IMPORT
~~~

The SOURCE line is an absolute path:line when Lowkey has real source. In terminals/editors that support file links, Ctrl+Click opens the file directly. Installed dependency sources are marked as INSTALLED DEPENDENCY; project sources are marked as VERIFIED PROJECT SOURCE; missing catalog dependencies are marked as REFERENCE ONLY.

Interfaces are treated as a learning topic, not just another symbol. Lowkey explains that an interface describes the callable surface while the implementation lives somewhere else, and shows important method shapes when they are known or can be extracted from source. For example, IERC20 exposes the standard token interaction surface such as balanceOf, transfer, allowance, approve, and transferFrom.

Contracts can also be labeled as abstract contract. An abstract contract is a base that cannot be deployed directly while it still has required unimplemented behavior. It can nevertheless contain real storage, modifiers, constructors, and implemented state-changing logic, so auditors should still inspect it as executable code.

Related components are deliberately connected. Starting at ERC721, the browser can point you to IERC721, IERC721Receiver, ERC721URIStorage, ERC721Enumerable, and ERC721Burnable, making the dependency folder a learning map rather than a pile of unfamiliar files.

Installation is explicit and idempotent. --dry-run shows the exact verified Forge install command without changing the project. Lowkey does not invent a dependency install recipe when it cannot verify the source/package.

For installed packages, Lowkey reads the package Git remote when possible and records a version/commit plus a source URL. Compatibility notes deliberately warn when examples may depend on a different package major version; the installed source remains the authority.

The project-usage view connects dependency code back to your application. lk import usage ERC721 shows where the project imports or references that symbol, with clickable path:line locations.

The import helper stays separate from audit target/RPC state. Ordinary lookup, search, explanation, graph/usage views, and JSON output are read-only; only explicit --install changes the project.


## Storage and state forensics

~~~bash
lk layout EthEscrow
lk mapping 3 0x1111111111111111111111111111111111111111
lk namespace MyNamespace
lk proof 3
lk snapshot 0 1 2 3
lk diff
~~~

For a real call, Lowkey can generate a temporary Forge test around Foundry's state-diff cheatcodes:

~~~bash
lk state-diff release
lk state-diff release --actor attacker
lk state-diff createEscrow 1 0x...
lk state-diff release --keep
~~~

The generated test records account accesses and storage accesses, including previous/new slot values and call depth.

## Local audit lab

Once a project has been onboarded, start or rebuild its local attack environment with:

~~~bash
lk lab
~~~

Lowkey automatically reuses an existing Anvil, or starts a disposable project-local Anvil when none is running. It first checks for a project-specific lab adapter, then falls back to a generic deployment from the current Foundry build artifacts.

The generic path deliberately refuses to call an upgradeable-style contract "ready" when it exposes `initialize()`. Complex protocols may require a proxy, registries, mocks, or initialization data that cannot be safely guessed. In those cases Lowkey reports the missing lab layer instead of giving a misleading live target.

### \`lk lab\` vs \`lk deploy\`

- \`lk lab\` is the environment-setup command. It prefers the project's own deployment script or test fixture, then falls back to generic deployment when appropriate. Its goal is a usable, project-aware attack environment—not merely an address with bytecode.
- \`lk deploy [Contract]\` is the direct-deployment shortcut. It deliberately selects the generic ABI deployment path and prompts for constructor values. It is equivalent to \`lk lab --generic [Contract]\`, but makes the intent explicit.
- Both commands reuse the same active local Anvil when available. Deploying to a reused node adds to its existing state; it does not reset the chain. A successful \`lk deploy\` proves that the contract was deployed and its runtime bytecode is present, not that the full protocol is initialized or audit-ready.


Stop an Anvil started by Lowkey with:

~~~bash
lk lab stop
~~~

The resulting target and actor are stored in the current project's `.audit/` context, so commands such as `lk changes` and `lk trace` work without manually copying addresses.

## Attack lab

### Break mode

`lk break` is the adversarial side of the Lowkey workflow. Instead of stopping at a static warning, it builds disposable Forge attack harnesses and tries to make the target violate an observable security property.


~~~bash
# Attack the current target
lk break

# Attack one function only
lk break --function 'withdraw(address,uint256)'

# Run one attack family
lk break --function withdraw --family reentrancy

# Attack every live target Lowkey can resolve for the project
lk break --system

# Keep attacking until Lowkey records an explicit BREAK or you press Ctrl-C
lk break --system --until-found

# Make a campaign reproducible
lk break --function withdraw --until-found --seed 42
~~~

The command separates:

~~~text
STATIC LEAD  ->  ATTACK EXPERIMENT  ->  OBSERVED BEHAVIOR  ->  BREAK CONDITION
~~~

A successful transaction is not itself a break. A Slither warning is not itself a break. For example, the reentrancy family deploys a hostile callback contract and checks whether nested calls actually produce attacker-controlled value movement. Repeat-claim experiments compare the first and second calls. Access-control experiments use an untrusted local caller. Other families record observations until Lowkey has enough protocol-specific evidence to assert a break condition.

The default scope is the selected target. `--function` narrows the attack to one ABI function. `--system` broadens the scope to all live targets Lowkey can resolve from the project/system model. `--until-found` is intentionally open-ended and stops only on a concrete break or user interruption; every experiment is written under `.audit/break/` and also published to the project audit context.

The attack library is based on recurring vulnerability classes documented in public Immunefi guidance and reports, CodeHawks contest findings, and public Solodit finding taxonomy. Lowkey keeps these as a data-driven public-finding playbook: missing validation, incorrect calculations, rounding, reentrancy, read-only reentrancy, access control, replay/signatures, oracle freshness/manipulation, transaction-order dependence, DoS/griefing, token integration, fee-on-transfer/rebasing assumptions, arbitrary calls, initialization/proxy/storage issues, governance, flash-loan-shaped invariant breaks, vault share inflation, liquidation boundaries, bridge/message replay, Merkle claim binding, predictable randomness, expiry boundaries, native-asset accounting, and state-slot corruption. The playbook is a source of attack logic and hypotheses, not copied reports and not automatic vulnerability verdicts.\n\nBreak mode requires Anvil for EVM campaigns. Vyper is treated as an EVM language, so Vyper contracts use the same local EVM attack machinery while Lowkey also records Vyper-specific source cues such as @external, @nonreentrant, raw_call, extcall, and send. A mixed workspace remains scope-aware: Lowkey attacks the selected audit entry and its live related targets rather than blindly treating every package as a standalone protocol.\n\nFor Cairo/Starknet, Move, and Solana/Anchor, lk break routes through native backends instead of forcing an EVM harness onto the project. Where Lowkey does not yet have a generic exploit generator for that language, it runs the native project test surface and stores the relevant public-finding attack plan as evidence rather than claiming a false BREAK.\n\nThe native backend architecture is:\n\n~~~text\nlk break\n   ↓\nproject detection / workspace scope\n   ↓\npublic-finding playbook\n   ↓\nEVM/Vyper breaker  OR  Cairo  OR  Move  OR  Solana/Anchor backend\n   ↓\nconcrete invariant evidence (or an explicit adapter limitation)\n~~~\nBreak mode requires Anvil and executes generated Forge tests against the local/forked execution environment. It does not deliberately send the attack campaign to a production contract. Complex protocol-specific classes such as oracle manipulation, economic/flash-loan interactions, unusual ERC-20 behavior, and proxy/storage abuse are represented explicitly and must earn a real invariant-based harness before Lowkey can call them BREAK.
### Probe

Probe a real ABI call as the current actor:

~~~bash
lk probe release
lk probe createEscrow 1 0x...
lk probe release --actor attacker
lk probe release --value 1ether
~~~

A probe is intentionally non-asserting. It is for discovering behavior.

Lowkey keeps the generated Forge test under test/ so the run itself becomes reusable evidence. --keep remains accepted for compatibility.

### Matrix

Turn attack assumptions into executable Forge scenarios:

~~~bash
lk matrix init
lk matrix actor Alice 0x...
lk matrix actor attacker 0x...
lk matrix state funded "Escrow is funded"
lk matrix add unauthorized-release release attacker "revert unauthorized"
lk matrix test unauthorized-release
~~~

The generated matrix test uses the saved actor and calls the target through a low-level call so the scenario can be executed even when no typed contract interface is available.

### Test generation

Turn the last recorded send into a Forge reproduction:

~~~bash
lk test-gen
~~~

Then edit the generated test to express the exact invariant or exploit you want to prove.

## Lowkey project-aware generation

Lowkey can generate readable, project-aware Foundry artifacts instead of only passing commands through to Forge:

~~~bash
# Rebuild, inspect the compiled artifact, and generate a reusable deployment script
lk generate deployment EthEscrow

# Generate a replay test from an available concrete send
lk generate test

# Generate a PoC candidate only when the actual calldata and impact assertion are known
lk generate poc withdraw --calldata 0x... --impact-assertion 'attackerAfter > attackerBefore'

# A PoC request can also include attached ETH and an explicit function label
lk generate poc withdraw --value 1ether --calldata 0x... --impact-assertion 'attackerAfter > attackerBefore'
~~~

Generated Solidity is intentionally teaching-oriented. Focused `//` comments sit beside important Foundry ideas such as `vm.prank`, `vm.startBroadcast`, `vm.deal`, `vm.snapshot`, revert-data handling, assertions, and the difference between transaction success and a proven security property.

The deployment generator uses the compiled ABI to externalize constructor inputs, adds post-deployment sanity checks, and writes a machine-readable deployment record. The PoC generator requires a concrete call and an explicit Boolean impact assertion over measured replay-state variables. Its evidence brief records the artifact as `candidate-not-validated` until the candidate is executed against the intended target and chain state. The test generator creates an exact-call replay test only when a real call is available; that test checks replay behavior, not exploitability. Neither generation nor compilation is reported as a security verdict.

No TODO-filled PoC/test is emitted as a substitute for missing inputs. Incomplete requests exit nonzero and preserve the reason in audit evidence.

## Optional external verification engines

The base Lowkey installer keeps third-party engines optional. On Linux x86_64, install the same pinned engine versions used by the live CI smoke tests from the repository root:

~~~bash
bash scripts/install-verification-engines.sh
lk verification engines --json
~~~

The installer uses isolated Python tool environments and installs Echidna 2.3.3, Medusa 1.5.1, Halmos 0.3.3, Slither 0.11.6, `crytic-compile` 0.4.2, `solc-select` 1.2.0, and Certora CLI 8.20.2. It also installs Solidity compiler 0.8.20 through `solc-select`; it does not replace or install Foundry.

Certora CLI availability is separate from proof execution. Submitting a proof requires a Certora account and personal access key exported as `CERTORAKEY`; Lowkey does not store that secret. The live CI validates Certora CLI startup but intentionally does not submit a remote proof without credentials. Engine availability and compatible harness/config files must still be checked for each project.

## Verification engine registry and campaigns

Inspect which verification tools are installed and which project/test kinds each supports:

~~~bash
lk verification engines
lk verification engines --json
~~~

Run a bounded serial campaign from a JSON manifest with explicit engine configuration and resource budgets:

~~~bash
lk verification run .audit/verification/campaign.json --profile balanced
~~~

Correlate the saved results with an existing audit finding (use its exact signal ID):

~~~bash
lk verification correlate .audit/verification/campaign.json --signal SLITHER-XXXXXXXXXX
~~~

Investigate an existing access-control signal with a targeted local test:

~~~bash
lk verification investigate SLITHER-XXXXXXXXXX
~~~

Use `lk mutation-check manifest.json` to test whether an existing suite detects explicit behavioral mutants, and `lk verification-benchmark manifest.json` to evaluate multiple project cases. Baseline failures, compiler/setup errors, timeouts, and mutants not killed are reported separately.

`lk verification correlate <campaign-report.json> --signal <SIGNAL_ID>` joins normalized engine outcomes and attaches one repeat-safe evidence record to an existing finding. A campaign manifest may instead name `investigation.signal_ids` (or `investigation.signal_id`) and a stable `investigation.property_id`. The correlator preserves the native report by reference and hash. It does not create missing findings or mark a vulnerability as proven: property failures remain review leads, and passing engines do not certify the protocol.

`lk verification investigate <SIGNAL_ID>` currently supports only an explicitly classified access-control finding that maps to one source-backed, simple `onlyOwner` state-changing function. It generates a non-owner-revert assertion, uses the existing generator validation path to compile and execute it with Forge, and attaches the run evidence to the originating signal. Findings without a defensible local test oracle are reported as unsupported with no test emitted. Required constructor arguments must be supplied with `--constructor-args`.

## Project-aware test generation

Lowkey writes only complete test artifacts with executable assertions. It does not write TODO-filled placeholders and label them tests.

```bash
# Generate executable tests for a recognized direct state property
lk test-gen Counter --types unit,fuzz,invariant --validate

# Supply real constructor values rather than guessed placeholders
lk test-gen Vault --types unit,fuzz,invariant \
  --constructor-args '["address(0x0000000000000000000000000000000000000001)", "1000"]' \
  --validate

# Strictly reject missing assertions, setup, or validation
lk test-gen Vault --types all --force --strict --validate
```

The project-aware generator currently has two native backends:

- **Solidity + Foundry:** recognizes a public integer getter with a one-statement direct setter and generates executable unit, fuzz, and invariant tests.
- **Vyper + Titanoboa:** recognizes the equivalent Vyper public integer getter/direct-setter relation and generates executable Python unit, Hypothesis fuzz, and setter-sequence tests. Use `lk test-gen Counter --language vyper --types unit,fuzz,invariant --validate --strict`; the project needs Vyper, Titanoboa, pytest, and Hypothesis installed.

In a mixed-language repository, `--language solidity` or `--language vyper` selects one backend. If the requested contract name matches a source in both backends, Lowkey runs both and keeps their evidence separate: Solidity under `.audit/test-gen/<Contract>/`, Vyper under `.audit/test-gen/vyper/<Contract>/`.

Both backends are deliberately narrow. They do not infer accounting invariants, dependency setup, exploit impact, or formal properties from contract names alone. Those requests are refused unless a real scenario/property and the necessary verification configuration are supplied. Rust, Move, Cairo, and other language/build-system generators are **not yet implemented** and must not be described as supported.

Integration, exploit/PoC, regression, and formal categories are not filled with TODO scaffolds. If Lowkey cannot derive a complete artifact, it records the reason in the backend-specific `report.json` (Solidity: `.audit/test-gen/<Contract>/`; Vyper: `.audit/test-gen/vyper/<Contract>/`) and returns a nonzero status. A recorded call replay is not an exploit PoC, and a generated formal specification is not a completed proof.

`--validate` builds the untouched project, compiles the generated files in a temporary test location, and executes eligible local unit/fuzz/invariant tests. Only files created by the current invocation are validated. A compile or test pass establishes evidence for those tests only—not protocol-wide security.

The generation plugin registry currently supports Solidity + Foundry and Vyper + Titanoboa. Other languages remain explicitly unsupported until a native adapter can generate meaningful assertions, run them under the correct build system, retain results, and pass real-project tests. See [evidence-backed test generation](docs/test-generation.md) for the exact support boundary and exit semantics.

## Shared audit context

All Lowkey subsystems are designed to share one project-scoped audit state instead of operating as isolated wrappers. The state lives under `.audit/`.

~~~text
.audit/
├── context.json          current target, actor, RPC, latest transaction, tool state
├── events.jsonl          append-only audit activity/evidence stream
├── slither/
│   ├── latest.json       raw machine-readable Slither evidence
│   └── latest.sarif      SARIF evidence for editors/CI
└── ...
~~~

Useful commands:

~~~bash
lk context
lk signals
lk signals all
lk investigate SLITHER-XXXXXXXXXX
lk signals set <ID> investigating "check reentrancy path"
~~~

A Slither detector result is normalized into an audit signal with a stable ID, impact, confidence, source location, and status. Forge commands and transaction-producing Lowkey commands publish execution evidence into the same context. Generators can read that context when deciding what target or project state they are working with.

The intended workflow is therefore connected:

~~~text
STATIC SIGNAL
     ↓
AUDIT CONTEXT
     ↓
FUNCTION / STORAGE / CALL-SITE INVESTIGATION
     ↓
FOUNDRY REPRODUCTION
     ↓
TRACE + STATE DIFF + LOG EVIDENCE
     ↓
FINDING
~~~

The context is deliberately project-scoped. Lowkey configuration under `~/.lowkey/` remains for reusable user settings, wallets, aliases, and RPC preferences; `.audit/` is the audit evidence shared by the tools working on the current Foundry project.

### Connected investigation evidence

When a Slither signal is focused, concrete evidence produced by `lk changes` is attached directly to that signal. The link is automatic, so the investigation keeps the detector context and the actual state mutation together:

~~~bash
lk slither
lk findings
lk focus SLITHER-XXXXXXXXXX

# Investigate the focused signal
lk changes release --as attacker

# The exact slot + before/after values now appear with the signal
lk findings investigating
lk focus SLITHER-XXXXXXXXXX
~~~

Stored state-diff evidence includes the function, caller, result, gas, calldata, and every decoded storage change with its raw 32-byte slot and before/after values. Re-running the same evidence updates the existing evidence record instead of creating duplicates.

## Auditor-mindset question frontier
Lowkey now has a deterministic, project-agnostic question layer that turns the evidence produced by your audit into the next useful question. It is designed to teach the reasoning process without replacing it.
~~~bash
lk q
lk q why
lk q evidence
lk q path
lk q note "the owner check is enforced in withdraw()"
lk q done
lk q skip "feature is not present"
lk q source ARCH-001

lk questions
lk questions --all
~~~
The question state lives beside the audit ledger:

~~~text
.audit/
├── context.json
├── events.jsonl
└── questions/
    ├── state.json
    └── history.jsonl
~~~

The underlying question universe is stable. Lowkey does not randomly swap the checklist on every run. Instead, project type, source structure, previous answers, recent commands, traces, state changes, tests, findings, and other audit evidence move the frontier so the current question becomes progressively narrower.

The core layer applies to ordinary software projects: purpose, assets/data, trust boundaries, entry points, state machines, invariants, external dependencies, input validation, failure handling, resource exhaustion, concurrency/order, secrets, lifecycle, testing, observability, and proof. Contextual packs add narrower questions when relevant behavior is detected, including blockchain/EVM, web/API, native/runtime, and data/database concerns.

This means the question system can guide a Rust service, FastAPI application, database-backed project, CLI/tool, or smart-contract protocol without pretending those projects have the same attack surface. The existing Lowkey adapters remain stack-aware where a command genuinely depends on Foundry, EVM, Anvil, Forge, Cairo, Vyper, Solana, or another toolchain.

Every major Lowkey command contributes through the shared evidence bus. For example, project and system mapping build architecture context; read, changes, and trace add behavior/state evidence; findings and focus open validation threads; walkthrough test, fuzz, invariant, and generated tests move questions toward reproducible proof.

The teaching boundary is deliberate:

~~~text
intended rule  !=  proof of enforcement
successful call !=  vulnerability
static warning  !=  vulnerability
revert          !=  property proved
test pass       !=  invariant proved
~~~

The goal is for Lowkey to feel like an experienced reviewer asking the next useful question: establish the rule, identify the exact enforcement or state evidence, look for alternate paths, test the assumption, and only then decide what the observation means.

For the question model, command-to-evidence mapping, question states, provenance, and extension model, see docs/auditor-question-engine.md.

## Slither static analysis

Lowkey treats Slither as the static-analysis layer of the audit workflow. It runs the current project through Slither's detectors, excludes dependency-only findings by default, and saves machine-readable evidence under `.audit/slither/`.

~~~bash
# Smart default: analyze the Foundry project you are currently inside
lk slither

# Keep using any native Slither option when you want a specialized pass
lk slither --detect reentrancy-eth,tx-origin
lk slither --print human-summary
lk slither --list-detectors

# CI-style gates are explicit; the default Lowkey pass does not abort just because findings exist
lk slither --fail-high
~~~

The default Lowkey pass writes:

~~~text
.audit/slither/latest.json
.audit/slither/latest.sarif
~~~

`lk doctor` reports whether Slither is installed. `lk forge audit --checks` also runs Slither as a static-analysis stage alongside Forge lint/geiger. Lowkey does not treat a Slither detector result as a vulnerability verdict; use it to choose what to investigate and prove with Foundry tests/traces. Slither supports project-directory analysis, detector selection/exclusion, printers, JSON/SARIF export, and explicit fail thresholds. 

## Foundry power tools

Lowkey exposes useful native Foundry testing paths directly:

~~~bash
lk fuzz
lk fuzz --fuzz-runs 1000
lk fuzz replay
lk fuzz failures

lk invariant
lk invariant new EthEscrow

lk mutate
lk symbolic
lk symbolic emit
lk brutalize
~~~

These are workflow wrappers around the installed Forge version. They do not pretend to replace the underlying test engine.

Foundry currently documents persistent fuzz/invariant failures, mutation testing, invariant testing, symbolic testing, and fuzz-corpus workflows as first-class testing workflows.

## Cheatcode quick reference

~~~bash
lk cheatcodes
lk cheatcode prank
lk cheatcode deal
lk cheatcode warp
lk cheatcode roll
lk cheatcode store
lk cheatcode load
lk cheatcode etch
lk cheatcode mock
lk cheatcode state-diff
lk cheatcode ffi
~~~

The intentionally aggressive lab techniques are useful when you need to manufacture an otherwise unreachable state:

~~~solidity
vm.store(...)
vm.etch(...)
vm.mockCall(...)
vm.prank(...)
vm.warp(...)
vm.roll(...)
vm.deal(...)
~~~

vm.ffi is shown as LAB ONLY because it can execute an external command from a test environment.

## Forking

Lowkey can start and manage its own local Anvil fork:

~~~bash
lk fork https://your-rpc.example
lk fork status
lk impersonate 0x...
lk fork stop
~~~

A block can be pinned:

~~~bash
lk fork https://your-rpc.example 18000000
~~~

For repository-native Hardhat tests that pin a historical fork, Lowkey preserves the pinned block. If the project's configured RPC cannot serve that history, Lowkey does not substitute latest state. Set an archive-capable endpoint for the fallback with:

~~~bash
export LOWKEY_ARCHIVE_RPC=https://your-archive-rpc.example
~~~

The fallback starts a temporary local Hardhat JSON-RPC node at the exact pinned block and runs the project's tests against that local node. This keeps Hardhat-specific test RPC methods available and avoids changing the repository's test semantics.

The fork is started on port 8546 by default so a normal development Anvil instance on 8545 can remain running.

## Cast shortcuts

~~~bash
lk c <function> [args]
lk s <function> [args]
lk gas <function> [args]
lk tx [<tx>]
lk receipt [<tx>]
lk trace [<tx>]
lk logs --decode
lk txpool
lk selectors --compare
lk disasm
~~~

For anything Lowkey does not wrap yet:

~~~bash
lk raw <cast-command> [args...]
~~~

Native Cast arguments are passed through rather than reimplemented.

## Forge shortcuts

~~~bash
lk build
lk test

lk forge test -vvvv
lk forge inspect MyContract storage-layout
lk forge inspect-audit MyContract
lk forge test-audit --match-test testWithdraw
lk forge audit
lk forge audit --checks
~~~

inspect-audit collects ABI, methods, errors, events, and storage layout.

audit runs build, traced tests, and coverage; --checks additionally uses forge lint and forge geiger when those commands are available.

## Workspace-aware builds and source-first audit

Lowkey treats a monorepo as a workspace containing independent package scopes. A workspace overview does not merge sibling source trees into one audit target.

~~~bash
# At the workspace root
lk project
lk workspace list
lk workspace select 2
lk workspace status

# From a concrete child package, that package wins over a saved workspace selection
cd packages/perps
lk project
~~~

Member selection accepts a stable 1-based list index, package name, relative path or absolute path. The saved selection lives in the workspace-local .audit/workspace.json. A real child package directory always overrides a stale workspace-level selection. If multiple Foundry members exist and none is selected, Lowkey stops rather than guessing or mixing them.

Foundry builds use the selected package's active config. An explicit FOUNDRY_CONFIG override is respected and shown in the plan. At a workspace root, Lowkey selects the saved Foundry member, selects the only Foundry member when there is exactly one, or stops for an explicit selection when several exist—even if the workspace root also has a foundry.toml. Inside a child package, its own foundry.toml wins; a child with no Foundry config is not silently built with the workspace's config.

~~~bash
lk build --plan
lk build --scope production
lk build --scope tests --plan
lk build --scope scripts
lk build --target TrancheVault --plan
lk build --root packages/perps --scope production
lk build --scope full --low-memory
~~~

Scopes:
- full preserves the normal full-project build.
- production passes the configured src directory; Forge follows its transitive import closure.
- tests passes the configured test directory and its imports.
- scripts passes the configured script directory and its imports.
- target accepts a source path or a unique contract name and relies on Forge for the import closure.
- The source-file inventory excludes remapped/imported dependencies outside the configured source directories; Forge compiles the actual transitive closure. The plan warns when a large selected scope may be risky even with one worker, without inventing a per-contract memory estimate.

Before compiling, Lowkey reads the active Foundry config, available RAM, swap/zram, CPU availability and memory pressure where the host exposes them. It chooses a conservative worker count; an explicit Forge --threads override is preserved and may produce a warning. The planner does not estimate exact compiler memory use. It does not silently alter solc, optimizer, optimizer runs or via_ir; delete cache/artifacts; change host swap; kill unrelated processes; or retry a resource failure. Existing Foundry cache/artifacts are reused. OOM/resource termination is reported separately from Solidity diagnostics. A successful build is not a test pass or an audit-completeness claim.

Source review does not require a deployment:

~~~bash
lk risk
lk risk --source
lk findings
lk focus <SIGNAL-ID>
lk context
~~~

With no live target, lk risk produces a read-only source risk surface and labels pattern matches as syntax-only leads. It does not compile, deploy, contact an RPC or send a transaction. Live runtime risk remains separate and requires a configured target contract address, RPC URL and actor; use lk risk --runtime to request that path explicitly.

### Finding-specific AI review

~~~bash
lk findings
lk ai preview --finding <SIGNAL-ID> --show-context
lk ai explain-finding <SIGNAL-ID>
lk ai test-plan --finding <SIGNAL-ID>
~~~

The preview is local-only: it makes no provider call and shows the exact bounded, redacted source and related test context prepared for that one native signal. The explanation/test-plan commands are explicit text-provider calls and may incur provider charges. They include the local commit/ref, containing function, reachable helper/modifier/base evidence, import closure and related tests within strict limits; they do not ship the whole repository.

AI must argue both sides and return exact source references. Quote matching proves only that the quoted text exists. Every result remains unverified: it cannot change a native signal's human disposition, confirm/reject/close a finding, write or run tests, deploy, select a target, contact an RPC, sign or broadcast. lk ai test-plan --finding proposes tests only. Local Jev/Jevos decision triage is separate from the configured text provider; running Jev does not prove provider connectivity.

This initial finding-specific path uses the local checkout as its source of truth. It does not fetch public GitHub/audit URLs; remote evidence retrieval must be a separate explicit step and must never override the exact local commit.

## Audit evidence

~~~bash
lk workspace init
lk session start
lk finding add high unauthorized-release "attacker can release without creator confirmation"
lk todo "check callback path"
lk checklist
lk export
~~~

Exported evidence goes into audit-report/.

## Protocol walkthrough

Lowkey also has a visual, source-guided protocol walkthrough for understanding an unfamiliar system as one connected execution rather than a pile of isolated calls.

```bash
lk walkthrough
lk walkthrough --auto
lk walkthrough --static
lk walkthrough --contract <ContractName> --steps 10
```

The walkthrough pipeline is:

```text
Foundry build
    ↓
ABI + storage layout + source model
    ↓
actor assignment (Alice / Bob / Attacker / ...)
    ↓
source-guided workflow planning
    ↓
REAL local-Anvil transactions
    ↓
receipt + events + trace + storage/balance deltas
    ↓
terminal protocol board
    ↓
replayable Forge script + JSON evidence
```

The terminal renderer deliberately uses different visual shapes for different Solidity concepts:

```text
▣ MAPPING          ╔─ key → value ─────────────────────╗
                   │ Alice → 1000   @ computed slot     │
                   ╰─────────────────────────────────────╯

▤ STRUCT           ╔═ STRUCT Position ══════════════════╗
                   │ owner  = 0x…   [address] @ slot 2 │
                   │ amount = 1000   [uint256] @ slot 3│
                   ╚════════════════════════════════════╝

⟦ FUNCTION ⟧       Alice ────▶ deposit(uint256)

EVENT              ✦ PoolCreated(...)
TRACE              ⇢ Factory ────▶ Pool
INHERITANCE        Parent ⋯⋯⋯▶ Child
STATE              ◆ slot / balance / transition
```

`LIVE` values come from the compiler artifacts and local chain execution. Workflow ordering and generated arguments are explicitly marked `INFERRED`; Lowkey does not pretend source code reveals developer intent perfectly.

Walkthrough evidence is kept project-scoped:

```text
.audit/walkthrough/
├── model.json          compiled/source protocol model
└── latest.json         executed steps, state deltas, events and traces
script/
└── LowkeyWalkthrough_<Contract>.s.sol
```

By default the interactive runner pauses after each transaction so you can watch the protocol state evolve. `--yes` or `--non-interactive` removes prompts for automation/CI.

## Real-world finding pattern pass

```bash
lk walkthrough test --cases 24
```

The security test now includes a separate finding-pattern pass distilled from recurring, adjudicated logic seen across CodeHawks, Immunefi, Code4rena, and public bug-fix research. The suite does not copy report titles into hardcoded protocol checks.

It currently looks for patterns such as:

- replayable claims/withdrawals with user-state consumption
- external interaction before a security-sensitive state update
- read-only reentrancy around callback/quote paths
- sensitive state changes with no obvious authorization boundary
- stale oracle/round validation
- zero-share and rounding-loss candidates
- signature replay / weak domain binding
- unbounded storage loops on mutating paths
- unchecked ERC20 transfer results
- fee-on-transfer accounting assumptions
- paired-variable validation mismatches
- predictable randomness
- initializer reuse
- arbitrary external call targets
- hardcoded economic fee/rate/price parameters
- zero-address configuration boundaries
- expired deadline/expiry boundaries

Source matches are **CANDIDATE** signals. A live probe can move a pattern to **CONFIRMED** only when the local chain reproduces concrete impact evidence. Successful calls without proven impact remain **REVIEW** rather than being called vulnerabilities.

The live pattern pass also includes isolated replay, initializer, and expired-deadline probes where the ABI and local state make them executable. Every probe is snapshot-isolated and restored afterward.

Research notes and the reasoning behind each pattern are documented in `docs/walkthrough-finding-patterns.md`.

The evidence is stored in `.audit/walkthrough/test.json` under `finding_patterns`, `finding_pattern_stories`, and `finding_pattern_steps`.

## Release / reliability gate

Before treating a Lowkey checkout as ready for real audit work, run:

~~~bash
lk benchmark
lk self-test
lk doctor
~~~

`lk benchmark` is a deterministic source-triage regression suite. It verifies that the documented review-marker detectors still fire on representative Solidity/Vyper/Rust/Cairo/Move inputs and that comments/strings do not create false markers. **It is a regression gate, not a real-world vulnerability-recall or audit-quality score.**

For the integrated audit pipeline:

~~~text
exit 0  = required execution evidence completed
exit 1  = an audit/tool step failed
exit 2  = review required because security coverage is incomplete
~~~

For Solidity projects, an unavailable Slither installation now keeps the pipeline non-clean instead of silently producing exit 0. Slither detector hits are collected as evidence without turning a normal finding into a process failure; a genuine analyzer error still makes the pipeline fail. Likewise, universal source triage returning `REVIEW NEEDED`, or a Foundry project with no tests found, is propagated as exit 2.

This is intentional: **absence of a finding is never treated as evidence of safety when Lowkey did not establish the relevant coverage.**

## Install

From a machine that already has Foundry:

~~~bash
curl -fsSL https://raw.githubusercontent.com/Toji254/foundry-lowkey/master/install.sh | bash
~~~

Then:

~~~bash
lk -h
lk doctor
~~~

The installer places the Lowkey runtime under:

~~~text
~/.lowkey/
~/.foundry/bin/lk
~~~

## Project layout

~~~text
foundry-lowkey/
├── bin/lk
├── lowkey/lk.py
├── lowkey/forge_tools.py
├── lowkey/generator.py
├── lowkey/slither_tools.py
├── lowkey/audit_context.py
├── tests/test_lk.py
├── tests/test_forge_tools.py
├── .github/workflows/ci.yml
├── SECURITY.md
├── install.sh
└── README.md
~~~

## Design rule

Lowkey is deliberately opinionated about the workflow, not the verdict.

It should help you answer:

Who can call this?
What state is this contract in?
What storage changed?
What external calls happened?
What happens if the caller is hostile?
Can I reproduce it?
Can I turn it into a Forge test?
Does fuzzing/invariant/symbolic testing catch it?

That is the job.

## Project-scoped audit memory

Lowkey keeps the active audit target and investigation state in the current Foundry project's
.audit/context.json rather than relying on one global target. The .audit/ directory is ignored
by git, so each project can remember its own target, focus, latest transaction, and tool evidence.

Target resolution is project-first:

- lk target reads the current project's remembered target.
- lk target auto searches that project's Foundry broadcast/ records.
- A target remembered for another Foundry project is ignored instead of leaking into the current one.
- lk fn <query> can inspect the current project's built out/ artifacts even when no live deployment exists.

A manually registered target (`lk target <name> <address>`) is saved to the current project and can be selected later by name. Target ownership is stored separately from ABI/artifact lookup roots, so an explicitly linked contract deployed from a sibling project remains selectable even after Lowkey discovers or refreshes its external ABI. Local test/mock artifacts and aliases owned by other projects remain excluded from the project target list.

A live target is still required for state-changing investigation commands such as lk changes,
because those commands need an address on the connected chain.

### Live target safety and deployment lifecycle

Lowkey treats a configured target address as **configuration**, not proof of deployment. Before a target is
selected or a Cast-backed contract operation is executed, Lowkey checks the effective connected RPC with
eth_getCode. A target can therefore be reported as:

- **LIVE** — contract bytecode exists on the current RPC.
- **NOT DEPLOYED** — the remembered/configured address currently returns 0x bytecode.
- **UNVERIFIED** — the RPC or runtime identity could not be proven.
- **CODE MISMATCH** — bytecode exists, but does not match the selected project artifact.

This matters especially with local Anvil: restarting or replacing Anvil can leave .audit/context.json,
old broadcast files, and ABI artifacts pointing at an address that no longer exists on the new chain.

Safety behavior is fail-closed:

- lk status shows the runtime deployment state, bytecode size, chain, and recovery commands.
- lk targets shows the live state beside each remembered target.
- lk target / lk target auto refuse to activate a stale no-code target as a live contract.
- lk send, lk read, and storage-backed Cast operations refuse to execute against a target that has no
  verified bytecode. This also prevents an attached --eth value from silently becoming a plain ETH
  transfer to an empty address.
- lk lab clears an invalid/stale remembered target before establishing a fresh local deployment.
- Successful lab target selection records runtime deployment evidence with the project audit context.

When deployment state is uncertain, use:

~~~bash
lk status
lk recon
lk deployments
lk target auto
lk lab
~~~

lk balance remains intentionally read-only and may inspect EOAs or empty addresses because balance lookup
does not claim that the address is a deployed contract.

<!-- unified regression gate: keep branch tip continuously validated -->


## Finding-specific source review

See [Finding-specific investigation and remote evidence](docs/finding-specific-review.md) for the local-first finding explainer, preview-only behaviour, explicitly requested public URLs, remote-source safety limits, and the plan-first verification/test-execution boundary.
