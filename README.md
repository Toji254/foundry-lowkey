# Foundry LowkeyCast

LowkeyCast (lk) is a small auditor-oriented command line tool that sits on top of Foundry. It keeps the repetitive parts of contract research, Anvil interaction, storage inspection, transaction forensics, and test reproduction behind one workflow.

The core idea is simple:

RECON → ATTACK → PROVE

Lowkey does not replace Forge or Cast. It orchestrates them and adds the local audit workflow around them.

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
lk -h
lk project
lk system
lk lab
lk walkthrough --auto --steps 8
lk walkthrough test --cases 24
lk walkthrough test --cases 24 --technical
lk audit run
lk audit run --poc
lk poc
~~~

#### Beginner-first walkthrough view

`lk walkthrough test` uses a simple teaching view by default. Each probe is reduced to one of four labels:

- `✅ NORMAL` — Lowkey has an explained reason for the rejection.
- `⚠️ CHECK THIS` — the chain accepted a state-changing action; inspect what changed.
- `❓ UNKNOWN` — Lowkey cannot yet prove why the call failed.
- `🔧 LAB ISSUE` — the local test setup appears broken, so the result should not be treated as a protocol finding.

The output tells you what happened, why it matters, and what source/function to inspect next. The full forensic renderer is still available with `lk walkthrough test --technical`.

The teaching layer is language-neutral: it does not assume the target is Solidity or a particular protocol. It can label Solidity, Vyper, Move, Cairo, Tact, FunC, Clarity, Rust, and unknown source files without changing the underlying audit semantics. Chain execution remains adapter-specific, so a language needs a compatible build/runtime adapter before live probes can run.
### Working inside a multi-project workspace

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
- Audit engine: runs project-aware build/test/coverage evidence, Slither when available, source triage, and PoC scaffolding. Vyper-aware preparation is retained for mixed/non-Foundry projects.
- Protocol walkthrough: uses the richer local Foundry walkthrough/lab engine for actual stateful execution and replayable observations.

lk audit and lk audit run are intentionally separate surfaces: the former is the interactive Lowkey audit console; the latter is the evidence pipeline. Neither should be read as a vulnerability verdict.
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

Plain `lk audit` detects and uses an existing Anvil node but never starts one. `lk audit auto` is the autonomous local mode: it starts a project-owned Anvil when needed, binds a safe local actor, resolves a project target when possible, and may deploy a zero-constructor-argument local artifact without inventing constructor values. Both modes collect the same audit evidence and PoC scaffold; `--checks` adds Slither and optional lint/geiger checks.

## Actors

Use actor names so your audit notes read like an attack story instead of a wall of addresses.

~~~bash
lk actor 0 Alice
lk actor 1 Bob
lk actor 2 attacker

lk actor
lk as attacker c balances 0x...
lk as attacker s release --preview
~~~

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

Lowkey’s import browser is a project-aware Solidity dependency and usage guide. It can resolve real symbols from `src/` and `lib/`, or fall back to a verified reference catalog for common components such as OpenZeppelin, Chainlink, and forge-std.

~~~bash
# Interactive browser
lk import

# Look up one thing
lk import ERC721
lk import AggregatorV3Interface

# Browse common reference entries
lk import common
~~~

A symbol lookup shows:

~~~text
package
install status
Forge install command
verified Solidity import
why to use it
when to use it
practical use cases
a small usage example
audit lens / things to inspect
~~~

For symbols that are already installed, Lowkey prefers the actual source and remapping discovered in the current Foundry project. For symbols that are not installed but exist in the reference catalog, Lowkey still explains the dependency and gives the standard install/import recipe.

Installation is explicit and idempotent:

~~~bash
lk import --install ERC721
lk import install AggregatorV3Interface
~~~

`--install` is the only import-helper mode that mutates the project. Lowkey runs only a verified `forge install ...` command, skips dependencies that are already installed, and leaves ordinary lookups read-only.

For unknown installed packages, Lowkey can inspect the package’s Git remote and derive a `forge install owner/repo` hint when the remote is a GitHub repository. It does not invent an install command when the source or remote cannot be verified.

The reference data is intentionally separated from project discovery: a local contract named `ERC721` or `Ownable` is not mislabeled as OpenZeppelin unless its source/import path matches the verified reference.

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

# Generate a PoC from the latest recorded cast send
lk generate poc

# Generate a Foundry reproduction test from the latest recorded cast send
lk generate test

# Or provide the call explicitly
lk generate test createescrow(uint256,address) 1000000000000000000 0x0000000000000000000000000000000000000001 --value 1ether
~~~

Generated Solidity is intentionally teaching-oriented. Focused `//` comments sit beside important Foundry ideas such as `vm.prank`, `vm.startBroadcast`, `vm.deal`, `vm.snapshot`, revert-data handling, assertions, and the difference between transaction success and a proven security property.

The deployment generator uses the compiled ABI to externalize constructor inputs, adds post-deployment sanity checks, and writes a machine-readable deployment record. The PoC generator replays concrete calldata and records before/after balances. The test generator turns the same observation into a deterministic Forge test where the actual invariant or exploit condition is deliberately left for the auditor to define.

These generators are scaffolding and education aids; they do not automatically declare that behavior is vulnerable.

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

A live target is still required for state-changing investigation commands such as lk changes,
because those commands need an address on the connected chain.


<!-- unified regression gate: keep branch tip continuously validated -->
