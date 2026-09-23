# Foundry LowkeyCast

LowkeyCast (lk) is a small auditor-oriented command line tool that sits on top of Foundry. It keeps the repetitive parts of contract research, Anvil interaction, storage inspection, transaction forensics, and test reproduction behind one workflow.

The core idea is simple:

RECON → ATTACK → PROVE

Lowkey does not replace Forge or Cast. It orchestrates them and adds the local audit workflow around them.

## Start here

~~~bash
anvil

lk -h
lk doctor
lk actor

lk actor 0 Alice
lk actor 1 Bob
lk actor 2 attacker

lk target 0x...
lk status
~~~

Lowkey automatically detects a local Anvil RPC on the common ports. For the default Anvil mnemonic it binds actors to account numbers and derives the corresponding key only when a signed local transaction is needed.

## Everyday audit flow

~~~bash
lk recon
lk deps
lk functions
lk fn release
lk ask createEscrow

lk c balances 0x...
lk s createEscrow 1 0x... --preview

lk selectors --compare
lk disasm
lk calldata 0x...
lk trace
lk logs --decode
~~~

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

## Attack lab

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
