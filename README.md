# Foundry LowkeyCast

LowkeyCast is a small auditor-oriented CLI that sits on top of Foundry Cast. It keeps common contract-research, transaction-forensics, storage-inspection, and audit-workflow actions behind one command: `lk`.

## What it does

### Contract interaction
- Target aliases and numbered target switching
- RPC profiles
- Wallet profiles with optional environment-backed private keys
- ABI loading with canonical tuple/struct signatures
- Overload detection instead of silently choosing the first match
- Read/send shortcuts: `lk c`, `lk s`, `lk st`
- Transaction previews and confirmation prompts
- Function search and argument wizard
- Calldata, return-data, custom-error, and event decoding

### Auditor inspection
- Contract reconnaissance: balance, codehash, code size, nonce
- EIP-1967 proxy inspection plus implementation/admin resolution
- Mapping-slot calculation
- ERC-7201 namespace indexing
- Storage proofs
- Runtime selector extraction
- Target/chain-scoped storage snapshots and diffs
- ERC20 metadata and holder balance helpers
- ENS forward/reverse lookup

### Source and forensic tooling
- Solidity review-marker scanner
- Import/inheritance map
- Forge storage-layout inspection
- ABI-level function risk-surface heuristic
- Gas estimation
- Transaction replay/trace helpers
- Log querying and optional ABI event decoding
- Raw Cast passthrough
- Batch command files

### Audit workflow
- Findings, notes, TODOs, sessions, checklist
- Attacker-state matrix
- Forge reproduction/test skeleton generation
- Audit dashboard
- Exportable `audit-report/`

These inspection and triage commands are deliberately heuristic: they help surface things to review; they do not declare that a contract is vulnerable.

## Install

From a machine with Foundry already installed:

```bash
curl -fsSL https://raw.githubusercontent.com/Toji254/foundry-lowkey/master/install.sh | bash
```

Then:

```bash
lk --help
lk self-test
lk doctor
```

The installer copies:

```text
~/.lowkey/lk.py
~/.foundry/bin/lk
```

## Typical audit flow

```bash
lk rpc set anvil http://127.0.0.1:8545
lk target auto

lk status
lk recon
lk functions
lk risk
lk scan src
lk deps src

lk snapshot 0 1 2 3
lk c someView
lk s someWrite --preview
lk receipt
lk last tx
lk trace
lk logs --decode

lk matrix init
lk matrix actor attacker 0x...
lk matrix add unauthorized-release release attacker "should revert"
lk matrix test unauthorized-release

lk export
```

For a historical transaction:

```bash
lk tx 0x...
lk replay 0x... --trace-printer --decode-internal
```

For a fork:

```bash
lk fork https://example-rpc.example
# Start the printed Anvil command, then:
lk rpc http://127.0.0.1:8545
```

## Wallet security

Prefer environment-backed signers:

```bash
export LK_ATTACKER_KEY=...
lk wallet set-env attacker LK_ATTACKER_KEY
lk wallet use attacker
```

`lk wallet set` is intended for local/test keys and stores the supplied private key in `~/.lowkey/config.json`. The file is restricted to mode 0600, but that does not make plaintext key storage a production key-management system.

## Source layout

```text
foundry-lowkey/
├── bin/
│   └── lk
├── lowkey/
│   └── lk.py
├── tests/
│   └── test_lk.py
├── .github/
│   └── workflows/
│       └── ci.yml
├── SECURITY.md
├── install.sh
├── README.md
└── .gitignore
```



## Lowkey project-aware generation

Lowkey can generate readable, project-aware Foundry artifacts instead of only passing commands through to Forge:

```bash
# Rebuild, inspect the compiled artifact, and generate a reusable deployment script
lk generate deployment EthEscrow

# Generate a PoC from the latest recorded cast send
lk generate poc

# Generate a Foundry reproduction test from the latest recorded cast send
lk generate test

# Or provide the call explicitly
lk generate test createescrow(uint256,address) 1000000000000000000 0x0000000000000000000000000000000000000001 --value 1ether
```

Generated files are intentionally teaching-oriented. The Solidity includes focused `//` comments beside important Foundry ideas such as `vm.prank`, `vm.startBroadcast`, `vm.deal`, `vm.snapshot`, revert-data handling, assertions, and the difference between transaction success and a proven security property.

The deployment generator uses the compiled ABI to externalize constructor inputs, adds post-deployment sanity checks, and writes a machine-readable deployment record. The PoC generator replays concrete calldata and records before/after balances. The test generator turns the same observation into a deterministic Forge test where the actual invariant or exploit condition is deliberately left for the auditor to define.

These generators are scaffolding and education aids; they do not automatically declare that behavior is vulnerable.

## LowkeyForge audit layer

LowkeyCast now includes a deliberately thin Forge layer. It removes repetitive
typing without hiding Forge behavior: native commands are passed through
unchanged.

### Native Forge passthrough

```bash
lk forge test -vvvv
lk forge build
lk forge inspect MyContract storage-layout
lk forge script ...
lk forge coverage
lk forge lint
lk forge geiger
```

The high-frequency commands `build`, `test`, `script`, `inspect`,
`coverage`, `lint`, `geiger`, and `fmt` also have direct
shortcuts such as `lk test` and `lk build`. Existing LowkeyCast commands
remain unchanged.

### Audit shortcuts

```bash
lk forge test-audit
lk forge test-audit --match-test testWithdraw
lk forge inspect-audit MyContract
lk forge audit
lk forge audit --checks
```

- `test-audit` runs native `forge test` with `-vvvv` unless you provide
  your own verbosity.
- `inspect-audit` builds first, then collects ABI, method identifiers, errors,
  events, and storage layout.
- `audit` runs build, traced tests, and coverage. `--checks` additionally
  runs `forge lint` and `forge geiger` when those commands exist in the
  installed Forge version.
- Use `lk forge <command> --help` whenever you need the exact native Forge
  behavior or options.

These helpers automate workflow only. They do not detect, rank, score, or
declare vulnerabilities.
