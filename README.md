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

Lowkey auto-detects a running local Anvil node when no RPC is configured. For Anvil's default development accounts, actor keys are derived only when needed and are not stored in Lowkey config.

A normal local workflow can therefore be:

```bash
lk --h
lk actor                 # choose account 0 and name it Alice
lk actor 1 Bob           # choose another Anvil account
lk target 0x...          # point at the deployed contract
lk status                # ABI is auto-discovered from local artifacts
lk scan src/EthEscrow.sol
lk deps
lk functions
lk risk
lk recon
lk forge inspect-audit Escrow
lk c escrow 1
lk s createescrow 1 0x... --preview
lk trace
lk logs --decode
lk export
```

The manual commands still exist for unusual setups:

```bash
lk rpc http://127.0.0.1:8545
lk abi out/EthEscrow.sol/Escrow.json
lk wallet set-env attacker LK_ATTACKER_KEY
```

`lk functions` separates normal read/write functions from storage getter functions such as public mapping getters.

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