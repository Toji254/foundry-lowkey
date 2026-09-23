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
lk --h
lk self-test
lk doctor
```

The installer copies:

```text
~/.lowkey/lk.py
~/.foundry/bin/lk
```

## Typical audit flow

Lowkey is designed around a local Foundry/Anvil audit workflow. You normally do **not** need to paste an ABI path or RPC URL when Anvil is running.

Anvil accounts are discovered automatically. For the default Anvil mnemonic, Lowkey derives the selected private key only when a transaction needs signing; it is not stored in Lowkey config. The selected account is locked to its actor name, so you cannot assign the same Anvil account number to a second actor until the first profile is removed.

```bash
anvil

lk --h
lk actor
lk actor 0 Alice
lk actor 1 Bob
lk target 0x...
lk status

lk scan src/EthEscrow.sol
lk deps
lk functions
lk fn release
lk ask createEscrow

lk c balances 0x...
lk s createEscrow 1 0x... --preview
lk trace
lk logs --decode

lk forge inspect-audit EthEscrow
lk export
```

`lk deps` scans the whole Foundry project by default and can also inspect one file:

```bash
lk deps
lk deps src/EthEscrow.sol
```

`lk functions` separates write functions, normal read functions, and public storage getters. A mapping such as `mapping(address => uint256) balances` still has an ABI getter (`balances(address)`), but it is shown under `STORAGE GETTERS` instead of being mixed into ordinary read functions.

### Automatic ABI discovery

After `lk target <address>`, Lowkey looks for the matching Foundry artifact in `out/` when a command needs an ABI. It uses the contract name from a deployment record when available, otherwise it can match deployed bytecode against local artifacts when an RPC is available.

You can still manually override the ABI for unusual layouts:

```bash
lk abi out/EthEscrow.sol/EthEscrow.json
```

Manual ABI paths are an override, not the normal workflow.

### Actors

```bash
lk actor
lk actor 0 Alice
lk actor 1 Bob
lk actor reset
```

For a default Anvil node, `lk actor` shows the available account numbers and who already owns each one. Lowkey will refuse:

```bash
lk actor 0 Alice
lk actor 0 Bob
```

because account `0` is already assigned to Alice.

Lowkey verifies that an Anvil-derived key still matches the live account before using it. If you switch to a custom Anvil mnemonic or another RPC, use an environment-backed signer instead of the default development keys.

### Manual RPC / wallets

```bash
lk rpc http://127.0.0.1:8545
lk wallet set-env attacker LK_ATTACKER_KEY
lk wallet use attacker
```

Use these when you intentionally want a specific network or a non-default signer.

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
