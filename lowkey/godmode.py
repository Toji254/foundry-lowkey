#!/usr/bin/env python3
"""Evidence-first offensive-security workflows for Lowkey.

Static signals are leads. Executed attacks, sequential controls, economic
measurements and reproofs are separate evidence stages.
"""
from __future__ import annotations

import argparse
import hashlib
import queue
import signal
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
try:
    import shared_context
    import capability_registry
except ImportError:
    from lowkey import shared_context, capability_registry

try:
    from .arithmetic_review import scan_source as scan_unsigned_source, _mask_comments_and_strings
except ImportError:
    from arithmetic_review import scan_source as scan_unsigned_source, _mask_comments_and_strings

VERSION = "0.2.0"
EXTS = {".sol", ".vy", ".yul", ".huff", ".rs", ".move", ".cairo"}
SKIP = {".git", ".audit", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", "lib", "out", "cache", "artifacts", "build", "dist", "target", "vendor", "coverage"}
EIP1967 = {
    "implementation": "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
    "admin": "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",
    "beacon": "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",
}
CAPABILITIES = capability_registry.CAPABILITIES

HELP_FLAGS = {"-h", "--h", "--help", "help"}

# This list mirrors the first Godmode dispatch case in bin/lk. The help test
# compares the two, so adding a shell route without adding it here fails CI.
ROUTED_COMMANDS = capability_registry.ROUTED_COMMANDS

GODMODE_COMMAND_DETAILS = {
    "capabilities": {
        "summary": "List the 44 registered Godmode capabilities and their honest implementation states.",
        "when": "Use it before relying on a capability or planning an audit workflow.",
        "example": "lk capabilities",
        "limits": "A registered name is not proof of a working exploit generator; partial and adapter-required states are deliberate.",
    },
    "archetype": {
        "summary": "Generate a protocol-shaped invariant starter, or classify source with the deterministic P3 archetype packs.",
        "when": "Use 'lk archetype classify' for source-backed classification; use a named profile only to render a starter checklist.",
        "example": "lk archetype classify --root . --json",
        "limits": "Classification is source-level, confidence-bounded and not deployment authentication or vulnerability proof. Ambiguous targets remain UNCLASSIFIED.",
    },
    "assumptions": {
        "summary": "Re-read the source citations in a saved P3 assumption ledger and verify their file hashes and cited lines.",
        "when": "Use it after archetype classification to check that every assumption citation still resolves.",
        "example": "lk assumptions --root .",
        "limits": "Citations establish where a trust assumption was extracted, not whether the assumption holds or is violated.",
    },
    "capability": {
        "summary": "Show the capability negotiation and explicit generic-mode skip list from a saved protocol classification.",
        "when": "Use it after 'lk archetype classify' to see which protocol-specific work Lowkey can and cannot perform.",
        "example": "lk capability --root .",
        "limits": "Only capabilities marked implemented are considered available; partial and adapter-required entries remain skipped.",
    },
    "godmode": {
        "summary": "Audit the Solidity source under --root, report source-level security leads, and optionally inspect a deployed target. It does not send a transaction by default.",
        "when": "Start here when you do not know which Godmode subcommand to use. Run it on the project folder first; add a target address and RPC only when you also want read-only on-chain reconnaissance.",
        "example": "START HERE — source-only scan (no address or RPC needed):\n  lk godmode --root .\n\nExplicit static-only plan (no RPC, attack, mutation or coverage execution):\n  lk godmode --root . --plan-only\n\nAdd read-only on-chain reconnaissance:\n  lk godmode 0xYourTargetAddress --root . --rpc-url http://127.0.0.1:8545\n\nOpt into local-Anvil attack exploration only after reviewing the target and controls:\n  lk godmode 0xYourTargetAddress --root . --rpc-url http://127.0.0.1:8545 --attack --control-manifest .audit/control.json",
        "limits": "Static matches are review leads, not confirmed vulnerabilities. --attack invokes lk break and is restricted to a local Anvil RPC; it can execute transactions on that disposable chain. --plan-only skips RPC, attack, mutation and coverage execution but still writes .audit/godmode/latest.json and provenance.json. A BREAK still requires matched control and independent evidence.",
    },
    "control": {
        "summary": "Compare an attack against a sequential control using matched execution evidence and a frozen experiment specification.",
        "when": "Use it before promoting a candidate BREAK; freeze expectations first, validate the freeze, then execute with the matching frozen inputs.",
        "example": "lk control --validate  # uses .audit/control.json; no RPC is needed",
        "limits": "Anvil callTracer mode accepts a local Anvil RPC only. Forge state-diff results are structural evidence, not gas-adjusted EOA profit.",
    },
    "trace-parity": {
        "summary": "Compare saved canonical Forge and Anvil traces field by field, preserving unknowns and storage-evidence limits.",
        "when": "Use it after running the same frozen experiment on both backends to check call-tree and calldata parity.",
        "example": "lk trace-parity .audit/forge-control.json .audit/anvil-control.json --root .",
        "limits": "The comparator cannot make transaction-level prestateTracer changes equivalent to Forge per-access storage observations; it reports that storage degradation explicitly.",
    },
    "steps": {
        "summary": "Validate a typed Step[] manifest and render a hash-addressed Foundry harness, with explicit machine-readable refusals.",
        "when": "Use it to turn a supported execution plan into a reviewable Solidity harness before running Forge tests.",
        "example": "lk steps .audit/steps.json --root . --output test/GeneratedSteps.t.sol --refusal-output .audit/steps-refusal.json",
        "limits": "The 15 family labels share a generic executable sequence; they are not 15 protocol-specific exploit generators. Generic flash_borrow and reenter callback steps remain backend_unsupported.",
    },
    "reprove": {
        "summary": "Re-run a PoC on a cheatcode-free local fork and calculate portfolio profit from a mined transaction receipt.",
        "when": "Use it after a candidate exploit has a reproducible harness and you need transaction, trace, gas, storage, and net-cost evidence.",
        "example": "lk reprove test/Exploit.t.sol --root . --rpc-url http://127.0.0.1:8545 --fork-block 19000000 --target-address 0x1111111111111111111111111111111111111111 --profit-address 0x2222222222222222222222222222222222222222 --prior-cost-wei 1000000000000000",
        "limits": "Pass verified prior deployment/funding/setup expenditure through --prior-cost-wei. Without it, net profit subtracts replay gas only. A local fixture is not production-deployment proof.",
    },
    "mutation-score": {
        "summary": "Run the configured mutation campaign against a manifest and enforce a minimum mutation score.",
        "when": "Use it to check whether the test suite detects representative security-relevant code changes.",
        "example": "lk mutation-score .audit/mutations.json --min-score 0.90 --timeout 300",
        "limits": "A mutation score measures test sensitivity; it does not establish exploitability or impact by itself.",
    },
    "target-coverage": {
        "summary": "Report Forge LCOV reachability for a selected source file and optional line interval.",
        "when": "Use it to see whether a harness reaches the target lines being discussed.",
        "example": "lk target-coverage src/Vault.sol --start-line 40 --end-line 95",
        "limits": "Coverage is reachability evidence, not assertion quality or proof of security impact.",
    },
    "provenance": {
        "summary": "Hash selected evidence artifacts and record the project revision, chain, fork, and tool versions; optionally sign the report.",
        "when": "Use it when saving a reproducible audit run or preparing evidence for review.",
        "example": "lk provenance .audit/godmode/latest.json --chain-id 31337 --fork-block 100",
        "limits": "A hash proves artifact identity, not correctness of the experiment or its conclusion.",
    },
    "fidelity": {
        "summary": "Inspect harness fidelity or append a declared evidence-strength record to the evidence ledger.",
        "when": "Use it to distinguish heuristic/simulated evidence from more realistic fork reproduction.",
        "example": "lk fidelity --inspect test/Exploit.t.sol",
        "limits": "The scanner is static and can miss aliases, wrappers, or custom state manipulation.",
    },
    "sandbox": {
        "summary": "Run an untrusted command in an isolated, network-disabled bubblewrap copy of the project.",
        "when": "Use it before executing untrusted build/test steps when bubblewrap is installed.",
        "example": "lk sandbox --root . --timeout 300 -- forge test",
        "limits": "If bubblewrap is unavailable, Lowkey refuses to run the command unsandboxed.",
    },
    "cheat-fingerprint": {
        "summary": "Scan source for dangerous cheatcode and state-fabrication sequences that can weaken exploit evidence.",
        "when": "Use it to review generated harnesses or replay scripts for synthetic state changes before trusting a reproduction.",
        "example": "lk cheat-fingerprint --root .",
        "limits": "This is a static source-pattern scan. A hit is a review lead, not proof that a test is invalid or an exploit is real.",
    },
    "decompile": {
        "summary": "Decompile unverified bytecode through a configured Heimdall adapter.",
        "when": "Use it when source is unavailable and a supported decompiler adapter is installed.",
        "example": "lk decompile --help",
        "limits": "Currently adapter-required; Lowkey refuses to guess a decompiler invocation.",
    },
    "flashmax": {
        "summary": "Prepare a venue-specific flash-loan integration plan for Aave, Balancer, or Uniswap V3.",
        "when": "Use it only after a protocol-specific callback adapter and venue details are available.",
        "example": "lk flashmax aave 0x1111111111111111111111111111111111111111 --adapter ./adapters/aave.py",
        "limits": "Requires a venue adapter. The command does not borrow funds or claim profitability.",
    },
    "sandwich": {
        "summary": "Simulate sandwich ordering using a pending-transaction feed and pool-specific simulator.",
        "when": "Use it only when a supported mempool feed and pool adapter are configured.",
        "example": "lk sandwich --help",
        "limits": "Adapter-required; no transaction is broadcast.",
    },
    "jit": {
        "summary": "Simulate just-in-time liquidity ordering using a pool-specific simulator.",
        "when": "Use it only when a supported pool adapter is configured.",
        "example": "lk jit --help",
        "limits": "Adapter-required; no transaction is broadcast.",
    },
}

_CAPABILITY_BY_NAME = {
    name: {"title": title, "status": status}
    for _number, name, title, status in CAPABILITIES
}


GODMODE_HELP_GUIDES = {
    "capabilities": {
        "usage": "lk capabilities",
        "when": "Use this before choosing an advanced command. It shows what is registered and whether Lowkey considers each capability implemented, partial, or adapter-required.",
        "variations": [
            "lk capabilities — print the full capability table; no files or chain state are changed."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "None."
        ],
        "workflow": [
            "Read the status column first. Prefer implemented capabilities for a workflow; treat partial as an investigative aid and adapter-required as unavailable until its adapter exists."
        ],
        "output": [
            "A numbered capability inventory with status and a short description."
        ],
        "limits": "A registered command name is not proof that its full workflow is implemented. Partial and adapter-required are intentional, meaningful states.",
        "related": [
            "lk godmode --h",
            "lk report --h"
        ]
    },
    "godmode": {
        "usage": "lk godmode [<target-address>] [--root DIR] [options]",
        "when": "Use this as the first audit command. Normally just type lk godmode. Lowkey detects the current project automatically. When you have a remembered target and project RPC, it can also inspect that deployment read-only. It never starts an attack unless you explicitly request --attack.",
        "variations": [
            "1) NORMAL USE — just run:  lk godmode",
            "   Lowkey detects the project from your current folder (including when you are inside src/ or test/). You do not need to type --root or any other flags.",
            "2) If you run it from Lowkey's own source checkout, it resumes the project attached to your currently selected target or last audit. If several previous projects are equally possible, it asks you to choose rather than guessing.",
            "3) If you deliberately want to scan a different project, use --root as an override:  lk godmode --root \"$HOME/path/to/project\"",
            "4) If you want to inspect a different deployment, pass its address. The address must exist on the selected RPC:  lk godmode 0xYOUR_LIVE_ADDRESS --rpc-url http://127.0.0.1:8545",
            "5) Active attack testing is always a separate opt-in:  lk godmode --attack. It uses the remembered project target/RPC, or add the target address and --rpc-url explicitly."
        ],
        "arguments": [
            "target-address — optional deployed contract address override. Normally Lowkey reuses the target already remembered for this project. You only need to supply an address when inspecting a different deployment; copy it from lk targets."
        ],
        "options": [
            "--root DIR — optional project-folder override. Lowkey normally detects the project containing your current directory. Use this only when you intentionally want to audit a different folder.",
            "--rpc-url URL — optional RPC override. If the current project's Lowkey context already remembers an RPC, Godmode uses it for read-only inspection. Otherwise omit it for a source-only scan.",
            "--profile light|balanced|deep — advanced on-chain proxy/storage scan depth: light checks 40 slots; balanced/deep check up to 120. Most users can ignore this.",
            "--attack — explicitly start active attack exploration through lk break. This is the only Godmode option that starts attack execution. Requires a deployed target and local Anvil; it can send transactions on that disposable local chain. Never point it at production.",
            "--ai-review — opt into semantic source review using the configured AI provider. Selected source excerpts leave this machine; all returned findings are unverified candidates. Without this flag, Godmode does not send source excerpts to an AI provider.",
            "--control-manifest FILE — advanced matched attack/control JSON manifest. Normally leave this alone; Lowkey's standard source scan does not need it. Use only with --attack after preparing and freezing the experiment; see lk control --h.",
            "--mutation-manifest FILE — advanced JSON recipe for deliberate source mutations and repeated test runs. Normally leave this alone; use it after a test suite exists. It requires command (for example [\"forge\", \"test\"]) and mutants entries with id, file, before, and after.",
            "--coverage-source FILE — optional Solidity file to measure (for example src/Token.sol). Use after you have relevant tests; coverage shows executed lines, not whether the tests assert the correct property.",
            "--plan-only — force a strictly local source scan. It disables RPC reads, attacks, mutation tests and coverage even when target/RPC context is remembered. Use this when you explicitly want no chain access."
        ],
        "workflow": [
            "1. Run lk godmode. Lowkey finds the project root automatically and scans its source.",
            "2. If the project has a remembered target and RPC, Godmode adds read-only chain inspection. If not, it stays source-only. Neither mode sends transactions.",
            "3. Review the potential source leads. Counts are code matches, not vulnerability totals. Use --ai-review only when you explicitly want selected source excerpts reviewed by the configured AI provider.",
            "4. Run lk report to create a readable Markdown report. It separates candidate findings, attack outcomes, proof gaps and navigation markers. You do not need to pass --root for the detected project.",
            "5. Only when you deliberately want active testing, run lk godmode --attack on local Anvil. The target/RPC can be taken from the current project's saved context."
        ],
        "output": [
            ".audit/godmode/latest.json — detailed source and optional chain results.",
            ".audit/godmode/provenance.json — hash of the saved report and run context.",
            "lk report — creates .audit/godmode/report.md, the readable version."
        ],
        "limits": "Source matches are investigation leads, not confirmed vulnerabilities. REVIEW_REQUIRED means this run has not completed all proof gates; it does not mean the command crashed. Read-only inspection is safe to run automatically when the project has a remembered target/RPC. Active attack execution remains opt-in and local-Anvil-only. AI-assisted source review is separately opt-in with --ai-review; selected source excerpts are sent to the configured provider and its findings remain unverified.",
        "related": [
            "lk targets",
            "lk break --h",
            "lk control --h",
            "lk mutation-score --h",
            "lk target-coverage --h",
            "lk report --h"
        ]
    },
    "control": {
        "usage": "lk control [MANIFEST] [--root DIR] [--rpc-url URL] [options]",
        "when": "Use this to compare a candidate attack with a matched sequential control before promoting a BREAK. Freeze the experiment first, validate the freeze, then execute against those frozen inputs.",
        "variations": [
            "lk control — use the default .audit/control.json manifest and the project's saved/environment RPC when available.",
            "lk control --freeze — freeze inputs and expectations without running the attack/control; no RPC is needed.",
            "lk control --validate — validate the frozen spec without executing it; no RPC is needed.",
            "lk control --require-frozen — execute only when a matching frozen spec exists; an RPC is needed and is resolved from project context/environment when available.",
            "Add --source-rpc-url <archive-url> when independent source-chain verification is required."
        ],
        "arguments": [
            "MANIFEST — optional JSON experiment manifest. Defaults to .audit/control.json when that file exists; otherwise create/provide the experiment manifest explicitly."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--rpc-url URL — needed only when executing. Lowkey first reuses the current project's saved RPC or a configured RPC environment variable.",
            "--source-rpc-url URL — optional independent read-only archive RPC.",
            "--output FILE — verdict JSON; default: .audit/godmode/control.json.",
            "--freeze — hash/freeze manifest, commands, harnesses and expectations; does not execute them.",
            "--validate — validate the frozen specification only.",
            "--freeze-file FILE — integrity-bound freeze file; default: .audit/godmode/control.freeze.json.",
            "--require-frozen — refuse execution without a matching freeze.",
            "--non-economic — require a passing semantic invariant instead of positive profit."
        ],
        "workflow": [
            "Create the manifest with an attack and a sequential control that differ only in the suspected exploit condition.",
            "Run --freeze and keep the resulting freeze file with the audit evidence.",
            "Run --validate after any manifest or harness change.",
            "Execute with --require-frozen only when the frozen inputs match the test you intend to run."
        ],
        "output": [
            "Machine-readable verdict at --output.",
            "Frozen expectation file at --freeze-file when --freeze is used."
        ],
        "limits": "The control is meaningful only when attack and control are matched. Anvil callTracer mode is local-Anvil-only. Forge state-diff evidence is structural; it is not automatically gas-adjusted EOA profit.",
        "related": [
            "lk godmode --h",
            "lk trace-parity --h",
            "lk fidelity --h",
            "lk reprove --h"
        ]
    },
    "trace-parity": {
        "usage": "lk trace-parity FORGE.json ANVIL.json [options]",
        "when": "Use it after the same frozen experiment has been recorded on Forge and Anvil. It compares canonical trace fields and reports mismatches or evidence loss.",
        "variations": [
            "lk trace-parity .audit/forge-control.json .audit/anvil-control.json --root .",
            "Use --forge-scenario control --anvil-scenario control when comparing controls instead of the default attack scenario."
        ],
        "arguments": [
            "FORGE.json — saved Forge evidence containing canonical_trace_events.",
            "ANVIL.json — saved Anvil evidence containing canonical_trace_events."
        ],
        "options": [
            "--root DIR — project root for input/output paths; default: .",
            "--forge-scenario control|attack|negative_control — scenario selected from Forge evidence; default: attack.",
            "--anvil-scenario control|attack|negative_control — scenario selected from Anvil evidence; default: attack.",
            "--output FILE — parity report; default: .audit/godmode/trace-parity.json."
        ],
        "workflow": [
            "Run the same experiment on each backend with the same target, actors and inputs.",
            "Save both canonical trace evidence files.",
            "Run the comparator with the matching scenario names.",
            "Review every UNKNOWN or degraded field instead of treating it as equal."
        ],
        "output": [
            "JSON parity report; default: .audit/godmode/trace-parity.json."
        ],
        "limits": "Trace parity does not make Anvil prestateTracer storage deltas equivalent to Forge per-access storage observations. It preserves and reports those limitations.",
        "related": [
            "lk control --h",
            "lk provenance --h",
            "lk fidelity --h"
        ]
    },
    "steps": {
        "usage": "lk steps MANIFEST.json [--root DIR] [options]",
        "when": "Use this to validate a typed Step[] execution plan and render a reviewable Foundry harness before running Forge.",
        "variations": [
            "lk steps .audit/steps.json --root .",
            "Minimal manifest shape: {\"family\":\"accounting\",\"target_address\":\"0x1111111111111111111111111111111111111111\",\"steps\":[{\"kind\":\"call\",\"selector\":\"0x12345678\",\"args\":[{\"type\":\"uint256\",\"value\":1}],\"value\":0}]}",
            "Choose a custom harness path with --output test/GeneratedSteps.t.sol.",
            "Choose a custom machine-readable refusal path with --refusal-output .audit/refusal.json."
        ],
        "arguments": [
            "MANIFEST.json — project-local JSON object with exactly family, optional target_address, and steps.",
            "family — one of reentrancy, replay, access, accounting, boundary, time, upgrade, callback, oracle, economic, erc20, proxy, storage, signature or dos.",
            "target_address — optional default 20-byte target address used when a step omits target.",
            "steps — non-empty array, maximum 128 entries. Each item uses only kind, target, selector, args, value, optional and expect.",
            "ABIValue — each args entry is exactly {\"type\":\"uint256\",\"value\":1} (use the actual ABI type)."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--output FILE — generated Solidity harness; default: .audit/godmode/steps/step-harness.t.sol.",
            "--refusal-output FILE — machine-readable refusal JSON; default: .audit/godmode/steps-refusal.json.",
            "Step kinds — call, read, unwind, skew, expect, assert, warp, roll, snapshot and revert are recognised. flash_borrow/reenter are explicitly unsupported without a protocol-specific callback actor.",
            "Step args — arrays of typed ABIValue objects; generic arrays are capped at 64 values and some nested/tuple forms need a specialised generator.",
            "Step expect — optional {\"count\":N,\"must_revert\":true|false}; count is used for an expected call, and must_revert asserts the call should fail.",
            "Step optional — optional boolean allowing a failed call without making the harness fail."
        ],
        "workflow": [
            "Create the manifest with only the top-level fields family, target_address and steps.",
            "For call/read/unwind/skew/expect steps, supply a target (or top-level target_address) and a 4-byte selector.",
            "Encode every argument as {\"type\":\"ABI_TYPE\",\"value\":VALUE}; do not pass pre-encoded shell strings.",
            "Use assert after a call/read when you need to assert success/revert state, and use expect immediately before its matching call.",
            "Run `lk steps ...`, inspect PROPOSED/refusal output and the generated Solidity, then compile and test it with Forge."
        ],
        "output": [
            "Generated harness plus SHA-256 digest on success.",
            "A structured refusal in stdout and --refusal-output when a plan is invalid or unsupported."
        ],
        "limits": "This is a typed harness renderer, not an exploit generator. A generated PROPOSED harness still needs protocol-specific actors, setup and meaningful assertions. flash_borrow/reenter require a protocol-specific callback actor and are refused rather than fabricated. The machine-readable refusal reason for those unsupported generic callback steps is `backend_unsupported`.",
        "related": [
            "lk attack-forge --h",
            "lk control --h",
            "lk target-coverage --h"
        ]
    },
    "mutation-score": {
        "usage": "lk mutation-score MANIFEST.json [options]",
        "when": "Use after creating a security test suite to check whether it catches deliberate, representative code changes.",
        "variations": [
            "lk mutation-score .audit/mutations.json",
            "Set a stricter threshold with --min-score 0.95.",
            "Increase the per-mutant timeout with --timeout 600."
        ],
        "arguments": [
            "MANIFEST.json — mutation campaign manifest describing mutations and the tests/commands used to detect them."
        ],
        "options": [
            "--min-score FLOAT — minimum accepted score from 0.0 to 1.0; default: 0.90.",
            "--timeout SECONDS — per-command timeout; default: 300.",
            "--output FILE — report path; default: .audit/verification/mutation-score-report.json."
        ],
        "workflow": [
            "Write a mutation manifest that changes security-relevant conditions (for example, removing a balance guard).",
            "Run the command and inspect killed, survived, skipped and failed mutants.",
            "Improve tests when a meaningful mutation survives."
        ],
        "output": [
            "JSON mutation report at --output."
        ],
        "limits": "A mutation score measures test sensitivity. It does not independently establish exploitability, deployment authenticity or impact.",
        "related": [
            "lk steps --h",
            "lk target-coverage --h",
            "lk report --h"
        ]
    },
    "target-coverage": {
        "usage": "lk target-coverage SOURCE.sol [options]",
        "when": "Use to verify that a generated test reaches the exact source lines involved in a suspected issue.",
        "variations": [
            "lk target-coverage src/Token.sol",
            "Restrict the measured lines with --start-line 30 --end-line 55."
        ],
        "arguments": [
            "SOURCE.sol — source file inside the project being audited."
        ],
        "options": [
            "--start-line N — first line included; default: 1.",
            "--end-line N — optional inclusive last line.",
            "--root DIR — Foundry project root; default: .",
            "--output FILE — report path; default: .audit/godmode/target-coverage.json."
        ],
        "workflow": [
            "Run the relevant Forge tests first or let the coverage command run Forge coverage.",
            "Inspect which target lines were hit and which were not.",
            "Add assertions for the security invariant; do not stop at line reachability."
        ],
        "output": [
            "JSON report with line hits, uncovered lines and percentage."
        ],
        "limits": "Coverage is reachability evidence, not assertion quality or security proof. Requires Forge and an LCOV report.",
        "related": [
            "lk steps --h",
            "lk mutation-score --h",
            "lk control --h"
        ]
    },
    "provenance": {
        "usage": "lk provenance [ARTIFACT ...] [options]",
        "when": "Use when you need to preserve exactly which artifacts, project revision and tool versions support an audit result.",
        "variations": [
            "lk provenance .audit/godmode/latest.json --root . --chain-id 31337 --fork-block 19000000",
            "Sign the resulting provenance record with --signing-key ./keys/audit-signing-key.pem."
        ],
        "arguments": [
            "ARTIFACT ... — zero or more files relative to --root. Every supplied file must exist inside the project root."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--chain-id ID — chain identifier to record.",
            "--fork-block N — block number anchoring the evidence.",
            "--signing-key FILE — optional PEM signing key for a detached signature; requires OpenSSL.",
            "--output FILE — provenance JSON path; default: .audit/godmode/provenance.json."
        ],
        "workflow": [
            "Run the audit and collect reports, harnesses and trace artifacts.",
            "Pass the relevant artifact paths and chain/fork metadata.",
            "Keep the JSON, detached signature (if requested) and original files together."
        ],
        "output": [
            "JSON provenance record containing SHA-256 hashes, Git revision and detected tool versions.",
            "Optional detached .sig file."
        ],
        "limits": "A hash or signature proves artifact identity/integrity, not that the experiment was correct or the finding is valid. Protect the signing key; never commit it.",
        "related": [
            "lk report --h",
            "lk fidelity --h",
            "lk trace-parity --h"
        ]
    },
    "fidelity": {
        "usage": "lk fidelity [options]",
        "when": "Use before trusting a PoC. Inspect its harness for synthetic setup/state changes, or record the declared evidence strength in the local evidence ledger.",
        "variations": [
            "lk fidelity --inspect test/Exploit.t.sol — inspect one harness; read-only.",
            "lk fidelity --record --strength simulated-funds --cheatcode vm.deal — append a declared fidelity record.",
            "lk fidelity --root . — list previously recorded fidelity events."
        ],
        "arguments": [
            "None. The harness path is supplied to --inspect."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--inspect FILE — inspect an existing harness inside the project root.",
            "--record — append a fidelity_record event to the evidence ledger.",
            "--cheatcode NAME — repeat to record declared cheatcodes used by the experiment.",
            "--strength heuristic|simulated-funds|reproduced-fork — declared evidence strength; default: heuristic."
        ],
        "workflow": [
            "Run --inspect on generated tests before accepting their result.",
            "Review flags such as vm.deal, vm.store, vm.etch, impersonation and time overrides.",
            "Record the declared evidence level only when the description matches what was actually done.",
            "Use cheatcode-free fork reproof for stronger evidence."
        ],
        "output": [
            "--inspect prints a JSON fidelity inventory.",
            "--record appends an event to the local evidence ledger.",
            "Without --inspect/--record, prints existing fidelity records."
        ],
        "limits": "The scanner is static and may miss aliases, wrappers or custom state mutation. A record is an operator declaration, not an independently verified claim.",
        "related": [
            "lk cheat-fingerprint --h",
            "lk reprove --h",
            "lk control --h"
        ]
    },
    "sandbox": {
        "usage": "lk sandbox [--root DIR] [--timeout SECONDS] -- COMMAND [ARG ...]",
        "when": "Use before running an untrusted build/test command. Lowkey copies the project while excluding sensitive files and runs the command with bubblewrap in a network-disabled sandbox.",
        "variations": [
            "lk sandbox --root . --timeout 300 -- forge test",
            "lk sandbox --root . --timeout 120 -- python3 scripts/check.py"
        ],
        "arguments": [
            "COMMAND [ARG ...] — exact executable and arguments after the mandatory `--` separator. Shell expansion is not performed."
        ],
        "options": [
            "--root DIR — project to copy into the sandbox; default: .",
            "--timeout SECONDS — command timeout; default: 300."
        ],
        "workflow": [
            "Choose a project root that does not need network access.",
            "Place `--` before the command to execute.",
            "Inspect the command output and exit code; the temporary copy is removed afterwards."
        ],
        "output": [
            "The child command's stdout, stderr and exit code."
        ],
        "limits": "Requires bubblewrap (`bwrap`). Lowkey refuses to run unsandboxed when it is unavailable. Network is disabled; .git, .audit, node_modules, build caches, environment files and credential-like files are excluded from the copied project.",
        "related": [
            "lk godmode --h",
            "lk fidelity --h"
        ]
    },
    "cheat-fingerprint": {
        "usage": "lk cheat-fingerprint [--root DIR]",
        "when": "Use to scan source and test files for cheatcode patterns that can fabricate balances, storage, code, time or caller identity and weaken exploit evidence.",
        "variations": [
            "lk cheat-fingerprint --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Run after generating a harness or importing a PoC.",
            "Inspect each hit in context; decide whether it is setup-only, required for a unit test, or invalidates the claimed reproduction.",
            "For production-fidelity evidence, replace synthetic setup with real transactions and a pinned fork."
        ],
        "output": [
            "JSON list of matched source locations and pattern categories."
        ],
        "limits": "Static pattern matching. A hit does not automatically make a test invalid; a clean scan does not prove that no state fabrication exists.",
        "related": [
            "lk fidelity --h",
            "lk reprove --h"
        ]
    },
    "decompile": {
        "usage": "lk decompile --h",
        "when": "Use only when verified source is unavailable and a supported Heimdall decompiler adapter has been installed and configured.",
        "variations": [
            "lk decompile --h — review the current adapter requirements."
        ],
        "arguments": [
            "No executable target arguments are exposed by this adapter-required placeholder yet."
        ],
        "options": [
            "No executable options are exposed yet."
        ],
        "workflow": [
            "Resolve the chain and deployed bytecode first.",
            "Install and configure a supported Heimdall adapter through the project toolchain.",
            "Do not treat decompiler output as verified source; compare selectors, runtime bytecode and behaviour."
        ],
        "output": [
            "No decompilation output is currently produced by this command."
        ],
        "limits": "Adapter-required. The command fails closed rather than guessing a decompiler invocation.",
        "related": [
            "lk selectors-full --h",
            "lk proxy-resolve --h",
            "lk storage-infer --h"
        ]
    },
    "storage-infer": {
        "usage": "lk storage-infer TARGET [options]",
        "when": "Use when source/verified storage layout is unavailable and you need candidate storage slots to investigate on-chain.",
        "variations": [
            "lk storage-infer 0x1111111111111111111111111111111111111111 --rpc-url http://127.0.0.1:8545",
            "Add --key <value> for repeated key-derived slot probes when you have a specific mapping key."
        ],
        "arguments": [
            "TARGET — deployed contract address."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is the configured Lowkey RPC.",
            "--slots N — number of sequential slots to inspect, capped at 120; default: 120.",
            "--no-resolve — skip optional key-slot derivation/resolution.",
            "--key VALUE — repeat for candidate mapping keys used in derived-slot probes."
        ],
        "workflow": [
            "Start with verified source or compiler storageLayout if available.",
            "Use storage-infer only to generate candidate slots when layout is missing.",
            "Cross-check candidate slots against known getters, state changes and transaction traces."
        ],
        "output": [
            "JSON candidate non-zero slots and any key-derived probes/derivation status."
        ],
        "limits": "Probabilistic inference, not a decoded storage layout. Slot collisions, packed fields, mapping hashing and proxy indirection can mislead.",
        "related": [
            "lk proxy-resolve --h",
            "lk state-diff --h",
            "lk trace --h"
        ]
    },
    "proxy-resolve": {
        "usage": "lk proxy-resolve TARGET [--rpc-url URL] [--slots N]",
        "when": "Use before reviewing a deployed contract when it may be a proxy. It inspects standard proxy slots and bounded storage candidates for implementation-like addresses.",
        "variations": [
            "lk proxy-resolve 0x1111111111111111111111111111111111111111 --rpc-url http://127.0.0.1:8545",
            "Reduce the sequential slot scan with --slots 40."
        ],
        "arguments": [
            "TARGET — deployed contract address."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is the configured Lowkey RPC.",
            "--slots N — sequential storage slots to inspect, capped at 120; default: 120."
        ],
        "workflow": [
            "Resolve the implementation candidate.",
            "Check whether the candidate has code and identify the proxy standard.",
            "Verify the actual implementation and admin semantics against runtime bytecode and deployment history."
        ],
        "output": [
            "JSON proxy slot candidates with code-presence and confidence hints."
        ],
        "limits": "Candidate slots only. A non-zero slot containing an address is not proof of a proxy; custom proxies and beacon patterns need separate review.",
        "related": [
            "lk upgrade-diff --h",
            "lk selectors-full --h",
            "lk storage-infer --h"
        ]
    },
    "selectors-full": {
        "usage": "lk selectors-full TARGET [--rpc-url URL]",
        "when": "Use to extract PUSH4-like values from deployed runtime bytecode and try to resolve them to known function signatures.",
        "variations": [
            "lk selectors-full 0x1111111111111111111111111111111111111111 --rpc-url http://127.0.0.1:8545"
        ],
        "arguments": [
            "TARGET — deployed contract address."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is the configured Lowkey RPC."
        ],
        "workflow": [
            "Fetch runtime bytecode.",
            "Review resolved and unresolved selector candidates.",
            "Confirm candidates against actual dispatch logic and ABI/source when available."
        ],
        "output": [
            "JSON rows of selector candidates, possible signatures and resolution status."
        ],
        "limits": "PUSH4 constants can be mistaken for function selectors. A resolved signature is a candidate, not proof that the contract exposes or routes to it.",
        "related": [
            "lk proxy-resolve --h",
            "lk decompile --h",
            "lk unravel --h"
        ]
    },
    "cfg": {
        "usage": "lk cfg [--root DIR]",
        "when": "Use for a quick static control-flow outline of functions containing external-call patterns.",
        "variations": [
            "lk cfg --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Run the outline to identify entry, external-call, state-write and exit points.",
            "Open the listed function in source and reconstruct branch/require conditions manually.",
            "Use a targeted test or symbolic tool for path feasibility."
        ],
        "output": [
            "JSON outline with source file, function and heuristic nodes."
        ],
        "limits": "This is not a compiler CFG or complete path graph. It is a source heuristic and may omit branches, modifiers, inherited functions and indirect calls.",
        "related": [
            "lk reentrancy-graph --h",
            "lk fallback-map --h",
            "lk path --h"
        ]
    },
    "reentrancy-graph": {
        "usage": "lk reentrancy-graph [--root DIR]",
        "when": "Use to identify possible storage variables read before and written after external calls—the source shape worth checking for reentrancy.",
        "variations": [
            "lk reentrancy-graph --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Inspect each call/read/write relationship.",
            "Confirm that the same storage location is involved, including aliases and internal helpers.",
            "Build a malicious callback and matched sequential control before claiming a vulnerability."
        ],
        "output": [
            "JSON graph-like rows with function, candidate variables, call location and source excerpt."
        ],
        "limits": "Heuristic only. Shared variable names do not prove storage identity or an exploitable callback; modifiers, inheritance and proxy flows can be missed.",
        "related": [
            "lk cfg --h",
            "lk fallback-map --h",
            "lk control --h"
        ]
    },
    "fallback-map": {
        "usage": "lk fallback-map [--root DIR]",
        "when": "Use to inventory fallback, receive and callback/receiver surfaces that may be externally reachable.",
        "variations": [
            "lk fallback-map --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Review each fallback/receive/hook match.",
            "Trace what state and assets it can access.",
            "Check caller expectations, reentrancy guards and token/NFT receiver semantics."
        ],
        "output": [
            "JSON source matches for fallback, receive and generic hook patterns."
        ],
        "limits": "Pattern map only; it does not prove reachability, callback ordering or impact.",
        "related": [
            "lk reentrancy-graph --h",
            "lk cfg --h",
            "lk token-weird --h"
        ]
    },
    "calldata-mine": {
        "usage": "lk calldata-mine TARGET HASH_FILE [--rpc-url URL]",
        "when": "Use to examine a supplied corpus of transaction hashes against a target and group repeated calldata/function-selector patterns.",
        "variations": [
            "lk calldata-mine 0x1111111111111111111111111111111111111111 .audit/tx-hashes.txt --rpc-url http://127.0.0.1:8545"
        ],
        "arguments": [
            "TARGET — contract address to compare against transaction destinations.",
            "HASH_FILE — text file containing one transaction hash per line; invalid lines are ignored."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is the configured Lowkey RPC."
        ],
        "workflow": [
            "Prepare a file of relevant transaction hashes.",
            "Run the command against the target address.",
            "Review grouped selectors and repeated calldata; decode important calls with the ABI and trace."
        ],
        "output": [
            "JSON groups of observed transaction/calldata patterns."
        ],
        "limits": "Only examines the supplied hashes; it does not search the whole chain or prove that repeated calldata is suspicious.",
        "related": [
            "lk unravel --h",
            "lk selectors-full --h",
            "lk trace --h"
        ]
    },
    "attack-forge": {
        "usage": "lk attack forge ATTACK_ID --target TARGET [--root DIR]",
        "when": "Use to render a Foundry harness starter for a known entry in Lowkey's attack library.",
        "variations": [
            "lk attack forge <attack-id-or-slug> --target 0x1111111111111111111111111111111111111111 --root ."
        ],
        "arguments": [
            "ATTACK_ID — attack catalogue ID or slug.",
            "--target TARGET — required contract address to place in the generated harness."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Find a relevant attack ID/slug in the attack catalogue.",
            "Generate the harness starter.",
            "Read the harness and fixture carefully; add protocol-specific setup, actors and assertions before running Forge."
        ],
        "output": [
            ".audit/attack-forge/<ID>/AttackHarness.template.t.sol and, when an available library snippet exists, a vulnerable fixture."
        ],
        "limits": "A harness starter is not an exploit proof. It may contain placeholder logic and requires protocol-specific assertions and a matched control.",
        "related": [
            "lk capabilities",
            "lk steps --h",
            "lk control --h"
        ]
    },
    "invariant-forge": {
        "usage": "lk invariant-forge [PROFILE] [--root DIR]",
        "when": "Use to create a protocol-shaped invariant checklist/starter before writing a Foundry invariant handler.",
        "variations": [
            "lk invariant-forge vault --root .",
            "lk invariant-forge lending --root .",
            "lk invariant-forge amm --root .",
            "lk invariant-forge staking --root .",
            "lk invariant-forge bridge --root .",
            "lk invariant-forge governance --root ."
        ],
        "arguments": [
            "PROFILE — vault, lending, amm, staking, bridge or governance; default: vault."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Choose the closest protocol profile.",
            "Inspect the generated invariants and bind them to the real protocol's accounting units and fees.",
            "Implement handlers/ghost state and assert each invariant in Forge."
        ],
        "output": [
            ".audit/godmode/invariant-forge-<profile>.md"
        ],
        "limits": "Starter checklist only. It does not generate a complete executable handler or prove that an invariant is correct for the protocol.",
        "related": [
            "lk archetype --h",
            "lk steps --h",
            "lk mutation-score --h"
        ]
    },
    "archetype": {
        "usage": "lk archetype [PROFILE] [--root DIR]  OR  lk archetype classify --root DIR --json",
        "when": "Use to classify a project into a known protocol shape or generate an invariant-oriented starter checklist.",
        "variations": [
            "lk archetype classify --root . --json — classify source using deterministic archetype packs.",
            "lk archetype vault --root . — write a vault starter checklist.",
            "lk archetype lending --root . — write a lending starter checklist."
        ],
        "arguments": [
            "PROFILE — vault, lending, amm, staking, bridge or governance for starter generation.",
            "classify — nested action that performs source-backed classification; it is not a profile name."
        ],
        "options": [
            "--root DIR — source/project root; default: .",
            "--json — classification output format for the classify subcommand.",
            "Additional classify options are shown by `lk archetype classify --help`."
        ],
        "workflow": [
            "Run `lk archetype classify --root . --json`.",
            "Check whether the result is OBSERVED or UNCLASSIFIED and inspect its source citations.",
            "Then use `lk assumptions` and `lk capability` to review extracted trust assumptions and skipped protocol-specific capabilities."
        ],
        "output": [
            "Classification JSON and, for a profile starter, .audit/godmode/archetype-<profile>.md."
        ],
        "limits": "Classification is source-level and confidence-bounded. It is not deployment authentication or vulnerability proof. Ambiguous targets should remain UNCLASSIFIED.",
        "related": [
            "lk assumptions --h",
            "lk capability --h",
            "lk invariant-forge --h"
        ]
    },
    "assumptions": {
        "usage": "lk assumptions [--root DIR] [--report FILE]",
        "when": "Use after archetype classification to re-read the source citations in the saved assumption ledger and verify their hashes and cited lines.",
        "variations": [
            "lk assumptions --root .",
            "Use --report .audit/archetype/report.json when reviewing a particular saved classification report."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--report FILE — optional saved classification report to inspect."
        ],
        "workflow": [
            "Run `lk archetype classify --root . --json` first.",
            "Run assumptions to validate that extracted source citations still resolve.",
            "Manually decide whether each trust assumption is valid or violated."
        ],
        "output": [
            "JSON assumption rows and citation-integrity status."
        ],
        "limits": "A source citation proves where an assumption was extracted, not whether the assumption is true or exploitable.",
        "related": [
            "lk archetype --h",
            "lk capability --h",
            "lk report --h"
        ]
    },
    "capability": {
        "usage": "lk capability [--root DIR] [--report FILE]",
        "when": "Use after archetype classification to see which protocol-specific checks are supported and which are explicitly skipped in generic mode.",
        "variations": [
            "lk capability --root .",
            "Pass --report <classification-report> to bind the review to a saved report."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--report FILE — optional saved classification report."
        ],
        "workflow": [
            "Classify the project first.",
            "Run capability to inspect negotiation results and skip reasons.",
            "Do not interpret skipped/partial functionality as a passing security check."
        ],
        "output": [
            "JSON capability negotiation and generic-mode skip list."
        ],
        "limits": "Only capabilities marked implemented are considered available. Partial and adapter-required entries remain skipped.",
        "related": [
            "lk archetype --h",
            "lk assumptions --h",
            "lk capabilities"
        ]
    },
    "token-weird": {
        "usage": "lk token-weird [--root DIR]",
        "when": "Use to generate adversarial ERC-20 mock contracts for testing integrations against non-standard token behaviour.",
        "variations": [
            "lk token-weird --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Generate the fixture source.",
            "Inspect the behaviours exposed by each mock (fees, false returns, pauses, rebasing/callback-like behaviour).",
            "Write focused tests proving the protocol handles each behaviour safely."
        ],
        "output": [
            ".audit/godmode/token-weird/WeirdTokens.sol"
        ],
        "limits": "Generates local test fixtures only. It does not deploy tokens, test your protocol automatically or imply every token has every behaviour.",
        "related": [
            "lk fallback-map --h",
            "lk invariant-forge --h",
            "lk steps --h"
        ]
    },
    "oracle-map": {
        "usage": "lk oracle-map [--root DIR]",
        "when": "Use to map source-level price-feed, pool spot-price and TWAP references before tracing their consumers.",
        "variations": [
            "lk oracle-map --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Review feed/pool read locations and any visible freshness checks.",
            "Trace every consumer into collateral, share, liquidation or swap calculations.",
            "Test stale/invalid rounds and manipulation resistance at the consumer; measure a downstream asset delta."
        ],
        "output": [
            "JSON oracle dependency/source matches and next-step guidance."
        ],
        "limits": "A read match does not prove price manipulation, stale data or exploitable impact. No pool manipulation is inferred from a source match.",
        "related": [
            "lk skew --h",
            "lk compose --h",
            "lk economic --h"
        ]
    },
    "skew": {
        "usage": "lk skew MANIFEST.json [--root DIR]",
        "when": "Use to prepare an oracle/pool skew investigation plan from explicit pool, asset, oracle-read, consumer-call and amount inputs.",
        "variations": [
            "lk skew .audit/skew.json --root ."
        ],
        "arguments": [
            "MANIFEST.json — JSON object requiring all five keys: pool, asset, oracle_read, consumer_call and amounts.",
            "pool — pool/market identity and address/details needed by the later adapter.",
            "asset — asset being evaluated.",
            "oracle_read — description or encoded read needed to obtain the oracle value.",
            "consumer_call — description or encoded call for the function that consumes the oracle value.",
            "amounts — candidate amounts/scenarios to evaluate."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Create a manifest with the target pool/asset and the precise oracle/consumer call data.",
            "Run skew to generate the plan.",
            "Validate the pool and consumer semantics, then build a controlled fork test."
        ],
        "output": [
            ".audit/godmode/skew-plan.json — plan containing the manifest hash, supplied dimensions and required assertions.",
            "The plan status is adapter-and-harness-required; no market state is changed."
        ],
        "limits": "This command validates the presence of the five manifest keys and writes a plan. It does not execute an oracle manipulation or consumer call, move a market, or prove economic impact.",
        "related": [
            "lk oracle-map --h",
            "lk compose --h",
            "lk economic --h"
        ]
    },
    "flashmax": {
        "usage": "lk flashmax VENUE ASSET --adapter FILE [--rpc-url URL]",
        "when": "Use only when you have an explicit venue-specific adapter for Aave, Balancer or Uniswap V3 and want to inspect the configured pool liquidity call.",
        "variations": [
            "lk flashmax aave 0x1111111111111111111111111111111111111111 --adapter .audit/adapters/aave.json --rpc-url http://127.0.0.1:8545",
            "Supported venue labels: aave, balancer, uniswap-v3."
        ],
        "arguments": [
            "VENUE — aave, balancer or uniswap-v3.",
            "ASSET — token contract address.",
            "--adapter FILE — required JSON adapter matching the venue and asset; includes pool and explicit liquidity_call calldata."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is the configured Lowkey RPC."
        ],
        "workflow": [
            "Prepare and validate a venue adapter from trusted ABI/source information.",
            "Run the command to read the configured pool's liquidity response.",
            "Design and implement a real callback/repayment harness separately."
        ],
        "output": [
            "JSON adapter and pool/liquidity observations."
        ],
        "limits": "An adapter-backed liquidity read is not a flash-loan execution. Lowkey does not borrow funds or claim profitability here.",
        "related": [
            "lk invariant-forge --h",
            "lk economic --h",
            "lk compose --h"
        ]
    },
    "time": {
        "usage": "lk time [--root DIR] [--output FILE]",
        "when": "Use to generate a starter Foundry time/block boundary test template for a protocol that uses timestamps or block numbers.",
        "variations": [
            "lk time --root .",
            "Choose a custom file with --output test/TimeLadder.t.sol."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--output FILE — generated Solidity template; default: .audit/godmode/TimeLadder.template.t.sol."
        ],
        "workflow": [
            "Generate the template.",
            "Replace placeholder comments with real target calls and invariant assertions.",
            "Test expiry, lock, vesting, epoch and boundary values against a pinned state."
        ],
        "output": [
            "A Solidity Foundry template with relative time/block offsets."
        ],
        "limits": "The generated functions are scaffolding with placeholder target calls. They do not execute a protocol-specific attack or prove timestamp dependence is exploitable.",
        "related": [
            "lk sig-matrix --h",
            "lk invariant-forge --h",
            "lk steps --h"
        ]
    },
    "sig-matrix": {
        "usage": "lk sig-matrix [--root DIR]",
        "when": "Use to locate signatures, permit/ECDSA usage and nonce/domain patterns, then plan replay and domain-separation tests.",
        "variations": [
            "lk sig-matrix --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Inspect signature and nonce matches.",
            "Test same signature twice, nonce consumption, wrong chain ID/verifying contract, deadline, signer and encoding collisions.",
            "Confirm the exact signed domain and state transition."
        ],
        "output": [
            "JSON signature-source map plus candidate replay cases."
        ],
        "limits": "Static mapping only. A signature match does not prove replayability or missing domain validation.",
        "related": [
            "lk init-frontrun --h",
            "lk control --h",
            "lk reprove --h"
        ]
    },
    "init-frontrun": {
        "usage": "lk init-frontrun [--root DIR]",
        "when": "Use to statically identify initializer/reinitializer functions and visible initializer-disable patterns in a proxy-oriented codebase.",
        "variations": [
            "lk init-frontrun --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Review initialize/reinitialize entry points and inherited initializers.",
            "Check constructor/implementation initializer disabling and deployment order.",
            "Verify access control and actual proxy initialization state on the target."
        ],
        "output": [
            "JSON initializer exposure map."
        ],
        "limits": "Read-only static map. Lowkey does not seize, front-run or initialize a live contract.",
        "related": [
            "lk proxy-resolve --h",
            "lk upgrade-diff --h",
            "lk custody --h"
        ]
    },
    "path": {
        "usage": "lk path MANIFEST.json [--root DIR]",
        "when": "Use to execute an explicitly declared symbolic/path-analysis engine command stored in a JSON manifest.",
        "variations": [
            "lk path .audit/path.json --root . — the manifest contains an argv array such as [\"halmos\", \"--function\", \"check_withdraw\"]."
        ],
        "arguments": [
            "MANIFEST.json — JSON object containing a non-empty argv string array.",
            "argv — exact executable and argument array, for example [\"halmos\",\"--function\",\"check_withdraw\"].",
            "timeout_seconds — optional command timeout; default: 600."
        ],
        "options": [
            "--root DIR — project root and working directory; default: .",
            "argv — exact command to execute; no shell expansion or string splitting is performed.",
            "timeout_seconds — command timeout from the manifest; default: 600."
        ],
        "workflow": [
            "Write the exact symbolic/formal tool and its arguments in manifest.argv.",
            "Review the manifest carefully; the command is executed in the project context.",
            "Run it and inspect the tool's native output and exit code.",
            "If the tool is not installed, Lowkey reports BLOCKED instead of silently substituting another engine."
        ],
        "output": [
            "Engine stdout/stderr and exit code."
        ],
        "limits": "Executes the command in the project context; shell expansion is not performed, but the executable itself can perform arbitrary actions. Only use a trusted manifest and engine.",
        "related": [
            "lk sandbox --h",
            "lk cfg --h",
            "lk steps --h"
        ]
    },
    "compose": {
        "usage": "lk compose [--root DIR]",
        "when": "Use to combine static reentrancy, oracle, signature, custody and initializer signals into a high-level cross-contract lead graph.",
        "variations": [
            "lk compose --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Run compose and inspect each signal node/edge.",
            "Resolve real contract-to-contract links and caller/asset identities.",
            "Turn a plausible chain into concrete steps and a measurable invariant."
        ],
        "output": [
            "JSON graph-like actor, signal and impact nodes/edges."
        ],
        "limits": "Heuristic composition of source signals. The asset-impact node is not measured, and a connected graph is not an executable exploit path.",
        "related": [
            "lk oracle-map --h",
            "lk reentrancy-graph --h",
            "lk sig-matrix --h",
            "lk control --h"
        ]
    },
    "reprove": {
        "usage": "lk reprove HARNESS [required options]",
        "when": "Use after a candidate PoC is reproducible and you need a cheatcode-free local-fork replay with trace, storage, deployment identity and portfolio-cost evidence.",
        "variations": [
            "lk reprove test/Exploit.t.sol --root . --rpc-url http://127.0.0.1:8545 --fork-block 19000000 --target-address 0x1111111111111111111111111111111111111111 --profit-address 0x2222222222222222222222222222222222222222",
            "Use --tx-hash <hash> to inspect an already-mined transaction instead of passing --argv-json.",
            "Repeat --profit-address for every relevant portfolio account (attacker, gas payer, payout recipient).",
            "Use --non-economic with --semantic-check-argv-json and --semantic-test when the invariant is not profit-based."
        ],
        "arguments": [
            "HARNESS — existing Foundry harness/source file inside --root.",
            "--rpc-url URL — required local Anvil fork endpoint.",
            "--fork-block N — required pinned fork block.",
            "--target-address ADDRESS — required deployed target identity.",
            "--profit-address ADDRESS — required; repeat for relevant portfolio addresses."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--tx-hash HASH — inspect a mined tx instead of executing --argv-json.",
            "--prior-cost-wei N — verified prior setup/deployment/funding cost in wei; default: 0.",
            "--source-rpc-url URL — independent read-only archive RPC for source-anchor/funding checks.",
            "--prestate-slot ADDRESS:SLOT — repeat to include extra storage slots in source/fork comparisons.",
            "--argv-json JSON — JSON string array for the replay command; never shell-evaluated.",
            "--support-file FILE — repeat for imported support files.",
            "--semantic-check-argv-json JSON — separate command whose assertion demonstrates the non-economic invariant.",
            "--semantic-test NAME — exact Foundry test expected to emit [PASS].",
            "--family NAME — attack family label; default: unknown.",
            "--non-economic — require a passing semantic invariant instead of positive net profit.",
            "--require-trace-storage — reject replay if trace-derived storage observations are absent."
        ],
        "workflow": [
            "Start with a reproducible harness and pinned fork block.",
            "Run against local Anvil using verified target and profit addresses.",
            "Supply prior costs when they exist; otherwise reported net profit may subtract replay gas only.",
            "Inspect source identity, prestate, trace, storage evidence and semantic/economic policy before promotion."
        ],
        "output": [
            "JSON replay evidence at .audit/godmode/reprove.json and stdout."
        ],
        "limits": "A local fixture is not production deployment proof. The workflow rejects direct state/balance/code/time overrides and caller impersonation as fork-reproduction setup. Include all relevant accounts and costs.",
        "related": [
            "lk control --h",
            "lk fidelity --h",
            "lk provenance --h",
            "lk economic --h"
        ]
    },
    "economic": {
        "usage": "lk economic --gross-wei N --gas-used N --max-fee-wei N [options]",
        "when": "Use to calculate a rough net-profit estimate after replay gas, pool fee, slippage and prior capital/setup cost.",
        "variations": [
            "lk economic --gross-wei 1000000000000000000 --gas-used 250000 --max-fee-wei 30000000000",
            "Add --pool-fee-bps 30 --slippage-bps 50 --capital-cost-wei 10000000000000000."
        ],
        "arguments": [
            "--gross-wei N — required gross portfolio gain in wei.",
            "--gas-used N — required measured gas used.",
            "--max-fee-wei N — required gas-price ceiling or selected fee in wei."
        ],
        "options": [
            "--pool-fee-bps N — fee deducted from gross; default: 0; range: 0–10000.",
            "--slippage-bps N — estimated slippage deducted from gross; default: 0; range: 0–10000.",
            "--capital-cost-wei N — additional cost; default: 0."
        ],
        "workflow": [
            "Use observed gross gain and receipt gas, not guessed values.",
            "Include the maximum fee, pool fee, slippage and prior capital costs.",
            "Treat a positive output as a candidate and account for omitted market/MEV factors."
        ],
        "output": [
            "JSON gross, gas, pool-fee, slippage, capital cost and net-profit values; status positive-candidate or OBSERVED."
        ],
        "limits": "Calculation only. MEV competition and unmodeled price impact are excluded. Output is only as reliable as the supplied inputs.",
        "related": [
            "lk reprove --h",
            "lk bundle --h"
        ]
    },
    "gas-ladder": {
        "usage": "lk gas-ladder MANIFEST.json [--root DIR]",
        "when": "Use to search for a gas/work threshold by running an explicit command repeatedly with a variable substituted into `{n}`.",
        "variations": [
            "lk gas-ladder .audit/gas-ladder.json --root ."
        ],
        "arguments": [
            "MANIFEST.json — JSON object with argv, a non-empty string array containing at least one `{n}` placeholder.",
            "min — optional lower bound; default: 1.",
            "max — optional upper bound; default: 10000.",
            "oom_regex — optional regular expression identifying the failing/OOG condition; defaults to common out-of-gas phrases and OOG.",
            "timeout_seconds — optional per-trial command timeout; default: 300."
        ],
        "options": [
            "--root DIR — project root and command working directory; default: .",
            "argv — every {n} occurrence is replaced with the current trial value; the argv is executed directly without a shell.",
            "min/max — bounded inclusive search range; max-min cannot exceed 10,000,000.",
            "oom_regex — regular expression used to classify a trial as the failing/OOG boundary.",
            "timeout_seconds — timeout applied to each trial; default: 300."
        ],
        "workflow": [
            "Create a manifest with the exact executable/test argv and a {n} placeholder in the parameter you want to vary.",
            "Set min/max so the lower value should succeed and the upper value should hit the target failure condition.",
            "Set oom_regex to match the actual failure text if the default does not match your tool.",
            "Run the command and inspect all recorded trials; it measures a threshold, not a vulnerability."
        ],
        "output": [
            "JSON trial observations including n, exit code, OOM classification and output tail.",
            "The first failing threshold, if a passing lower bound and failing upper bound are established."
        ],
        "limits": "Executes the manifest command repeatedly. Use only trusted commands and bounded search ranges; gas thresholds depend on compiler, chain and environment.",
        "related": [
            "lk sandbox --h",
            "lk target-coverage --h",
            "lk mutation-score --h"
        ]
    },
    "watch": {
        "usage": "lk watch TARGET [--rpc-url URL] [options]",
        "when": "Use for a bounded poll of a target's runtime bytecode and block height to detect code changes during an observation window.",
        "variations": [
            "lk watch 0x1111111111111111111111111111111111111111 --rpc-url http://127.0.0.1:8545 --count 10 --interval 3"
        ],
        "arguments": [
            "TARGET — contract address to poll."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is configured Lowkey RPC.",
            "--count N — number of polls, 1–100; default: 1.",
            "--interval SECONDS — delay between polls, 0–60; default: 3."
        ],
        "workflow": [
            "Choose the deployment address and authorised RPC.",
            "Set a bounded poll count and interval.",
            "Compare reported code hashes and block numbers; investigate any code change."
        ],
        "output": [
            "JSON/check rows containing block, runtime code hash and change observations."
        ],
        "limits": "Polling is observational and bounded. It is not a continuous background watcher or notification service.",
        "related": [
            "lk upgrade-diff --h",
            "lk provenance --h",
            "lk proxy-resolve --h"
        ]
    },
    "custody": {
        "usage": "lk custody [--root DIR]",
        "when": "Use to inventory source-level owner/admin/guardian/pause/timelock/rescue/upgrade patterns and identify who may control protocol assets.",
        "variations": [
            "lk custody --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Review the authority map and source locations.",
            "Trace modifiers and internal role checks to the protected state transitions.",
            "Confirm actual on-chain roles and ownership for the deployment."
        ],
        "output": [
            "JSON custody/authority source map."
        ],
        "limits": "Pattern map only. It cannot establish the actual deployed role holders or prove that a control path is exploitable.",
        "related": [
            "lk init-frontrun --h",
            "lk proxy-resolve --h",
            "lk upgrade-diff --h"
        ]
    },
    "agent-split": {
        "usage": "lk agent-split [--root DIR] [--harness FILE]",
        "when": "Use to split a candidate audit into planner, attacker, verifier and critic review roles, with optional cheatcode scanning of a harness.",
        "variations": [
            "lk agent-split --root .",
            "lk agent-split --root . --harness test/Exploit.t.sol"
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--harness FILE — optional harness inside the project root to scan for synthetic state/caller/time cheatcodes."
        ],
        "workflow": [
            "Run once without a harness to get the project/source role split.",
            "Supply a generated harness to inspect its trust assumptions.",
            "Have the verifier independently check assertions and the critic challenge the exploit hypothesis."
        ],
        "output": [
            "JSON planner/attacker/verifier/critic work split and optional harness cheatcode matches."
        ],
        "limits": "Role separation is an audit organisation aid, not four independent agents or independent exploit proof. Harness pattern matching is static.",
        "related": [
            "lk godmode --h",
            "lk fidelity --h",
            "lk control --h"
        ]
    },
    "verify-hack": {
        "usage": "lk verify-hack TX_HASH --rpc-url URL --block N",
        "when": "Use to verify that a supplied exploit transaction was mined in the declared attacked block and to derive the required preceding fork anchor.",
        "variations": [
            "lk verify-hack 0x<64-hex-tx-hash> --rpc-url https://<archive-rpc> --block 19000000"
        ],
        "arguments": [
            "TX_HASH — 32-byte transaction hash.",
            "--rpc-url URL — required RPC that can retrieve the transaction.",
            "--block N — required positive attacked block number."
        ],
        "options": [
            "--rpc-url URL — required.",
            "--block N — required."
        ],
        "workflow": [
            "Get the transaction hash and the block it was mined in from reliable chain data.",
            "Run the verifier against an archive-capable RPC.",
            "Use the returned attacked block and required fork-block guidance when preparing a reproducible historical test."
        ],
        "output": [
            "JSON transaction identity and attacked-block/fork-anchor evidence."
        ],
        "limits": "Read-only transaction lookup. It verifies the declared block placement; it does not prove the transaction was a successful exploit or caused a loss.",
        "related": [
            "lk unravel --h",
            "lk reprove --h",
            "lk provenance --h"
        ]
    },
    "unravel": {
        "usage": "lk unravel TX_HASH [--rpc-url URL]",
        "when": "Use to decode a mined transaction's nested call tree using the RPC debug_traceTransaction callTracer.",
        "variations": [
            "lk unravel 0x<64-hex-tx-hash> --rpc-url http://127.0.0.1:8545"
        ],
        "arguments": [
            "TX_HASH — 32-byte transaction hash."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is configured Lowkey RPC."
        ],
        "workflow": [
            "Find the transaction hash.",
            "Run against an RPC that supports debug_traceTransaction/callTracer.",
            "Inspect call depth, caller/callee, value, gas, calldata and revert/error fields."
        ],
        "output": [
            "JSON flattened call tree with depth, call type, from/to, value, gas, input prefix and errors."
        ],
        "limits": "Requires a tracing-capable RPC and retained transaction state. Flattened call data is truncated for readability; it is not a full source-level explanation.",
        "related": [
            "lk trace --h",
            "lk verify-hack --h",
            "lk calldata-mine --h"
        ]
    },
    "bundle": {
        "usage": "lk bundle --tx RAW_TX [--tx RAW_TX ...] --target-block N --relay-url URL --auth-signature SIGNATURE",
        "when": "Use to request a private-bundle simulation from a compatible relay, not to broadcast a bundle.",
        "variations": [
            "lk bundle --tx 0x<raw-signed-transaction> --target-block 19000000 --relay-url https://relay.example --auth-signature <address:signature>",
            "Repeat --tx once for each transaction in the ordered bundle."
        ],
        "arguments": [
            "--tx RAW_TX — required and repeatable; raw signed transaction hex.",
            "--target-block N — required positive block number to simulate against.",
            "--relay-url URL — required compatible relay endpoint.",
            "--auth-signature VALUE — required relay authentication signature/header."
        ],
        "options": [
            "No optional flags are currently exposed. All four argument types above are required; --tx is repeatable."
        ],
        "workflow": [
            "Prepare raw signed transactions offline and verify their order.",
            "Choose a relay that supports eth_callBundle and understand its privacy/retention policy.",
            "Run simulation and inspect per-transaction result, gas and revert status.",
            "Do not interpret simulation acceptance as inclusion or profitability."
        ],
        "output": [
            "Relay JSON-RPC eth_callBundle response."
        ],
        "limits": "This sends the raw signed transactions and authentication signature to the supplied relay URL for simulation. It does not broadcast them as a bundle, but the relay receives the payload. Never submit private transactions to an untrusted endpoint.",
        "related": [
            "lk economic --h",
            "lk reprove --h"
        ]
    },
    "sandwich": {
        "usage": "lk sandwich --h",
        "when": "Use only when a pending-transaction feed and a pool-specific simulator adapter have been configured.",
        "variations": [
            "lk sandwich --h — review adapter requirements; execution is currently blocked without them."
        ],
        "arguments": [
            "No executable arguments are exposed while the required feed/adapter integration is unavailable."
        ],
        "options": [
            "No executable options are exposed yet."
        ],
        "workflow": [
            "Configure a supported mempool/pending-transaction feed.",
            "Provide a pool-specific simulator and a reproducible fork environment.",
            "Review legal, ethical and protocol constraints before running any ordering simulation."
        ],
        "output": [
            "No simulation output is currently produced by this adapter-required placeholder."
        ],
        "limits": "Adapter-required. Current command fails closed and does not submit or broadcast a transaction.",
        "related": [
            "lk jit --h",
            "lk bundle --h",
            "lk economic --h"
        ]
    },
    "jit": {
        "usage": "lk jit --h",
        "when": "Use only after a pool-specific just-in-time liquidity simulator is installed and configured.",
        "variations": [
            "lk jit --h — review current adapter requirements."
        ],
        "arguments": [
            "No executable arguments are exposed while the required pool adapter is unavailable."
        ],
        "options": [
            "No executable options are exposed yet."
        ],
        "workflow": [
            "Configure a supported concentrated-liquidity pool simulator.",
            "Model mint/swap/burn ordering against a pinned state.",
            "Measure fees, inventory exposure and net outcome separately."
        ],
        "output": [
            "No simulation output is currently produced by this adapter-required placeholder."
        ],
        "limits": "Adapter-required. Current command fails closed; it does not submit or broadcast a transaction.",
        "related": [
            "lk sandwich --h",
            "lk bundle --h",
            "lk economic --h"
        ]
    },
    "fork-cache": {
        "usage": "lk fork-cache ACTION [options]",
        "when": "Use to save and restore local Anvil snapshots during a controlled experiment.",
        "variations": [
            "lk fork-cache list --root . — list recorded snapshot IDs; no RPC call required.",
            "lk fork-cache snapshot --rpc-url http://127.0.0.1:8545 --root . — create and record a local snapshot.",
            "lk fork-cache revert --id 0x1 --rpc-url http://127.0.0.1:8545 --root . — revert to a recorded snapshot."
        ],
        "arguments": [
            "ACTION — snapshot, revert or list.",
            "--id ID — required for revert; a snapshot ID recorded by a previous snapshot action."
        ],
        "options": [
            "--rpc-url URL — local Anvil RPC for snapshot/revert; default is configured Lowkey RPC.",
            "--root DIR — where .audit/godmode/fork-cache.json is stored; default: ."
        ],
        "workflow": [
            "Create a snapshot before a destructive test.",
            "Record the returned snapshot ID.",
            "Run the experiment.",
            "Revert to the recorded snapshot or list saved IDs."
        ],
        "output": [
            "Snapshot metadata in .audit/godmode/fork-cache.json and action confirmation."
        ],
        "limits": "Local Anvil only. Revert mutates the local chain state and consumes the snapshot. Do not use a production RPC.",
        "related": [
            "lk control --h",
            "lk godmode --h"
        ]
    },
    "upgrade-diff": {
        "usage": "lk upgrade-diff OLD_ADDRESS NEW_ADDRESS [options]",
        "when": "Use to compare old/new deployed runtime bytecode selectors and, when supplied, compiler storage-layout JSON.",
        "variations": [
            "lk upgrade-diff 0x<old-address> 0x<new-address> --rpc-url http://127.0.0.1:8545",
            "Add --old-layout old-layout.json --new-layout new-layout.json to compare storage layout entries."
        ],
        "arguments": [
            "OLD_ADDRESS — prior implementation or contract address.",
            "NEW_ADDRESS — candidate implementation or contract address."
        ],
        "options": [
            "--rpc-url URL — RPC endpoint; default is configured Lowkey RPC.",
            "--old-layout FILE — optional prior compiler storage-layout JSON.",
            "--new-layout FILE — optional new compiler storage-layout JSON; supply both layout files for storage comparison."
        ],
        "workflow": [
            "Resolve the actual old/new implementation addresses.",
            "Compare runtime selectors and source/compiler storage layouts.",
            "Review removed/added selectors, slot movement, type/packing changes and upgrade authorization."
        ],
        "output": [
            "JSON bytecode/selector and optional storage-layout comparison."
        ],
        "limits": "Selector and layout diff only. It does not prove proxy routing, initializer safety or runtime semantic compatibility.",
        "related": [
            "lk proxy-resolve --h",
            "lk storage-infer --h",
            "lk custody --h"
        ]
    },
    "cross-vm": {
        "usage": "lk cross-vm [--root DIR]",
        "when": "Use to locate cross-VM source markers for Solana, Move, Cairo and Soroban authorization/account models.",
        "variations": [
            "lk cross-vm --root ."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Review language-specific signals and source locations.",
            "Trace signer/owner/capability/auth checks in the native language.",
            "Use the language's native framework and proof tooling to verify behaviour."
        ],
        "output": [
            "JSON cross-VM static marker map."
        ],
        "limits": "Marker scan only. It does not execute native-chain tests or prove authorization correctness.",
        "related": [
            "lk capabilities",
            "lk archetype --h",
            "lk cfg --h"
        ]
    },
    "learn": {
        "usage": "lk learn --title TEXT --lesson TEXT --evidence TEXT [options]",
        "when": "Use to store an evidence-backed project/audit lesson in Lowkey's local experience memory.",
        "variations": [
            "lk learn --title \"Token subtraction guard\" --lesson \"Compare balance before subtraction\" --evidence \"src/Token.sol:18\"",
            "Choose a category with --kind false-positive-rule or protocol-pattern.",
            "Add --when and --rationale to record the trigger and why it matters."
        ],
        "arguments": [
            "--title TEXT — required short lesson title.",
            "--lesson TEXT — required rule/lesson to remember.",
            "--evidence TEXT — required evidence pointer; cite a file/line, test or report."
        ],
        "options": [
            "--kind KIND — protocol-pattern, test-procedure, tool-configuration, project-fact or false-positive-rule; default: protocol-pattern.",
            "--when TEXT — optional condition for applying the lesson.",
            "--rationale TEXT — optional explanation.",
            "--root DIR — project root/memory scope; default: ."
        ],
        "workflow": [
            "Write a specific lesson, not a vague conclusion.",
            "Attach a source/test/report citation.",
            "Select a kind that matches the content and provide when/rationale if useful."
        ],
        "output": [
            "Local experience-memory record and confirmation."
        ],
        "limits": "This writes local project memory. Evidence text is operator-supplied; Lowkey does not independently validate its truth.",
        "related": [
            "lk questions --h",
            "lk godmode --h"
        ]
    },
    "report": {
        "usage": "lk report [options]",
        "when": "Use after Godmode has saved .audit/godmode/latest.json and you want a readable Markdown report.",
        "variations": [
            "lk report --root .",
            "Choose --input .audit/godmode/latest.json and --output .audit/godmode/review.md."
        ],
        "arguments": [
            "None."
        ],
        "options": [
            "--root DIR — project root; default: .",
            "--input FILE — saved Godmode JSON; default: .audit/godmode/latest.json.",
            "--output FILE — Markdown report path; default: .audit/godmode/report.md."
        ],
        "workflow": [
            "Run Godmode or another workflow that writes the expected JSON report.",
            "Run `lk report --root .`.",
            "Read stage statuses, findings and source maps; do not promote unverified signals."
        ],
        "output": [
            "Markdown report, default .audit/godmode/report.md.",
            "A sibling .sha256 file containing the report digest."
        ],
        "limits": "Renders saved evidence. It does not run a new audit or turn source signals into validated findings.",
        "related": [
            "lk godmode --h",
            "lk provenance --h",
            "lk capabilities"
        ]
    },
    "questions": {
        "usage": "lk questions [ACTION] [NOTE ...] [--root DIR]",
        "when": "Use to continue Lowkey's question-driven audit loop, inspect the current question or record an answer/note.",
        "variations": [
            "lk questions --root . — show the current audit question (default action: current).",
            "lk questions next --root . — request the next active question.",
            "lk questions why --root . — inspect why the current question was selected.",
            "lk questions evidence --root . — inspect the evidence relevant to the current question.",
            "lk questions note \"The transfer check subtracts before comparing\" --root . — save your conclusion/evidence and advance the question frontier.",
            "lk questions done --root . — mark the current question answered without a note.",
            "lk questions skip \"Not relevant to this contract\" --root . — explicitly skip/defer with a reason.",
            "lk questions na \"No oracle in this protocol\" --root . — mark the current question not applicable."
        ],
        "arguments": [
            "ACTION — current/next, why, evidence, path/source, done, note, skip/defer, na/not-applicable, all/catalog or reset; default: current.",
            "NOTE ... — optional free-text explanation for note, skip/defer or na actions."
        ],
        "options": [
            "--root DIR — project root; default: ."
        ],
        "workflow": [
            "Start with `lk questions` to open the current question.",
            "Use why/evidence/path to understand the prompt and relevant source context.",
            "Save a conclusion with `lk questions note \"...\"` or mark it done/skip/not-applicable.",
            "The command advances the question frontier; a TRY command does not answer a question."
        ],
        "output": [
            "Question-engine output and any saved question-loop context."
        ],
        "limits": "Accepted actions and state transitions are defined by the question engine; review its response rather than assuming every free-form action is accepted.",
        "related": [
            "lk learn --h",
            "lk godmode --h",
            "lk report --h"
        ]
    }
}

GODMODE_SUBCOMMAND_HELP_GUIDES = {
    "archetype classify": {
        "summary": "Classify source into a supported protocol archetype and emit source-cited assumptions/capability negotiation.",
        "when": "Use this when you want a protocol classification rather than a generic starter checklist.",
        "usage": "lk archetype classify [options]",
        "variations": [
            "lk archetype classify --root . --json — classify the current project and print JSON.",
            "lk archetype classify --root . --output .audit/godmode/classification.json — choose the report path.",
            "lk archetype classify --verify .audit/godmode/classification.json --root . — re-read and verify saved source citations.",
            "lk archetype classify --assumptions --root . — print and re-verify the assumption ledger.",
            "lk archetype classify --capability --root . — print capability negotiation from the saved report."
        ],
        "arguments": ["None. This subcommand uses flags only."],
        "options": [
            "--root DIR — source/project root; default: .",
            "--output FILE — classification output path; default: .audit/godmode/archetype-classification.json.",
            "--json — print machine-readable JSON.",
            "--verify REPORT — re-read and verify citations in an existing report.",
            "--report FILE — saved report used by --verify/assumption/capability actions; default: .audit/godmode/archetype-classification.json.",
            "--assumptions — print and re-verify the assumption ledger.",
            "--capability — print capability negotiation from a saved report."
        ],
        "workflow": [
            "Run classification with --json and inspect the archetype plus status.",
            "If the result is UNCLASSIFIED, do not force a category; inspect the missing evidence.",
            "Run --verify on a saved report after source changes.",
            "Use --assumptions and --capability to review trust assumptions and generic-mode skips."
        ],
        "output": [
            "Classification JSON/report at --output or the configured --report path.",
            "Source citations and explicit OBSERVED/UNCLASSIFIED status."
        ],
        "limits": "Classification is source-level evidence. It does not authenticate the deployed bytecode or establish a vulnerability.",
        "related": ["lk archetype --h", "lk assumptions --h", "lk capability --h"]
    }
}


def _godmode_help_details(command):
    command = str(command or "").strip().lower()
    if command in GODMODE_COMMAND_DETAILS:
        return GODMODE_COMMAND_DETAILS[command]
    capability = _CAPABILITY_BY_NAME.get(command)
    if capability:
        title = capability["title"]
        return {
            "summary": title + ".",
            "when": "Use it when this review surface is relevant to the current protocol or evidence.",
            "example": "lk " + command + " --help",
            "limits": "Capability status: " + capability["status"] + ". Review the returned evidence and limitations before treating it as a finding.",
        }
    return None


class LowkeyArgumentParser(argparse.ArgumentParser):
    """Godmode parser with consistent help aliases and human-readable command context."""

    def __init__(self, *args, **kwargs):
        raw_prog = kwargs.get("prog")
        command = str(raw_prog or "").strip().split()[-1] if raw_prog else ""
        details = _godmode_help_details(command)
        existing_description = str(kwargs.get("description") or "").strip()
        if details:
            context = (
                "What it does: " + details["summary"] + "\n"
                "When to use: " + details["when"]
            )
            kwargs["description"] = context + (
                "\n\n" + existing_description if existing_description else ""
            )
            existing_epilog = str(kwargs.get("epilog") or "").strip()
            command_epilog = (
                "Example: " + details["example"] + "\n"
                "Limitations: " + details["limits"]
            )
            kwargs["epilog"] = (
                existing_epilog + "\n\n" + command_epilog
                if existing_epilog else command_epilog
            )
        kwargs.setdefault("formatter_class", argparse.ArgumentDefaultsHelpFormatter)
        kwargs["add_help"] = False
        super().__init__(*args, **kwargs)
        self.add_argument(
            "-h", "--help", "--h",
            action="help",
            help="Show this command's usage, options, examples, and limitations.",
        )

    def parse_args(self, args=None, namespace=None):
        # argparse requires option strings to begin with a prefix character.
        # Keep bare "help" as a CLI alias by normalizing it before parsing.
        values = list(sys.argv[1:] if args is None else args)
        values = ["--help" if str(value).strip().lower() == "help" else value for value in values]
        return super().parse_args(values, namespace)


def print_command_catalog():
    """Print the Godmode command inventory used by the root Lowkey help menu."""
    print()
    print("GODMODE / EVIDENCE-FIRST SECURITY COMMANDS")
    print("------------------------------------------")
    capability_by_name = _CAPABILITY_BY_NAME
    for command in ROUTED_COMMANDS:
        details = _godmode_help_details(command)
        summary = details["summary"] if details else "Godmode evidence workflow."
        status = capability_by_name.get(command, {}).get("status")
        if command == "capabilities":
            status = "catalog"
        elif command == "steps":
            status = "partial"
        elif command == "skew":
            status = "partial"
        elif command in {"jit", "sandwich", "decompile"}:
            status = "adapter-required"
        status_text = (" [" + status + "]") if status else ""
        print(f"  lk {command:<22} {summary}{status_text}")
    print()
    print("  Detailed guide (syntax, arguments, defaults, workflows, outputs and limits): lk <command> --h")
    print("  Help spellings accepted by these commands: --h, --help, -h, help")
    print("  lk capabilities lists all 44 capability states; registered does not mean fully implemented.")

FALLBACK = {
"receive":r"\breceive\s*\(\s*\)\s*external",
"fallback":r"\bfallback\s*(?:\([^)]*\))?\s*external",
"erc721_receiver":r"\bonERC721Received\s*\(",
"erc1155_single":r"\bonERC1155Received\s*\(",
"erc1155_batch":r"\bonERC1155BatchReceived\s*\(",
"erc777_hook":r"\btokensReceived\s*\(",
"erc1363_hook":r"\bonTransferReceived\s*\(",
"erc1363_approval_hook":r"\bonApprovalReceived\s*\(",
"callback":r"\b(?:callback|executeOperation|uniswapV3FlashCallback|receiveFlashLoan)\s*\(",
"try_catch":r"\btry\b|\bcatch\b",
"low_level_call":r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()",
}
PATTERNS = {
"oracle":r"\b(?:latestRoundData|latestAnswer|getReserves|slot0|observe|consult|exchangeRate|virtualPrice|sharePrice)\s*\(",
"freshness":r"\b(?:updatedAt|answeredInRound|heartbeat|stale|staleness)\b",
"signature":r"\b(?:ecrecover|ECDSA\.recover|tryRecover|SignatureChecker|permit)\s*\(",
"nonce_domain":r"\b(?:nonces?|DOMAIN_SEPARATOR|domainSeparator|EIP712|chainId)\b",
"initializer":r"\b(?:initializer|reinitializer|initialize[A-Z_a-z0-9]*|_disableInitializers)\b",
"custody":r"\b(?:onlyOwner|owner\s*\(|onlyRole|grantRole|revokeRole|guardian|Timelock|upgradeTo|_authorizeUpgrade|pause|unpause)\b",
"cross_vm":r"\b(?:Signer<|is_signer|find_program_address|create_program_address|AccountInfo|TreasuryCap|AdminCap|get_caller_address|require_auth)\b",
"external_call":r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()|\.transfer\s*\(|\.send\s*\(|safeTransfer(?:From)?\s*\(",
}
def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
def root_path(value="."):
    p=Path(value).expanduser().resolve()
    if not p.is_dir(): raise ValueError(f"project root does not exist: {p}")
    return p
def safe_out(root,path):
    p=(root/path).resolve()
    if not p.is_relative_to(root): raise ValueError("output path must stay inside project")
    p.parent.mkdir(parents=True,exist_ok=True)
    return p
def write_json(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix(path.suffix+".tmp")
    temp.write_text(json.dumps(data,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    os.replace(temp,path)
    return path
def sha(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(1024*1024),b""): h.update(b)
    return h.hexdigest()
def files(root,include_tests=False):
    out=[]
    for p in root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in EXTS: continue
        rel=p.relative_to(root); parts=set(rel.parts[:-1])
        if parts & SKIP or (not include_tests and parts & {"test","tests","script","scripts","fixtures","mocks"}): continue
        try:
            if p.stat().st_size <= 2_000_000: out.append(p)
        except OSError: pass
    return sorted(out)

# Godmode uses one auditable inventory for every mandatory source scanner.
# The legacy files() helper remains for unrelated commands; it must not be
# used to establish complete audit coverage because it predates error reporting.
_SOURCE_FILE_MAX_BYTES = 2_000_000
_SOURCE_INVENTORY_MAX_BYTES = 128 * 1024 * 1024
_SOURCE_TEST_PARTS = {"test", "tests", "script", "scripts", "fixtures", "mocks"}


def _source_stat(path: Path):
    """Small seam for deterministic stat-failure regression tests."""
    return path.stat()


def _read_source_text(path: Path) -> str:
    """Small seam for deterministic read-failure regression tests."""
    return path.read_text(encoding="utf-8", errors="replace")


def _collect_source_inventory(root: str | Path, *, include_tests: bool = True) -> dict[str, Any]:
    """Enumerate and read first-party source files, retaining every inspection failure.

    Traversal never follows symlinks. A directory that cannot be enumerated is
    reported as an unknown subtree because its children cannot be named safely.
    """
    project = Path(root).expanduser().resolve()
    inventory: dict[str, Any] = {
        "root": project,
        "files": [],
        "contents": {},
        "discovered_paths": [],
        "failures": [],
        "bytes_read": 0,
    }
    failures = inventory["failures"]
    discovered = inventory["discovered_paths"]
    contents = inventory["contents"]
    inspected = inventory["files"]

    def relative(path: Path) -> str:
        try:
            return path.relative_to(project).as_posix() or "."
        except (OSError, ValueError):
            return str(path)

    def record(path: Path, phase: str, error: BaseException | str, *, scope: str) -> None:
        detail = (
            f"{type(error).__name__}: {error}"
            if isinstance(error, BaseException) else str(error)
        )
        failures.append({
            "path": relative(path),
            "phase": phase,
            "scope": scope,
            "error": detail[:600],
        })

    def walk(directory: Path) -> None:
        pending = []
        try:
            with os.scandir(directory) as iterator:
                while True:
                    try:
                        pending.append(next(iterator))
                    except StopIteration:
                        break
                    except OSError as exc:
                        record(directory, "directory-enumeration", exc, scope="directory")
                        break
        except OSError as exc:
            record(directory, "directory-enumeration", exc, scope="directory")
            return

        for entry in sorted(pending, key=lambda item: item.name.casefold()):
            path = Path(entry.path)
            suffix = path.suffix.lower()
            try:
                is_symlink = entry.is_symlink()
                if is_symlink:
                    try:
                        is_directory_target = entry.is_dir(follow_symlinks=True)
                    except OSError as exc:
                        if suffix in EXTS:
                            discovered.append(relative(path))
                        record(
                            path,
                            "entry-inspection",
                            exc,
                            scope="source-file" if suffix in EXTS else "directory-or-entry",
                        )
                        continue
                    if entry.name in SKIP:
                        continue
                    if suffix in EXTS:
                        discovered.append(relative(path))
                    if suffix in EXTS or is_directory_target:
                        record(
                            path,
                            "symlink-not-followed",
                            "Source symlinks are not followed during an audit scan.",
                            scope="source-file" if suffix in EXTS else "directory",
                        )
                    continue
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError as exc:
                record(
                    path, "entry-inspection", exc,
                    scope="source-file" if suffix in EXTS else "directory-or-entry",
                )
                if suffix in EXTS:
                    discovered.append(relative(path))
                continue

            if is_directory:
                if entry.name in SKIP:
                    continue
                if not include_tests and entry.name in _SOURCE_TEST_PARTS:
                    continue
                walk(path)
                continue

            if suffix not in EXTS:
                continue

            discovered.append(relative(path))
            try:
                info = _source_stat(path)
            except OSError as exc:
                record(path, "stat", exc, scope="source-file")
                continue

            if not stat.S_ISREG(info.st_mode):
                record(path, "file-type", "Source candidate is not a regular file.", scope="source-file")
                continue
            if info.st_size > _SOURCE_FILE_MAX_BYTES:
                record(
                    path, "size-limit",
                    f"Source file is {info.st_size} bytes; scan limit is {_SOURCE_FILE_MAX_BYTES} bytes.",
                    scope="source-file",
                )
                continue
            if inventory["bytes_read"] + info.st_size > _SOURCE_INVENTORY_MAX_BYTES:
                record(
                    path, "inventory-budget",
                    f"Total source inventory budget of {_SOURCE_INVENTORY_MAX_BYTES} bytes was reached.",
                    scope="source-file",
                )
                continue
            try:
                text = _read_source_text(path)
            except OSError as exc:
                record(path, "read", exc, scope="source-file")
                continue

            encoded_size = len(text.encode("utf-8", errors="replace"))
            if encoded_size > _SOURCE_FILE_MAX_BYTES:
                record(
                    path, "size-limit-after-read",
                    f"Source file grew beyond the {_SOURCE_FILE_MAX_BYTES}-byte scan limit while being read.",
                    scope="source-file",
                )
                continue
            inventory["bytes_read"] += encoded_size
            inspected.append(path)
            contents[path] = text

    try:
        root_info = _source_stat(project)
    except OSError as exc:
        record(project, "root-stat", exc, scope="directory")
    else:
        if not stat.S_ISDIR(root_info.st_mode):
            record(project, "root-validation", "Project root is not a directory.", scope="directory")
        else:
            walk(project)

    source_discovered = [
        item for item in discovered
        if not (set(Path(item).parts[:-1]) & _SOURCE_TEST_PARTS)
    ]
    if not source_discovered and not failures:
        record(
            project,
            "source-discovery",
            "No in-scope first-party source files were discovered outside tests, scripts, fixtures, and mocks.",
            scope="project",
        )

    inspected.sort(key=lambda item: relative(item).casefold())
    discovered.sort(key=str.casefold)
    failures.sort(key=lambda item: (str(item.get("path", "")).casefold(), str(item.get("phase", ""))))
    return inventory


def _inventory_paths(inventory: dict[str, Any], *, include_tests: bool = False) -> list[Path]:
    root = Path(inventory["root"])
    selected = []
    for path in inventory.get("files", []):
        try:
            parts = set(path.relative_to(root).parts[:-1])
        except (OSError, ValueError):
            continue
        if not include_tests and parts & _SOURCE_TEST_PARTS:
            continue
        selected.append(path)
    return selected


def _source_inventory_status(inventory: dict[str, Any]) -> str:
    """Return completed only when at least one in-scope source exists and all were read."""
    source_files = _inventory_paths(inventory, include_tests=False)
    if not source_files:
        return "blocked"
    if inventory.get("failures"):
        return "review"
    return "completed"


def _source_inventory_report(inventory: dict[str, Any]) -> dict[str, Any]:
    failures = list(inventory.get("failures") or [])
    discovered_paths = list(inventory.get("discovered_paths") or [])
    source_discovered = [
        item for item in discovered_paths
        if item != "."
        and not (set(Path(item).parts[:-1]) & _SOURCE_TEST_PARTS)
    ]
    source_inspected = len(_inventory_paths(inventory, include_tests=False))
    complete = not failures and bool(source_discovered) and source_inspected == len(source_discovered)
    return {
        "root": str(inventory.get("root") or ""),
        "complete": complete,
        "files_discovered": len(discovered_paths),
        "files_inspected": len(inventory.get("files") or []),
        "source_files_discovered": len(source_discovered),
        "source_files_inspected": source_inspected,
        "bytes_read": int(inventory.get("bytes_read") or 0),
        "uninspected_count": len(failures),
        "uninspected": failures,
    }


def patterns(root, table, include_tests=False, inventory=None):
    project = Path(root).expanduser().resolve()
    compiled = {key: re.compile(value, re.I) for key, value in table.items()}
    if inventory is None:
        inventory = _collect_source_inventory(project, include_tests=True)
    rows = []
    for path in _inventory_paths(inventory, include_tests=include_tests):
        text = inventory["contents"][path]
        for number, line in enumerate(text.splitlines(), 1):
            for key, regex in compiled.items():
                if regex.search(line):
                    rows.append({
                        "kind": key,
                        "file": path.relative_to(project).as_posix(),
                        "line": number,
                        "text": line.strip()[:400],
                    })
    return rows

def funcs(text):
    rx=re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\([^;{}]*\)[^{;]*\{")
    for m in rx.finditer(text):
        depth=1; i=m.end()
        while i<len(text) and depth:
            if text[i]=="{": depth+=1
            elif text[i]=="}": depth-=1
            i+=1
        if depth==0: yield {"name":m.group(1),"start":m.start(),"body":text[m.end():i-1]}
def reentrancy_graph(root, inventory=None):
    project = Path(root).expanduser().resolve()
    if inventory is None:
        inventory = _collect_source_inventory(project, include_tests=True)
    out = []
    calls = re.compile(r"\.(?:call|delegatecall|staticcall)\s*(?:\{|\()|\.transfer\s*\(|\.send\s*\(|safeTransfer(?:From)?\s*\(")
    reads = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\[[^\]]+\]")
    writes = re.compile(r"\b([A-Za-z_$][\w$]*)\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|[+\-*/]?=)")
    for path in _inventory_paths(inventory, include_tests=False):
        text = inventory["contents"][path]
        for function in funcs(text):
            read_rows = list(reads.finditer(function["body"]))
            write_rows = list(writes.finditer(function["body"]))
            for call in calls.finditer(function["body"]):
                before = {match.group(1) for match in read_rows if match.start() < call.start()}
                after = {match.group(1) for match in write_rows if match.start() > call.start()}
                shared = sorted(before & after)
                if shared:
                    out.append({
                        "file": path.relative_to(project).as_posix(),
                        "function": function["name"],
                        "variables": shared,
                        "call_offset": call.start(),
                        "confidence": "heuristic",
                        "excerpt": function["body"][max(0, call.start() - 80):call.end() + 100].strip()[:280],
                    })
    return out

def source_maps(root, inventory=None):
    project = Path(root).expanduser().resolve()
    if inventory is None:
        inventory = _collect_source_inventory(project, include_tests=True)

    arithmetic_rows = []
    for path in _inventory_paths(inventory, include_tests=False):
        if path.suffix.lower() != ".sol":
            continue
        try:
            arithmetic_rows.extend(
                scan_unsigned_source(
                    inventory["contents"][path],
                    path.relative_to(project).as_posix(),
                    project,
                )
            )
        except Exception as exc:
            inventory["failures"].append({
                "path": path.relative_to(project).as_posix(),
                "phase": "arithmetic-analysis",
                "scope": "source-file",
                "error": f"{type(exc).__name__}: {exc}"[:600],
            })

    cfg_outline = []
    for path in _inventory_paths(inventory, include_tests=False):
        text = inventory["contents"][path]
        for function in funcs(text):
            if not re.search(PATTERNS["external_call"], function["body"], re.I):
                continue
            operations = sorted(
                list(re.finditer(PATTERNS["external_call"], function["body"], re.I))
                + list(re.finditer(r"\b[A-Za-z_$][\w$]*\s*(?:\[[^\]]+\])?\s*(?:\+\+|--|[+\-*/]?=)", function["body"])),
                key=lambda item: item.start(),
            )
            cfg_outline.append({
                "file": path.relative_to(project).as_posix(),
                "function": function["name"],
                "nodes": ([{"kind": "entry", "offset": 0}]
                    + [{
                        "kind": "external_call" if "call" in item.group(0) else "state_write",
                        "offset": item.start(),
                        "text": item.group(0)[:90],
                    } for item in operations]
                    + [{"kind": "exit", "offset": len(function["body"])}]),
            })

    return {
        "fallback_map": patterns(root, {**FALLBACK, "generic_hook": r"\bon[A-Z][A-Za-z0-9_]*\s*\("}, True, inventory),
        "oracle_map": patterns(root, {
            "chainlink_aggregator": r"\b(?:latestRoundData|latestAnswer|getRoundData)\s*\(",
            "uniswap_v2_spot": r"\bgetReserves\s*\(",
            "uniswap_v3_spot": r"\bslot0\s*\(",
            "twap_observation": r"\b(?:observe|consult)\s*\(",
            "generic_price_or_rate": r"\b(?:price|oracle|exchangeRate|virtualPrice|sharePrice)\b",
            "freshness_guard": r"\b(?:updatedAt|answeredInRound|heartbeat|stale|staleness)\b",
        }, inventory=inventory),
        "time_map": patterns(root, {
            "timestamp": r"\bblock\.timestamp\b", "block_number": r"\bblock\.number\b",
            "blockhash": r"\bblockhash\s*\(", "prevrandao": r"\bblock\.prevrandao\b",
            "deadline": r"\b(?:deadline|expiry|expiration)\b",
            "lock_window": r"\b(?:unlock|lockUntil|epoch|vesting)\b",
        }, inventory=inventory),
        "storage_map": patterns(root, {
            "mapping_declaration": r"\bmapping\s*\(",
            "dynamic_array": r"\b[A-Za-z_$][\w$]*\s*\[\s*\]\s+(?:public|private|internal|external)?",
            "storage_assembly": r"\b(?:sload|sstore)\s*\(",
            "hash_derived_slot": r"\b(?:keccak256|keccak)\s*\(",
        }, inventory=inventory),
        "token_map": patterns(root, {
            "erc20_transfer": r"\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom)\s*\(",
            "unchecked_balance": r"\bbalanceOf\s*\(", "decimals_assumption": r"\bdecimals\s*\(",
            "permit": r"\bpermit\s*\(", "approval": r"\b(?:approve|allowance)\s*\(",
        }, inventory=inventory),
        "arithmetic_review": arithmetic_rows,
        "signature_map": patterns(root, {
            "signature": PATTERNS["signature"], "nonce_domain": PATTERNS["nonce_domain"],
        }, inventory=inventory),
        "initializer_map": patterns(root, {
            "initializer": r"\binitializer\b", "reinitializer": r"\breinitializer\s*\(",
            "initialize_function": r"\bfunction\s+initialize[A-Za-z0-9_]*\s*\(",
            "disable_initializers": r"\b_disableInitializers\s*\(",
        }, inventory=inventory),
        "custody_map": patterns(root, {
            "owner": r"\b(?:onlyOwner|owner\s*\(|transferOwnership|renounceOwnership)\b",
            "access_control": r"\b(?:AccessControl|onlyRole|grantRole|revokeRole|hasRole)\b",
            "guardian": r"\bguardian\b", "pause": r"\b(?:pause|unpause|whenNotPaused|Pausable)\b",
            "timelock": r"\b(?:Timelock|timelock|schedule|execute)\b",
            "upgrade": r"\b(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade|ProxyAdmin|beacon)\b",
        }, inventory=inventory),
        "cross_vm_map": patterns(root, {
            "solana_signer": r"\bSigner\s*<|\bis_signer\b",
            "solana_pda": r"\bseeds\s*=|find_program_address|create_program_address",
            "solana_account": r"\bAccountInfo\b|\bowner\s*==\s*\*?program_id",
            "move_capability": r"\b(?:has key|acquires|TreasuryCap|AdminCap|public entry|friend)\b",
            "cairo_caller": r"\b(?:get_caller_address|caller_address|external\s*\()",
            "soroban_auth": r"\b(?:require_auth|require_auth_for_args|\.auth\s*\()",
        }, inventory=inventory),
        "reentrancy_graph": reentrancy_graph(project, inventory),
        "cfg_outline": cfg_outline,
    }

class AhoCorasick:
    def __init__(self,patterns):
        self.next=[{}]; self.fail=[0]; self.out=[[]]
        for label,tokens in patterns:
            state=0
            for token in tokens:
                if token not in self.next[state]:
                    self.next[state][token]=len(self.next); self.next.append({}); self.fail.append(0); self.out.append([])
                state=self.next[state][token]
            self.out[state].append((label,len(tokens)))
        q=list(self.next[0].values()); pos=0
        while pos<len(q):
            state=q[pos]; pos+=1
            for token,nxt in self.next[state].items():
                q.append(nxt); failure=self.fail[state]
                while failure and token not in self.next[failure]: failure=self.fail[failure]
                self.fail[nxt]=self.next[failure].get(token,0)
                self.out[nxt].extend(self.out[self.fail[nxt]])
    def scan(self,tokens):
        state=0; hits=[]
        for i,token in enumerate(tokens):
            while state and token not in self.next[state]: state=self.fail[state]
            state=self.next[state].get(token,0)
            hits.extend((i-size+1,label,size) for label,size in self.out[state])
        return hits
def cheat_fingerprints(root, inventory=None):
    project = Path(root).expanduser().resolve()
    if inventory is None:
        inventory = _collect_source_inventory(project, include_tests=True)
    try:
        try:
            from .solidity_cheat_topics import register_topics
        except ImportError:
            from solidity_cheat_topics import register_topics
        entries = []

        def collect(*args, **kwargs):
            label = str(args[0]) if args else "cheat-topic"
            for item in args[1:]:
                if not isinstance(item, str):
                    continue
                for line in item.splitlines():
                    if not re.search(r"(?:mapping|call|delegatecall|keccak|sload|sstore|fallback|receive|signature|nonce|vm\.)", line, re.I):
                        continue
                    tokens = tuple(re.findall(r"[A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|=>|&&|\|\||[^\s]", line))
                    if 3 <= len(tokens) <= 30:
                        entries.append((label, tokens))

        register_topics(collect)
    except Exception:
        entries = []

    unique = {}
    for label, tokens in entries:
        unique.setdefault(tokens, label)
    if not unique:
        unique = {
            ("delegatecall",): "delegatecall", ("mapping",): "mapping",
            ("sstore",): "storage-write", ("call",): "external-call",
        }
    automaton = AhoCorasick([(label, tokens) for tokens, label in unique.items()])
    result = []
    for path in _inventory_paths(inventory, include_tests=False):
        text = inventory["contents"][path]
        matches = list(re.finditer(r"[A-Za-z_$][\w$]*|0x[0-9a-fA-F]+|\d+|==|!=|<=|>=|=>|&&|\|\||[^\s]", text))
        tokens = [match.group(0) for match in matches]
        for index, label, size in automaton.scan(tokens):
            line = text.count("\n", 0, matches[index].start()) + 1
            result.append({
                "topic": label,
                "file": path.relative_to(project).as_posix(),
                "line": line,
                "fingerprint": hashlib.sha256(" ".join(tokens[index:index + size]).encode()).hexdigest()[:16],
            })
    return {
        "patterns": len(unique),
        "hits": result,
        "meaning": "Fingerprint matches are leads, never vulnerability verdicts.",
    }

_PRIVILEGED_STATE_NAMES = {
    "owner", "admin", "authority", "guardian", "governor", "governance",
    "operator", "manager", "maintainer", "pauser", "upgrader", "minter",
    "treasury", "feerecipient", "protocoladmin", "emergencyadmin",
    "pendingowner", "controller", "issuer", "whitelistadmin",
}


def _balanced_block_end(masked: str, opening: int) -> int | None:
    if opening < 0 or opening >= len(masked) or masked[opening] != "{":
        return None
    depth = 0
    for index in range(opening, len(masked)):
        if masked[index] == "{":
            depth += 1
        elif masked[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _solidity_entry_blocks(masked: str) -> list[dict[str, Any]]:
    """Extract externally callable Solidity function/receive/fallback bodies."""
    pattern = re.compile(
        r"\bfunction\s+(?P<function_name>[A-Za-z_$][\w$]*)\s*"
        r"\([^;{}]*\)(?P<function_header>[^{};]*)\{"
        r"|\b(?P<special_name>receive|fallback)\s*\(\s*\)"
        r"(?P<special_header>[^{};]*)\{"
    )
    blocks = []
    for match in pattern.finditer(masked):
        opening = match.end() - 1
        closing = _balanced_block_end(masked, opening)
        if closing is None:
            continue
        kind = "function" if match.group("function_name") else str(match.group("special_name"))
        name = str(match.group("function_name") or kind)
        header = str(match.group("function_header") or match.group("special_header") or "")
        externally_callable = kind in {"receive", "fallback"} or bool(
            re.search(r"\b(?:external|public)\b", header)
        )
        if not externally_callable:
            continue
        blocks.append({
            "kind": kind,
            "name": name,
            "header": header,
            "body": masked[opening + 1:closing],
            "start": match.start(),
            "body_start": opening + 1,
        })
    return blocks


def _authorization_guard(expression: str, privileged_names: set[str]) -> bool:
    if not re.search(r"\b(?:msg\.sender|_msgSender\s*\(\s*\))", expression):
        return False
    # A positive caller == authority comparison is the common fail-closed
    # authorization predicate. caller != authority may be the bug itself.
    if not re.search(r"==", expression):
        return False
    return any(re.search(r"\b" + re.escape(name) + r"\b", expression) for name in privileged_names)


def _source_security_candidates(root: str | Path, inventory: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Find generic unguarded writes to state used as an authorization principal.

    This is a conservative source-level rule: it derives custom authority variable
    names from the project's own caller-comparison guards, then checks every public,
    external, receive and fallback entry point for writes to those variables.
    """
    project = Path(root).expanduser().resolve()
    if inventory is None:
        inventory = _collect_source_inventory(project, include_tests=True)
    findings: list[dict[str, Any]] = []
    guard_call = re.compile(r"\b(?:require|assert|if)\s*\(([^{};]*)\)")
    modifier_pattern = re.compile(
        r"\bmodifier\s+(?P<name>[A-Za-z_$][\w$]*)\s*(?:\([^{};]*\))?[^{};]*\{"
    )
    assignment_pattern = re.compile(
        r"\b(?P<name>[A-Za-z_$][\w$]*)\s*(?:\[[^\]\n]+\]\s*)?"
        r"(?P<operator>=(?!=)|\+=|-=|\+\+|--)"
    )

    for path in _inventory_paths(inventory, include_tests=False):
        if path.suffix.lower() != ".sol":
            continue
        source = inventory["contents"][path]
        masked = _mask_comments_and_strings(source)
        blocks = _solidity_entry_blocks(masked)

        privileged_names = {
            name for name in re.findall(r"[A-Za-z_$][\w$]*", masked)
            if name.lower() in _PRIVILEGED_STATE_NAMES
        }
        # Derive non-standard authority names (e.g. chief, controller, steward)
        # from actual msg.sender/_msgSender comparisons in guards.
        for guard in guard_call.finditer(masked):
            expression = guard.group(1)
            if not re.search(r"\b(?:msg\.sender|_msgSender\s*\(\s*\))", expression):
                continue
            if not re.search(r"==|!=", expression):
                continue
            identifiers = re.findall(r"\b[A-Za-z_$][\w$]*\b", expression)
            privileged_names.update(
                item for item in identifiers
                if item.lower() not in {"msg", "sender", "_msgsender", "require", "assert"}
            )
        if not privileged_names or not blocks:
            continue

        auth_modifiers: set[str] = set()
        for modifier in modifier_pattern.finditer(masked):
            opening = modifier.end() - 1
            closing = _balanced_block_end(masked, opening)
            if closing is None:
                continue
            body = masked[opening + 1:closing]
            has_caller_guard = any(
                _authorization_guard(match.group(1), privileged_names)
                for match in guard_call.finditer(body)
            )
            has_role_guard = bool(re.search(r"\b(?:_checkRole|hasRole|requireRole)\s*\(", body))
            if has_caller_guard or has_role_guard:
                auth_modifiers.add(modifier.group("name"))

        for block in blocks:
            header = block["header"]
            body = block["body"]
            modifier_names = set(re.findall(r"\b([A-Za-z_$][\w$]*)\b", header))
            protected = bool(modifier_names & auth_modifiers)
            protected = protected or bool(
                modifier_names & {
                    "onlyOwner", "onlyAdmin", "onlyRole", "onlyGuardian",
                    "onlyGovernance", "onlyOperator", "onlyMinter", "onlyPauser",
                    "onlyUpgrader", "requiresAuth",
                }
            )
            if not protected:
                protected = any(
                    _authorization_guard(match.group(1), privileged_names)
                    for match in guard_call.finditer(body)
                )
            if not protected and re.search(r"\b(?:_checkRole|requireRole)\s*\(", body):
                protected = True
            if protected:
                continue

            for assignment in assignment_pattern.finditer(body):
                variable = assignment.group("name")
                if variable not in privileged_names:
                    continue
                absolute_offset = block["body_start"] + assignment.start()
                line = source.count("\n", 0, absolute_offset) + 1
                source_lines = source.splitlines()
                excerpt = source_lines[line - 1].strip() if line <= len(source_lines) else ""
                title = f"Unprotected write to privileged state '{variable}'"
                fingerprint = hashlib.sha256(
                    f"{path.relative_to(project).as_posix()}:{line}:{variable}:{block['name']}".encode()
                ).hexdigest()[:16]
                findings.append({
                    "finding_id": "SRC-" + fingerprint,
                    "title": title,
                    "category": "access-control",
                    "severity": "high",
                    "confidence": "medium",
                    "location": {
                        "path": path.relative_to(project).as_posix(),
                        "symbol": block["name"] + ("()" if block["kind"] != "function" else ""),
                    },
                    "file": path.relative_to(project).as_posix(),
                    "line": line,
                    "function": block["name"],
                    "privileged_variable": variable,
                    "evidence_quote": excerpt[:500],
                    "reasoning": (
                        f"The externally callable {block['kind']} entry point writes '{variable}', "
                        "a state variable used as an authorization principal elsewhere in this source file, "
                        "without an authorization modifier or a caller-to-authority guard in this entry point."
                    ),
                    "impact": (
                        "An untrusted caller may be able to change the contract's authority and then use "
                        "privileged functions. Reachability and the surrounding state machine still require testing."
                    ),
                    "exploit_preconditions": (
                        "The entry point must be reachable by an untrusted caller and the authority write must "
                        "not be constrained by another inherited or external authorization check."
                    ),
                    "recommendation": (
                        "Restrict authority changes to the current authorized principal; consider a two-step "
                        "ownership transfer and add a test proving an ordinary account cannot change this state."
                    ),
                    "status": "candidate",
                    "verified": False,
                    "tool": "lowkey-source-review",
                    "evidence_level": "static-source-candidate",
                })
    return findings


def _run_slither_analysis(root: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run Slither's full detector suite when installed; retain explicit skip/error states."""
    project = Path(root).expanduser().resolve()
    solidity_files = [path for path in files(project) if path.suffix.lower() == ".sol"]
    if not solidity_files:
        return ({
            "name": "slither-analysis",
            "status": "skipped",
            "reason": "No first-party Solidity source files were found.",
        }, [])
    try:
        try:
            from . import slither_tools
        except ImportError:
            import slither_tools
        if not slither_tools.slither_path():
            return ({
                "name": "slither-analysis",
                "status": "skipped",
                "reason": "Slither is not installed or not available on PATH; built-in source review still ran.",
            }, [])
        exit_code = int(slither_tools.run_default(project, quiet=True))
        evidence_path = project / ".audit" / "slither" / "latest.json"
        raw = json.loads(evidence_path.read_text(encoding="utf-8")) if evidence_path.is_file() else {}
        detectors = ((raw.get("results") or {}).get("detectors") or []) if isinstance(raw, dict) else []
        if not isinstance(detectors, list):
            detectors = []
        findings = []
        for item in detectors:
            if not isinstance(item, dict):
                continue
            elements = item.get("elements") if isinstance(item.get("elements"), list) else []
            location = {}
            function = None
            for element in elements:
                if not isinstance(element, dict):
                    continue
                mapping = element.get("source_mapping") if isinstance(element.get("source_mapping"), dict) else {}
                file_name = mapping.get("filename_relative") or mapping.get("filename_short") or mapping.get("filename_used")
                lines = mapping.get("lines") if isinstance(mapping.get("lines"), list) else []
                if file_name:
                    location = {"path": str(file_name), "line": lines[0] if lines else None}
                if str(element.get("type") or "").lower() == "function":
                    function = str(element.get("name") or "")
                if location:
                    break
            check = str(item.get("check") or "slither-detector")
            description = str(item.get("description") or item.get("markdown") or "").strip()
            findings.append({
                "finding_id": "SL-" + hashlib.sha256(
                    (check + "|" + json.dumps(location, sort_keys=True) + "|" + description).encode()
                ).hexdigest()[:16],
                "title": check.replace("-", " ").replace("_", " ").title(),
                "category": "static-analysis",
                "severity": str(item.get("impact") or "info").lower(),
                "confidence": str(item.get("confidence") or "low").lower(),
                "location": location,
                "function": function,
                "evidence_quote": description[:1200],
                "reasoning": description[:2400],
                "impact": "Slither reported this detector. Confirm reachability and concrete impact before treating it as a vulnerability.",
                "recommendation": "Inspect the detector explanation and surrounding control flow, then write a focused Foundry regression test.",
                "status": "candidate",
                "verified": False,
                "tool": "slither",
                "check": check,
                "evidence_level": "static-analysis-candidate",
            })
        status = "completed" if evidence_path.is_file() and exit_code == 0 else (
            "review" if evidence_path.is_file() else "blocked"
        )
        return ({
            "name": "slither-analysis",
            "status": status,
            "exit_code": exit_code,
            "finding_count": len(findings),
            "evidence": ".audit/slither/latest.json",
            "reason": "" if status == "completed" else (
                "Slither produced evidence but exited non-zero; inspect its compiler/tool diagnostics."
                if status == "review" else
                "Slither did not produce its JSON evidence file; inspect the tool or compiler error."
            ),
        }, findings)
    except Exception as exc:
        return ({
            "name": "slither-analysis",
            "status": "blocked",
            "reason": f"Slither execution failed: {type(exc).__name__}: {exc}",
        }, [])




def _run_ai_security_review(root: str | Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run the configured AI source reviewer only after explicit operator opt-in."""
    project = Path(root).expanduser().resolve()
    try:
        try:
            from . import security_review
        except ImportError:
            import security_review
        review = security_review.review_project_security(project)
        raw_findings = review.get("candidate_findings") if isinstance(review, dict) else []
        if not isinstance(raw_findings, list):
            raw_findings = []
        findings: list[dict[str, Any]] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            location = item.get("location") if isinstance(item.get("location"), dict) else {}
            findings.append({
                "finding_id": str(item.get("finding_id") or ""),
                "title": str(item.get("title") or "AI-assisted security candidate"),
                "category": str(item.get("category") or "security-review"),
                "severity": str(item.get("severity") or "info").lower(),
                "confidence": str(item.get("confidence") or "low").lower(),
                "location": location,
                "file": str(location.get("path") or ""),
                "line": item.get("line"),
                "function": str(location.get("symbol") or ""),
                "evidence_quote": str(item.get("evidence_quote") or ""),
                "reasoning": str(item.get("reasoning") or ""),
                "impact": str(item.get("impact") or ""),
                "exploit_preconditions": str(item.get("exploit_preconditions") or ""),
                "recommendation": str(item.get("recommendation") or ""),
                "source_quote_status": item.get("source_quote_status"),
                "status": "candidate",
                "verified": False,
                "ai_generated": True,
                "tool": "security-review-agent",
                "evidence_level": "ai-assisted-source-candidate",
            })
        meta = review.get("_lowkey_meta") if isinstance(review, dict) else {}
        meta = meta if isinstance(meta, dict) else {}
        limitations = review.get("limitations") if isinstance(review, dict) else []
        return ({
            "name": "ai-review",
            "status": "completed",
            "finding_count": len(findings),
            "summary": str(review.get("summary") or "") if isinstance(review, dict) else "",
            "limitations": limitations if isinstance(limitations, list) else [],
            "report_path": str(meta.get("report_path") or ""),
            "review_id": str(meta.get("review_id") or ""),
            "provider": str(meta.get("provider") or ""),
            "model": str(meta.get("model") or ""),
        }, findings)
    except Exception as exc:
        return ({
            "name": "ai-review",
            "status": "blocked",
            "reason": f"AI security review could not complete: {type(exc).__name__}: {exc}",
        }, [])


def rpc_url(v=None):
    url=v or os.environ.get("FOUNDRY_ETH_RPC_URL") or os.environ.get("ETH_RPC_URL") or os.environ.get("LOWKEY_RPC_URL")
    if not url or urlparse(url).scheme not in {"http","https"}: raise ValueError("Pass --rpc-url or set FOUNDRY_ETH_RPC_URL/ETH_RPC_URL.")
    return url
def rpc(url,method,params,timeout=20):
    data=json.dumps({"jsonrpc":"2.0","id":1,"method":method,"params":params}).encode()
    req=Request(
        url,
        data=data,
        headers={
            "Content-Type":"application/json",
            "Accept":"application/json",
            "User-Agent":"LowkeyCast/1.0 (+https://github.com/Toji254/foundry-lowkey)",
        },
    )
    with urlopen(req,timeout=timeout) as res: body=json.loads(res.read().decode())
    if body.get("error"): raise RuntimeError(f"{method}: {body['error']}")
    return body.get("result")
def addr(v):
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}",v or ""): raise ValueError("Expected a 20-byte 0x-prefixed address.")
    return v.lower()

def storage_slot_key(value):
    """Canonicalize integer/hex storage slot notation to a 32-byte hex word."""
    raw=str(value or "").strip().lower()
    if re.fullmatch(r"0x[0-9a-f]{64}",raw):
        return raw
    try:
        number=int(raw,16) if raw.startswith("0x") else int(raw,10)
    except (TypeError,ValueError):
        raise ValueError("Storage slot must be an integer or 0x-prefixed bytes32 value.")
    if number<0 or number>=2**256:
        raise ValueError("Storage slot must fit bytes32.")
    return "0x"+format(number,"064x")
def local_rpc(url):
    return (urlparse(url).hostname or "").lower() in {"127.0.0.1","localhost","::1"}
def push4(code):
    raw=bytes.fromhex(code[2:] if code.startswith("0x") else code)
    found=set(); i=0
    while i<len(raw):
        op=raw[i]
        if op==0x63 and i+4<len(raw): found.add("0x"+raw[i+1:i+5].hex()); i+=5
        elif 0x60<=op<=0x7f: i+=1+op-0x5f
        else: i+=1
    return sorted(found)
def proxy(target,url,slots=120):
    target=addr(target); slots=max(0,min(int(slots),120))
    queries=[("eth_getStorageAt",[target,s,"latest"]) for s in EIP1967.values()]
    queries += [("eth_getStorageAt",[target,hex(i),"latest"]) for i in range(slots)]
    values=[rpc(url,m,p) for m,p in queries]
    rows=[]
    for i,(name,slot) in enumerate(EIP1967.items()):
        value=str(values[i] or "0x"+"0"*64); a="0x"+value[-40:]
        if int(a,16): rows.append({"kind":name,"slot":slot,"address":a})
    for i,value in enumerate(values[len(EIP1967):]):
        if value and int(value,16):
            a="0x"+value[-40:]
            if int(a,16): rows.append({"kind":"code-address-candidate","slot":hex(i),"address":a})
    out=[]
    for row in rows:
        code=rpc(url,"eth_getCode",[row["address"],"latest"])
        has=bool(code and code!="0x")
        out.append({**row,"has_code":has,"confidence":"high" if has and row["kind"] in EIP1967 else "medium" if has else "low"})
    return {"target":target,"candidates":out,"warning":"Candidate slots only; confirm the actual proxy standard and upgrade semantics."}
def selectors(target,url):
    target=addr(target); code=rpc(url,"eth_getCode",[target,"latest"]); values=push4(code or "0x")
    rows=[]
    for s in values:
        names=[]
        if shutil.which("cast"):
            try:
                p=subprocess.run(["cast","4byte",s],capture_output=True,text=True,timeout=5)
                if p.returncode==0: names=[x.strip() for x in p.stdout.splitlines() if x.strip()]
            except (OSError,subprocess.TimeoutExpired): pass
        rows.append({"selector":s,"signatures":names,"status":"resolved" if names else "unresolved"})
    return {"target":target,"selectors":rows,"count":len(rows),"warning":"PUSH4 constants can be mistaken for selectors; unresolved values remain unresolved."}
def run(argv,cwd,timeout=300,env=None):
    if not argv or not all(isinstance(x,str) for x in argv): raise ValueError("Supply a non-empty argv array.")
    return subprocess.run(argv,cwd=str(cwd),capture_output=True,text=True,timeout=max(1,min(timeout,3600)),shell=False,env=env)


def run_live(argv, cwd, timeout=None, env=None, heartbeat_seconds=20, tail_limit=3000):
    """Run a child command with live combined output and a bounded evidence tail.

    The child is placed in its own process group so Ctrl-C can be forwarded
    cleanly and the attack engine can persist its interrupted-run evidence.
    """
    if not argv or not all(isinstance(item, str) for item in argv):
        raise ValueError("Supply a non-empty argv array.")

    child_env = os.environ.copy()
    if env:
        child_env.update(env)
    # Python children otherwise switch to block buffering when stdout is piped.
    child_env["PYTHONUNBUFFERED"] = "1"

    process = subprocess.Popen(
        list(argv),
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        shell=False,
        env=child_env,
        start_new_session=(os.name == "posix"),
    )
    output_queue = queue.Queue()

    def _read_output():
        try:
            if process.stdout is not None:
                for line in process.stdout:
                    output_queue.put(line)
        finally:
            output_queue.put(None)

    reader = threading.Thread(target=_read_output, name="lowkey-live-command-output", daemon=True)
    reader.start()
    output_tail = ""
    started = time.monotonic()
    last_output = started
    reader_done = False
    timed_out = False
    terminate_at = None

    def _signal_child(signum):
        try:
            if os.name == "posix":
                os.killpg(process.pid, signum)
            elif signum == signal.SIGKILL:
                process.kill()
            else:
                process.terminate()
        except (ProcessLookupError, PermissionError):
            pass

    def _forward(line):
        nonlocal output_tail, last_output
        sys.stdout.write(line)
        sys.stdout.flush()
        output_tail = (output_tail + line)[-max(1, int(tail_limit)):]
        last_output = time.monotonic()

    try:
        while not reader_done:
            now = time.monotonic()
            elapsed = now - started
            if timeout is not None and not timed_out and elapsed >= timeout:
                timed_out = True
                print(
                    f"[LOWKEY] Child command exceeded its {int(timeout)} second limit; stopping it.",
                    file=sys.stderr,
                    flush=True,
                )
                _signal_child(signal.SIGTERM)
                terminate_at = now + 3
            elif timed_out and terminate_at is not None and now >= terminate_at and process.poll() is None:
                _signal_child(signal.SIGKILL)
                terminate_at = None

            poll_interval = 0.5
            if heartbeat_seconds:
                poll_interval = min(poll_interval, max(0.01, float(heartbeat_seconds)))
            if timeout is not None and not timed_out:
                remaining = max(0.01, float(timeout) - elapsed)
                poll_interval = min(poll_interval, remaining)
            try:
                line = output_queue.get(timeout=poll_interval)
            except queue.Empty:
                now = time.monotonic()
                if (
                    heartbeat_seconds
                    and process.poll() is None
                    and now - last_output >= heartbeat_seconds
                ):
                    quiet_for = int(now - last_output)
                    total_for = int(now - started)
                    print(
                        f"[LOWKEY] Attack worker is still running ({total_for}s elapsed); "
                        f"no new output for {quiet_for}s. A probe may be executing. "
                        "Ctrl+C requests a clean stop.",
                        flush=True,
                    )
                    last_output = now
                continue

            if line is None:
                reader_done = True
            else:
                _forward(line)
    except KeyboardInterrupt:
        print(
            "[LOWKEY] Interrupt received; asking the attack worker to stop cleanly...",
            file=sys.stderr,
            flush=True,
        )
        _signal_child(signal.SIGINT)
        try:
            process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            _signal_child(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _signal_child(signal.SIGKILL)
                process.wait()
        while not reader_done:
            try:
                line = output_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if line is None:
                reader_done = True
            else:
                _forward(line)

    returncode = process.wait()
    reader.join(timeout=1)
    if timed_out:
        output_tail = (output_tail + "\nLOWKEY_CHILD_TIMEOUT true\n")[-max(1, int(tail_limit)):]
        returncode = 124
    return subprocess.CompletedProcess(list(argv), returncode, output_tail, "")
def analyze_harness_fidelity(source_text, path="<memory>"):
    """Static fidelity inventory for a generated test harness; never a proof verdict."""
    source_text=str(source_text or "")
    patterns={
        "synthetic_eth":r"\bvm\.deal\s*\(",
        "synthetic_token_balance":r"(?<![\w.])deal\s*\(",
        "caller_impersonation":r"\bvm\.(?:prank|startPrank|hoax)\s*\(",
        "storage_override":r"\bvm\.(?:store|load)\s*\(",
        "code_injection":r"\bvm\.etch\s*\(",
        "external_call_mock":r"\bvm\.(?:mockCall|mockCallRevert|mockFunction|expectCall)\s*\(",
        "time_or_block_override":r"\bvm\.(?:warp|roll|setBlockhash)\s*\(",
        "test_assumption":r"\bvm\.(?:assume|bound)\s*\(",
    }
    signals=[]
    for kind,pattern in patterns.items():
        rx=re.compile(pattern)
        for match in rx.finditer(source_text):
            line=source_text.count("\n",0,match.start())+1
            signals.append({"kind":kind,"line":line,"token":match.group(0)})
    pinned=bool(re.search(r"\bvm\.(?:createSelectFork|createFork)\s*\([^;]*,\s*(?:0x[0-9a-fA-F]+|[0-9]+)",source_text))
    gas_measured=bool(re.search(r"\bgasleft\s*\(|snapshotGas|startSnapshotGas",source_text,re.I))
    synthetic_kinds={x["kind"] for x in signals}
    synthetic_state=bool(synthetic_kinds & {"synthetic_eth","synthetic_token_balance","storage_override","code_injection","external_call_mock","time_or_block_override"})
    gaps=[]
    labels={
        "synthetic_eth":"Foundry ETH balances are synthetically assigned",
        "synthetic_token_balance":"Token balances are synthetically assigned",
        "caller_impersonation":"Caller identity is impersonated with a test cheatcode",
        "storage_override":"Storage is directly overridden with a test cheatcode",
        "code_injection":"Runtime code is injected with a test cheatcode",
        "external_call_mock":"External dependency behavior is mocked",
        "time_or_block_override":"Timestamp or block number is overridden",
        "test_assumption":"Fuzzer inputs are constrained with assumptions",
    }
    for kind in sorted(synthetic_kinds):
        gaps.append(labels.get(kind,kind))
    if not pinned: gaps.append("No explicit block-pinned fork creation was detected")
    if not gas_measured: gaps.append("Transaction gas cost is not measured by this harness")
    gaps.append("Net profit and financing costs are not independently verified by a test harness scan")
    hard_blocked={"synthetic_eth","synthetic_token_balance","caller_impersonation","storage_override","code_injection","external_call_mock","time_or_block_override"}
    observed_kinds=sorted(synthetic_kinds)
    fork_blockers=sorted(hard_blocked & synthetic_kinds)
    policy={
        "SIMULATED_BREAK":{"allowed":"All detected test cheatcodes are permitted only as disclosed simulation inputs; never label as realistic."},
        "FORK_REPRODUCED":{"allowed":["test_assumption"],"blocked":sorted(hard_blocked)},
        "REALISTIC":{"allowed":[],"blocked":sorted(hard_blocked | {"test_assumption"})},
        "PROFITABLE":{"requirements":["FORK_REPRODUCED","measured recipient/attacker balance deltas","actual receipt gasUsed and effectiveGasPrice","net profit greater than zero"]},
        "HUMAN_CONFIRMED":{"requirements":["PROFITABLE or documented non-profit impact","native evidence reviewed","explicit human disposition in evidence ledger"]},
    }
    return {
        "schema_version":1,
        "path":str(path),
        "source_sha256":hashlib.sha256(source_text.encode("utf-8")).hexdigest(),
        "signals":signals,
        "synthetic_eth":"synthetic_eth" in synthetic_kinds,
        "synthetic_token_balance":"synthetic_token_balance" in synthetic_kinds,
        "caller_impersonation":"caller_impersonation" in synthetic_kinds,
        "storage_override":"storage_override" in synthetic_kinds,
        "code_injection":"code_injection" in synthetic_kinds,
        "external_call_mock":"external_call_mock" in synthetic_kinds,
        "time_or_block_override":"time_or_block_override" in synthetic_kinds,
        "fork_block_pinned":pinned,
        "gas_measured":gas_measured,
        "transaction_gas_verified":False,
        "net_profit_verified":False,
        "synthetic_state":synthetic_state,
        "classification":"SIMULATED" if synthetic_state or not pinned else "FORK_REPRODUCTION_CANDIDATE",
        "confirmation_eligible":False,
        "promotion_policy":policy,
        "fork_reproduction_blockers":fork_blockers,
        "allowed_cheatcodes_for_fork_reproduction":policy["FORK_REPRODUCED"]["allowed"],
        "observed_cheatcodes":observed_kinds,
        "proof_gaps":gaps,
        "policy":"Static harness inspection only. This record does not prove exploitability, authorization, gas realism, or profitability.",
    }


def _trace_flatten(trace, limit=512):
    rows=[]
    def walk(node,depth=0):
        if not isinstance(node,dict) or len(rows)>=limit: return
        rows.append({
            "depth":depth,
            "type":str(node.get("type") or ""),
            "from":str(node.get("from") or "").lower(),
            "to":str(node.get("to") or "").lower(),
            "created_address":str(node.get("createdAddress") or "").lower() or None,
            "input":str(node.get("input")).lower() if node.get("input") is not None else None,
            "value":str(node.get("value")).lower() if node.get("value") is not None else None,
            "error":str(node.get("error")) if node.get("error") is not None else None,
        })
        for child in node.get("calls") or []:
            walk(child,depth+1)
    walk(trace)
    return rows

def _normalize_rpc_trace_events(calls):
    try:
        from .trace_evidence import normalize_rpc_trace_events
    except ImportError:
        try:
            from lowkey.trace_evidence import normalize_rpc_trace_events
        except ImportError:
            from trace_evidence import normalize_rpc_trace_events
    return normalize_rpc_trace_events(calls, backend="anvil-calltracer")

def _normalize_trace_events_v2(calls, storage_trace=None):
    """Build canonical v2 events; changed slots remain transaction-level partial evidence."""
    try:
        from .trace_schema import TRACE_SCHEMA_VERSION, normalize_calltracer
    except ImportError:
        try:
            from lowkey.trace_schema import TRACE_SCHEMA_VERSION, normalize_calltracer
        except ImportError:
            from trace_schema import TRACE_SCHEMA_VERSION, normalize_calltracer
    storage_trace = storage_trace if isinstance(storage_trace, dict) else {}
    if storage_trace.get("supported"):
        partial_rows = [
            {
                "account": row.get("address"),
                "slot": row.get("slot"),
                "previous_value": row.get("value"),
                "new_value": row.get("post_value"),
                "is_write": row.get("value") != row.get("post_value"),
                "reverted": False,
            }
            for row in storage_trace.get("slots", [])
            if isinstance(row, dict)
        ]
        events = normalize_calltracer(
            calls,
            storage_support="partial",
            partial_storage={0: partial_rows},
        )
    else:
        events = normalize_calltracer(calls, storage_support="declared_only")
    return TRACE_SCHEMA_VERSION, events



def _control_transaction_envelope(tx, chain_id):
    """Canonical transaction fields that can affect call context or gas accounting."""
    fields=("nonce","gas","gasPrice","maxFeePerGas","maxPriorityFeePerGas","type","accessList")
    envelope={"chain_id":str(chain_id).lower()}
    for name in fields:
        value=tx.get(name)
        if name=="accessList" and isinstance(value,list):
            envelope[name]=[
                {"address":str(row.get("address") or "").lower(),
                 "storageKeys":sorted(str(key).lower() for key in (row.get("storageKeys") or []))}
                for row in value if isinstance(row,dict)
            ]
        elif value is None:
            envelope[name]=None
        elif isinstance(value,str):
            envelope[name]=value.lower()
        else:
            envelope[name]=value
    digest=hashlib.sha256(json.dumps(envelope,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    return digest,envelope


def _control_entry_digest(tx, chain_id):
    value=tx.get("value") or "0x0"
    try: value_int=int(str(value),16) if str(value).startswith("0x") else int(value)
    except (TypeError,ValueError): raise ValueError("Traced transaction has an invalid value field.")
    entry={
        "chain_id":str(chain_id).lower(),
        "from":str(tx.get("from") or "").lower(),
        "to":str(tx.get("to") or "").lower(),
        "input":str(tx.get("input") or tx.get("data") or "").lower(),
        "value_wei":value_int,
    }
    if not entry["from"] or not entry["to"] or not entry["input"].startswith("0x"):
        raise ValueError("RPC transaction is missing sender, recipient or calldata.")
    return hashlib.sha256(json.dumps(entry,sort_keys=True,separators=(",",":")).encode()).hexdigest(),entry


def _control_prestate_digest(url, receipt, addresses, slots, comparison_excluded_slots=None,
                            equivalence_addresses=None, equivalence_slots=None):
    block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
    tx_index=int(str(receipt.get("transactionIndex") or "0x0"),16)
    if block_number<1 or tx_index!=0:
        raise ValueError("Trace-backed control requires an automined transaction at index 0 so its parent block is the exact pre-state.")
    block=rpc(url,"eth_getBlockByNumber",[hex(block_number-1),False])
    if not isinstance(block,dict): raise ValueError("RPC did not return the transaction's parent block.")
    prestate={"parent_block_number":block_number-1,"parent_block_hash":str(block.get("hash") or "").lower(),
              "timestamp":str(block.get("timestamp") or "").lower(),
              "base_fee_per_gas":str(block.get("baseFeePerGas") or "").lower(),
              "addresses":[],"storage":[]}
    for address in sorted(set(addresses)):
        prestate["addresses"].append({
            "address":address,
            "balance":rpc(url,"eth_getBalance",[address,hex(block_number-1)]),
            "nonce":rpc(url,"eth_getTransactionCount",[address,hex(block_number-1)]),
            "code_sha256":hashlib.sha256(bytes.fromhex(str(rpc(url,"eth_getCode",[address,hex(block_number-1)]) or "0x").removeprefix("0x"))).hexdigest(),
        })
    for item in sorted(slots,key=lambda x:(x["address"],x["slot"])):
        prestate["storage"].append({
            "address":item["address"],"slot":item["slot"],
            "value":rpc(url,"eth_getStorageAt",[item["address"],item["slot"],hex(block_number-1)]),
        })
    # The parent hash itself includes the intentionally different attacker-only
    # scenario setup transaction. Keep it in evidence, but compare the execution
    # context and explicitly declared target/account state rather than the hash.
    excluded={str(x.get("address","")).lower()+":"+str(x.get("slot","")).lower()
              for x in (comparison_excluded_slots or []) if isinstance(x,dict)}
    comparable={key:value for key,value in prestate.items() if key!="parent_block_hash"}
    declared_addresses=set(str(x).lower() for x in (equivalence_addresses or addresses))
    declared_slot_keys={
        str(item.get("address","")).lower()+":"+str(item.get("slot","")).lower()
        for item in (equivalence_slots if equivalence_slots is not None else slots)
    }
    comparable["addresses"]=[
        row for row in comparable["addresses"]
        if str(row.get("address","")).lower() in declared_addresses
    ]
    comparable["storage"]=[
        row for row in comparable["storage"]
        if str(row.get("address","")).lower()+":"+str(row.get("slot","")).lower()
           in declared_slot_keys
        and str(row.get("address","")).lower()+":"+str(row.get("slot","")).lower()
           not in excluded
    ]
    digest=hashlib.sha256(json.dumps(comparable,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    prestate["equivalence_fields"] = sorted(comparable.keys())
    prestate["equivalence_addresses"] = sorted(declared_addresses)
    prestate["equivalence_slots"] = sorted(declared_slot_keys)
    prestate["comparison_excluded_slots"] = sorted(excluded)
    prestate["equivalence_policy"] = (
        "Parent block hash is retained for provenance but excluded because scenario preparation "
        "transactions differ. Equality uses only manifest-declared prestate_addresses and "
        "prestate_slots, plus explicit scenario-parameter slots excluded only after their "
        "control/attack values are independently verified. Per-run trace-discovered addresses "
        "and slots remain in full evidence and are compared through shared trace observations; "
        "they do not silently expand one run's declared equality participant set."
    )
    return digest,prestate



def _trace_storage_prestate(url, tx_hash):
    """Best-effort Geth/Anvil prestateTracer diff for one mined transaction."""
    try:
        payload=rpc(url,"debug_traceTransaction",[
            tx_hash,{"tracer":"prestateTracer","tracerConfig":{"diffMode":True}}
        ],60)
    except Exception as exc:
        return {"supported":False,"reason":str(exc)[:500],"addresses":[],"slots":[],"slot_count":0}
    if not isinstance(payload,dict):
        return {"supported":False,"reason":"prestateTracer diff returned a non-object result.","addresses":[],"slots":[],"slot_count":0}
    pre=payload.get("pre")
    post=payload.get("post")
    if not isinstance(pre,dict) or not isinstance(post,dict):
        return {
            "supported":False,
            "reason":"prestateTracer diff must return both pre and post account maps.",
            "addresses":[],"slots":[],"slot_count":0,
        }
    addresses=set()
    slots=[]
    for raw_address in set(pre) | set(post):
        try:
            address=addr(raw_address)
        except ValueError:
            continue
        before=pre.get(raw_address) if isinstance(pre.get(raw_address),dict) else {}
        after=post.get(raw_address) if isinstance(post.get(raw_address),dict) else {}
        addresses.add(address)
        before_storage=before.get("storage") or {}
        after_storage=after.get("storage") or {}
        if not isinstance(before_storage,dict) or not isinstance(after_storage,dict):
            continue
        # Diff mode reports changed slots only. Preserve the parent value and
        # post value separately; never infer a missing parent value as zero.
        for raw_slot in set(before_storage) | set(after_storage):
            raw_before=before_storage.get(raw_slot)
            raw_after=after_storage.get(raw_slot)
            if raw_before is None:
                continue
            slot_raw=str(raw_slot).lower().removeprefix("0x")
            value_raw=str(raw_before).lower().removeprefix("0x")
            post_raw=str(raw_after if raw_after is not None else raw_before).lower().removeprefix("0x")
            if (re.fullmatch(r"[0-9a-f]{1,64}",slot_raw) and
                re.fullmatch(r"[0-9a-f]{1,64}",value_raw) and
                re.fullmatch(r"[0-9a-f]{1,64}",post_raw)):
                slots.append({
                    "address":address,
                    "slot":"0x"+slot_raw.rjust(64,"0"),
                    "value":"0x"+value_raw.rjust(64,"0"),
                    "post_value":"0x"+post_raw.rjust(64,"0"),
                })
    slots.sort(key=lambda item:(item["address"],item["slot"]))
    if not addresses:
        return {"supported":False,"reason":"prestateTracer diff did not contain account state changes.",
                "addresses":[],"slots":[],"slot_count":0}
    return {
        "supported":True,
        "mode":"prestateTracer-diff",
        "addresses":sorted(addresses),
        "slots":slots,
        "slot_count":len(slots),
        "storage_scope":"transaction-level changed slots only; read-only slots may be absent and slots are not associated with individual call frames",
        "note":"Partial transaction-level pre/post storage evidence. It is not a complete read set or per-frame storage trace.",
    }




def _analyze_control_fidelity(root, entry, spec):
    candidates=[]
    harness=entry.get("harness") or spec.get("harness")
    if isinstance(harness,str):
        candidates.append(harness)
    for key in ("support_files",):
        values=entry.get(key) or []
        if isinstance(values,str):
            candidates.append(values)
        elif isinstance(values,list):
            candidates.extend(x for x in values if isinstance(x,str))
    for value in spec.get("fidelity_sources") or []:
        if isinstance(value,str):
            candidates.append(value)
    paths=[]
    for value in candidates:
        path=(root/value).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError("Fidelity source must be an existing project file: "+str(value))
        if path not in paths:
            paths.append(path)
    results=[]
    for path in paths:
        source=path.read_text(encoding="utf-8",errors="replace")
        results.append(analyze_harness_fidelity(source,path.relative_to(root).as_posix()))
    signals=[]
    blockers=[]
    for result in results:
        signals.extend(result.get("signals",[]))
        blockers.extend(result.get("fork_reproduction_blockers",[]))
    kinds={row.get("kind") for row in signals}
    return {
        "scan_complete":bool(paths),
        "scanned_files":[path.relative_to(root).as_posix() for path in paths],
        "synthetic_state":any(result.get("synthetic_state",False) for result in results),
        "signals":signals,
        "fork_reproduction_blockers":blockers,
        "classification":"SIMULATED" if any(result.get("synthetic_state",False) for result in results)
            else ("CLEAN_STATIC_SCAN" if paths else "UNKNOWN"),
        "static_scan_clear":bool(paths) and not blockers and not kinds.intersection({
            "synthetic_eth","caller_impersonation","storage_override","external_call_mock","time_or_block_override"
        }),
        "confirmation_eligible":False,
        "net_profit_verified":False,
        "coverage_limit":"Static scan covers only the explicit harness/support/fidelity source files; imported/transitive helpers must be listed in support_files or fidelity_sources.",
    }




def _semantic_execution_verified(exit_code, output, expected_test=None):
    """Require the named invariant test to pass, not just any command/test."""
    if exit_code != 0 or not isinstance(expected_test, str) or not expected_test.strip():
        return False
    text_value = str(output or "")
    name = re.escape(expected_test.strip())
    failed = re.search(r"\b[1-9][0-9]*\s+failed\b", text_value, re.I)
    if failed:
        return False
    passed_test = re.search(
        r"\[PASS\]\s+" + name + r"\s*\(",
        text_value,
        re.I,
    )
    explicit_marker = "LOWKEY_SEMANTIC_INVARIANT_PASS:" + expected_test.strip()
    return bool(passed_test or explicit_marker in text_value)



def _trace_control_run(root, url, name, entry, spec, env):
    fidelity_entry=dict(entry)
    support_files=list(entry.get("support_files") or [])
    for raw_argv in (entry.get("prepare_argv"),entry.get("argv"),entry.get("semantic_check_argv")):
        if not isinstance(raw_argv,list):
            continue
        for token in raw_argv:
            if not isinstance(token,str):
                continue
            candidate=Path(token).expanduser()
            candidate=(root/candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
            if (candidate.is_relative_to(root) and candidate.is_file() and
                candidate.suffix.lower() in {".sol",".vy",".py",".sh",".js",".ts",".rs",".move",".cairo"}):
                support_files.append(candidate.relative_to(root).as_posix())
    fidelity_entry["support_files"]=sorted(set(
        value for value in support_files if isinstance(value,str)
    ))
    fidelity=_analyze_control_fidelity(root,fidelity_entry,spec)
    snapshot=rpc(url,"evm_snapshot",[])
    if snapshot is None: raise RuntimeError("Anvil did not return an evm_snapshot ID.")
    try:
        temp=Path(tempfile.mkdtemp(prefix="lk-control-")); work=temp/"project"
        try:
            shutil.copytree(root,work,ignore=shutil.ignore_patterns(".git",".audit","out","cache","node_modules","__pycache__"))
            addresses=[addr(x) for x in (spec.get("prestate_addresses") or [])]
            # Freeze the equality participant set from the manifest before
            # adding run-specific trace discoveries. An attack-only path may
            # touch extra accounts; they remain evidence rather than silently
            # expanding one run's declared shared-prestate requirements.
            declared_addresses=list(addresses)
            scenario_parameters=[]
            prepare_argv=entry.get("prepare_argv")
            for command_name,command_argv in (("prepare_argv",prepare_argv),("argv",entry.get("argv"))):
                if command_argv:
                    command_audit=inspect_reproduction_command(root,command_argv)
                    if command_audit["blocked"]:
                        raise ValueError(f"{name} {command_name} contains local RPC state-fabrication calls: {command_audit['state_fabrication_calls']}")
            if spec.get("scenario_parameters") and not prepare_argv:
                raise ValueError(f"{name} requires prepare_argv so attacker-only scenario variables can be verified before transaction execution.")
            if prepare_argv:
                prepared=run([str(x) for x in prepare_argv],work,int(spec.get("prepare_timeout_seconds",60)),env=env)
                prepared_output=(prepared.stdout or "")+"\n"+(prepared.stderr or "")
                if prepared.returncode!=0:
                    raise RuntimeError(f"{name} scenario preparation failed (exit {prepared.returncode}): {prepared_output[-1200:]}")
            for scenario in spec.get("scenario_parameters") or []:
                if not isinstance(scenario,dict): raise ValueError("scenario_parameters entries must be objects.")
                scenario_address=addr(scenario.get("address"))
                if scenario_address not in addresses:
                    raise ValueError(f"Scenario parameter address {scenario_address} must also appear in prestate_addresses.")
                scenario_slot=storage_slot_key(scenario.get("slot"))
                observed=rpc(url,"eth_getStorageAt",[scenario_address,scenario_slot,"latest"])
                expected_raw=scenario.get(name+"_value")
                if expected_raw is None: raise ValueError(f"scenario parameter is missing {name}_value.")
                expected_value=int(str(expected_raw),16) if str(expected_raw).lower().startswith("0x") else int(expected_raw)
                observed_value=int(str(observed),16)
                if observed_value!=expected_value:
                    raise ValueError(f"Scenario parameter {scenario.get('name') or scenario_slot} has value {observed}, expected {expected_raw} for {name} before the transaction.")
                scenario_parameters.append({"name":scenario.get("name"),"address":scenario_address,
                                            "slot":scenario_slot,"observed_value":observed,
                                            "expected_value":expected_raw,"description":scenario.get("description"),
                                            "verified_before_transaction":True})
            expected_receipt_status=str(entry.get("expected_receipt_status") or "0x1").lower()
            if expected_receipt_status not in {"0x0","0x1","0","1"}:
                raise ValueError(f"{name} expected_receipt_status must be 0x0 or 0x1.")
            expected_receipt_status="0x1" if expected_receipt_status in {"0x1","1"} else "0x0"
            proc=run([str(x) for x in entry["argv"]],work,int(spec.get("timeout_seconds",300)),env=env)
            combined=(proc.stdout or "")+"\n"+(proc.stderr or "")
            hashes=re.findall(r"LOWKEY_TRACE_TX_HASH\s+(0x[0-9a-fA-F]{64})",combined)
            if len(hashes)!=1:
                raise ValueError(
                    f"{name} command must emit exactly one LOWKEY_TRACE_TX_HASH marker "
                    f"(exit {proc.returncode}); output tail: {combined[-1600:]}"
                )
            if proc.returncode!=0 and expected_receipt_status!="0x0":
                raise RuntimeError(f"{name} command failed (exit {proc.returncode}): {combined[-1600:]}")
            tx_hash=hashes[0].lower()
            tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
            receipt=rpc(url,"eth_getTransactionReceipt",[tx_hash])
            if not isinstance(tx,dict) or not isinstance(receipt,dict):
                raise ValueError(
                    f"{name} transaction was not mined on the supplied Anvil node; "
                    f"command output tail: {combined[-1600:]}"
                )
            receipt_status=str(receipt.get("status") or "").lower()
            if receipt_status not in {expected_receipt_status, "1" if expected_receipt_status=="0x1" else "0"}:
                raise ValueError(
                    f"{name} receipt status {receipt_status} differs from expected "
                    f"{expected_receipt_status}; command output tail: {combined[-1600:]}"
                )
            chain_id=rpc(url,"eth_chainId",[])
            block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
            latest=int(str(rpc(url,"eth_blockNumber",[])),16)
            if block_number>latest: raise ValueError(f"{name} transaction receipt refers to a future block.")
            block=rpc(url,"eth_getBlockByNumber",[hex(block_number),False])
            hashes_in_block=[str(x).lower() for x in ((block or {}).get("transactions") or [])]
            if len(hashes_in_block)!=1 or hashes_in_block[0]!=tx_hash:
                raise ValueError(f"{name} transaction must be the only transaction in its block; disable batching/mining bundles for this control run.")
            trace=rpc(url,"debug_traceTransaction",[tx_hash,{"tracer":"callTracer"}],60)
            if not isinstance(trace,dict): raise ValueError(f"{name} node did not return a callTracer result.")
            calls=_trace_flatten(trace)
            target=str(spec.get("target_address") or "").lower()
            touched={x["to"] for x in calls if x.get("to")}
            if target and target not in touched: raise ValueError(f"{name} transaction trace never called the manifest target {target}.")
            required={str(tx.get("from") or "").lower(),str(tx.get("to") or "").lower()}
            if not required.issubset(set(addresses)): raise ValueError(f"{name} prestate_addresses must include the transaction sender and root recipient.")
            if target and target not in addresses: raise ValueError(f"{name} prestate_addresses must include target_address.")
            storage_trace=_trace_storage_prestate(url,tx_hash)
            canonical_trace_schema_version, canonical_trace_events = _normalize_trace_events_v2(
                calls, storage_trace
            )
            for discovered_address in storage_trace.get("addresses",[]):
                if discovered_address not in addresses:
                    addresses.append(discovered_address)
            slots=[]
            for raw in spec.get("prestate_slots") or []:
                if not isinstance(raw,dict): raise ValueError("prestate_slots entries must be objects with address and slot.")
                address=addr(raw.get("address"))
                try:
                    slot=storage_slot_key(raw.get("slot"))
                except ValueError as exc:
                    raise ValueError(f"Invalid prestate slot: {raw.get('slot')}") from exc
                slots.append({"address":address,"slot":slot})
            declared_slots=list({(item["address"],item["slot"]):item for item in slots}.values())
            for item in storage_trace.get("slots",[]):
                slots.append({"address":item["address"],"slot":item["slot"]})
            slots=list({(item["address"],item["slot"]):item for item in slots}.values())
            if not slots:
                raise ValueError("No target/dependency storage slots were declared or discovered by prestateTracer.")
            if spec.get("require_trace_storage") and not storage_trace.get("supported"):
                raise ValueError("Manifest requires trace-derived storage, but the RPC does not support prestateTracer: "+str(storage_trace.get("reason")))
            entry_digest,entry_call=_control_entry_digest(tx,chain_id)
            envelope_digest,envelope=_control_transaction_envelope(tx,chain_id)
            trace_entry_digest,trace_entry=_control_entry_digest(trace,chain_id)
            if trace_entry_digest!=entry_digest:
                raise ValueError(f"{name} callTracer root does not match eth_getTransactionByHash.")
            scenario_exclusions=[
                {"address":row["address"],"slot":storage_slot_key(row["slot"])}
                for row in scenario_parameters
            ]
            prestate_digest,prestate=_control_prestate_digest(
                url,receipt,addresses,slots,
                comparison_excluded_slots=scenario_exclusions,
                equivalence_addresses=declared_addresses,
                equivalence_slots=declared_slots,
            )
            parent_storage={(item["address"],item["slot"]):str(item["value"]).lower()
                            for item in prestate.get("storage",[])}
            for observed_slot in storage_trace.get("slots",[]):
                key=(observed_slot["address"],observed_slot["slot"])
                if key in parent_storage and parent_storage[key]!=str(observed_slot["value"]).lower():
                    raise ValueError(
                        f"{name} prestateTracer value for {key[0]}:{key[1]} "
                        "does not match eth_getStorageAt at the transaction parent block."
                    )
            metric_addresses=sorted({addr(x) for x in (spec.get("metric_addresses") or [])})
            sender=str(tx.get("from") or "").lower()
            if not metric_addresses or sender not in metric_addresses:
                raise ValueError("metric_addresses must include the actual transaction sender so gas expenditure is included in the measured portfolio.")
            if not set(metric_addresses).issubset(set(addresses)):
                raise ValueError("Every metric_address must also appear in prestate_addresses.")
            before_by_address={x["address"]:int(str(x["balance"]),16) for x in prestate["addresses"]}
            after_by_address={address:int(str(rpc(url,"eth_getBalance",[address,hex(block_number)])),16)
                              for address in metric_addresses}
            metric=sum(after_by_address[x]-before_by_address[x] for x in metric_addresses)
            gas_used=int(str(receipt.get("gasUsed") or "0x0"),16)
            gas_price=int(str(receipt.get("effectiveGasPrice") or tx.get("gasPrice") or "0x0"),16)
            gas_cost=gas_used*gas_price
            semantic_check=None
            semantic_argv=entry.get("semantic_check_argv")
            if semantic_argv:
                semantic_audit=inspect_reproduction_command(root,semantic_argv)
                if semantic_audit["blocked"]:
                    raise ValueError(f"{name} semantic_check_argv contains local RPC state-fabrication calls.")
                semantic_proc=run([str(x) for x in semantic_argv],work,
                                  int(spec.get("semantic_timeout_seconds",600)),env=env)
                semantic_output=(semantic_proc.stdout or "")+"\\n"+(semantic_proc.stderr or "")
                semantic_check={
                    "argv":semantic_argv,"exit_code":semantic_proc.returncode,
                    "verified":_semantic_execution_verified(
                        semantic_proc.returncode, semantic_output,
                        entry.get("semantic_check_test") or spec.get("semantic_check_test"),
                    ),
                    "expected_test":entry.get("semantic_check_test") or spec.get("semantic_check_test"),
                    "output_tail":semantic_output[-1600:],
                    "verification_rule":"requires an explicit passing assertion marker or recognized test-runner PASS summary; exit code alone is insufficient",
                }
            return {
                "exit_code":proc.returncode,
                "execution_verified":True,
                "metric":metric,
                "metric_kind":"native_balance_delta_after_gas",
                "metric_addresses":metric_addresses,
                "gas_used":gas_used,
                "effective_gas_price_wei":gas_price,
                "gas_cost_wei":gas_cost,
                "tx_hash":tx_hash,
                "receipt_status":receipt_status,
                "expected_receipt_status":expected_receipt_status,
                "chain_id":chain_id,
                "block_number":block_number,
                "entry_call_sha256":entry_digest,
                "entry_call":entry_call,
                "transaction_envelope_sha256":envelope_digest,
                "transaction_envelope":envelope,
                "prestate_sha256":prestate_digest,
                "prestate":prestate,
                "storage_trace":storage_trace,
                "derived_storage_slots":storage_trace.get("slots",[]),
                "scenario_parameters":scenario_parameters,
                "fidelity":fidelity,
                "fidelity_label":(
                    "synthetic_state" if fidelity.get("synthetic_state") else
                    ("simulated_caller" if any(x.get("kind")=="caller_impersonation" for x in fidelity.get("signals",[])) else
                     ("simulated_dependencies" if any(x.get("kind")=="external_call_mock" for x in fidelity.get("signals",[])) else
                      ("constrained_inputs" if any(x.get("kind")=="test_assumption" for x in fidelity.get("signals",[])) else
                       ("unknown" if not fidelity.get("scan_complete") else "real_funded"))))
                ),
                "semantic_check":semantic_check,
                "trace_schema_version":1,
                "trace_events":_normalize_rpc_trace_events(calls),
                "canonical_trace_schema_version":canonical_trace_schema_version,
                "canonical_trace_events":canonical_trace_events,
                "call_trace":calls,
                "argv":entry["argv"],
                "output_tail":combined[-2500:],
            }
        finally: shutil.rmtree(temp,ignore_errors=True)
    finally:
        reverted=rpc(url,"evm_revert",[snapshot])
        if reverted is not True: raise RuntimeError("Could not revert the local Anvil snapshot after the control run.")




_SOURCIFY_IDENTITY_CACHE = {}


def _sourcify_contract_identity(chain_id, address):
    """Fetch independent exact-match source metadata from the current Sourcify v2 API."""
    chain_id = int(chain_id)
    address = addr(address)
    cache_key = (chain_id, address)
    if cache_key in _SOURCIFY_IDENTITY_CACHE:
        return dict(_SOURCIFY_IDENTITY_CACHE[cache_key])
    endpoint = (
        "https://sourcify.dev/server/v2/contract/"
        + str(chain_id) + "/" + address + "?fields=sources,proxyResolution,deployment.blockNumber"
    )
    request = Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "User-Agent": "Lowkey/0.2.0 (+https://github.com/Toji254/foundry-lowkey)",
        },
    )
    with urlopen(request, timeout=12) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Sourcify returned a non-object contract response.")
    _SOURCIFY_IDENTITY_CACHE[cache_key] = dict(payload)
    return payload


def _verify_sourcify_exact(chain_id, address):
    payload = _sourcify_contract_identity(chain_id, address)
    if str(payload.get("chainId")) != str(int(chain_id)):
        raise ValueError("Sourcify response chainId does not match the selected chain.")
    if str(payload.get("address") or "").lower() != addr(address):
        raise ValueError("Sourcify response address does not match the requested contract.")
    fields = {
        "match": payload.get("match"),
        "runtimeMatch": payload.get("runtimeMatch"),
        "creationMatch": payload.get("creationMatch"),
    }
    missing = [name for name, value in fields.items() if value != "exact_match"]
    if missing:
        raise ValueError("Sourcify did not return exact runtime and creation matches: " + ", ".join(missing))
    sources = payload.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("Sourcify did not return verified source file contents.")
    source_file_hashes = {}
    for path, source_row in sorted(sources.items()):
        if not isinstance(path, str):
            raise ValueError("Sourcify source file paths must be strings.")
        # Sourcify v2 returns SourceFile objects with a "content" field.
        # Accept a bare string too for compatible cached/test fixtures.
        source_text = source_row.get("content") if isinstance(source_row, dict) else source_row
        if not isinstance(source_text, str):
            raise ValueError("Sourcify source entries must contain string source content.")
        source_file_hashes[path] = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
    source_bundle_sha256 = hashlib.sha256(
        json.dumps(source_file_hashes, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    deployment = payload.get("deployment") or {}
    try:
        sourcify_deployment_block = int(deployment.get("blockNumber"))
    except (TypeError, ValueError):
        raise ValueError("Sourcify response did not include a valid deployment.blockNumber.")
    return {
        "provider": "sourcify-v2",
        "match": fields["match"],
        "runtime_match": fields["runtimeMatch"],
        "creation_match": fields["creationMatch"],
        "verified_at": payload.get("verifiedAt"),
        "match_id": payload.get("matchId"),
        "source_file_count": len(source_file_hashes),
        "source_file_hashes": source_file_hashes,
        "source_bundle_sha256": source_bundle_sha256,
        "deployment_block": sourcify_deployment_block,
        "proxy_resolution": payload.get("proxyResolution"),
    }


def _verify_first_code_block(source_url, address, deployment_block, expected_code):
    try:
        deployment_block = int(deployment_block)
    except (TypeError, ValueError):
        raise ValueError("deployment_block must be a positive integer.")
    if deployment_block < 1:
        raise ValueError("deployment_block must be a positive integer.")
    before = str(rpc(source_url, "eth_getCode", [address, hex(deployment_block - 1)]) or "0x").lower()
    at = str(rpc(source_url, "eth_getCode", [address, hex(deployment_block)]) or "0x").lower()
    expected_code = str(expected_code or "0x").lower()
    if before not in {"0x", "0x0"}:
        raise ValueError("Contract code already existed before the declared deployment_block.")
    if at in {"0x", "0x0"}:
        raise ValueError("No contract code exists at the declared deployment_block.")
    if at != expected_code:
        raise ValueError("Runtime bytecode at deployment_block does not match the pinned target bytecode.")
    return {
        "deployment_block": deployment_block,
        "code_absent_before": True,
        "code_present_at": True,
        "runtime_code_matches_pinned_block": True,
    }


def _eip1167_implementation(runtime_code):
    """Return the implementation address from the exact canonical EIP-1167 runtime.

    Non-canonical variants (vanity PUSHn, immutable-args, or custom clones) are
    deliberately not guessed. They require a separately verified adapter.
    """
    raw = str(runtime_code or "").lower()
    if raw.startswith("0x"):
        raw = raw[2:]
    prefix = "363d3d373d3d3d363d73"
    suffix = "5af43d82803e903d91602b57fd5bf3"
    if len(raw) != 90 or not raw.startswith(prefix) or not raw.endswith(suffix):
        return None
    implementation_hex = raw[len(prefix):len(prefix) + 40]
    if len(implementation_hex) != 40 or not re.fullmatch(r"[0-9a-f]{40}", implementation_hex):
        return None
    if int(implementation_hex, 16) == 0:
        raise ValueError("Canonical EIP-1167 clone contains a zero implementation address.")
    return "0x" + implementation_hex


def _verify_eip1167_implementation(
    source_url, fork_url, chain_id, block_number, implementation,
    proxy_spec, prestate_by_address, trace_addresses,
):
    """Independently verify the immutable clone destination and its source."""
    if implementation not in trace_addresses:
        raise ValueError("EIP-1167 implementation address was not observed in the recorded call tree.")
    implementation_code = str(
        rpc(source_url, "eth_getCode", [implementation, hex(block_number)]) or "0x"
    ).lower()
    if implementation_code in {"0x", "0x0"}:
        raise ValueError("EIP-1167 implementation address has no runtime code at the pinned fork block.")
    local_implementation_code = str(
        rpc(fork_url, "eth_getCode", [implementation, hex(block_number)]) or "0x"
    ).lower()
    if local_implementation_code != implementation_code:
        raise ValueError("EIP-1167 implementation bytecode differs between local fork and source archive.")
    source_identity = _verify_sourcify_exact(chain_id, implementation)
    declared_deployment = proxy_spec.get("implementation_deployment_block")
    deployment_block = (
        int(declared_deployment) if declared_deployment is not None
        else int(source_identity["deployment_block"])
    )
    if deployment_block > block_number:
        raise ValueError("EIP-1167 implementation deployment block is after the pinned fork block.")
    if source_identity["deployment_block"] != deployment_block:
        raise ValueError("Sourcify implementation deployment block does not match target_identity.proxy.implementation_deployment_block.")
    deployment = _verify_first_code_block(
        source_url, implementation, deployment_block, implementation_code
    )
    implementation_prestate = prestate_by_address.get(implementation) or {}
    trace_code_hash = str(implementation_prestate.get("code_hash") or "").lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}", trace_code_hash):
        raise ValueError("Trace did not preserve a usable EIP-1167 implementation code hash.")
    proof = rpc(source_url, "eth_getProof", [implementation, [], hex(block_number)])
    archive_code_hash = str((proof or {}).get("codeHash") or "").lower()
    if archive_code_hash != trace_code_hash:
        raise ValueError("EIP-1186 implementation code hash differs from the call-trace implementation code hash.")
    declared = proxy_spec.get("implementation_address")
    if declared and addr(declared) != implementation:
        raise ValueError("Decoded EIP-1167 implementation does not match target_identity.proxy.implementation_address.")
    return {
        "type": "eip1167",
        "implementation_address": implementation,
        "runtime_prefix": "0x" + "363d3d373d3d3d363d73",
        "runtime_suffix": "0x" + "5af43d82803e903d91602b57fd5bf3",
        "implementation_code_hash": archive_code_hash,
        **deployment,
        **source_identity,
    }


def _forge_source_verification(source_url, fork_url, normalized, spec):
    result = {
        "verified": False,
        "method": "independent archive comparison at pinned fork block: parent/header, code, balances, nonces and trace-derived storage",
        "checked_addresses": [],
        "checked_storage_slots": [],
        "unverified_trace_addresses": [],
        "archive_state_verified": False,
        "identity_verified": False,
        "identity": None,
    }
    if not source_url:
        result["reason"] = "No independent --source-rpc-url was supplied."
        return result

    source = rpc_url(source_url)
    if urlparse(source).hostname == urlparse(fork_url).hostname:
        result["reason"] = "Source RPC host must differ from the Foundry fork RPC host."
        return result

    chain_id = int(normalized["chain_id"])
    block_number = int(normalized["block_number"])
    if block_number < 1:
        result["reason"] = "Pinned fork block must be at least 1."
        return result

    source_chain = rpc(source, "eth_chainId", [])
    local_chain = rpc(fork_url, "eth_chainId", [])
    try:
        source_chain_int = int(str(source_chain), 16)
    except ValueError:
        source_chain_int = int(source_chain)
    try:
        local_chain_int = int(str(local_chain), 16)
    except ValueError:
        local_chain_int = int(local_chain)
    if source_chain_int != chain_id or local_chain_int != chain_id:
        result["reason"] = "Forge artifact, fork RPC and archive RPC chain IDs do not all match."
        return result

    expected_parent = str(normalized.get("fork_parent_hash") or "").lower()
    if not expected_parent or expected_parent == "0x" + "0" * 64:
        result["reason"] = "Recorder artifact has no usable parent-block hash."
        return result
    local_parent = rpc(fork_url, "eth_getBlockByNumber", [hex(block_number - 1), False])
    source_parent = rpc(source, "eth_getBlockByNumber", [hex(block_number - 1), False])
    if not isinstance(local_parent, dict) or not isinstance(source_parent, dict):
        result["reason"] = "Fork or archive RPC did not return the block preceding the pinned fork block."
        return result
    if str(local_parent.get("hash") or "").lower() != expected_parent:
        result["reason"] = "Fork RPC parent hash does not match the recorder artifact."
        return result
    if str(source_parent.get("hash") or "").lower() != expected_parent:
        result["reason"] = "Archive parent hash does not match the recorder artifact."
        return result

    local_block = rpc(fork_url, "eth_getBlockByNumber", [hex(block_number), False])
    source_block = rpc(source, "eth_getBlockByNumber", [hex(block_number), False])
    if not isinstance(local_block, dict) or not isinstance(source_block, dict):
        result["reason"] = "Fork or archive RPC did not return the pinned fork block."
        return result
    for field in ("hash", "parentHash", "stateRoot", "timestamp"):
        local_value = str(local_block.get(field) or "").lower()
        source_value = str(source_block.get(field) or "").lower()
        if not local_value or local_value != source_value:
            result["reason"] = "Pinned fork block " + field + " differs between fork and archive RPC."
            return result

    target = str(normalized["target_address"]).lower()
    protocol_addresses = sorted({addr(x) for x in (spec.get("source_addresses") or [target])})
    if target not in protocol_addresses:
        raise ValueError("source_addresses must include target_address.")

    prestate_by_address = {
        item["address"]: item for item in (normalized.get("prestate") or [])
    }
    trace_addresses = sorted(set(prestate_by_address))
    missing = [address for address in protocol_addresses if address not in trace_addresses]
    if missing:
        result["reason"] = "Declared protocol source address(es) were not touched in the state diff: " + ", ".join(missing)
        return result

    source_code_by_address = {}
    for address in protocol_addresses:
        try:
            local_code = str(rpc(fork_url, "eth_getCode", [address, hex(block_number)]) or "0x").lower()
            source_code = str(rpc(source, "eth_getCode", [address, hex(block_number)]) or "0x").lower()
            local_balance = int(str(rpc(fork_url, "eth_getBalance", [address, hex(block_number)])), 16)
            source_balance = int(str(rpc(source, "eth_getBalance", [address, hex(block_number)])), 16)
            local_nonce = int(str(rpc(fork_url, "eth_getTransactionCount", [address, hex(block_number)])), 16)
            source_nonce = int(str(rpc(source, "eth_getTransactionCount", [address, hex(block_number)])), 16)
        except Exception as exc:
            result["reason"] = "Could not compare declared protocol address " + address + ": " + str(exc)[:300]
            return result
        if local_code != source_code:
            result["reason"] = "Protocol bytecode differs between fork and archive at " + address + "."
            return result
        source_code_by_address[address] = source_code
        if local_balance != source_balance or local_nonce != source_nonce:
            result["reason"] = "Protocol account balance or nonce differs at the pinned fork block: " + address
            return result

        if address == target:
            try:
                proof = rpc(source, "eth_getProof", [address, [], hex(block_number)])
            except Exception as exc:
                result["reason"] = "Archive eth_getProof unavailable for target code identity: " + str(exc)[:300]
                return result
            actual_code_hash = str((proof or {}).get("codeHash") or "").lower()
            expected_code_hash = str(normalized.get("target_code_hash") or "").lower()
            trace_target_prestate = prestate_by_address.get(address) or {}
            trace_account_code_hash = str(trace_target_prestate.get("code_hash") or "").lower()
            if not expected_code_hash or actual_code_hash != expected_code_hash:
                result["reason"] = (
                    "Target EIP-1186 code hash differs from the recorder's pre-execution target code hash "
                    + f"(target={address}, recorder_target_code_hash={expected_code_hash or 'missing'}, "
                    + f"forge_account_access_code_hash={trace_account_code_hash or 'missing'}, "
                    + f"archive_eip1186_code_hash={actual_code_hash or 'missing'})."
                )
                result["target_code_hash_diagnostics"] = {
                    "target_address": address,
                    "recorder_target_code_hash": expected_code_hash or None,
                    "forge_account_access_code_hash": trace_account_code_hash or None,
                    "archive_eip1186_code_hash": actual_code_hash or None,
                }
                return result
            if trace_account_code_hash and trace_account_code_hash != actual_code_hash:
                result["reason"] = (
                    "Forge account-access code hash differs from archive EIP-1186 code hash "
                    + f"(target={address}, forge={trace_account_code_hash}, archive={actual_code_hash})."
                )
                result["target_code_hash_diagnostics"] = {
                    "target_address": address,
                    "recorder_target_code_hash": expected_code_hash,
                    "forge_account_access_code_hash": trace_account_code_hash,
                    "archive_eip1186_code_hash": actual_code_hash,
                }
                return result
        else:
            actual_code_hash = None

        result["checked_addresses"].append({
            "address": address,
            "code_hash": actual_code_hash,
            "code_bytes_match": True,
            "balance_wei": local_balance,
            "nonce": local_nonce,
        })

        prestate = prestate_by_address[address]
        for storage in prestate.get("storage") or []:
            slot = str(storage["slot"]).lower()
            expected_value = str(storage["value"]).lower()
            try:
                local_value = str(rpc(
                    fork_url, "eth_getStorageAt", [address, slot, hex(block_number)]
                )).lower()
                source_value = str(rpc(
                    source, "eth_getStorageAt", [address, slot, hex(block_number)]
                )).lower()
            except Exception as exc:
                result["reason"] = "Storage comparison failed for " + address + ":" + slot + ": " + str(exc)[:200]
                return result
            if local_value != source_value:
                result["reason"] = "Fork and archive storage differ for " + address + ":" + slot + "."
                return result
            if local_value != expected_value:
                result["reason"] = (
                    "The first recorded StorageAccess previous_value is not the pinned-block prestate for "
                    + address + ":" + slot + "."
                )
                return result
            result["checked_storage_slots"].append({
                "address": address, "slot": slot, "value": local_value
            })

    result["unverified_trace_addresses"] = sorted(set(trace_addresses) - set(protocol_addresses))
    result["archive_state_verified"] = True
    result["source_chain_id"] = source_chain
    result["fork_chain_id"] = local_chain
    result["fork_block"] = block_number
    result["fork_parent_hash"] = expected_parent
    result["fork_block_hash"] = str(local_block.get("hash") or "").lower()
    result["protocol_addresses_checked"] = protocol_addresses
    result["trace_addresses_observed"] = trace_addresses
    result["scope_note"] = (
        "Archive verification covers the pinned header, declared source addresses and observed storage slots. "
        "This is separate from source identity verification; other trace-touched accounts are not treated as deployed dependencies."
    )

    if str(spec.get("target_authenticity") or "unknown").lower() != "forked_deployment":
        result["verified"] = False
        result["identity_verified"] = False
        result["reason"] = "Archive state is consistent, but the manifest does not request forked-deployment identity."
        return result

    identity_spec = spec.get("target_identity")
    if not isinstance(identity_spec, dict):
        result["reason"] = "forked_deployment requires target_identity with a deployment block and independent source verification."
        return result
    if identity_spec.get("source_provider", "sourcify") != "sourcify":
        result["reason"] = "Only source_provider='sourcify' is currently supported for independent contract identity."
        return result

    target_clone_implementation = None
    try:
        target_deployment_block = int(identity_spec.get("deployment_block"))
        if target_deployment_block > block_number:
            raise ValueError("target_identity.deployment_block is after the pinned fork block.")
        target_runtime_code = source_code_by_address.get(target)
        target_deployment = _verify_first_code_block(
            source, target, target_deployment_block, target_runtime_code,
        )
        target_clone_implementation = _eip1167_implementation(target_runtime_code)
        if target_clone_implementation:
            declared_proxy = identity_spec.get("proxy") or {}
            if declared_proxy and declared_proxy.get("type") not in {"eip1167", "eip-1167", "minimal-proxy"}:
                raise ValueError("Canonical EIP-1167 bytecode conflicts with target_identity.proxy.type.")
            target_source = {
                "provider": "eip1167-runtime-bytecode",
                "match": "canonical_eip1167",
                "runtime_bytecode_sha256": hashlib.sha256(
                    bytes.fromhex(str(target_runtime_code).lower().removeprefix("0x"))
                ).hexdigest(),
                "deployment_block": target_deployment_block,
                "source_scope": "The clone has canonical immutable forwarding bytecode; source identity is verified on its embedded implementation.",
            }
        else:
            target_source = _verify_sourcify_exact(chain_id, target)
            if target_source["deployment_block"] != target_deployment_block:
                raise ValueError("Sourcify deployment.blockNumber does not match target_identity.deployment_block.")
    except Exception as exc:
        result["reason"] = "Target source identity verification failed: " + str(exc)[:500]
        return result

    identity = {
        "provider": "sourcify-v2+canonical-proxy-bytecode",
        "target": {
            "address": target,
            **target_deployment,
            **target_source,
        },
        "proxy": None,
    }

    try:
        if target_clone_implementation:
            proxy_spec = identity_spec.get("proxy") or {}
            identity["proxy"] = _verify_eip1167_implementation(
                source, fork_url, chain_id, block_number,
                target_clone_implementation, proxy_spec,
                prestate_by_address, trace_addresses,
            )
        else:
            implementation_slot = EIP1967["implementation"]
            beacon_slot = EIP1967["beacon"]
            implementation_word = str(rpc(
                source, "eth_getStorageAt", [target, implementation_slot, hex(block_number)]
            ) or "0x" + "0" * 64).lower()
            beacon_word = str(rpc(
                source, "eth_getStorageAt", [target, beacon_slot, hex(block_number)]
            ) or "0x" + "0" * 64).lower()
            if not re.fullmatch(r"0x[0-9a-f]{64}", implementation_word):
                raise ValueError("EIP-1967 implementation storage value is not a full bytes32 word.")
            if not re.fullmatch(r"0x[0-9a-f]{64}", beacon_word):
                raise ValueError("EIP-1967 beacon storage value is not a full bytes32 word.")
            implementation_int = int(implementation_word, 16)
            beacon_int = int(beacon_word, 16)
            provider_proxy = target_source.get("proxy_resolution") or {}
            if provider_proxy.get("proxyResolutionError"):
                raise ValueError("Sourcify proxy resolution failed: " + str(provider_proxy["proxyResolutionError"]))
            if beacon_int:
                result["reason"] = (
                    "Target has a non-zero EIP-1967 beacon slot. Beacon-proxy implementation resolution "
                    "is not supported yet; refusing to infer implementation identity."
                )
                result["identity"] = identity
                return result
            if implementation_int:
                implementation = "0x" + implementation_word[-40:]
                if provider_proxy.get("isProxy") is not True or provider_proxy.get("proxyType") != "EIP1967Proxy":
                    raise ValueError("Sourcify did not independently resolve the target as an EIP1967Proxy.")
                provider_implementations = {
                    addr(item.get("address"))
                    for item in (provider_proxy.get("implementations") or [])
                    if isinstance(item, dict) and item.get("address")
                }
                if implementation not in provider_implementations:
                    raise ValueError("Sourcify proxyResolution does not contain the on-chain EIP-1967 implementation address.")
                if implementation not in trace_addresses:
                    raise ValueError("EIP-1967 implementation address was not observed in the recorded call tree.")
                proxy_spec = identity_spec.get("proxy") or {}
                if proxy_spec and proxy_spec.get("type") != "eip1967":
                    raise ValueError("Resolved EIP-1967 implementation slot conflicts with target_identity.proxy.type.")
                declared_implementation = proxy_spec.get("implementation_address")
                if declared_implementation and addr(declared_implementation) != implementation:
                    raise ValueError("EIP-1967 implementation slot does not match target_identity.proxy.implementation_address.")
                implementation_code = str(
                    rpc(source, "eth_getCode", [implementation, hex(block_number)]) or "0x"
                ).lower()
                if implementation_code in {"0x", "0x0"}:
                    raise ValueError("EIP-1967 implementation address has no runtime code at the pinned fork block.")
                implementation_deployment_block = int(proxy_spec.get("implementation_deployment_block"))
                if implementation_deployment_block > block_number:
                    raise ValueError("Proxy implementation deployment block is after the pinned fork block.")
                local_implementation_code = str(
                    rpc(fork_url, "eth_getCode", [implementation, hex(block_number)]) or "0x"
                ).lower()
                if local_implementation_code != implementation_code:
                    raise ValueError("Proxy implementation bytecode differs between local fork and source archive.")
                implementation_deployment = _verify_first_code_block(
                    source, implementation,
                    implementation_deployment_block,
                    implementation_code,
                )
                implementation_source = _verify_sourcify_exact(chain_id, implementation)
                if implementation_source["deployment_block"] != implementation_deployment_block:
                    raise ValueError("Sourcify implementation deployment block does not match target_identity.proxy.implementation_deployment_block.")
                implementation_prestate = prestate_by_address.get(implementation) or {}
                trace_implementation_code_hash = str(implementation_prestate.get("code_hash") or "").lower()
                if not re.fullmatch(r"0x[0-9a-f]{64}", trace_implementation_code_hash):
                    raise ValueError("Trace did not preserve a usable implementation code hash.")
                implementation_proof = rpc(
                    source, "eth_getProof", [implementation, [], hex(block_number)]
                )
                archive_implementation_code_hash = str(
                    (implementation_proof or {}).get("codeHash") or ""
                ).lower()
                if archive_implementation_code_hash != trace_implementation_code_hash:
                    raise ValueError("EIP-1186 implementation code hash differs from the call-trace implementation code hash.")
                identity["proxy"] = {
                    "type": "eip1967",
                    "sourcify_proxy_type": provider_proxy.get("proxyType"),
                    "implementation_address": implementation,
                    **implementation_deployment,
                    **implementation_source,
                    "implementation_slot": implementation_slot,
                }
            else:
                if provider_proxy.get("isProxy") is not False:
                    raise ValueError("EIP-1967 slots are empty but Sourcify did not confirm a non-proxy target.")
                if identity_spec.get("proxy"):
                    raise ValueError("Manifest declares a proxy but the EIP-1967 implementation slot is zero at the pinned block.")
    except Exception as exc:
        result["reason"] = "Proxy/implementation identity verification failed: " + str(exc)[:500]
        result["identity"] = identity
        return result

    result["identity"] = identity
    result["identity_verified"] = True
    result["verified"] = True
    result["identity_method"] = (
        "Canonical EIP-1167 runtime bytecode and archive first-code-present target deployment block, "
        "plus exact Sourcify v2 implementation source/deployment/code-hash verification"
        if target_clone_implementation else
        "Sourcify v2 exact runtime+creation match, archive first-code-present deployment block, "
        "and EIP-1967 implementation resolution where applicable"
    )
    return result




def _forge_scenario_prestate(normalized, spec, scenario_name):
    """Verify declared per-scenario state, then exclude only those slots from equivalence."""
    prestate = json.loads(json.dumps(normalized.get("prestate") or []))
    exclusions = set()
    verified = []

    def word(value, label):
        try:
            number = int(str(value), 16) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
        except (TypeError, ValueError):
            raise ValueError("Invalid " + label + " scenario storage value: " + str(value))
        if number < 0 or number >= 1 << 256:
            raise ValueError(label + " scenario storage value does not fit bytes32.")
        return "0x" + format(number, "064x")

    for item in spec.get("scenario_parameters") or []:
        if not isinstance(item, dict):
            raise ValueError("scenario_parameters entries must be objects.")
        address = addr(item.get("address"))
        slot = storage_slot_key(item.get("slot"))
        expected_raw = item.get(scenario_name + "_value")
        if expected_raw is None:
            raise ValueError(
                "Forge scenario parameter " + str(item.get("name") or slot) +
                " requires " + scenario_name + "_value."
            )
        expected = word(expected_raw, scenario_name)
        account = next((row for row in prestate if row.get("address") == address), None)
        storage = next(
            (row for row in (account or {}).get("storage", []) if row.get("slot") == slot),
            None,
        )
        if storage is None:
            raise ValueError(
                "Forge state diff did not observe scenario slot " + address + ":" + slot +
                "; it cannot verify and safely exclude this parameter."
            )
        observed = word(storage.get("value"), "observed")
        if observed != expected:
            raise ValueError(
                "Forge scenario parameter " + str(item.get("name") or slot) +
                " observed " + observed + ", expected " + expected + " for " + scenario_name + "."
            )
        exclusions.add((address, slot))
        verified.append({
            "name": item.get("name"), "address": address, "slot": slot,
            "observed_value": observed, "expected_value": expected,
            "verified_in_trace_prestate": True,
            "description": item.get("description"),
        })

    comparison = json.loads(json.dumps(prestate))
    for account in comparison:
        account["storage"] = [
            row for row in account.get("storage", [])
            if (account.get("address"), row.get("slot")) not in exclusions
        ]
    digest = hashlib.sha256(
        json.dumps(comparison, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return digest, prestate, verified, sorted(
        address + ":" + slot for address, slot in exclusions
    )



def _forge_storage_metric(normalized, metric_spec):
    """Compute a declared uint256 storage delta from trace-derived state accesses.

    Unlike account balance deltas, this does not depend on Forge emitting a
    balance record for every contract participating in a callback. The slot
    must be observed in the trace and its transaction-prestate value must be
    present in the normalized artifact.
    """
    if not isinstance(metric_spec, dict):
        raise ValueError("metric_storage must be an object with address and slot.")
    address = addr(metric_spec.get("address"))
    slot = storage_slot_key(metric_spec.get("slot"))
    kind = str(metric_spec.get("kind") or "uint256_delta").lower()
    if kind != "uint256_delta":
        raise ValueError("metric_storage.kind currently supports only uint256_delta.")

    prestate_account = next(
        (row for row in (normalized.get("prestate") or [])
         if str(row.get("address") or "").lower() == address),
        None,
    )
    prestate_slot = next(
        (row for row in (prestate_account or {}).get("storage") or []
         if str(row.get("slot") or "").lower() == slot),
        None,
    )
    if prestate_slot is None:
        raise ValueError(
            "Trace did not capture the declared metric_storage prestate slot "
            + address + ":" + slot
        )
    try:
        before = int(str(prestate_slot.get("value")), 16)
    except (TypeError, ValueError) as exc:
        raise ValueError("metric_storage prestate value is not a valid bytes32 quantity.") from exc

    observations = [
        item for item in (normalized.get("storage_accesses") or [])
        if str(item.get("account") or "").lower() == address
        and str(item.get("slot") or "").lower() == slot
        and not item.get("reverted", False)
    ]
    if not observations:
        raise ValueError(
            "Trace did not observe the declared metric_storage slot during execution: "
            + address + ":" + slot
        )
    try:
        first_observed_before = int(str(observations[0].get("previous_value")), 16)
    except (TypeError, ValueError) as exc:
        raise ValueError("metric_storage first trace value is not a valid bytes32 quantity.") from exc
    if first_observed_before != before:
        raise ValueError(
            "metric_storage first trace value differs from the normalized transaction prestate."
        )

    # Use the final successful SSTORE, not the final access: the harness
    # deliberately reads the counter after the callback, and SLOAD encoding
    # of new_value is backend-specific. The fixture writes this counter on
    # every callback, including a valid zero result.
    successful_writes = [item for item in observations if item.get("is_write")]
    if not successful_writes:
        raise ValueError(
            "Trace observed metric_storage but recorded no successful write to its declared slot."
        )
    try:
        after = int(str(successful_writes[-1].get("new_value")), 16)
    except (TypeError, ValueError) as exc:
        raise ValueError("metric_storage final write is not a valid bytes32 quantity.") from exc

    return {
        "kind": "forge_trace_storage_uint256_delta",
        "address": address,
        "slot": slot,
        "before": before,
        "after": after,
        "delta": after - before,
        "observations": len(observations),
        "writes": len(successful_writes),
        "source": "Vm.startStateDiffRecording successful storage writes",
    }


def _forge_control_run(root, fork_url, name, entry, spec, env, source_url=None, paired_entry=None):
    try:
        try:
            from .forge_state_diff import normalize_forge_state_diff
        except ImportError:
            from forge_state_diff import normalize_forge_state_diff
    except ImportError as exc:
        raise RuntimeError("Forge state-diff normalizer is unavailable: " + str(exc)) from exc

    entries = [(name, entry)]
    if paired_entry is not None:
        paired_name = "attack" if name == "control" else "control"
        entries.append((paired_name, paired_entry))

    if paired_entry is not None:
        same_commands = entry.get("argv") == paired_entry.get("argv")
        same_harness = (entry.get("harness") or spec.get("harness")) == (
            paired_entry.get("harness") or spec.get("harness")
        )
        same_prepare = entry.get("prepare_argv") == paired_entry.get("prepare_argv")
        distinct_artifacts = entry.get("state_diff_file") != paired_entry.get("state_diff_file")
        if name != "control" or not (same_commands and same_harness and same_prepare and distinct_artifacts):
            raise ValueError("Paired Forge requires the same control/attack harness, argv and preparation, plus two distinct artifact paths.")

    validated = []
    for scenario_name, scenario_entry in entries:
        harness_name = scenario_entry.get("harness") or spec.get("harness")
        if not isinstance(harness_name, str) or not harness_name:
            raise ValueError(scenario_name + " requires harness pointing to the Foundry test file.")
        harness = (root / harness_name).resolve()
        if not harness.is_relative_to(root) or not harness.is_file():
            raise ValueError(scenario_name + " harness must be an existing file inside the project.")
        artifact_name = scenario_entry.get("state_diff_file")
        if not isinstance(artifact_name, str) or not artifact_name:
            raise ValueError(scenario_name + " requires state_diff_file written by LowkeyForgeStateDiffRecorder.")
        artifact_rel = Path(artifact_name)
        if artifact_rel.is_absolute() or ".." in artifact_rel.parts:
            raise ValueError(scenario_name + " state_diff_file must be a safe project-relative path.")
        argv = scenario_entry.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) for x in argv):
            raise ValueError(scenario_name + " argv must be a non-empty string array.")
        if Path(argv[0]).name not in {"forge", "forge.exe"}:
            raise ValueError(scenario_name + " Forge backend argv must invoke forge directly.")
        command_audit = inspect_reproduction_command(root, argv)
        if command_audit["blocked"]:
            raise ValueError(scenario_name + " command contains local RPC state-fabrication calls: " +
                             str(command_audit["state_fabrication_calls"]))
        fidelity = _analyze_control_fidelity(root, scenario_entry, spec)
        validated.append((scenario_name, scenario_entry, artifact_rel, argv, fidelity))

    temp = Path(tempfile.mkdtemp(prefix="lk-forge-control-"))
    work = temp / "project"
    try:
        shutil.copytree(
            root, work,
            ignore=shutil.ignore_patterns(".git", ".audit", "out", "cache", "node_modules", "__pycache__"),
        )
        artifact_paths = {}
        for scenario_name, _, artifact_rel, _, _ in validated:
            artifact_path = (work / artifact_rel).resolve()
            if not artifact_path.is_relative_to(work):
                raise ValueError(scenario_name + " state_diff_file escaped the isolated Forge project.")
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                artifact_path.unlink()
            except FileNotFoundError:
                pass
            artifact_paths[scenario_name] = artifact_path

        prepare_argv = entry.get("prepare_argv")
        if prepare_argv:
            prepare_audit = inspect_reproduction_command(root, prepare_argv)
            if prepare_audit["blocked"]:
                raise ValueError(name + " prepare_argv contains state fabrication.")
            prepared = run([str(x) for x in prepare_argv], work,
                           int(spec.get("prepare_timeout_seconds", 120)), env=env)
            if prepared.returncode != 0:
                raise RuntimeError(name + " Forge preparation failed: " +
                                   ((prepared.stdout or "") + (prepared.stderr or ""))[-1200:])

        argv = validated[0][3]
        proc = run(argv, work, int(spec.get("timeout_seconds", 600)), env=env)
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode != 0:
            raise RuntimeError(name + " Forge test command failed (exit " +
                               str(proc.returncode) + "): " + combined[-1600:])

        results = {}
        target = addr(spec.get("target_address"))
        for scenario_name, scenario_entry, artifact_rel, scenario_argv, fidelity in validated:
            artifact_path = artifact_paths[scenario_name]
            if not artifact_path.is_file():
                raise ValueError(
                    scenario_name + " Forge test passed but did not write the declared state_diff_file "
                    + artifact_rel.as_posix()
                    + "; ensure the harness recorder writes to that exact path."
                )
            # The harness runs in an isolated copy so its build/test outputs do
            # not contaminate the caller's project. The declared evidence file,
            # however, is an explicit output contract: persist the exact raw
            # recorder artifact back to the project before parsing it or
            # cleaning up the isolated workspace. This preserves diagnostics
            # even when normalization or later proof checks fail.
            project_root = Path(root).resolve()
            persisted_artifact = (project_root / artifact_rel).resolve()
            if not persisted_artifact.is_relative_to(project_root):
                raise ValueError(
                    scenario_name + " state_diff_file resolves outside the project root."
                )
            persisted_artifact.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(artifact_path, persisted_artifact)
            raw = json.loads(artifact_path.read_text(encoding="utf-8"))
            normalized = normalize_forge_state_diff(raw, expected_target=target)
            prestate_digest, full_prestate, scenario_parameters, excluded_scenario_slots = (
                _forge_scenario_prestate(normalized, spec, scenario_name)
            )
            semantic_check = None
            semantic_argv = scenario_entry.get("semantic_check_argv")
            if semantic_argv:
                audit = inspect_reproduction_command(root, semantic_argv)
                if audit["blocked"]:
                    raise ValueError(scenario_name + " semantic_check_argv contains state fabrication.")
                semantic_proc = run([str(x) for x in semantic_argv], work,
                                    int(spec.get("semantic_timeout_seconds", 600)), env=env)
                semantic_output = (semantic_proc.stdout or "") + "\n" + (semantic_proc.stderr or "")
                semantic_check = {
                    "argv": semantic_argv, "exit_code": semantic_proc.returncode,
                    "verified": _semantic_execution_verified(
                        semantic_proc.returncode, semantic_output,
                        scenario_entry.get("semantic_check_test") or spec.get("semantic_check_test"),
                    ),
                    "expected_test": scenario_entry.get("semantic_check_test") or spec.get("semantic_check_test"),
                    "output_tail": semantic_output[-1200:],
                    "verification_rule": "requires an explicit passing assertion marker or recognized test-runner PASS summary; exit code alone is insufficient",
                }
            metrics = {x["address"]: x["delta_wei"] for x in normalized.get("balance_deltas", [])}
            metric_addresses = sorted({addr(x) for x in (spec.get("metric_addresses") or [])})
            metric = None
            metric_evidence = None
            metric_storage = spec.get("metric_storage")
            if metric_storage is not None:
                metric_evidence = _forge_storage_metric(normalized, metric_storage)
                metric = metric_evidence["delta"]
                metric_kind = metric_evidence["kind"]
            else:
                if metric_addresses and all(address in metrics for address in metric_addresses):
                    metric = sum(metrics[address] for address in metric_addresses)
                metric_kind = "forge_account_balance_delta_without_eoa_gas"
            source_verification = _forge_source_verification(source_url, fork_url, normalized, spec)
            fidelity_label = "simulated_caller"
            if fidelity.get("synthetic_state"):
                fidelity_label = "synthetic_state"
            elif any(signal.get("kind") == "external_call_mock" for signal in fidelity.get("signals", [])):
                fidelity_label = "simulated_dependencies"
            results[scenario_name] = {
                "backend": "forge-state-diff", "exit_code": proc.returncode,
                "execution_verified": proc.returncode == 0, "metric": metric,
                "metric_kind": metric_kind, "metric_evidence": metric_evidence,
                "metric_addresses": metric_addresses, "gas_verified": False,
                "transaction_envelope_verified": False, "tx_hash": None,
                "chain_id": normalized["chain_id"], "block_number": normalized["block_number"],
                "fork_parent_hash": normalized.get("fork_parent_hash"),
                "entry_call_sha256": normalized["entry_call_sha256"],
                "entry_call": normalized["entry_call"],
                "prestate_sha256": prestate_digest, "prestate": full_prestate,
                "scenario_parameters": scenario_parameters,
                "comparison_excluded_scenario_slots": excluded_scenario_slots,
                "derived_storage_accesses": normalized["storage_accesses"],
                "derived_storage_slots": [
                    {"address": item["account"], "slot": item["slot"],
                     "prestate_value": item["previous_value"]}
                    for item in normalized["storage_accesses"]
                ],
                "balance_deltas": normalized.get("balance_deltas", []),
                "trace_schema_version": normalized["trace_schema_version"],
                "trace_events": normalized["trace_events"],
                "canonical_trace_schema_version": normalized.get("canonical_trace_schema_version"),
                "canonical_trace_events": normalized.get("canonical_trace_events"),
                "canonical_trace_events_error": normalized.get("canonical_trace_events_error"),
                "setup_events": normalized.get("setup_events", []),
                "domain_events": normalized.get("domain_events", []),
                "call_trace": normalized["calls"], "raw_account_accesses": normalized["raw_account_accesses"],
                "target_code_hash": normalized["target_code_hash"],
                "source_verification": source_verification,
                "target_authenticity_verified": source_verification["verified"],
                "fidelity": fidelity, "fidelity_label": fidelity_label, "semantic_check": semantic_check,
                "state_diff_file": artifact_rel.as_posix(), "argv": scenario_argv,
                "paired_execution": paired_entry is not None,
                "output_tail": combined[-2500:],
                "limitations": normalized["limitations"],
            }
        return results if paired_entry is not None else results[name]
    finally:
        shutil.rmtree(temp, ignore_errors=True)



def trace_parity(args):
    parser = LowkeyArgumentParser(
        prog="lk trace-parity",
        description="Compare canonical Forge and Anvil trace evidence without treating unknown fields as matches.",
    )
    parser.add_argument("forge_file", nargs="?", help="JSON evidence containing canonical_trace_events from Forge.")
    parser.add_argument("anvil_file", nargs="?", help="JSON evidence containing canonical_trace_events from Anvil.")
    parser.add_argument("--root", default=".", help="Project root for input and output paths.")
    parser.add_argument("--forge-scenario", choices=("control", "attack", "negative_control"), default="attack")
    parser.add_argument("--anvil-scenario", choices=("control", "attack", "negative_control"), default="attack")
    parser.add_argument("--output", default=".audit/godmode/trace-parity.json")
    ns = parser.parse_args(args)
    if not ns.forge_file or not ns.anvil_file:
        print("TRACE PARITY NOT RUN")
        if not ns.forge_file:
            print("  Missing required Forge evidence JSON.")
        if not ns.anvil_file:
            print("  Missing required Anvil evidence JSON.")
        print("  These two saved artifacts are the data being compared; Lowkey will not guess or substitute them.")
        print("  Example:")
        print("    lk trace-parity .audit/forge-control.json .audit/anvil-control.json --root .")
        print("  Create both artifacts by running the same experiment on Forge and Anvil, then compare them.")
        return 2
    root = root_path(ns.root)

    try:
        from .trace_parity import compare_trace_events
        from .trace_schema import from_legacy_event, TRACE_SCHEMA_VERSION
    except ImportError:
        try:
            from lowkey.trace_parity import compare_trace_events
            from lowkey.trace_schema import from_legacy_event, TRACE_SCHEMA_VERSION
        except ImportError:
            from trace_parity import compare_trace_events
            from trace_schema import from_legacy_event, TRACE_SCHEMA_VERSION

    def load_evidence(token, label):
        path = (root / Path(token).expanduser()).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(label + " trace evidence must be an existing file inside the project root.")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise ValueError(label + " trace evidence must contain a JSON object.")
        scenario = ns.forge_scenario if label == "Forge" else ns.anvil_scenario
        scenario_row = (payload.get("runs") or {}).get(scenario) if isinstance(payload.get("runs"), dict) else None
        event_source = scenario_row if isinstance(scenario_row, dict) else payload
        events = event_source.get("canonical_trace_events")
        if events is None:
            events = event_source.get("trace_events")
            if not isinstance(events, list):
                raise ValueError(
                    label + " evidence has no canonical_trace_events or legacy trace_events array "
                    + "for scenario " + scenario + "."
                )
            events = [
                from_legacy_event(event, seq=index)
                for index, event in enumerate(events)
            ]
        if not isinstance(events, list):
            raise ValueError(label + " canonical_trace_events must be an array.")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        return {
            "path": path.relative_to(root).as_posix(),
            "sha256": digest,
            "chain_id": event_source.get("chain_id", payload.get("chain_id")),
            "block_number": event_source.get("block_number", payload.get("block_number")),
            "scenario": scenario,
            "events": events,
        }

    forge = load_evidence(ns.forge_file, "Forge")
    anvil = load_evidence(ns.anvil_file, "Anvil")
    report = compare_trace_events(forge["events"], anvil["events"])
    report.update({
        "forge_evidence": {key: forge[key] for key in ("path", "sha256", "chain_id", "block_number")},
        "anvil_evidence": {key: anvil[key] for key in ("path", "sha256", "chain_id", "block_number")},
        "schema_contract": "Lowkey canonical TraceEvent v2",
    })
    output_path = safe_out(root, ns.output)
    write_json(output_path, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "MATCHED" else (2 if report["status"] == "MISMATCH" else 1)


def control(args):
    p=LowkeyArgumentParser(prog="lk control")
    p.add_argument("manifest",nargs="?",default=".audit/control.json",help="Experiment manifest; defaults to .audit/control.json.")
    p.add_argument("--root",default=".",help="Foundry project root; manifest and evidence paths are resolved inside it.")
    p.add_argument("--rpc-url",help="Execution RPC; defaults to the project's saved RPC or configured RPC environment variable.")
    p.add_argument("--source-rpc-url",help="Independent read-only archive RPC used for source-chain verification.")
    p.add_argument("--output",default=".audit/godmode/control.json",help="Path for the machine-readable control verdict.")
    p.add_argument("--freeze",action="store_true",help="Freeze the manifest, commands, harnesses and expectations without running them.")
    p.add_argument("--validate",action="store_true",help="Validate a frozen spec without executing control or attack commands.")
    p.add_argument("--freeze-file",default=".audit/godmode/control.freeze.json",help="Path for the integrity-bound frozen expectations file.")
    p.add_argument("--require-frozen",action="store_true",help="Refuse to execute unless a matching frozen manifest exists.")
    p.add_argument("--non-economic",action="store_true",help="Require a passing semantic invariant instead of positive profit.")
    ns=p.parse_args(args)
    if ns.freeze and ns.validate:
        raise ValueError("--freeze and --validate are separate operations; run them in separate invocations.")
    if ns.validate and ns.require_frozen:
        raise ValueError("--validate already requires an existing frozen spec; do not combine it with --require-frozen.")

    root=root_path(ns.root)
    mf=(root/ns.manifest).expanduser().resolve()
    if not mf.is_relative_to(root):
        raise ValueError("Manifest must be an existing file inside project; paths outside --root are not allowed.")
    if not mf.is_file():
        print("CONTROL NOT RUN — experiment manifest is missing.")
        print("  Expected: " + str(mf.relative_to(root)))
        print("  A matched attack/control experiment cannot be invented safely.")
        print("  Create the JSON manifest with the target, control.argv, attack.argv, metric_addresses and same_calls_id,")
        print("  or pass its path explicitly: lk control path/to/experiment.json")
        print("  Use lk control --h for the workflow and manifest requirements.")
        return 2
    spec=json.loads(mf.read_text(encoding="utf-8"))
    attack=spec.get("attack") or {}
    control_run=spec.get("control") or {}
    backend=str(spec.get("trace_backend") or "anvil-calltracer").lower()
    if backend not in {"anvil-calltracer","forge-state-diff"}:
        raise ValueError("trace_backend must be anvil-calltracer or forge-state-diff.")
    paired_forge = bool(spec.get("paired_forge_experiment", False))
    if paired_forge:
        if backend != "forge-state-diff":
            raise ValueError("paired_forge_experiment is supported only by the forge-state-diff backend.")
        if (control_run.get("argv") != attack.get("argv") or
            (control_run.get("harness") or spec.get("harness")) !=
            (attack.get("harness") or spec.get("harness")) or
            control_run.get("prepare_argv") != attack.get("prepare_argv") or
            control_run.get("state_diff_file") == attack.get("state_diff_file")):
            raise ValueError("paired_forge_experiment requires the same harness/argv/preparation and two distinct state_diff_file paths.")
    if not spec.get("same_calls_id"):
        raise ValueError("Declare same_calls_id as a human-readable label for the matched experiment.")
    if not isinstance(attack.get("argv"),list) or not isinstance(control_run.get("argv"),list):
        raise ValueError("Manifest requires control.argv and attack.argv.")
    target=addr(spec.get("target_address"))
    if not isinstance(spec.get("metric_addresses"),list) or not spec["metric_addresses"]:
        raise ValueError("Declare metric_addresses for the attacker portfolio.")
    metric_addresses={addr(value) for value in spec["metric_addresses"]}
    metric_storage=spec.get("metric_storage")
    if metric_storage is not None:
        if backend != "forge-state-diff":
            raise ValueError("metric_storage is supported only by the forge-state-diff backend.")
        if not isinstance(metric_storage,dict):
            raise ValueError("metric_storage must be an object with address, slot and optional kind.")
        metric_storage_address=addr(metric_storage.get("address"))
        storage_slot_key(metric_storage.get("slot"))
        if str(metric_storage.get("kind") or "uint256_delta").lower() != "uint256_delta":
            raise ValueError("metric_storage.kind currently supports only uint256_delta.")
        prestate_addresses={
            addr(value) for value in (spec.get("prestate_addresses") or [])
        }
        if metric_storage_address not in prestate_addresses:
            raise ValueError("metric_storage.address must appear in prestate_addresses.")
        if metric_storage_address not in metric_addresses:
            raise ValueError("metric_storage.address must appear in metric_addresses.")

    try:
        try:
            from . import proof_evidence
        except ImportError:
            import proof_evidence
    except ImportError as exc:
        raise RuntimeError("Proof evidence policy module is unavailable: " + str(exc)) from exc

    if ns.freeze:
        frozen, freeze_path = proof_evidence.freeze_control_manifest(
            root, mf, spec, ns.freeze_file
        )
        print("CONTROL EXPECTATIONS FROZEN")
        print("  file: " + str(freeze_path.relative_to(root)))
        print("  sha256: " + frozen["freeze_sha256"])
        print("  manifest: " + frozen["manifest_sha256"])
        print("No attack or control command was executed.")
        return 0

    freeze_status=proof_evidence.validate_control_freeze(
        root, mf, spec, required=ns.require_frozen and not ns.validate, freeze_path=ns.freeze_file
    )
    if ns.validate:
        digest_rejected = freeze_status.get("reason_code") == "digest_mismatch"
        freeze_valid = bool(freeze_status.get("verified"))
        status = "PROPOSED" if freeze_valid else ("REJECTED" if digest_rejected else "UNRESOLVED")
        payload = {
            "created_at": now(),
            "status": status,
            "proof_status": status,
            "outcome": "not_run",
            "family": proof_evidence.normalize_family(spec.get("family")),
            "target_address": target,
            "trace_backend": backend,
            "freeze": freeze_status,
            "freeze_valid": freeze_valid,
            "execution_attempted": False,
            "rejection_codes": ["digest_mismatch"] if digest_rejected else [],
            "reasons": [] if freeze_valid else [freeze_status.get("reason")],
            "next_action": (
                "Run lk control with --require-frozen to execute the already validated experiment."
                if freeze_valid else
                "Review the frozen artifact and inputs; do not execute until validation succeeds."
            ),
        }
        out = safe_out(root, ns.output)
        write_json(out, payload)
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0 if freeze_valid else (2 if digest_rejected else 1)
    if freeze_status.get("requires_refreeze"):
        digest_rejected = freeze_status.get("reason_code") == "digest_mismatch"
        rejected_status = "REJECTED" if digest_rejected else "UNPROVEN"
        rejection_codes = [freeze_status["reason_code"]] if digest_rejected else []
        payload = {
            "created_at": now(),
            "status": rejected_status,
            "proof_status": rejected_status,
            "outcome": "rejected" if digest_rejected else "not_run",
            "family": proof_evidence.normalize_family(spec.get("family")),
            "target_address": target,
            "trace_backend": backend,
            "freeze": freeze_status,
            "execution_attempted": False,
            "rejection_codes": rejection_codes,
            "reasons": [freeze_status.get("reason")],
            "next_action": (
                "Restore the expected manifest and freeze file, review the mismatch, then freeze again. "
                "No control or attack command was executed."
            ),
        }
        out = safe_out(root, ns.output)
        write_json(out, payload)
        if digest_rejected:
            print("REJECTED: frozen expectations digest mismatch; no control or attack command was executed.")
        else:
            print("UNPROVEN: generator drift; re-freeze required; no experiment executed.")
        print("  evidence " + out.relative_to(root).as_posix())
        return 2
    selected_rpc, rpc_source = _resolve_godmode_rpc(
        ns.rpc_url, _load_godmode_project_context(root)
    )
    if not selected_rpc:
        raise ValueError(
            "Control execution needs an RPC. Pass --rpc-url, configure the project's saved RPC, "
            "or set ETH_RPC_URL/FOUNDRY_ETH_RPC_URL. --freeze and --validate do not need an RPC."
        )
    url = rpc_url(selected_rpc)
    if backend=="anvil-calltracer" and not local_rpc(url):
        raise ValueError("Anvil callTracer control accepts a local Anvil RPC endpoint only.")
    if backend=="forge-state-diff" and not url:
        raise ValueError("Forge state-diff requires a fork RPC URL via --rpc-url.")

    env=os.environ.copy()
    env.update({"ETH_RPC_URL":url,"FOUNDRY_ETH_RPC_URL":url,"LOWKEY_RPC_URL":url})
    rows={}
    scenarios=[("control",control_run),("attack",attack)]
    negative=spec.get("negative_control")
    if negative is not None:
        if not isinstance(negative,dict) or not isinstance(negative.get("argv"),list):
            raise ValueError("negative_control must contain an argv string array.")
        scenarios.append(("negative_control",negative))
    elif spec.get("require_negative_control"):
        raise ValueError("Manifest requires negative_control but does not define it.")

    for name,entry in scenarios:
        if paired_forge and name=="attack":
            continue
        try:
            if backend=="forge-state-diff":
                if paired_forge and name=="control":
                    rows.update(_forge_control_run(
                        root,url,name,entry,spec,env,source_url=ns.source_rpc_url,
                        paired_entry=attack,
                    ))
                else:
                    rows[name]=_forge_control_run(
                        root,url,name,entry,spec,env,source_url=ns.source_rpc_url
                    )
            else:
                rows[name]=_trace_control_run(root,url,name,entry,spec,env)
        except Exception as exc:
            failed_names = ("control", "attack") if paired_forge and name=="control" else (name,)
            for failed_name in failed_names:
                failed_entry = control_run if failed_name=="control" else attack if failed_name=="attack" else entry
                rows[failed_name]={
                    "exit_code":None,"execution_verified":False,"metric":None,
                    "trace_error":str(exc),"argv":failed_entry.get("argv"),"backend":backend,
                }

    control_metric=rows.get("control",{}).get("metric")
    attack_metric=rows.get("attack",{}).get("metric")
    delta=None
    if isinstance(control_metric,int) and isinstance(attack_metric,int):
        delta=attack_metric-control_metric
    same_entry=bool(
        rows.get("control",{}).get("entry_call_sha256") and
        rows.get("control",{}).get("entry_call_sha256")==rows.get("attack",{}).get("entry_call_sha256")
    )
    same_envelope=(
        backend=="forge-state-diff" or bool(
            rows.get("control",{}).get("transaction_envelope_sha256") and
            rows.get("control",{}).get("transaction_envelope_sha256")==rows.get("attack",{}).get("transaction_envelope_sha256")
        )
    )
    same_prestate=bool(
        rows.get("control",{}).get("prestate_sha256") and
        rows.get("control",{}).get("prestate_sha256")==rows.get("attack",{}).get("prestate_sha256")
    )
    same_chain=bool(
        rows.get("control",{}).get("chain_id") is not None and
        str(rows["control"]["chain_id"]).lower()==str(rows.get("attack",{}).get("chain_id","")).lower()
    )

    scenario_excluded_keys={
        addr(item.get("address"))+":"+storage_slot_key(item.get("slot"))
        for item in (spec.get("scenario_parameters") or []) if isinstance(item,dict)
    }
    def _trace_slot_values(run_row):
        return {
            addr(item.get("address"))+":"+storage_slot_key(item.get("slot")):
            str(item.get("value","")).lower()
            for item in ((run_row.get("storage_trace") or {}).get("slots") or [])
        }
    control_trace_slots=_trace_slot_values(rows.get("control",{}))
    attack_trace_slots=_trace_slot_values(rows.get("attack",{}))
    shared_trace_slot_keys=(set(control_trace_slots)&set(attack_trace_slots))-scenario_excluded_keys
    trace_storage_mismatches=[
        {"slot":key,"control_value":control_trace_slots[key],"attack_value":attack_trace_slots[key]}
        for key in sorted(shared_trace_slot_keys)
        if control_trace_slots[key]!=attack_trace_slots[key]
    ]
    trace_storage_control_only=sorted(set(control_trace_slots)-set(attack_trace_slots)-scenario_excluded_keys)
    trace_storage_attack_only=sorted(set(attack_trace_slots)-set(control_trace_slots)-scenario_excluded_keys)
    same_trace_storage_values=not trace_storage_mismatches
    same_block=bool(
        rows.get("control",{}).get("block_number") is not None and
        rows.get("control",{}).get("block_number")==rows.get("attack",{}).get("block_number")
    )
    same_fork_anchor=(
        backend!="forge-state-diff" or bool(
            rows.get("control",{}).get("fork_parent_hash") and
            str(rows.get("control",{}).get("fork_parent_hash")).lower()==
            str(rows.get("attack",{}).get("fork_parent_hash","")).lower()
        )
    )
    fork_pin_verified=True
    if backend=="forge-state-diff":
        expected_block=spec.get("expected_fork_block")
        expected_chain=spec.get("expected_chain_id")
        if expected_block is None or expected_chain is None:
            fork_pin_verified=False
        else:
            try:
                expected_block_int=int(str(expected_block),16) if str(expected_block).lower().startswith("0x") else int(expected_block)
                expected_chain_int=int(str(expected_chain),16) if str(expected_chain).lower().startswith("0x") else int(expected_chain)
            except (TypeError,ValueError):
                raise ValueError("expected_fork_block and expected_chain_id must be integers or 0x quantities.")
            fork_pin_verified=(
                rows.get("control",{}).get("block_number")==expected_block_int and
                rows.get("attack",{}).get("block_number")==expected_block_int and
                int(rows.get("control",{}).get("chain_id") or -1)==expected_chain_int and
                int(rows.get("attack",{}).get("chain_id") or -1)==expected_chain_int
            )

    trace_expectations=spec.get("trace_expectations") or []
    trace_checks=[]
    trace_delta_verified=bool(trace_expectations)
    reasons_placeholder="Manifest must declare trace_expectations for the expected target/callback path delta."
    for expectation in trace_expectations:
        if not isinstance(expectation,dict):
            trace_delta_verified=False
            trace_checks.append({"verified":False,"reason":"trace_expectation must be an object"})
            continue
        address=addr(expectation.get("address"))
        counts={}
        expected={}
        names=["control","attack"]
        if negative is not None:
            names.append("negative_control")
        for name in names:
            calls=rows.get(name,{}).get("call_trace") or []
            counts[name]=sum(1 for call in calls if str(call.get("to") or "").lower()==address)
            lo=expectation.get(name+"_min_calls")
            hi=expectation.get(name+"_max_calls")
            if lo is None or hi is None or int(lo)<0 or int(hi)<int(lo):
                if name=="negative_control" and not spec.get("require_negative_control"):
                    expected[name]={"configured":False,"matched":None}
                else:
                    trace_delta_verified=False
                    expected[name]={"valid":False,"reason":"min/max calls are missing or invalid"}
            else:
                expected[name]={"min":int(lo),"max":int(hi),
                                "matched":int(lo)<=counts[name]<=int(hi)}
                if not expected[name]["matched"]:
                    trace_delta_verified=False
        trace_checks.append({
            "address":address,"description":expectation.get("description"),
            "observed_call_counts":counts,"expected":expected,
            "verified":all(item.get("matched",True) is not False for item in expected.values()),
        })
    trace_delta_verified=trace_delta_verified and all(item.get("verified",False) for item in trace_checks)

    negative_control_present=negative is not None
    negative_control_verified=(
        negative_control_present and
        all("negative_control" in check.get("expected",{}) and
            check["expected"]["negative_control"].get("matched") is True
            for check in trace_checks)
    )
    if spec.get("require_negative_control") and not negative_control_verified:
        trace_delta_verified=False

    attack_metric_positive=bool(isinstance(attack_metric,int) and attack_metric>0)
    semantic_check=rows.get("attack",{}).get("semantic_check") or {}
    semantic_invariant_verified=bool(semantic_check.get("verified"))
    family=proof_evidence.normalize_family(spec.get("family"))
    evidence_capabilities={}
    evidence_checks={}
    for scenario_name in ("control", "attack"):
        scenario_row=rows.get(scenario_name,{})
        storage_trace_row=scenario_row.get("storage_trace") or {}
        storage_observations=(
            len(scenario_row.get("derived_storage_accesses") or []) if backend=="forge-state-diff"
            else len(storage_trace_row.get("slots") or [])
        )
        storage_supported=(
            True if backend=="forge-state-diff" else
            bool(storage_trace_row.get("supported"))
        )
        capabilities=proof_evidence.trace_evidence_capabilities(
            backend, storage_trace_supported=storage_supported,
            storage_observations=storage_observations,
        )
        evidence_capabilities[scenario_name]=capabilities
        evidence_checks[scenario_name]=proof_evidence.evaluate_evidence_requirements(
            family, capabilities, spec.get("evidence_requirements"),
            require_trace_storage=bool(spec.get("require_trace_storage",False)),
        )
    evidence_requirements_verified=all(
        item.get("accepted") for item in evidence_checks.values()
    )
    non_economic=bool(ns.non_economic or spec.get("non_economic") or
                      family in proof_evidence.NON_ECONOMIC_FAMILIES)
    economics=proof_evidence.evaluate_economic_policy(
        family,attack_metric,non_economic=non_economic,
        semantic_invariant_verified=semantic_invariant_verified,
    )
    if backend=="forge-state-diff" and not non_economic:
        # Forge test metrics are structural observations, never net profitability.
        # A storage counter is dimensionless and must not be mislabeled as wei.
        if spec.get("metric_storage") is not None:
            economics={
                "accepted":False,
                "economic":False,
                "metric_kind":"forge_trace_storage_uint256_delta",
                "observed_metric_delta":attack_metric,
                "net_profit_wei":None,
                "reason":"Trace-derived storage behavior is structural evidence only; a separate mined Anvil reproof is required for economics.",
                "promotion_cap":"SIMULATED_BREAK",
            }
        else:
            economics={
                "accepted":False,
                "economic":True,
                "gross_balance_delta_wei":attack_metric,
                "net_profit_wei":None,
                "reason":"Forge state-diff has no EOA receipt gas accounting; a funded Anvil reproof is required.",
                "promotion_cap":"SIMULATED_BREAK",
            }

    scenario_errors=[name for name,_ in scenarios if rows.get(name,{}).get("trace_error")]
    execution_names=["control","attack"]
    if negative is not None:
        execution_names.append("negative_control")
    execution_attempted=all(
        rows.get(name,{}).get("execution_verified") is True for name in execution_names
    )
    base_valid=(
        same_entry and same_prestate and same_trace_storage_values and same_chain and
        same_block and same_fork_anchor and trace_delta_verified and
        evidence_requirements_verified and
        not scenario_errors and freeze_status.get("verified",False)
    )
    if backend=="anvil-calltracer":
        base_valid=base_valid and same_envelope
    else:
        # Forge has no signed transaction envelope or EOA receipt gas. Require a
        # block-pinned, independently verified target before calling it fork evidence.
        identity_required = str(spec.get("target_authenticity") or "unknown").lower() == "forked_deployment"
        base_valid = base_valid and fork_pin_verified
        if identity_required:
            base_valid = base_valid and all(
                rows.get(name,{}).get("target_authenticity_verified",False)
                for name in ("control","attack")
            )

    if non_economic:
        passed=base_valid and economics["accepted"] and semantic_invariant_verified
    elif backend=="forge-state-diff":
        # This is a paired structural acceptance only: positive gross balance
        # observations plus attack-over-control. It is never a profit verdict.
        passed=bool(paired_forge and base_valid and attack_metric_positive and isinstance(delta,int) and delta>0)
    else:
        # The Anvil path uses mined receipts and actual gas, so it can evaluate
        # net profitability for the selected local/forked target.
        passed=(base_valid and economics["accepted"] and attack_metric_positive and
                isinstance(delta,int) and delta>0)

    rejection_reasons=[]
    for name in ("control","attack","negative_control"):
        if rows.get(name,{}).get("trace_error"):
            rejection_reasons.append(name+": "+rows[name]["trace_error"])
    if not same_entry: rejection_reasons.append("Control and attack do not share the same target entry call.")
    if not same_prestate: rejection_reasons.append("Control and attack manifest-declared pre-state digests differ.")
    if not same_trace_storage_values:
        rejection_reasons.append("A storage slot read in both traces had different prestate values.")
    if not same_chain: rejection_reasons.append("Control and attack were executed on different chain IDs.")
    if not same_block: rejection_reasons.append("Control and attack used different block numbers.")
    if not same_fork_anchor: rejection_reasons.append("Control and attack used different fork parent hashes.")
    if not evidence_requirements_verified:
        for scenario_name, check in evidence_checks.items():
            for item in check.get("missing", []):
                rejection_reasons.append(
                    scenario_name + " lacks required " + item["dimension"] +
                    " evidence (" + str(item["actual"]) + " < " + str(item["required"]) + ")."
                )
    if backend=="forge-state-diff" and not fork_pin_verified:
        rejection_reasons.append("Forge runs do not match the manifest's expected_chain_id and expected_fork_block pins.")
    if backend=="anvil-calltracer" and not same_envelope:
        rejection_reasons.append("RPC-derived transaction nonce/gas/fee/type/access-list envelope differs.")
    if not trace_delta_verified:
        rejection_reasons.append(reasons_placeholder if not trace_expectations else
            "Observed nested-call trace did not match the frozen manifest expectations.")
    if spec.get("require_negative_control") and not negative_control_verified:
        rejection_reasons.append("Required negative control is missing or did not match its expected callback/path behavior.")
    if not freeze_status.get("verified"):
        rejection_reasons.append("Frozen expectations are missing or were not verified; this run cannot be promoted.")
    if non_economic and not semantic_invariant_verified:
        rejection_reasons.append("Non-economic attack requires a passing semantic_check_argv.")
    if not non_economic and backend=="forge-state-diff" and not passed:
        rejection_reasons.append("Forge paired state-diff did not verify a positive gross attack-over-control result; gas-adjusted profitability remains unproven.")
    if not non_economic and delta is None:
        rejection_reasons.append("Attack-over-control delta is unavailable because one or both scenario metrics are missing.")
    elif not non_economic and delta<=0:
        rejection_reasons.append("Attack metric did not exceed the control metric.")
    if not non_economic and not attack_metric_positive:
        if backend=="forge-state-diff" and rows.get("attack",{}).get("metric_kind")=="forge_trace_storage_uint256_delta":
            rejection_reasons.append("Trace-derived attack-state metric is zero or negative; the expected mutation/control effect was not observed.")
        elif backend=="forge-state-diff":
            rejection_reasons.append("Gross attacker balance delta is not positive.")
        else:
            rejection_reasons.append("Attack metric is not positive after measured costs.")

    authenticity=(
        "forked_deployment" if all(
            rows.get(name,{}).get("target_authenticity_verified",False)
            for name in ("control","attack")
        ) else str(spec.get("target_authenticity") or "unknown")
    )
    fidelity_labels=[rows.get(name,{}).get("fidelity_label") for name in ("control","attack")]
    if backend=="forge-state-diff":
        fidelity="simulated_caller"
        if "synthetic_state" in fidelity_labels: fidelity="synthetic_state"
        elif "simulated_dependencies" in fidelity_labels: fidelity="simulated_dependencies"
        elif "constrained_inputs" in fidelity_labels: fidelity="constrained_inputs"
    else:
        scanned_fidelity=[
            rows.get(name,{}).get("fidelity") or {}
            for name in ("control","attack")
        ]
        if any(item.get("synthetic_state") for item in scanned_fidelity):
            fidelity="synthetic_state"
        elif any(any(signal.get("kind")=="caller_impersonation"
                     for signal in item.get("signals",[])) for item in scanned_fidelity):
            fidelity="simulated_caller"
        elif any(any(signal.get("kind")=="external_call_mock"
                     for signal in item.get("signals",[])) for item in scanned_fidelity):
            fidelity="simulated_dependencies"
        elif any(any(signal.get("kind")=="test_assumption"
                     for signal in item.get("signals",[])) for item in scanned_fidelity):
            fidelity="constrained_inputs"
        elif all(item.get("scan_complete") and not item.get("fork_reproduction_blockers")
                 for item in scanned_fidelity):
            fidelity="real_funded"
        else:
            fidelity="unknown"


    rejection_codes=[]
    if not same_entry:
        rejection_codes.append("fidelity_insufficient")
    if (not same_prestate or not same_trace_storage_values or not same_chain or
        not same_block or not same_fork_anchor or
        (backend=="anvil-calltracer" and not same_envelope) or
        (backend=="forge-state-diff" and not fork_pin_verified)):
        rejection_codes.append("fidelity_insufficient")
    if not trace_delta_verified:
        rejection_codes.append("control_passed")
    if spec.get("require_negative_control") and not negative_control_verified:
        rejection_codes.append("control_passed")
    if non_economic and not semantic_invariant_verified:
        rejection_codes.append("semantic_default_missing")
    if not non_economic and backend=="anvil-calltracer" and isinstance(attack_metric,int) and attack_metric<=0:
        rejection_codes.append("net_negative")
    if not non_economic and delta is None:
        rejection_codes.append("fidelity_insufficient")
    elif not non_economic and isinstance(delta,int) and delta<=0:
        rejection_codes.append("control_passed")
    if not non_economic and backend=="forge-state-diff" and attack_metric is None:
        rejection_codes.append("fidelity_insufficient")
    rejected=(
        execution_attempted and not scenario_errors and not passed and bool(rejection_codes)
    )
    outcome="profitable" if passed and not non_economic and backend=="anvil-calltracer" else (
        "observed" if passed or execution_attempted else "not_run"
    )
    if rejected:
        outcome="rejected"
    proof=proof_evidence.classify_proof(
        authenticity,fidelity,outcome,
        authenticity_verified=authenticity=="forked_deployment" and all(
            rows.get(name,{}).get("target_authenticity_verified",False)
            for name in ("control","attack")
        ),
    )
    legacy_status=(
        "SIMULATED_BREAK" if backend=="forge-state-diff" and passed else
        ("BREAK" if passed else ("REJECTED" if rejected else "OBSERVED"))
    )
    proof_status=proof["status"]
    # Fixture/Forge evidence can establish an observed structural break, never
    # gas-adjusted profitability or proof of an authentic deployment.
    if (backend=="forge-state-diff" and passed):
        proof_status=proof_evidence.forge_promotion_status(proof, passed=True)
    elif non_economic and passed:
        proof_status="SIMULATED_BREAK"
    if not freeze_status.get("verified"):
        proof_status="OBSERVED"
    if not evidence_requirements_verified and not rejected:
        proof_status="UNPROVEN"

    memory_feedback=None
    if rejected:
        try:
            try:
                from . import experience_memory
            except ImportError:
                try:
                    import experience_memory
                except ImportError:
                    from lowkey import experience_memory
            memory_feedback=experience_memory.record_feedback(
                kind="false-positive",
                summary="Rejected control-gate hypothesis for "+str(spec.get("same_calls_id")),
                evidence="Control evidence rejected this attempted exploit. Reasons: "+
                         "; ".join(rejection_reasons)[:1000],
                finding_id="",
                context={
                    "family":family,
                    "backend":backend,
                    "fidelity":fidelity,
                    "target_shape":str(
                        spec.get("target_shape") or
                        rows.get("attack",{}).get("target_code_hash") or target or "unknown"
                    ),
                },
                root=root,
            )
        except Exception as exc:
            memory_feedback={"recorded":False,"reason":str(exc)[:300]}

    payload={
        "created_at":now(),"status":proof_status,"proof_status":proof_status,
        "legacy_status":legacy_status,"proof_axes":proof,
        "target_authenticity":authenticity,"fidelity":fidelity,
        "outcome":outcome,"family":family,"economic_policy":economics,
        "trace_backend":backend,"trace_schema_version":1,
        "canonical_trace_schema_version":2,"evidence_backend":backend,
        "paired_forge_experiment":paired_forge,
        "state_diff_pair_verified":bool(backend=="forge-state-diff" and paired_forge and passed),
        "gross_attack_metric_wei":(
            attack_metric if backend=="forge-state-diff"
            and rows.get("attack",{}).get("metric_kind")=="forge_account_balance_delta_without_eoa_gas"
            else None
        ),
        "attack_metric":attack_metric,
        "attack_metric_kind":rows.get("attack",{}).get("metric_kind"),
        "metric_definition":spec.get("metric_storage"),
        "metric_evidence":{
            scenario:rows.get(scenario,{}).get("metric_evidence")
            for scenario in ("control","attack")
        } if spec.get("metric_storage") is not None else rows.get("attack",{}).get("metric_evidence"),
        "economic_reproof_required":bool(backend=="forge-state-diff" and not non_economic and passed),
        "evidence_capabilities":evidence_capabilities,
        "evidence_requirements":evidence_checks,
        "evidence_requirements_verified":evidence_requirements_verified,
        "verification_method":(
            "Foundry Vm.startStateDiffRecording/stopAndReturnStateDiff" if backend=="forge-state-diff"
            else "local-Anvil RPC transaction plus debug_traceTransaction callTracer"
        ),
        "freeze":freeze_status,"negative_control_present":negative_control_present,
        "negative_control_verified":negative_control_verified,
        "control_delta":delta,"metric_name":spec.get("metric_name","attacker_gain"),
        "same_calls_id":spec["same_calls_id"],"execution_attempted":execution_attempted,
        "same_entry_call_verified":same_entry,
        "same_transaction_envelope_verified":same_envelope,
        "same_prestate_verified":same_prestate,
        "same_trace_storage_values_verified":same_trace_storage_values,
        "trace_storage_shared_mismatches":trace_storage_mismatches,
        "trace_storage_control_only":trace_storage_control_only,
        "trace_storage_attack_only":trace_storage_attack_only,
        "same_chain_verified":same_chain,
        "same_block_verified":same_block,"same_fork_anchor_verified":same_fork_anchor,
        "fork_pin_verified":fork_pin_verified,
        "trace_delta_verified":trace_delta_verified,"trace_checks":trace_checks,
        "attack_metric_positive_after_gas":attack_metric_positive if backend=="anvil-calltracer" else None,
        "semantic_invariant_verified":semantic_invariant_verified,
        "target_address":target,"prestate_slots_declared":spec.get("prestate_slots") or [],
        "storage_slots_derived_from_trace":sorted({
            (item.get("address") or item.get("account","")).lower()+":"+str(item.get("slot","")).lower()
            for name in ("control","attack","negative_control")
            for item in rows.get(name,{}).get("derived_storage_accesses",[])
        }),
        "runs":rows,"reasons":rejection_reasons,"rejection_codes":sorted(set(rejection_codes)),
        "reason_code":rejection_codes[0] if rejection_codes else None,
        "memory_feedback":memory_feedback,
        "gate":"Promotion requires frozen expectations, matched entry calls and pre-state, the configured trace backend, expected path/callback deltas, and a family-appropriate outcome. Forge state-diff can pass only as SIMULATED_BREAK; a separate mined Anvil reproof is required for LOCAL_PROFITABLE.",
    }
    out=safe_out(root,ns.output)
    write_json(out,payload)
    print(f"{proof_status}: {backend}; delta {delta}; entry {'matched' if same_entry else 'DIFFERENT'}; pre-state {'matched' if same_prestate else 'DIFFERENT'}; frozen {'verified' if freeze_status.get('verified') else 'NO'}; evidence {out.relative_to(root)}")
    return 0 if passed else 1



def coverage(args):
    p=LowkeyArgumentParser(prog="lk target-coverage"); p.add_argument("source_file"); p.add_argument("--start-line",type=int,default=1); p.add_argument("--end-line",type=int); p.add_argument("--root",default="."); p.add_argument("--output",default=".audit/godmode/target-coverage.json"); ns=p.parse_args(args)
    root=root_path(ns.root); src=(root/ns.source_file).resolve()
    if not src.is_relative_to(root) or not src.is_file(): raise ValueError("Target source must be inside the project.")
    if not shutil.which("forge"): raise RuntimeError("Forge not installed.")
    proc=run(["forge","coverage","--report","lcov"],root,900)
    lcov=next((x for x in (root/"lcov.info",root/"coverage"/"lcov.info") if x.is_file()),None)
    if proc.returncode or not lcov: raise RuntimeError("Forge did not produce lcov.info; inspect coverage output.")
    current=None; rows=[]
    for line in lcov.read_text(errors="replace").splitlines():
        if line.startswith("SF:"):
            candidate=Path(line[3:])
            current=(candidate if candidate.is_absolute() else root/candidate).resolve()
        elif line.startswith("DA:") and current==src:
            n,count=map(int,line[3:].split(",")[:2])
            if n>=ns.start_line and (ns.end_line is None or n<=ns.end_line): rows.append({"line":n,"hits":count,"covered":count>0})
    total=len(rows); covered=sum(r["covered"] for r in rows)
    payload={"source":src.relative_to(root).as_posix(),"start_line":ns.start_line,"end_line":ns.end_line,
             "lines":total,"covered":covered,"uncovered":[x["line"] for x in rows if not x["covered"]],
             "percent":round(covered*100/total,2) if total else None,"warning":"Execution reachability is not assertion quality or security proof."}
    write_json(safe_out(root,ns.output),payload); print(json.dumps(payload,indent=2)); return 0 if total else 1
def provenance(args):
    p=LowkeyArgumentParser(prog="lk provenance")
    p.add_argument("artifacts",nargs="*"); p.add_argument("--root",default="."); p.add_argument("--chain-id")
    p.add_argument("--fork-block"); p.add_argument("--signing-key")
    p.add_argument("--output",default=".audit/godmode/provenance.json"); ns=p.parse_args(args)
    root=root_path(ns.root); rows=[]
    for raw in ns.artifacts:
        f=(root/raw).resolve()
        if not f.is_relative_to(root) or not f.is_file(): raise ValueError(f"Artifact must exist inside project: {raw}")
        rows.append({"path":f.relative_to(root).as_posix(),"sha256":sha(f),"bytes":f.stat().st_size})
    rev=None
    if shutil.which("git"):
        x=run(["git","rev-parse","HEAD"],root,5); rev=x.stdout.strip() if x.returncode==0 else None
    versions={}
    for tool in ("forge","cast","anvil","slither","halmos","heimdall","bwrap"):
        if shutil.which(tool):
            x=run([tool,"--version"],root,4); versions[tool]=(x.stdout or x.stderr).strip().splitlines()[0][:160]
    payload={"created_at":now(),"project":str(root),"git_revision":rev,"chain_id":ns.chain_id,
             "fork_block":ns.fork_block,"artifacts":rows,"tool_versions":versions,
             "signature":"detached .sig file when --signing-key is provided"}
    out=safe_out(root,ns.output); write_json(out,payload)
    signature=None
    if ns.signing_key:
        key=Path(ns.signing_key).expanduser().resolve()
        if not key.is_file(): raise ValueError("Signing key file does not exist.")
        if not shutil.which("openssl"): raise RuntimeError("OpenSSL is required for detached provenance signing.")
        sig=out.with_suffix(out.suffix+".sig")
        proc=run(["openssl","dgst","-sha256","-sign",str(key),"-out",str(sig),str(out)],root,20)
        if proc.returncode: raise RuntimeError("OpenSSL signing failed: "+proc.stderr[-1000:])
        signature=str(sig.relative_to(root))
    print("Provenance: "+str(out.relative_to(root)))
    print("SHA-256: "+sha(out))
    print("Detached signature: "+(signature or "not requested"))
    return 0

def output(payload):
    print(json.dumps(payload,indent=2,sort_keys=True)); return 0
def source_cmd(command,args):
    p=LowkeyArgumentParser(prog="lk "+command); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); data=source_maps(root)
    key={"fallback-map":"fallback_map","oracle-map":"oracle_map","sig-matrix":"signature_map","init-frontrun":"initializer_map","custody":"custody_map","cross-vm":"cross_vm_map","reentrancy-graph":"reentrancy_graph","cfg":"cfg_outline"}[command]
    payload={"command":command,"signals":data[key]}
    if command=="sig-matrix": payload["candidate_replay_cases"]=["same signature twice","nonce not consumed","wrong chain ID","wrong verifying contract","expired deadline","wrong signer","malleable s","v normalization","wrong action/domain","packed-encoding collision","ERC-1271 contract signer"]
    if command=="oracle-map": payload["next"]="Trace the consumer and prove a downstream asset delta; no pool manipulation is inferred from a read."
    if command=="init-frontrun": payload["safety"]="Read-only static map only; Lowkey does not seize or initialize a live contract."
    if command=="reentrancy-graph": payload["confidence"]="heuristic; check exact storage identity and run a callback plus sequential control."
    return output(payload)
def fingerprint(args):
    p=LowkeyArgumentParser(prog="lk cheat-fingerprint"); p.add_argument("--root",default="."); ns=p.parse_args(args); data=cheat_fingerprints(root_path(ns.root)); print(json.dumps(data,indent=2)); return 0
def economic(args):
    p=LowkeyArgumentParser(prog="lk economic"); p.add_argument("--gross-wei",type=int,required=True); p.add_argument("--gas-used",type=int,required=True); p.add_argument("--max-fee-wei",type=int,required=True); p.add_argument("--pool-fee-bps",type=int,default=0); p.add_argument("--slippage-bps",type=int,default=0); p.add_argument("--capital-cost-wei",type=int,default=0); ns=p.parse_args(args)
    vals=[ns.gross_wei,ns.gas_used,ns.max_fee_wei,ns.pool_fee_bps,ns.slippage_bps,ns.capital_cost_wei]
    if min(vals)<0 or ns.pool_fee_bps>10000 or ns.slippage_bps>10000: raise ValueError("Economic inputs must be nonnegative; bps <= 10000.")
    gas=ns.gas_used*ns.max_fee_wei; pool=ns.gross_wei*ns.pool_fee_bps//10000; slip=ns.gross_wei*ns.slippage_bps//10000
    net=ns.gross_wei-gas-pool-slip-ns.capital_cost_wei
    return output({"gross_wei":ns.gross_wei,"gas_cost_wei":gas,"pool_fee_wei":pool,"slippage_wei":slip,"capital_cost_wei":ns.capital_cost_wei,"net_profit_wei":net,"status":"positive-candidate" if net>0 else "OBSERVED","limitations":["MEV competition and unmodeled price impact are excluded."]})
def rpc_command(kind,args):
    p=LowkeyArgumentParser(prog="lk "+kind); p.add_argument("target"); p.add_argument("--rpc-url")
    if kind in {"proxy-resolve", "storage-infer"}:
        p.add_argument("--slots",type=int,default=120)
    if kind == "storage-infer":
        p.add_argument("--no-resolve",action="store_true"); p.add_argument("--key",action="append",default=[])
    ns=p.parse_args(args); url=rpc_url(ns.rpc_url); target=addr(ns.target)
    if kind=="selectors-full": return output(selectors(target,url))
    if kind=="proxy-resolve": return output(proxy(target,url,ns.slots))
    count=max(1,min(ns.slots,120))
    calls=[rpc(url,"eth_getStorageAt",[target,hex(i),"latest"]) for i in range(count)]
    nonzero=[{"slot":i,"word":v} for i,v in enumerate(calls) if v and int(v,16)]
    probes=[]; derivation="not-run"
    if ns.key:
        try:
            from Crypto.Hash import keccak
            derivation="pycryptodome-keccak"
            for raw_key in ns.key:
                key=addr(raw_key)
                for anchor in range(count):
                    packed=bytes.fromhex(key[2:].rjust(64,"0")+format(anchor,"064x"))
                    digest=keccak.new(digest_bits=256); digest.update(packed)
                    derived="0x"+digest.hexdigest()
                    value=rpc(url,"eth_getStorageAt",[target,derived,"latest"])
                    if value and int(value,16):
                        probes.append({"key":key,"mapping_anchor_slot":anchor,"derived_slot":derived,"value":value,"confidence":"known-key-probe-hit"})
        except ImportError:
            if shutil.which("cast"):
                derivation="cast-index"
                for raw_key in ns.key:
                    key=addr(raw_key)
                    for anchor in range(count):
                        proc=run(["cast","index","address",key,str(anchor)],Path.cwd(),5)
                        if proc.returncode: continue
                        derived=proc.stdout.strip()
                        if not re.fullmatch(r"0x[0-9a-fA-F]{64}",derived): continue
                        value=rpc(url,"eth_getStorageAt",[target,derived,"latest"])
                        if value and int(value,16):
                            probes.append({"key":key,"mapping_anchor_slot":anchor,"derived_slot":derived,"value":value,"confidence":"known-key-probe-hit"})
            else: derivation="blocked-no-keccak-library-or-cast"
    return output({"target":target,"scanned_slots":count,"nonzero_slots":nonzero,
                   "known_key_probes":probes,"probe_derivation":derivation,
                   "warning":"A hit supports a mapping candidate at that anchor. No hit does not disprove a mapping; nested mappings and struct offsets need explicit modelling."})
def unravel(args):
    p=LowkeyArgumentParser(prog="lk unravel"); p.add_argument("tx_hash"); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",ns.tx_hash): raise ValueError("Transaction hash must be 32-byte hex.")
    trace=rpc(rpc_url(ns.rpc_url),"debug_traceTransaction",[ns.tx_hash,{"tracer":"callTracer"}],60)
    def walk(x,d=0):
        if not isinstance(x,dict): return []
        rows=[{"depth":d,"type":x.get("type"),"from":x.get("from"),"to":x.get("to"),"value":x.get("value"),"gasUsed":x.get("gasUsed"),"error":x.get("error"),"input":str(x.get("input") or "")[:74]}]
        for y in x.get("calls") or []: rows += walk(y,d+1)
        return rows
    return output({"tx_hash":ns.tx_hash,"call_tree":walk(trace)})
def state_diff(args):
    p=LowkeyArgumentParser(prog="lk state-diff"); p.add_argument("target"); p.add_argument("--before",required=True); p.add_argument("--after",required=True); p.add_argument("--slot",action="append",required=True); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    url=rpc_url(ns.rpc_url); target=addr(ns.target); rows=[]
    for x in ns.slot:
        slot=x if x.startswith("0x") else hex(int(x))
        a=rpc(url,"eth_getStorageAt",[target,slot,ns.before if ns.before.startswith("0x") else hex(int(ns.before))])
        b=rpc(url,"eth_getStorageAt",[target,slot,ns.after if ns.after.startswith("0x") else hex(int(ns.after))])
        if a!=b: rows.append({"slot":slot,"before":a,"after":b})
    return output({"target":target,"changed_slots":rows,"count":len(rows)})
def attack_forge(args):
    p=LowkeyArgumentParser(prog="lk attack forge"); p.add_argument("attack_id"); p.add_argument("--target",required=True); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); target=addr(ns.target)
    try:
        try: from .attack_catalog import ATTACKS
        except ImportError: from attack_catalog import ATTACKS
    except Exception: ATTACKS=[]
    entry=next((x for x in ATTACKS if str(x.get("id","")).lower()==ns.attack_id.lower() or str(x.get("slug","")).lower()==ns.attack_id.lower()),None)
    if not entry: raise ValueError("Unknown attack ID/slug.")
    out=safe_out(root,".audit/attack-forge/"+str(entry["id"])+"/AttackHarness.template.t.sol")
    fixture=None
    try:
        try: from .attack_library import LAB_SNIPPETS
        except ImportError: from attack_library import LAB_SNIPPETS
        snippet=LAB_SNIPPETS.get(str(entry.get("slug") or ""))
        if snippet:
            fixture=safe_out(root,".audit/attack-forge/"+str(entry["id"])+"/VulnerableFixture.sol")
            fixture.write_text(str(snippet).rstrip()+"\n",encoding="utf-8")
    except (ImportError,AttributeError,TypeError):
        snippet=None
    out.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport \"forge-std/Test.sol\";\ncontract LowkeyAttackCandidate is Test {\n address constant TARGET = "+target+";\n function test_candidate() external { assertGt(TARGET.code.length, 0, \"no runtime code\"); /* add exact protocol invariant and impact */ }\n}\n",encoding="utf-8")
    attack={key:entry.get(key) for key in ("id","slug","title","category","severity","plain","pattern","audit_signal","local_lab","mitigation","references")}
    write_json(out.parent/"attack.json",{"attack":attack,"target":target,"fixture":str(fixture.relative_to(root)) if fixture else None,
      "status":"starter-needs-protocol-specific-predicate","proof":False,
      "required":["bind exact target ABI and function","set up realistic actors, permissions and asset state",
        "assert a measurable security-property violation","run the matched sequential control","validate test sensitivity with mutation",
        "record fork block, gas, fees, recipient delta and artifact hashes"]})
    (out.parent/"README.md").write_text("# Attack candidate: "+str(entry.get("title") or entry["id"])+"\n\n"+
       "Library metadata is preserved in attack.json. The generated harness only checks that the target has code; replace it with the actual exploit preconditions and measurable impact before treating it as a PoC.\n\n"+
       ("A local fixture snippet was included. Review it; do not assume it is byte-for-byte compatible with the live target.\n" if fixture else "No runnable fixture snippet exists for this catalogue entry yet.\n"),encoding="utf-8")
    print("Attack workspace: "+str(out.parent.relative_to(root)))
    print("Fixture: "+(str(fixture.relative_to(root)) if fixture else "none available"))
    print("Status: starter only; no exploit proof claimed.")
    return 0

def _archetype_index_main(args):
    module_dir = str(Path(__file__).resolve().parent)
    if module_dir not in sys.path:
        sys.path.insert(0, module_dir)
    try:
        from archetypes._index import main as archetype_main
    except ImportError as exc:
        print(f"Archetype index is unavailable: {exc}", file=sys.stderr)
        return 2
    return archetype_main(list(args or []))


def generate(args,kind):
    p=LowkeyArgumentParser(prog="lk "+kind); p.add_argument("profile",nargs="?",choices=("vault","lending","amm","staking","bridge","governance"),default="vault"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); out=safe_out(root,f".audit/godmode/{kind}-{ns.profile}.md")
    templates={
      "invariant-forge":{"vault":["totalAssets >= totalSupply after matching units/fees","sum(user shares) == totalSupply"],"lending":["total debt reconciles with account debt","collateral and debt valuation obey liquidation rules"],"amm":["fee-adjusted invariant is preserved","pool balances reconcile with reserves"],"staking":["sum(user stake) == totalStaked","claimed rewards never exceed earned rewards"],"bridge":["message nonce consumed at most once","minted representation never exceeds finalized deposits"],"governance":["proposal executes at most once","vote weight counted once at declared snapshot"]},
      "archetype":{"vault":["deposit/withdraw/preview/share-inflation handlers","donation and rounding ghost state"],"lending":["borrow/repay/liquidate handlers","health-factor and bad-debt ghosts"],"amm":["swap/mint/burn/flash handlers","reserve and invariant ghosts"],"staking":["stake/unstake/claim handlers","reward-index and lockup ghosts"],"bridge":["send/relay/claim handlers","message nonce and finality ghosts"],"governance":["propose/vote/queue/execute handlers","snapshot and timelock ghosts"]}
    }
    if kind not in templates or ns.profile not in templates[kind]: raise ValueError("Unknown protocol profile.")
    out.write_text("# "+kind+" / "+ns.profile+"\n\n"+"".join("- [ ] "+x+"\n" for x in templates[kind][ns.profile])+"\nThese are candidates/starters. Bind the real protocol, actors, ghost state and assertions before running a proof engine.\n")
    print(f"Starter: {out.relative_to(root)}"); return 0
def token_weird(args):
    p=LowkeyArgumentParser(prog="lk token-weird"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root)
    out=safe_out(root,".audit/godmode/token-weird/WeirdTokens.sol")
    out.write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract WeirdERC20 {
 uint8 public decimals=18; uint256 public totalSupply; bool public paused; bool public returnFalse; uint256 public feeBps;
 mapping(address=>uint256) public balanceOf; mapping(address=>mapping(address=>uint256)) public allowance;
 mapping(address=>bool) public blocked; address public hook;
 function configure(uint8 d,uint256 fee,bool pause_,bool false_,address hook_) external {decimals=d;feeBps=fee;paused=pause_;returnFalse=false_;hook=hook_;}
 function setBlocked(address a,bool b) external {blocked[a]=b;}
 function mint(address a,uint256 n) external {balanceOf[a]+=n;totalSupply+=n;}
 function approve(address s,uint256 n) external returns(bool){allowance[msg.sender][s]=n;return true;}
 function transfer(address to,uint256 n) external returns(bool){if(returnFalse)return false;_move(msg.sender,to,n);return true;}
 function transferFrom(address f,address t,uint256 n) external returns(bool){if(returnFalse)return false;uint256 a=allowance[f][msg.sender];require(a>=n);allowance[f][msg.sender]=a-n;_move(f,t,n);return true;}
 function rebase(address account,int256 delta) external {if(delta>=0){balanceOf[account]+=uint256(delta);totalSupply+=uint256(delta);}else{uint256 cut=uint256(-delta);require(balanceOf[account]>=cut);balanceOf[account]-=cut;totalSupply-=cut;}}
 function _move(address f,address t,uint256 n) internal {require(!paused&&!blocked[f]&&!blocked[t]&&balanceOf[f]>=n);balanceOf[f]-=n;uint256 fee=n*feeBps/10000;balanceOf[t]+=n-fee;totalSupply-=fee;if(hook!=address(0)){(bool ok,)=hook.call(abi.encodeWithSignature("tokensReceived(address,address,address,uint256,bytes,bytes)",msg.sender,f,t,n,bytes(""),bytes("")));require(ok);}}
}
contract NoReturnERC20 {mapping(address=>uint256) public balanceOf;mapping(address=>mapping(address=>uint256)) public allowance;function mint(address a,uint n) external {balanceOf[a]+=n;}function approve(address s,uint n) external {allowance[msg.sender][s]=n;}function transfer(address a,uint n) external {require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[a]+=n;}function transferFrom(address f,address t,uint n) external {require(allowance[f][msg.sender]>=n&&balanceOf[f]>=n);allowance[f][msg.sender]-=n;balanceOf[f]-=n;balanceOf[t]+=n;}}
contract WideDecimalsToken {uint256 public decimals=1000;mapping(address=>uint256) public balanceOf;function mint(address a,uint256 n) external {balanceOf[a]+=n;}function transfer(address to,uint256 n) external returns(bool){require(balanceOf[msg.sender]>=n);balanceOf[msg.sender]-=n;balanceOf[to]+=n;return true;}}
contract ERC1155ReceiverLike {function onERC1155Received(address,address,uint256,uint256,bytes calldata) external pure returns(bytes4){return this.onERC1155Received.selector;}function onERC1155BatchReceived(address,address,uint256[] calldata,uint256[] calldata,bytes calldata) external pure returns(bytes4){return this.onERC1155BatchReceived.selector;}}
contract ERC777ReceiverLike {function tokensReceived(address,address,address,uint256,bytes calldata,bytes calldata) external pure {}}
""")
    print(f"Hostile token fixtures: {out.relative_to(root)}"); print("Includes fee-on-transfer, explicit rebasing, false-return, no-return transfer/transferFrom, pause, blacklist, reentrant hooks, and ERC1155/777 receivers. WideDecimalsToken returns uint256(1000) deliberately; a standard IERC20Metadata decimals() returns uint8."); return 0
def run_control_alias(args): return control(args)
def run_control(args):
    """Entry point used by break_engine for the mandatory control gate."""
    return control(args)


def mutation(args):
    p=LowkeyArgumentParser(prog="lk mutation-score")
    p.add_argument("manifest")
    p.add_argument("--min-score",type=float,default=0.90)
    p.add_argument("--timeout",type=int,default=300)
    p.add_argument("--output",default=".audit/verification/mutation-score-report.json")
    ns=p.parse_args(args)
    if not 0.0<=ns.min_score<=1.0: raise ValueError("--min-score must be between 0 and 1.")
    try:
        try: from . import behavioral_validation
        except ImportError: import behavioral_validation
    except ImportError as exc: raise RuntimeError("Existing mutation runner unavailable: "+str(exc))
    rc=behavioral_validation.run_cli([ns.manifest,"--output",ns.output,"--timeout",str(ns.timeout)])
    if rc!=0:
        print("MUTATION GATE: FAIL (baseline or mutation campaign did not complete)")
        return rc
    report_path=Path(ns.output).expanduser()
    if not report_path.is_absolute(): report_path=Path.cwd()/report_path
    if not report_path.is_file(): raise RuntimeError("Mutation runner did not create its report: "+str(report_path))
    report=json.loads(report_path.read_text(encoding="utf-8"))
    score=report.get("mutation_score")
    passed=isinstance(score,(float,int)) and score>=ns.min_score
    print("MUTATION GATE: "+("PASS" if passed else "FAIL"))
    print("  Required: "+format(ns.min_score,".1%"))
    print("  Observed: "+(format(score,".1%") if isinstance(score,(int,float)) else "not available"))
    print("  Invalid/timeouts are excluded from the score and must be reviewed separately.")
    return 0 if passed else 1

def inspect_reproduction_command(root, argv):
    """Inspect the replay argv and referenced local scripts for state-fabricating RPCs."""
    patterns={
        "rpc_storage_override":r"\b(?:anvil|hardhat)_setStorageAt\b|\bevm_setAccountStorageAt\b",
        "rpc_balance_override":r"\b(?:anvil|hardhat)_setBalance\b|\bevm_setAccountBalance\b",
        "rpc_code_override":r"\b(?:anvil|hardhat)_setCode\b|\bevm_setAccountCode\b",
        "rpc_impersonation":r"\b(?:anvil|hardhat)_impersonateAccount\b|\bev[m]?_unlockUnknownAccount\b",
        "rpc_time_override":r"\b(?:anvil|hardhat)_(?:setNextBlockTimestamp|setBlockTimestamp(?:Interval)?|removeBlockTimestampInterval)\b|\bevm_setNextBlockTimestamp\b",
    }
    findings=[]
    inspected=[]
    candidates=[str(x) for x in argv]
    for token in candidates:
        for kind,pattern in patterns.items():
            for match in re.finditer(pattern,token,re.I):
                findings.append({"kind":kind,"source":"argv","token":match.group(0)})
        possible=Path(token).expanduser()
        if not possible.is_absolute():
            possible=(root/possible).resolve()
        else:
            possible=possible.resolve()
        if possible.is_relative_to(root) and possible.is_file() and possible not in inspected:
            inspected.append(possible)
            try: text_value=possible.read_text(encoding="utf-8",errors="replace")
            except OSError: continue
            for kind,pattern in patterns.items():
                for line_number,line in enumerate(text_value.splitlines(),1):
                    for match in re.finditer(pattern,line,re.I):
                        findings.append({"kind":kind,"source":possible.relative_to(root).as_posix(),
                                         "line":line_number,"token":match.group(0)})
    return {"inspected_scripts":[x.relative_to(root).as_posix() for x in inspected],
            "state_fabrication_calls":findings,
            "blocked":bool(findings),
            "policy":"Direct local RPC state/balance/code/time overrides and account impersonation are not accepted as fork-reproduction setup. Configure the attacker through real transactions instead."}


def reprove(args):
    p=LowkeyArgumentParser(prog="lk reprove")
    p.add_argument("harness", help="Existing Foundry harness/source file to replay; it must stay inside --root."); p.add_argument("--root",default=".",help="Project root containing the harness and optional replay support files."); p.add_argument("--rpc-url",required=True,help="Local Anvil fork endpoint used for the replay.")
    p.add_argument("--fork-block",required=True,type=int,help="Pinned fork block whose parent state anchors the reproduction."); p.add_argument("--tx-hash",help="Already-mined transaction hash to inspect instead of running --argv-json.")
    p.add_argument("--prior-cost-wei",type=int,default=0,
                   help="Verified prior deployment/funding/setup expenditure in wei; subtract it from net profit in addition to replay gas. Defaults to 0, so pass measured costs when they exist.")
    p.add_argument("--target-address",required=True,help="Contract address whose execution and runtime code are verified."); p.add_argument("--profit-address",action="append",required=True,help="Portfolio address to measure; repeat for attacker, gas payer, and payout recipient.")
    p.add_argument("--source-rpc-url",help="Independent read-only archive RPC used to verify the fork anchor and real sender funding.")
    p.add_argument("--prestate-slot",action="append",default=[],help="Additional storage slot to compare between local fork and source, as ADDRESS:SLOT.")
    p.add_argument("--argv-json",help="JSON string array for the replay command; it is never shell-evaluated.")
    p.add_argument("--support-file",action="append",default=[],
                   help="Additional project file imported by the harness/replay script; repeat for transitive helpers.")
    p.add_argument("--semantic-check-argv-json",help="Separate command whose passing assertion demonstrates the non-economic security invariant.")
    p.add_argument("--semantic-test",help="Exact Foundry test name expected to emit [PASS] in the semantic check output.")
    p.add_argument("--family",default="unknown",help="Attack family used by the evidence and economic policy.")
    p.add_argument("--non-economic",action="store_true",help="Require a separately passing semantic invariant instead of positive net profit.")
    p.add_argument("--require-trace-storage",action="store_true",help="Reject the replay unless trace-derived storage observations are present.")
    ns=p.parse_args(args)
    if ns.prior_cost_wei < 0:
        raise ValueError("--prior-cost-wei must be a non-negative integer.")
    root=root_path(ns.root); harness=(root/ns.harness).resolve()
    if not harness.is_relative_to(root) or not harness.is_file(): raise ValueError("Harness must be inside project.")
    try:
        try:
            from . import proof_evidence
        except ImportError:
            import proof_evidence
    except ImportError as exc:
        raise RuntimeError("Proof evidence policy module is unavailable: "+str(exc)) from exc
    family=proof_evidence.normalize_family(ns.family)
    non_economic=bool(ns.non_economic or family in proof_evidence.NON_ECONOMIC_FAMILIES)
    url=rpc_url(ns.rpc_url)
    if not local_rpc(url): raise ValueError("Reproof accepts local Anvil fork endpoint only.")
    if ns.fork_block<0: raise ValueError("--fork-block must be non-negative.")
    support_files=list(ns.support_file)
    for value in support_files:
        candidate=(root/value).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise ValueError("Support file must be an existing project file: "+value)
    # Include directly referenced local scripts from both commands. Imported
    # helpers beyond these files remain the operator's responsibility and are
    # called out explicitly in the fidelity report.
    command_candidates=[]
    for raw_argv in (ns.argv_json,ns.semantic_check_argv_json):
        if not raw_argv:
            continue
        try:
            parsed=json.loads(raw_argv)
        except json.JSONDecodeError as exc:
            raise ValueError("Replay/semantic command argv must be valid JSON.") from exc
        if not isinstance(parsed,list) or not all(isinstance(x,str) for x in parsed):
            raise ValueError("Replay/semantic command argv must be a string array.")
        for token in parsed:
            candidate=Path(token).expanduser()
            candidate=(root/candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
            if candidate.is_relative_to(root) and candidate.is_file():
                command_candidates.append(candidate.relative_to(root).as_posix())
    scan_entry={"harness":harness.relative_to(root).as_posix(),
                "support_files":sorted(set(support_files+command_candidates))}
    fidelity=_analyze_control_fidelity(root,scan_entry,{})
    blockers=fidelity.get("fork_reproduction_blockers") or []
    if blockers:
        payload={"status":"SIMULATED_BREAK","command_run":False,"fidelity":fidelity,
                 "blocked_cheatcodes":blockers,
                 "reason":"Harness contains state-fabricating or environment-changing cheatcodes that are not allowed for fork reproduction."}
        write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
    tx_hash=ns.tx_hash
    command_result=None
    execution_command={"inspected_scripts":[],"state_fabrication_calls":[],"blocked":False}
    if ns.argv_json:
        argv=json.loads(ns.argv_json)
        if not isinstance(argv,list) or not argv or not all(isinstance(x,str) for x in argv):
            raise ValueError("--argv-json must be a non-empty JSON string array.")
        execution_command=inspect_reproduction_command(root,argv)
        if execution_command["blocked"]:
            payload={"status":"SIMULATED_BREAK","command_run":False,"fidelity":fidelity,
                     "execution_command":execution_command,
                     "reason":"Replay script contains a local RPC state-fabrication call; configure actors through actual transactions."}
            write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
        env=os.environ.copy(); env.update({"ETH_RPC_URL":url,"FOUNDRY_ETH_RPC_URL":url,"LOWKEY_RPC_URL":url})
        command_result=run(argv,root,900,env=env)
        if command_result.returncode:
            payload={"status":"UNPROVEN","command_run":True,"exit_code":command_result.returncode,
                     "stdout":command_result.stdout[-3000:],"stderr":command_result.stderr[-1500:],
                     "fidelity":fidelity,"reason":"Reproduction command did not complete successfully."}
            write_json(safe_out(root,".audit/godmode/reprove.json"),payload); print(json.dumps(payload,indent=2)); return 1
        hashes=re.findall(r"LOWKEY_TRACE_TX_HASH\s+(0x[0-9a-fA-F]{64})",command_result.stdout+"\n"+command_result.stderr)
        if len(hashes)!=1: raise ValueError("Reproof command must emit exactly one LOWKEY_TRACE_TX_HASH for the transaction it just executed.")
        if tx_hash and tx_hash.lower()!=hashes[0].lower():
            raise ValueError("--tx-hash does not match the transaction emitted by --argv-json.")
        tx_hash=hashes[0]
    if not tx_hash or not re.fullmatch(r"0x[0-9a-fA-F]{64}",tx_hash):
        raise ValueError("Supply --tx-hash or make --argv-json emit LOWKEY_TRACE_TX_HASH <32-byte hash>.")
    semantic_check=None
    if ns.semantic_check_argv_json:
        semantic_argv=json.loads(ns.semantic_check_argv_json)
        if not isinstance(semantic_argv,list) or not semantic_argv or not all(isinstance(x,str) for x in semantic_argv):
            raise ValueError("--semantic-check-argv-json must be a non-empty JSON string array.")
        semantic_audit=inspect_reproduction_command(root,semantic_argv)
        if semantic_audit["blocked"]:
            raise ValueError("Semantic check command contains local RPC state-fabrication calls.")
        semantic_env=os.environ.copy()
        semantic_env.update({"ETH_RPC_URL":url,"FOUNDRY_ETH_RPC_URL":url,"LOWKEY_RPC_URL":url})
        semantic_proc=run(semantic_argv,root,900,env=semantic_env)
        semantic_output=(semantic_proc.stdout or "")+"\\n"+(semantic_proc.stderr or "")
        semantic_check={
            "argv":semantic_argv,"exit_code":semantic_proc.returncode,
            "verified":_semantic_execution_verified(
                semantic_proc.returncode, semantic_output,
                ns.semantic_test,
            ),
            "expected_test":ns.semantic_test,
            "output_tail":semantic_output[-1600:],
            "verification_rule":"requires an explicit passing assertion marker or recognized test-runner PASS summary; exit code alone is insufficient",
        }
    elif non_economic:
        semantic_check={
            "verified":False,"reason":"Non-economic reproof requires --semantic-check-argv-json."
        }
    tx_hash=tx_hash.lower()
    tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
    receipt=rpc(url,"eth_getTransactionReceipt",[tx_hash])
    if not isinstance(tx,dict) or not isinstance(receipt,dict):
        raise ValueError("Transaction hash is not mined on this Anvil node.")
    if str(receipt.get("status") or "").lower() not in {"0x1","1"}:
        raise ValueError("Reproof transaction reverted.")
    block_number=int(str(receipt.get("blockNumber") or "0x0"),16)
    tx_index=int(str(receipt.get("transactionIndex") or "0x0"),16)
    if block_number!=ns.fork_block+1 or tx_index!=0:
        raise ValueError("For a precise fork reproof, the tested transaction must be the first and only transaction in the block immediately after --fork-block.")
    parent=rpc(url,"eth_getBlockByNumber",[hex(ns.fork_block),False])
    if not isinstance(parent,dict) or not parent.get("hash"):
        raise ValueError("The declared fork parent block is unavailable from this RPC.")
    block=rpc(url,"eth_getBlockByNumber",[hex(block_number),False])
    block_txs=[str(x).lower() for x in ((block or {}).get("transactions") or [])]
    if block_txs!=[tx_hash]:
        raise ValueError("The tested transaction must be the only transaction in its block.")
    chain_id=rpc(url,"eth_chainId",[])
    target=addr(ns.target_address)
    profit_addresses=sorted({addr(x) for x in ns.profit_address})
    if not profit_addresses: raise ValueError("At least one --profit-address is required.")
    trace=rpc(url,"debug_traceTransaction",[tx_hash,{"tracer":"callTracer"}],60)
    if not isinstance(trace,dict): raise ValueError("The node did not return a callTracer execution trace.")
    storage_trace=_trace_storage_prestate(url,tx_hash)
    trace_storage_observed=bool(storage_trace.get("slots"))
    if ns.require_trace_storage and (
        not storage_trace.get("supported") or not trace_storage_observed
    ):
        detail=storage_trace.get("reason") or "prestateTracer diff returned no changed storage slots for this transaction."
        raise ValueError("The required derived-storage evidence is unavailable: "+str(detail))
    if ns.source_rpc_url and (
        not storage_trace.get("supported") or not trace_storage_observed
    ):
        detail=storage_trace.get("reason") or "prestateTracer diff returned no changed storage slots for this transaction."
        raise ValueError("Source-verified reproof requires at least one prestateTracer-derived changed storage slot: "+str(detail))
    source_verification={"verified":False,"reason":"No independent source archive RPC was supplied; result is local-only."}
    if ns.source_rpc_url:
        if not ns.argv_json:
            raise ValueError("Source-verified FORK_REPRODUCED/PROFITABLE status requires --argv-json so the replay command can be inspected.")
        source_url=rpc_url(ns.source_rpc_url)
        if local_rpc(source_url) or urlparse(source_url).hostname==urlparse(url).hostname:
            raise ValueError("--source-rpc-url must be an independent non-local source endpoint, not the local Anvil node.")
        source_chain_id=rpc(source_url,"eth_chainId",[])
        source_parent=rpc(source_url,"eth_getBlockByNumber",[hex(ns.fork_block),False])
        if str(source_chain_id).lower()!=str(chain_id).lower():
            raise ValueError("Local Anvil chain ID does not match the independent source RPC.")
        if not isinstance(source_parent,dict) or str(source_parent.get("hash") or "").lower()!=str(parent.get("hash") or "").lower():
            raise ValueError("Local Anvil parent block hash does not match the independent source chain at --fork-block.")
        local_target_code=rpc(url,"eth_getCode",[target,hex(ns.fork_block)])
        source_target_code=rpc(source_url,"eth_getCode",[target,hex(ns.fork_block)])
        if not local_target_code or local_target_code=="0x" or str(local_target_code).lower()!=str(source_target_code or "").lower():
            raise ValueError("Target bytecode on the local fork does not match the independent source chain at --fork-block.")
        if not ns.prestate_slot and not storage_trace.get("slots"):
            raise ValueError("Source-verified fork reproduction needs trace-derived or explicitly declared target storage slots.")
        checked_slots=[]
        for raw_slot in ns.prestate_slot:
            if ":" not in raw_slot: raise ValueError("--prestate-slot must use ADDRESS:SLOT.")
            raw_address,raw_slot_value=raw_slot.split(":",1)
            slot_address=addr(raw_address)
            if slot_address!=target:
                raise ValueError("Source-verified reproof slots must belong to --target-address.")
            slot_value=raw_slot_value.lower()
            if re.fullmatch(r"0x[0-9a-f]{64}",slot_value) is None:
                try: slot_value=hex(int(slot_value,0))
                except ValueError: raise ValueError("Invalid --prestate-slot slot value.")
            local_value=rpc(url,"eth_getStorageAt",[slot_address,slot_value,hex(ns.fork_block)])
            source_value=rpc(source_url,"eth_getStorageAt",[slot_address,slot_value,hex(ns.fork_block)])
            if str(local_value).lower()!=str(source_value).lower():
                raise ValueError(f"Pre-state slot {slot_address}:{slot_value} differs between local fork and source chain.")
            checked_slots.append({"address":slot_address,"slot":slot_value,"value":local_value})
        trace_addresses=sorted(set(storage_trace.get("addresses",[])) | {target} | set(profit_addresses) | {str(tx.get("from")).lower()})
        checked_trace_accounts=[]
        for address in trace_addresses:
            local_code=rpc(url,"eth_getCode",[address,hex(ns.fork_block)])
            source_code=rpc(source_url,"eth_getCode",[address,hex(ns.fork_block)])
            if str(local_code or "0x").lower()!=str(source_code or "0x").lower():
                raise ValueError("Trace-touched account code differs between the local fork and source chain: "+address)
            local_balance=int(str(rpc(url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            source_balance=int(str(rpc(source_url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            local_nonce=int(str(rpc(url,"eth_getTransactionCount",[address,hex(ns.fork_block)])),16)
            source_nonce=int(str(rpc(source_url,"eth_getTransactionCount",[address,hex(ns.fork_block)])),16)
            if local_balance!=source_balance or local_nonce!=source_nonce:
                raise ValueError("Trace-touched account balance/nonce differs at fork block: "+address)
            checked_trace_accounts.append({"address":address,"code_sha256":hashlib.sha256(
                bytes.fromhex(str(source_code or "0x").removeprefix("0x"))).hexdigest(),
                "balance_wei":source_balance,"nonce":source_nonce})
        checked_trace_slots=[]
        for item in storage_trace.get("slots",[]):
            address=item["address"]; slot_value=item["slot"]; expected_value=item["value"]
            local_value=rpc(url,"eth_getStorageAt",[address,slot_value,hex(ns.fork_block)])
            source_value=rpc(source_url,"eth_getStorageAt",[address,slot_value,hex(ns.fork_block)])
            if (str(local_value).lower()!=str(expected_value).lower() or
                str(source_value).lower()!=str(expected_value).lower()):
                raise ValueError("Trace-derived prestate slot differs between replay, local fork and source: "+address+":"+slot_value)
            checked_trace_slots.append({"address":address,"slot":slot_value,"value":expected_value})
        source_sender_balance=int(str(rpc(source_url,"eth_getBalance",[str(tx.get("from")).lower(),hex(ns.fork_block)])),16)
        source_profit_balances=[]
        for address in profit_addresses:
            local_balance=int(str(rpc(url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            source_balance=int(str(rpc(source_url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
            if local_balance!=source_balance:
                raise ValueError(f"Profit account {address} has a different fork-block balance on local Anvil and the independent source chain.")
            source_profit_balances.append({"address":address,"balance_wei":source_balance})
        source_verification={"verified":True,"source_chain_id":source_chain_id,
                             "source_parent_hash":source_parent.get("hash"),
                             "target_code_sha256":hashlib.sha256(bytes.fromhex(str(source_target_code).removeprefix("0x"))).hexdigest(),
                             "sender_balance_at_fork_wei":source_sender_balance,
                             "profit_account_balances":source_profit_balances,
                             "prestate_slots":checked_slots,
                             "trace_touched_accounts":checked_trace_accounts,
                             "trace_derived_storage_slots":checked_trace_slots,
                             "storage_trace_supported":True}
    tx_digest,entry=_control_entry_digest(tx,chain_id)
    trace_digest,_=_control_entry_digest(trace,chain_id)
    if tx_digest!=trace_digest: raise ValueError("CallTracer root does not match the mined transaction.")
    calls=_trace_flatten(trace)
    if target not in {x.get("to") for x in calls}:
        raise ValueError("The transaction trace did not call --target-address.")
    sender=str(tx.get("from") or "").lower()
    if sender not in profit_addresses:
        # If the gas payer is omitted from the measured portfolio, subtract its actual fee explicitly below.
        subtract_fee=True
    else:
        subtract_fee=False
    before_total=0; after_total=0; balances=[]
    for address in profit_addresses:
        before=int(str(rpc(url,"eth_getBalance",[address,hex(ns.fork_block)])),16)
        after=int(str(rpc(url,"eth_getBalance",[address,hex(block_number)])),16)
        before_total+=before; after_total+=after
        balances.append({"address":address,"before_wei":before,"after_wei":after,"delta_wei":after-before})
    gas_used=int(str(receipt.get("gasUsed") or "0x0"),16)
    gas_price=receipt.get("effectiveGasPrice") or tx.get("gasPrice") or "0x0"
    effective_gas_price=int(str(gas_price),16)
    gas_cost=gas_used*effective_gas_price
    if source_verification["verified"] and source_verification["sender_balance_at_fork_wei"]<gas_cost:
        raise ValueError("Transaction sender did not have enough native ETH on the source chain to pay the measured gas cost.")
    gross_delta=after_total-before_total
    # When the transaction sender is in the measured portfolio, its mined gas
    # is already reflected in gross_delta. Otherwise subtract the receipt fee
    # explicitly. Prior setup capital/fees are always separate measured costs.
    transaction_gas_cost = 0 if not subtract_fee else gas_cost
    prior_cost = int(ns.prior_cost_wei)
    net_profit=gross_delta-transaction_gas_cost-prior_cost
    total_cost=gas_cost+prior_cost
    if command_result is None:
        final_status="LOCAL_TRACE_ONLY"
    elif source_verification["verified"]:
        final_status="PROFITABLE" if net_profit>0 else "FORK_REPRODUCED"
    else:
        final_status="LOCAL_PROFITABLE" if net_profit>0 else "LOCAL_REPRODUCED"
    fidelity_label="real_funded"
    if fidelity.get("synthetic_state"):
        fidelity_label="synthetic_state"
    elif any(signal.get("kind")=="caller_impersonation" for signal in fidelity.get("signals",[])):
        fidelity_label="simulated_caller"
    elif any(signal.get("kind")=="external_call_mock" for signal in fidelity.get("signals",[])):
        fidelity_label="simulated_dependencies"
    elif any(signal.get("kind")=="test_assumption" for signal in fidelity.get("signals",[])):
        fidelity_label="constrained_inputs"
    if not fidelity.get("scan_complete"):
        fidelity_label="unknown"
    semantic_invariant_verified=bool((semantic_check or {}).get("verified"))
    economic_policy=proof_evidence.evaluate_economic_policy(
        family,net_profit,non_economic=non_economic,
        semantic_invariant_verified=semantic_invariant_verified,
    )
    proof_outcome=(
        "profitable" if (net_profit>0 and not non_economic) else
        ("observed" if (not non_economic or semantic_invariant_verified) else "rejected")
    )
    if not fidelity.get("scan_complete"):
        fidelity_label="unknown"
    try:
        proof_axes=proof_evidence.classify_proof(
            "forked_deployment" if source_verification.get("verified") else "unknown",
            fidelity_label,proof_outcome,
            authenticity_verified=bool(source_verification.get("verified")),
        )
    except Exception as exc:
        proof_axes={
            "status":"OBSERVED","target_authenticity":"unknown","fidelity":fidelity_label,
            "outcome":proof_outcome,"policy_error":str(exc),
        }
    if non_economic and semantic_invariant_verified:
        proof_axes["status"]="SIMULATED_BREAK"
    if non_economic and not semantic_invariant_verified:
        proof_axes["status"]="REJECTED"
    if not economic_policy.get("accepted") and not non_economic and net_profit<=0:
        proof_axes["status"]="REJECTED"
    payload={
        "status":proof_axes["status"],
        "proof_status":proof_axes["status"],
        "legacy_status":final_status,
        "proof_axes":proof_axes,
        "command_run":bool(command_result),
        "exit_code":command_result.returncode if command_result else None,
        "tx_hash":tx_hash,"chain_id":chain_id,"fork_parent_block":ns.fork_block,
        "source_fork_verification":source_verification,
        "transaction_block":block_number,"transaction_index":tx_index,
        "target_address":target,"entry_call":entry,"entry_call_sha256":tx_digest,
        "call_trace":calls,"receipt_status":receipt.get("status"),
        "gas_used":gas_used,"effective_gas_price_wei":effective_gas_price,"gas_cost_wei":gas_cost,
        "gas_cost_in_portfolio_delta":not subtract_fee,
        "prior_cost_wei":prior_cost,"total_cost_wei":total_cost,
        "profit_addresses":balances,"gross_balance_delta_wei":gross_delta,
        "net_profit_wei":net_profit,
        "fidelity":fidelity,
        "fidelity_label":fidelity_label,
        "target_authenticity":"forked_deployment" if source_verification.get("verified") else "unknown",
        "outcome":proof_outcome,
        "family":family,
        "economic_policy":economic_policy,
        "semantic_check":semantic_check,
        "semantic_invariant_verified":semantic_invariant_verified,
        "storage_trace":storage_trace,
        "derived_storage_slots":storage_trace.get("slots",[]),
        "execution_command":execution_command,
        "promotion_policy":{
            "FORK_REPRODUCED":"Block-pinned parent state, real mined local Anvil transaction, successful receipt, callTracer match, declared target reached, no synthetic funding/storage/code/mock/time/caller cheatcodes.",
            "PROFITABLE":"FORK_REPRODUCED plus measured portfolio balance delta net of actual transaction gas is positive.",
            "HUMAN_CONFIRMED":"Never assigned automatically; requires explicit human disposition in the evidence ledger.",
        },
        "human_confirmation_required":True,
        "limitations":["Native-ETH balance accounting only; ERC20/ERC4626 share profit requires token-specific balance measurement.",
                       "Without --source-rpc-url, this is a local Anvil reproduction only, not an independently verified source-chain fork.",
                       "An independent source check verifies chain ID, parent block hash, target bytecode, and transaction-sender ETH balance; it does not prove that every dependency or storage slot is identical.",
                       "A replayed transaction proves only the tested path and state; it is not a completeness guarantee."],
    }
    rejection_codes=[]
    if non_economic and not semantic_invariant_verified:
        rejection_codes.append("semantic_invariant_failed")
    if not non_economic and net_profit<=0:
        rejection_codes.append("net_negative")
    payload["rejection_codes"]=rejection_codes
    if rejection_codes:
        try:
            try:
                from . import experience_memory
            except ImportError:
                import experience_memory
            payload["memory_feedback"]=experience_memory.record_feedback(
                kind="false-positive",
                summary="Rejected reproof hypothesis for "+family,
                evidence="Reproof did not satisfy the economic/semantic gate: "+", ".join(rejection_codes)+
                         "; net_profit_wei="+str(net_profit),
                root=root,
            )
        except Exception as exc:
            payload["memory_feedback"]={"recorded":False,"reason":str(exc)[:300]}
    out=safe_out(root,".audit/godmode/reprove.json"); write_json(out,payload)
    print(json.dumps(payload,indent=2))
    return 0 if (economic_policy.get("accepted") and
                  (not non_economic or semantic_invariant_verified)) else 1

def fork_cache(args):
    p=LowkeyArgumentParser(prog="lk fork-cache"); p.add_argument("action",choices=("snapshot","revert","list")); p.add_argument("--id"); p.add_argument("--rpc-url"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); f=safe_out(root,".audit/godmode/fork-cache.json"); data=json.loads(f.read_text()) if f.exists() else {}
    if ns.action=="list": return output(data)
    url=rpc_url(ns.rpc_url)
    if not local_rpc(url): raise ValueError("Fork cache is local Anvil only.")
    if ns.action=="snapshot":
        sid=rpc(url,"evm_snapshot",[]); data[str(sid)]={"snapshot_id":sid,"block":rpc(url,"eth_blockNumber",[]),"chain_id":rpc(url,"eth_chainId",[]),"created_at":now()}
        write_json(f,data); print("Snapshot "+str(sid)); return 0
    if ns.id not in data: raise ValueError("Snapshot ID not found.")
    ok=rpc(url,"evm_revert",[ns.id]); data.pop(ns.id,None) if ok else None; write_json(f,data); print("Reverted: "+str(bool(ok))); return 0 if ok else 1
def questions(args):
    p=LowkeyArgumentParser(prog="lk questions"); p.add_argument("action",nargs="?",default="current"); p.add_argument("--root",default="."); p.add_argument("note",nargs="*"); ns=p.parse_args(args)
    try:
        try: from . import question_engine
        except ImportError: import question_engine
        return question_engine.run({},[ns.action,*ns.note],root=root_path(ns.root),mode="current")
    except ImportError as exc: raise RuntimeError(str(exc))
def learn(args):
    p=LowkeyArgumentParser(prog="lk learn"); p.add_argument("--kind",default="protocol-pattern",choices=("protocol-pattern","test-procedure","tool-configuration","project-fact","false-positive-rule")); p.add_argument("--title",required=True); p.add_argument("--lesson",required=True); p.add_argument("--evidence",required=True); p.add_argument("--when",default=""); p.add_argument("--rationale",default=""); p.add_argument("--root",default="."); ns=p.parse_args(args)
    try:
        try: from . import experience_memory
        except ImportError: import experience_memory
        root=root_path(ns.root); old=Path.cwd()
        try:
            os.chdir(root)
            return experience_memory.main(["propose","--kind",ns.kind,"--title",ns.title,"--lesson",ns.lesson,"--evidence",ns.evidence,"--when",ns.when,"--rationale",ns.rationale])
        finally: os.chdir(old)
    except ImportError as exc: raise RuntimeError(str(exc))
def _is_godmode_help_request(tokens):
    """Help after '--' belongs to the child command, not to Lowkey."""
    before_separator = []
    for token in tokens:
        if token == "--":
            break
        before_separator.append(str(token).strip().lower())
    return any(token in HELP_FLAGS for token in before_separator)


def print_godmode_command_help(command):
    """Render the same task-oriented help layout for every routed Godmode command."""
    command = str(command or "").strip().lower()
    details = _godmode_help_details(command) or {}
    guide = GODMODE_HELP_GUIDES.get(command) or GODMODE_SUBCOMMAND_HELP_GUIDES.get(command)
    if not guide:
        print("No curated help page is registered for: " + command)
        return 2

    summary = details.get("summary") or guide.get("summary") or (command + " Godmode workflow.")
    when = guide.get("when") or details.get("when") or "Use it when this review surface is relevant to your current investigation."
    limitations = guide.get("limits") or details.get("limits") or "Review the returned evidence and limitations before treating an observation as a finding."
    print("LOWKEY HELP  •  lk " + ("attack forge" if command == "attack-forge" else command))
    print("=" * 72)
    print("What it does: " + summary)
    print()
    print("When to use:")
    print("  " + when)
    print()

    print("USAGE")
    print("------")
    print("  " + guide["usage"])
    print()

    sections = (
        ("COMMAND VARIATIONS", "variations"),
        ("ARGUMENTS", "arguments"),
        ("OPTIONS / MODES", "options"),
        ("RECOMMENDED WORKFLOW", "workflow"),
        ("OUTPUT / EVIDENCE", "output"),
    )
    for heading, key in sections:
        rows = guide.get(key) or []
        if not rows:
            continue
        print(heading)
        print("-" * len(heading))
        for row in rows:
            print("  " + str(row))
        print()

    print("SAFETY / LIMITATIONS")
    print("--------------------")
    print("  " + limitations)
    capability = _CAPABILITY_BY_NAME.get(command)
    if capability:
        print("  Capability status: " + capability["status"] + ".")
    related = guide.get("related") or []
    if related:
        print()
        print("RELATED COMMANDS")
        print("----------------")
        for row in related:
            print("  " + str(row))
    print()
    print("HELP TIP")
    print("--------")
    print("  Help is read-only: it does not run the command or change project/chain state.")
    print("  Accepted forms: --h, --help, -h, help.")
    print("  Run the source-only/read-only variation first when available.")
    return 0


def _print_godmode_help():
    """Keep the legacy helper pointed at the single curated Godmode help page."""
    return print_godmode_command_help("godmode")


_GODMODE_STAGE_LABELS = {
    "source-recon": "Source map",
    "source-security": "Built-in security review",
    "slither-analysis": "Slither analysis",
    "ai-review": "AI-assisted source review",
    "arithmetic-review": "Targeted arithmetic check",
    "cheat-fingerprints": "Harness cheatcode scan",
    "onchain-recon": "On-chain inspection",
    "attack": "Attack campaign",
    "control": "Matched control",
    "mutation": "Mutation tests",
    "target-coverage": "Source coverage",
}

_GODMODE_STATUS_LABELS = {
    "completed": "DONE",
    "skipped": "SKIPPED",
    "not-run": "NOT REQUESTED",
    "blocked": "BLOCKED",
    "review": "NEEDS REVIEW",
    "provided": "PROVIDED",
    "interrupted": "INTERRUPTED",
}


def _godmode_stage_detail(stage):
    """Turn internal stage fields into a short, explicit operator explanation."""
    name = str(stage.get("name") or "")
    status = str(stage.get("status") or "unknown")
    reason = str(stage.get("reason") or "").strip()

    if name == "source-recon":
        count = int(stage.get("files_scanned") or stage.get("signals") or 0)
        markers = int(stage.get("markers") or 0)
        return f"Indexed {count} first-party source file(s); {markers} source-map markers are navigation/context, not findings."
    if name == "source-security":
        count = int(stage.get("finding_count") or 0)
        return f"{count} unverified access-control candidate(s) from source-level state/guard analysis."
    if name == "slither-analysis":
        count = int(stage.get("finding_count") or 0)
        if status == "skipped":
            return "Not run: " + (reason or "Slither unavailable.")
        return f"{count} Slither detector candidate(s); JSON evidence: {stage.get('evidence', '.audit/slither/latest.json')}." + ((" " + reason) if reason else "")
    if name == "ai-review":
        if status == "not-run":
            return "Not run. Pass --ai-review to send selected source excerpts to the configured AI provider; results remain unverified."
        count = int(stage.get("finding_count") or 0)
        path = str(stage.get("report_path") or "review metadata saved in the evidence ledger")
        summary = str(stage.get("summary") or "").strip()
        return f"{count} AI-assisted candidate(s); unverified. Review evidence: {path}." + ((" " + summary) if summary else "")
    if name == "arithmetic-review":
        count = int(stage.get("signals") or 0)
        wrap = int(stage.get("wraparound_candidates") or 0)
        return f"{count} arithmetic candidate(s); {wrap} possible unsigned-wraparound candidate(s)."
    if name == "cheat-fingerprints":
        hits = int(stage.get("hits") or 0)
        patterns = int(stage.get("patterns") or 0)
        return f"{hits} harness/cheatcode fingerprint match(es) against {patterns} registered patterns; these are not vulnerability findings."
    if name == "onchain-recon" and status == "completed":
        selectors_count = int(stage.get("selectors") or 0)
        chain = stage.get("chain_id")
        block = stage.get("block_number")
        network = f" Chain ID {chain}; block {block}." if chain is not None and block is not None else ""
        return f"Read-only inspection completed; {selectors_count} selector-like value(s) found.{network}"
    if name == "attack":
        if status == "not-run":
            return "Not requested. No attack campaign or attack transactions were run."
        if status == "interrupted":
            return "The local attack process was stopped by the operator; review its last probe and local-chain state before resuming."
        if status in {"review", "completed", "blocked"}:
            raw = str(stage.get("output") or "")
            highlights = []
            for line in raw.splitlines():
                if re.match(r"^\s*(Rounds|Probes|Skipped|Blocked|Observed|Timeouts|Breaks|Report|Conclusion|Error|LOWKEY BREAK)\s*:", line, re.I):
                    highlights.append(line.strip())
            summary = "; ".join(highlights[-4:])
            code = stage.get("exit_code")
            base = f"lk break exited with code {code}." if code is not None else "lk break completed."
            detail = stage.get("reason") or ""
            if status == "blocked" and detail:
                base += " " + str(detail)
            return base + (" " + summary if summary else " Open .audit/break/ for per-probe results.")
    if name == "control":
        if status == "provided":
            return f"Manifest supplied: {stage.get('manifest')}. The attack engine must still report a passing matched control."
        if status == "not-run":
            return "No matched-control manifest was supplied; an attack observation cannot be promoted to a confirmed BREAK."
    if name == "mutation":
        if status == "not-run":
            return "Not requested. No source mutations or test reruns were performed."
        if status in {"completed", "review"}:
            return f"Mutation runner exit code {stage.get('exit_code')}; report: .audit/verification/mutation-score-report.json."
    if name == "target-coverage":
        if status == "not-run":
            return "Not requested. Forge coverage was not run."
        if status in {"completed", "review"}:
            return f"Forge coverage runner exit code {stage.get('exit_code')}; report: .audit/godmode/target-coverage.json."

    if status == "skipped":
        if "--plan-only" in reason:
            return "Disabled by --plan-only; this was intentional."
        if "No address supplied" in reason:
            return "No deployed address was supplied, so chain inspection was not needed."
        return "Skipped: " + (reason or "this stage was not applicable.")
    if status == "not-run":
        return "Not requested. This is not a command failure."
    if status == "blocked":
        return "Could not run: " + (reason or "a required input or dependency was unavailable.")
    if status == "provided":
        return reason or "Input was supplied; see the saved report for details."
    if status == "review":
        return "Ran, but needs review. " + (reason or "See the saved evidence for details.")
    return reason or "Completed."


def _print_godmode_result(payload, arithmetic_rows, wraparound_rows, report_path, provenance_path, root):
    """Print a beginner-readable summary while preserving full JSON evidence."""
    target = payload.get("target")
    chain_id = payload.get("chain_id")
    block_number = payload.get("fork_block")
    print("LOWKEY GODMODE — RUN SUMMARY")
    print("=" * 72)
    print("Project : " + str(root))
    print("Target  : " + (target if target else "source-only (no deployed address supplied)"))
    if chain_id is not None:
        print("Chain   : " + str(chain_id))
    if block_number is not None:
        print("Block   : " + str(block_number))
    print()
    print("AUDIT STATE: REVIEW REQUIRED")
    print("  This run did not confirm a vulnerability. Static matches are leads;")
    print("  proof stages must be completed before Lowkey can claim a verified BREAK.")
    print()
    print("STAGE RESULTS")
    print("-" * 72)
    for stage in payload.get("stages") or []:
        name = str(stage.get("name") or "unknown")
        label = _GODMODE_STAGE_LABELS.get(name, name)
        status = _GODMODE_STATUS_LABELS.get(str(stage.get("status") or ""), "UNKNOWN")
        detail = _godmode_stage_detail(stage)
        print(f"  {label:<22} [{status:<13}] {detail}")

    static_findings = payload.get("findings") if isinstance(payload.get("findings"), list) else []
    print()
    print("STATIC ANALYSIS CANDIDATES — UNVERIFIED")
    print("-" * 72)
    if static_findings:
        for index, finding in enumerate(static_findings[:15], 1):
            location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
            where = str(location.get("path") or finding.get("file") or "source location unavailable")
            line = location.get("line") or finding.get("line")
            if line:
                where += ":" + str(line)
            symbol = str(location.get("symbol") or finding.get("function") or "")
            if symbol:
                where += " (" + symbol + ")"
            print(f"  {index}. [{str(finding.get('severity') or 'review').upper()}] {finding.get('title', 'Untitled candidate')} — {where}")
            quote = str(finding.get("evidence_quote") or "").strip()
            if quote:
                print("     " + " ".join(quote.split())[:220])
        if len(static_findings) > 15:
            print(f"  ... {len(static_findings) - 15} additional candidate(s) in the JSON report.")
        print("  These are static leads, not confirmed vulnerabilities; prove reachability and impact.")
    else:
        print("  No candidate was emitted by the built-in rule or Slither pass. This is not proof of safety.")

    if arithmetic_rows:
        print()
        print("TARGETED ARITHMETIC IDIOM CHECK — NOT A GENERAL VULNERABILITY SCAN")
        print("-" * 72)
        for index, row in enumerate(arithmetic_rows[:20], 1):
            location = f"{row.get('file')}:{row.get('line')}"
            function = f" in {row.get('function')}()" if row.get("function") else ""
            print(f"  {index}. {row.get('status', 'REVIEW')} — {location}{function}")
            print("     " + str(row.get("expression") or "(source expression unavailable)"))
        if len(arithmetic_rows) > 20:
            print(f"  ... and {len(arithmetic_rows) - 20} more candidate(s) in the JSON report.")
        if wraparound_rows:
            print("  Next check: verify compiler semantics and reachability, then write a focused Foundry test.")
    else:
        print()
        print("TARGETED ARITHMETIC IDIOM CHECK")
        print("  No subtraction-before-zero-guard idiom was detected. Other vulnerability classes are analyzed separately.")

    print()
    print("SAVED EVIDENCE")
    print("-" * 72)
    print("  Detailed JSON : " + str(report_path.relative_to(root)))
    print("  Provenance    : " + str(provenance_path.relative_to(root)))
    print("  Readable view : run lk report --root . to create .audit/godmode/report.md.")
    print()
    print("NEXT STEP")
    if arithmetic_rows:
        print("  Inspect the source lines listed above and test whether the condition is reachable.")
    else:
        print("  Review the source maps in the JSON report and select a concrete function/property to test.")
    if not target:
        print("  For chain details, run lk targets, copy an address marked LIVE, then use --rpc-url.")
    print("  Keep --attack for a disposable local Anvil lab; do not point it at production.")

def _is_lowkey_checkout(path):
    """Return True when path is Lowkey's own source checkout, not an audit target."""
    path = Path(path).expanduser().resolve()
    return (
        (path / "lowkey" / "lk.py").is_file()
        and (path / "lowkey" / "project_detection.py").is_file()
        and (path / "install.sh").is_file()
    )


def _is_godmode_project(path):
    """Accept recognizable project roots while explicitly rejecting Lowkey itself."""
    path = Path(path).expanduser().resolve()
    if not path.is_dir() or _is_lowkey_checkout(path):
        return False
    markers = (
        "foundry.toml", "hardhat.config.js", "hardhat.config.cjs",
        "hardhat.config.mjs", "hardhat.config.ts", "Scarb.toml",
        "Anchor.toml", "Move.toml", "ape-config.yaml", "ape-config.yml",
        "brownie-config.yaml", "brownie-config.yml", "Cargo.toml",
    )
    if any((path / marker).is_file() for marker in markers):
        return True
    for dirname in ("src", "contracts", "programs"):
        folder = path / dirname
        if folder.is_dir():
            try:
                if any(item.is_file() and item.suffix.lower() in EXTS for item in folder.rglob("*")):
                    return True
            except OSError:
                pass
    return False


def _preferred_godmode_project_root(config_path=None):
    """Resolve the current target owner or last explicit audit project, if still valid."""
    path = Path(config_path).expanduser() if config_path else Path(os.path.expanduser("~/.lowkey/config.json"))
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(config, dict):
        return None
    target = str(config.get("target") or "")
    owners = config.get("target_owners") if isinstance(config.get("target_owners"), dict) else {}
    roots = config.get("project_roots") if isinstance(config.get("project_roots"), dict) else {}
    for value in (
        owners.get(target) if target else None,
        config.get("audit_project"),
        config.get("last_tx_project_root"),
        roots.get(target) if target else None,
    ):
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            candidate = Path(value).expanduser().resolve()
        except OSError:
            continue
        if _is_godmode_project(candidate):
            return candidate
    return None


def _saved_godmode_project_roots(config_path=None):
    """Return validated remembered project roots when there is no single active project."""
    path = Path(config_path).expanduser() if config_path else Path(os.path.expanduser("~/.lowkey/config.json"))
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if not isinstance(config, dict):
        return []
    owners = config.get("target_owners") if isinstance(config.get("target_owners"), dict) else {}
    roots = config.get("project_roots") if isinstance(config.get("project_roots"), dict) else {}
    values = list(owners.values()) + list(roots.values())
    unique = []
    seen = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        try:
            candidate = Path(value).expanduser().resolve()
        except OSError:
            continue
        key = str(candidate)
        if key in seen or not _is_godmode_project(candidate):
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _select_godmode_project(candidates):
    """Choose one discovered project, prompting only when there is real ambiguity."""
    candidates = list(dict.fromkeys(Path(item).expanduser().resolve() for item in candidates))
    if not candidates:
        raise ValueError("No remembered project was available.")
    if len(candidates) == 1:
        selected = candidates[0]
        print("INFO  Automatically selected audit project: " + str(selected))
        return selected
    print("LOWKEY FOUND MULTIPLE POSSIBLE AUDIT PROJECTS")
    print("=" * 72)
    for index, candidate in enumerate(candidates, 1):
        print(f"  {index}. {candidate}")
    if not sys.stdin.isatty():
        raise ValueError(
            "More than one project could be audited. Run lk godmode from inside the project "
            "you want, or pass --root only when you need to override automatic detection."
        )
    while True:
        try:
            answer = input(f"Which project should Godmode audit? [1-{len(candidates)}] or q: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            raise ValueError("Project selection cancelled.")
        if answer == "q":
            raise ValueError("Project selection cancelled.")
        if answer.isdigit() and 1 <= int(answer) <= len(candidates):
            selected = candidates[int(answer) - 1]
            print("INFO  Selected audit project: " + str(selected))
            return selected
        print(f"Enter a number from 1 to {len(candidates)}, or q to cancel.")


def resolve_godmode_root(explicit_root=None, *, cwd=None, config_path=None):
    """Resolve audit scope automatically; --root is an override, not a requirement."""
    if explicit_root:
        return root_path(explicit_root)

    current = Path(cwd or Path.cwd()).expanduser().resolve()
    if current.is_file():
        current = current.parent
    lowkey_checkout = next((parent for parent in (current, *current.parents) if _is_lowkey_checkout(parent)), None)

    if not lowkey_checkout:
        # Check workspace membership before accepting the aggregate root. A
        # Cargo/npm workspace can itself have a manifest but is not necessarily
        # the project whose contracts should be audited.
        try:
            from project_detection import workspace_context
            scope = workspace_context(current)
            active = scope.get("active")
            inside = scope.get("current")
            if active and _is_godmode_project(active):
                return Path(active).resolve()
            if inside and _is_godmode_project(inside):
                return Path(inside).resolve()
            projects = [
                Path(item["root"]).resolve()
                for item in (scope.get("projects") or [])
                if isinstance(item, dict) and item.get("root") and _is_godmode_project(item["root"])
            ]
            if len(projects) == 1:
                return projects[0]
            if len(projects) > 1:
                return _select_godmode_project(projects)
        except (ImportError, OSError, ValueError, TypeError):
            pass

        try:
            from project_detection import project_root as detected_project_root
            detected = Path(detected_project_root(current)).expanduser().resolve()
        except Exception:
            detected = current
        if _is_godmode_project(detected):
            return detected

    preferred = _preferred_godmode_project_root(config_path)
    if preferred:
        print("INFO  Resuming the project associated with Lowkey's current target/audit context: " + str(preferred))
        return preferred

    remembered = _saved_godmode_project_roots(config_path)
    if remembered:
        return _select_godmode_project(remembered)

    if lowkey_checkout:
        raise ValueError(
            "You're running inside Lowkey's own source repository, not a contract project. "
            "Lowkey could not find a previously selected audit project. Open a terminal in "
            "your Solidity project's folder and run lk godmode; Lowkey will detect the "
            "project automatically. You only need --root when intentionally auditing a different folder."
        )
    raise ValueError(
        f"Lowkey could not identify a contract/source project from {current}. "
        "Move into the project folder and run lk godmode, or use --root only to override detection."
    )


def _load_godmode_project_context(root, config_path=None, *, explicit_target=None):
    """Resolve project target/RPC/actor through Lowkey's shared context service.

    Project-local audit state is authoritative. Legacy global target/RPC values
    are accepted only when target_owners proves that the target belongs to this
    exact project. Environment RPC selection is left to the normal precedence
    helper so source-only project context stays independent of process env.
    """
    root = Path(root).expanduser().resolve()
    path = root / ".audit" / "context.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}

    # Use the shared identity check rather than reimplementing path ownership.
    project_state = shared_context.project_state_for_root(root, data)
    has_owned_project_state = bool(data) and bool(project_state)
    config_file = (
        Path(config_path).expanduser()
        if config_path is not None
        else Path(os.path.expanduser("~/.lowkey/config.json"))
    )
    try:
        legacy = json.loads(config_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        legacy = {}
    if not isinstance(legacy, dict):
        legacy = {}

    resolved = shared_context.resolve_runtime_context(
        root,
        project_state,
        legacy,
        validated_target=project_state.get("target"),
        explicit_target=explicit_target,
        allow_legacy_target=True,
        environ={},
    )

    # Preserve the rest of the project audit metadata for Godmode's report,
    # while replacing context-bearing fields with the canonical resolution.
    # A default global wallet profile alone is not project-owned context.
    if not has_owned_project_state and not resolved.get("target") and not resolved.get("rpc"):
        return {}
    context = dict(project_state)
    context.update({
        "project": resolved.get("project"),
        "target": resolved.get("target"),
        "rpc": resolved.get("rpc"),
        "rpc_source": resolved.get("rpc_source"),
        "actor": resolved.get("actor"),
        "actor_source": resolved.get("actor_source"),
        "legacy_target_owned": resolved.get("legacy_target_owned"),
    })
    return context


def _resolve_godmode_rpc(explicit_rpc=None, project_context=None, environ=None):
    """Use the same RPC precedence rules as every other Lowkey command."""
    context = project_context if isinstance(project_context, dict) else {}
    return shared_context.choose_rpc(
        explicit_rpc,
        project_rpc=context.get("rpc"),
        environ=environ,
    )


def godmode(args):
    if _is_godmode_help_request(args):
        return print_godmode_command_help("godmode")
    p=LowkeyArgumentParser(prog="lk godmode")
    p.add_argument("target", nargs="?", help="Optional deployed contract address override. Omit it to reuse the target remembered for this project, if one exists.")
    p.add_argument("--root", default=None, help="Optional override. Godmode normally detects the current/remembered audit project automatically.")
    p.add_argument("--rpc-url", help="RPC for read-only inspection of target. Use local Anvil if you plan to opt into --attack.")
    p.add_argument("--profile", choices=("light", "balanced", "deep"), default="balanced", help="Proxy/implementation reconnaissance depth: light or deeper balanced/deep lookup.")
    p.add_argument("--attack", action="store_true", help="Opt into lk break exploration. Requires target + local Anvil; may send transactions on that local chain.")
    p.add_argument("--ai-review", action="store_true", help="Opt into semantic source review using the configured AI provider. Selected source excerpts leave this machine; findings remain unverified.")
    p.add_argument("--control-manifest", help="Frozen paired-control manifest used by the attack/proof workflow.")
    p.add_argument("--mutation-manifest", help="Mutation-test manifest to execute as an optional test-sensitivity check.")
    p.add_argument("--coverage-source", help="Solidity source file whose target lines should be checked with Forge coverage.")
    p.add_argument("--plan-only", action="store_true", help="Static source scan only: skip RPC, attack, mutation and coverage execution; still save a local report.")
    ns=p.parse_args(args)
    if ns.plan_only and ns.attack:
        p.error("--plan-only cannot be combined with --attack; remove one of the flags.")
    if ns.control_manifest and not ns.attack:
        p.error("--control-manifest is only used by the attack workflow; add --attack or remove --control-manifest.")
    root=resolve_godmode_root(ns.root)
    project_context=_load_godmode_project_context(root, explicit_target=ns.target)
    remembered_target=(project_context.get("target") or {}).get("address") if isinstance(project_context.get("target"),dict) else None
    selected_target=ns.target or remembered_target
    target=addr(selected_target) if selected_target else None
    selected_rpc,rpc_source=_resolve_godmode_rpc(ns.rpc_url, project_context)
    if not ns.target and remembered_target:
        print("INFO  Using the target address remembered for this project: " + str(remembered_target))
    if selected_rpc and target and not ns.plan_only:
        rpc_label = {
            "command-line": "the explicitly supplied",
            "project": "the current project's remembered",
            "environment": "the environment-configured",
        }.get(rpc_source, "the configured")
        print(f"INFO  Using {rpc_label} RPC for read-only inspection.")
    source_inventory = _collect_source_inventory(root, include_tests=True)

    def record_scanner_failure(scanner: str, exc: BaseException) -> None:
        source_inventory["failures"].append({
            "path": ".",
            "phase": scanner,
            "scope": "scanner",
            "error": f"{type(exc).__name__}: {exc}"[:600],
        })

    try:
        maps = source_maps(root, inventory=source_inventory)
    except Exception as exc:
        record_scanner_failure("source-map-analysis", exc)
        maps = {
            "fallback_map": [], "oracle_map": [], "time_map": [],
            "storage_map": [], "token_map": [], "arithmetic_review": [],
            "signature_map": [], "initializer_map": [], "custody_map": [],
            "cross_vm_map": [], "reentrancy_graph": [], "cfg_outline": [],
        }
    try:
        cheat = cheat_fingerprints(root, inventory=source_inventory)
    except Exception as exc:
        record_scanner_failure("cheat-fingerprint-analysis", exc)
        cheat = {"patterns": 0, "hits": [], "meaning": "Analysis incomplete."}
    try:
        source_findings = _source_security_candidates(root, inventory=source_inventory)
    except Exception as exc:
        record_scanner_failure("source-security-analysis", exc)
        source_findings = []
    slither_stage,slither_findings=_run_slither_analysis(root)
    if ns.ai_review:
        ai_stage,ai_findings=_run_ai_security_review(root)
    else:
        ai_stage={"name":"ai-review","status":"not-run","reason":"Not requested. Pass --ai-review to send selected source excerpts to the configured AI provider."}
        ai_findings=[]
    findings=source_findings+slither_findings+ai_findings
    stages=[]
    raw_map_count=sum(len(v) for key,v in maps.items() if isinstance(v,list) and key != "arithmetic_review")
    source_file_count = len(_inventory_paths(source_inventory, include_tests=False))
    coverage_status = _source_inventory_status(source_inventory)
    coverage_report = _source_inventory_report(source_inventory)
    coverage_reason = ""
    if source_inventory["failures"]:
        coverage_reason = (
            f"Source coverage is incomplete: {len(source_inventory['failures'])} file, directory, "
            "or scanner inspection failure(s). See source_inventory.uninspected in the JSON report."
        )
    stages.append({
        "name": "source-recon",
        "status": coverage_status,
        "signals": source_file_count,
        "files_discovered": coverage_report["source_files_discovered"],
        "files_scanned": coverage_report["source_files_inspected"],
        "uninspected_count": coverage_report["uninspected_count"],
        "uninspected": coverage_report["uninspected"],
        "coverage_complete": coverage_report["complete"],
        "reason": coverage_reason,
        "markers": raw_map_count,
    })
    stages.append({
        "name": "source-security",
        "status": coverage_status,
        "finding_count": len(source_findings),
        "files_scanned": len([
            path for path in _inventory_paths(source_inventory, include_tests=False)
            if path.suffix.lower() == ".sol"
        ]),
        "uninspected_count": coverage_report["uninspected_count"],
        "uninspected": coverage_report["uninspected"],
        "coverage_complete": coverage_report["complete"],
        "reason": coverage_reason,
    })
    stages.append(slither_stage)
    stages.append(ai_stage)
    arithmetic_rows=maps.get("arithmetic_review", [])
    wraparound_rows=[row for row in arithmetic_rows if row.get("status")=="WRAPAROUND_POSSIBLE"]
    stages.append({
        "name": "arithmetic-review",
        "status": coverage_status,
        "signals": len(arithmetic_rows),
        "wraparound_candidates": len(wraparound_rows),
        "coverage_complete": coverage_report["complete"],
        "uninspected_count": coverage_report["uninspected_count"],
        "uninspected": coverage_report["uninspected"],
        "reason": coverage_reason,
    })
    stages.append({
        "name": "cheat-fingerprints",
        "status": coverage_status,
        "hits": len(cheat["hits"]),
        "patterns": int(cheat.get("patterns", 0)),
        "coverage_complete": coverage_report["complete"],
        "uninspected_count": coverage_report["uninspected_count"],
        "uninspected": coverage_report["uninspected"],
        "reason": coverage_reason,
    })
    chain=block=None
    onchain={}
    target_has_code=None
    if ns.plan_only:
        stages.append({"name":"onchain-recon","status":"skipped","reason":"--plan-only: RPC access is disabled."})
    elif target and selected_rpc:
        try:
            url=rpc_url(selected_rpc)
            chain=rpc(url,"eth_chainId",[])
            block=rpc(url,"eth_blockNumber",[])
            runtime_code=rpc(url,"eth_getCode",[target,"latest"])
            runtime_hex=str(runtime_code or "").strip().lower()
            runtime_payload=runtime_hex[2:] if runtime_hex.startswith("0x") else runtime_hex
            runtime_bytes=0 if not runtime_payload or int(runtime_payload or "0",16)==0 else (len(runtime_payload)+1)//2
            target_has_code=runtime_bytes>0
            onchain={"runtime_code_bytes":runtime_bytes}
            if not target_has_code:
                stages.append({
                    "name":"onchain-recon",
                    "status":"blocked",
                    "chain_id":chain,
                    "block_number":block,
                    "runtime_code_bytes":0,
                    "reason":"The remembered address has no runtime bytecode on this RPC. This target is stale or was not deployed to the current Anvil instance; redeploy it or select the live address before any attack.",
                })
            else:
                onchain.update({"proxy":proxy(target,url,40 if ns.profile=="light" else 120),"selectors":selectors(target,url)})
                stages.append({"name":"onchain-recon","status":"completed","selectors":onchain["selectors"]["count"],"runtime_code_bytes":runtime_bytes,"chain_id":chain,"block_number":block})
        except Exception as exc:
            stages.append({"name":"onchain-recon","status":"blocked","reason":str(exc)})
    elif target:
        stages.append({"name":"onchain-recon","status":"skipped","reason":"A target is selected, but no project RPC is configured; source review still completed. Set an RPC only when you want chain inspection."})
    else:
        stages.append({"name":"onchain-recon","status":"skipped","reason":"No address supplied; source-only mode."})
    if ns.plan_only:
        stages.append({"name":"attack","status":"skipped","reason":"--plan-only: attack execution is disabled."})
    elif ns.attack:
        if not target:
            stages.append({"name":"attack","status":"blocked","reason":"Target address required."})
        elif not selected_rpc or not local_rpc(rpc_url(selected_rpc)):
            stages.append({"name":"attack","status":"blocked","reason":"Attack requires local Anvil RPC; non-local RPC is rejected."})
        elif target_has_code is not True:
            stages.append({"name":"attack","status":"blocked","reason":"Attack refused because runtime bytecode at the remembered target address was not verified on the selected Anvil chain. Redeploy the target or update the project target first."})
        elif not shutil.which("lk"):
            stages.append({"name":"attack","status":"blocked","reason":"lk command not found."})
        else:
            argv=["lk","break","--system","--until-found"]
            if ns.control_manifest:
                argv += ["--control-manifest",ns.control_manifest]
            print()
            print("LOWKEY GODMODE // LIVE ATTACK MONITOR")
            print("=====================================")
            print("Attack output is streamed as it arrives. --until-found has no fixed runtime limit; press Ctrl+C to stop cleanly.")
            proc=run_live(argv,root,timeout=None,heartbeat_seconds=20)
            attack_status=("completed" if proc.returncode==0 else
                           ("interrupted" if proc.returncode==130 else "blocked"))
            attack_reason="" if proc.returncode in {0,130} else (
                f"lk break exited with code {proc.returncode}; inspect the streamed error and .audit/break evidence."
            )
            stages.append({"name":"attack","status":attack_status,"exit_code":proc.returncode,
                           "reason":attack_reason,"output":proc.stdout[-6000:]})
    else:
        stages.append({"name":"attack","status":"not-run","reason":"No attack was run. Add --attack only for an explicitly reviewed local-Anvil experiment."})
    if ns.plan_only:
        stages.append({"name":"control","status":"skipped","reason":"--plan-only: no attack/control execution."})
    elif ns.control_manifest:
        stages.append({"name":"control","status":"provided","manifest":ns.control_manifest})
    else:
        stages.append({"name":"control","status":"not-run","reason":"No sequential-control manifest; BREAK remains ineligible."})
    if ns.plan_only:
        stages.append({"name":"mutation","status":"skipped","reason":"--plan-only: mutation tests were not executed."})
    elif ns.mutation_manifest:
        old=Path.cwd()
        try:
            os.chdir(root)
            rc=mutation([ns.mutation_manifest])
        finally:
            os.chdir(old)
        stages.append({"name":"mutation","status":"completed" if rc==0 else "review","exit_code":rc})
    else:
        stages.append({"name":"mutation","status":"not-run","reason":"No mutation manifest was supplied."})
    if ns.plan_only:
        stages.append({"name":"target-coverage","status":"skipped","reason":"--plan-only: Forge coverage was not executed."})
    elif ns.coverage_source:
        old=Path.cwd()
        try:
            os.chdir(root)
            rc=coverage([ns.coverage_source,"--root",str(root)])
        finally:
            os.chdir(old)
        stages.append({"name":"target-coverage","status":"completed" if rc==0 else "review","exit_code":rc})
    else:
        stages.append({"name":"target-coverage","status":"not-run","reason":"No target source line scope was supplied."})
    requested_stages = set()
    if ns.ai_review:
        requested_stages.add("ai-review")
    if target and selected_rpc and not ns.plan_only:
        requested_stages.add("onchain-recon")
    if ns.attack:
        requested_stages.add("attack")
    if ns.mutation_manifest and not ns.plan_only:
        requested_stages.add("mutation")
    if ns.coverage_source and not ns.plan_only:
        requested_stages.add("target-coverage")

    mandatory_stages = {
        "source-recon", "source-security", "arithmetic-review", "cheat-fingerprints"
    }
    blockers = [
        stage for stage in stages
        if stage.get("name") in (mandatory_stages | requested_stages)
        and stage.get("status") in {"blocked", "failed", "review"}
    ]
    payload={"created_at":now(),"target":target,"project_root":str(root),"git_revision":None,"chain_id":chain,"fork_block":block,
             "profile":ns.profile,"stages":stages,"signals":maps,"cheat_fingerprints":cheat,
             "findings":findings,"source_security_findings":source_findings,"slither_findings":slither_findings,"ai_findings":ai_findings,
             "source_inventory": coverage_report,
             "onchain":onchain,"overall_status":"REVIEW_REQUIRED",
             "proof_gate":["attack must demonstrate a measurable security-property delta","matched sequential control must pass",
               "target lines must be covered","harness mutation score must meet threshold","net profit must remain positive after costs",
               "reproof must not depend on state-fabricating cheatcodes"]}
    out=safe_out(root,".audit/godmode/latest.json")
    write_json(out,payload)
    prov=safe_out(root,".audit/godmode/provenance.json")
    write_json(prov,{"created_at":now(),"sha256":hashlib.sha256(out.read_bytes()).hexdigest(),"chain_id":chain,"fork_block":block,"artifacts":["latest.json"]})
    _print_godmode_result(payload, arithmetic_rows, wraparound_rows, out, prov, root)
    if source_inventory["failures"]:
        print("\nSOURCE COVERAGE INCOMPLETE")
        print("=========================")
        print(coverage_reason)
        for failure in source_inventory["failures"]:
            print(
                f"  {failure.get('path')} [{failure.get('phase')}]: "
                f"{failure.get('error')}"
            )
    if any(stage.get("name") == "attack" and stage.get("status") == "interrupted" for stage in stages):
        return 130
    # Not-requested control, mutation and coverage stages keep the audit
    # REVIEW_REQUIRED, but they are not process failures. Return non-zero only
    # when a requested operation was blocked or failed.
    return 2 if blockers else 0
def _report_clean(value, fallback="Not recorded", limit=None):
    if value is None:
        return fallback
    text = " ".join(str(value).replace("\x00", "").split()).strip()
    if not text:
        return fallback
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return text


def _report_code(value):
    marker = chr(96)
    raw = str(value or "").replace(marker, "'").strip()
    return marker + raw + marker if raw else "Not recorded"


def _report_cell(value, fallback="Not recorded", limit=None):
    return _report_clean(value, fallback, limit).replace("|", chr(92) + "|")


def _report_source_ref(path, line_no, root, report_path):
    raw = str(path or "").strip()
    if not raw:
        return "Source location not recorded"
    source_path = Path(raw).expanduser()
    if not source_path.is_absolute():
        source_path = root / source_path
    try:
        source_path = source_path.resolve()
        if not source_path.is_relative_to(root):
            return _report_code(raw)
        destination = Path(os.path.relpath(source_path, report_path.parent)).as_posix()
        destination = destination.replace(" ", "%20")
        if line_no:
            destination += "#L" + str(line_no)
        label = raw + (":" + str(line_no) if line_no else "")
        return f"[{_report_code(label)}]({destination})"
    except (OSError, ValueError):
        return _report_code(raw + (":" + str(line_no) if line_no else ""))


def _report_quote(lines, label, value):
    quote = str(value or "").strip()
    if not quote:
        return
    lines.extend(["**" + label + "**", ""])
    for part in quote.splitlines():
        clean = part.rstrip()
        lines.append("> " + clean if clean else ">")
    lines.append("")


def _report_stage_status(stage):
    status = str(stage.get("status") or "unknown").lower()
    names = {
        "completed": "Completed",
        "passed": "Passed",
        "review": "Needs review",
        "blocked": "Blocked",
        "failed": "Failed",
        "skipped": "Skipped",
        "not-run": "Not requested",
        "provided": "Input supplied",
        "interrupted": "Interrupted",
    }
    return names.get(status, status.replace("-", " ").title())


def _report_latest_attack_evidence(root, attack_stage, target):
    """Load the exact campaign/break evidence path saved by the attack output."""
    output_text = str((attack_stage or {}).get("output") or "")
    paths = []
    for line in output_text.splitlines():
        match = re.search(r"(?:Report|Evidence)\s*:\s*(\S+\.json)", line, re.I)
        if match:
            raw_path = Path(match.group(1)).expanduser()
            candidate = raw_path if raw_path.is_absolute() else root / raw_path
            try:
                candidate = candidate.resolve()
                if candidate.is_relative_to(root) and candidate.is_file():
                    paths.append(candidate)
            except OSError:
                continue

    seen = set()
    for candidate in reversed(paths):
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and isinstance(payload.get("results"), list):
            return candidate, payload

    # A concrete BREAK exits before the campaign summary is written. Only
    # search for a prior break record when this run's own output says a break
    # condition was reached; do not attach an unrelated older record.
    attack_status = str((attack_stage or {}).get("status") or "").lower()
    if attack_status not in {"completed", "review", "interrupted", "blocked"}:
        return None, None
    if not re.search(r"BREAK CONDITION REACHED", output_text, re.I):
        return None, None
    run_root = root / ".audit" / "break" / "runs"
    if run_root.is_dir():
        break_files = sorted(
            run_root.glob("*_break_*.json"),
            key=lambda item: item.stat().st_mtime if item.exists() else 0,
            reverse=True,
        )
        for candidate in break_files:
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict) or not payload.get("family"):
                continue
            recorded_target = str(payload.get("address") or "").lower()
            if target and recorded_target and recorded_target != str(target).lower():
                continue
            return candidate, {
                "mode": "break-found",
                "rounds": None,
                "results": [payload],
            }
    return None, None


def report(args):
    parser = LowkeyArgumentParser(prog="lk report")
    parser.add_argument("--root", default=".")
    parser.add_argument("--input", default=".audit/godmode/latest.json")
    parser.add_argument("--output", default=".audit/godmode/report.md")
    ns = parser.parse_args(args)

    root = root_path(ns.root)
    src = (root / ns.input).resolve()
    if not src.is_relative_to(root) or not src.is_file():
        raise ValueError("Report input not found inside project.")
    out = safe_out(root, ns.output)
    data = json.loads(src.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Report input must contain a JSON object.")

    stages = data.get("stages") if isinstance(data.get("stages"), list) else []
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    signals = data.get("signals") if isinstance(data.get("signals"), dict) else {}
    confirmed = [
        item for item in findings
        if isinstance(item, dict)
        and (
            item.get("verified") is True
            or str(item.get("status") or "").lower() in {"confirmed", "validated"}
        )
    ]
    candidates = [item for item in findings if isinstance(item, dict) and item not in confirmed]
    stage_by_name = {
        str(item.get("name") or ""): item
        for item in stages if isinstance(item, dict)
    }
    source_stage = stage_by_name.get("source-recon", {})
    attack_stage = stage_by_name.get("attack", {})
    slither_stage = stage_by_name.get("slither-analysis", {})
    ai_stage = stage_by_name.get("ai-review", {})
    total_markers = sum(
        len(rows) for rows in signals.values() if isinstance(rows, list)
    )
    overall = _report_clean(data.get("overall_status"), "REVIEW_REQUIRED")
    target = _report_clean(data.get("target"), "Source workspace")
    chain = _report_clean(data.get("chain_id"), "Not inspected")
    block = _report_clean(data.get("fork_block"), "Not inspected")

    lines = [
        "# Smart-contract security review",
        "",
        f"> **Assessment:** {overall.replace('_', ' ').title()}  ",
        f"> **Target:** {target}  ",
        f"> **Project:** {_report_code(data.get('project_root') or str(root))}  ",
        f"> **Generated:** {_report_clean(data.get('created_at'), now())}",
        "",
        "## 1. Executive summary",
        "",
    ]
    if confirmed:
        lines.append(
            f"Lowkey recorded **{len(confirmed)} confirmed/validated item(s)** and "
            f"**{len(candidates)} unverified candidate(s)** in this run. "
            "Review each item’s evidence and validation basis before relying on it."
        )
    elif candidates:
        lines.append(
            f"Lowkey recorded **{len(candidates)} unverified candidate(s)**. "
            "No candidate in this report is a confirmed vulnerability. Static analysis "
            "identifies suspicious code; an executable exploit and independent proof are "
            "needed before claiming impact."
        )
    else:
        lines.append(
            "This run did not record a concrete vulnerability candidate. That is not a "
            "security clearance: scanners have coverage limits, and untested paths may "
            "still contain vulnerabilities."
        )
    lines.extend([
        "",
        "### Run at a glance",
        "",
        "| Item | Result |",
        "|---|---|",
        f"| First-party source files indexed | {int(source_stage.get('files_scanned') or source_stage.get('signals') or 0)} |",
        f"| Source-navigation markers (not findings) | {total_markers} |",
        f"| Unverified candidates | {len(candidates)} |",
        f"| Confirmed/validated findings | {len(confirmed)} |",
        f"| Slither | {_report_stage_status(slither_stage) if slither_stage else 'Not recorded'} |",
        f"| AI source review | {_report_stage_status(ai_stage) if ai_stage else 'Not requested'} |",
        f"| Attack campaign | {_report_stage_status(attack_stage) if attack_stage else 'Not requested'} |",
        f"| Chain ID / block | {chain} / {block} |",
        "",
    ])

    lines.extend([
        "## 2. What Lowkey ran",
        "",
        "This table separates completed checks from checks that were skipped, blocked, "
        "or never requested. A skipped stage is not a passing test.",
        "",
        "| Audit step | Status | What it means |",
        "|---|---|---|",
    ])
    stage_names = {
        "source-recon": "Source indexing",
        "source-security": "Built-in access-control review",
        "slither-analysis": "Slither static analysis",
        "ai-review": "AI-assisted source review",
        "arithmetic-review": "Targeted arithmetic check",
        "cheat-fingerprints": "Harness/cheatcode fingerprints",
        "onchain-recon": "On-chain inspection",
        "attack": "Local attack campaign",
        "control": "Matched control",
        "mutation": "Mutation testing",
        "target-coverage": "Target source coverage",
    }
    for stage in stages:
        if not isinstance(stage, dict):
            continue
        name = str(stage.get("name") or "Unknown step")
        label = stage_names.get(name, name.replace("-", " ").title())
        status = _report_stage_status(stage)
        try:
            detail = _godmode_stage_detail(stage)
        except Exception:
            detail = str(stage.get("reason") or stage.get("summary") or "")
        lines.append(
            f"| {label} | {status} | {_report_cell(detail, 'No additional detail recorded.')} |"
        )
    lines.append("")

    if attack_stage:
        attack_output = str(attack_stage.get("output") or "")
        observations = []
        seen = set()
        for raw_line in attack_output.splitlines():
            clean = raw_line.strip()
            if not clean:
                continue
            if re.match(r"^\[(?:!!! BREAK !!!|SIMULATED BREAK|BREAK|BLOCKED|OBSERVED|SKIPPED)\]", clean):
                if clean not in seen:
                    seen.add(clean)
                    observations.append(clean)
        if observations:
            lines.extend([
                "### Attack observations",
                "",
                "These are the probe outcomes captured in the run log. **OBSERVED** means "
                "the call was executed and a behaviour was seen; it does not mean the "
                "behaviour is exploitable. **BLOCKED** means the probe did not complete.",
                "",
            ])
            for item in observations[-20:]:
                lines.append("- " + item.replace("|", "\\|"))
            lines.append("")

    campaign_path, campaign_data = _report_latest_attack_evidence(root, attack_stage, target if target.startswith("0x") else None)
    if campaign_data:
        results = campaign_data.get("results") if isinstance(campaign_data.get("results"), list) else []
        lines.extend([
            "### Attack probe results",
            "",
            f"Saved campaign: {_report_source_ref(str(campaign_path), None, root, out)}  ",
            f"Mode: {_report_clean(campaign_data.get('mode'), 'Not recorded')} · Rounds: {_report_clean(campaign_data.get('rounds'), 'Not recorded')}",
            "",
            "Each row is one attempted probe. A blocked probe is an execution gap, not evidence that the path is safe.",
            "",
            "| Function | Probe family | Outcome | What happened |",
            "|---|---|---|---|",
        ])
        for result in results[:30]:
            if not isinstance(result, dict):
                continue
            detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}
            function = result.get("function") or "Target-level probe"
            family = result.get("family") or "unknown"
            outcome = result.get("status") or "unknown"
            explanation = result.get("summary") or detail.get("error") or detail.get("reason_code") or "No explanation was recorded."
            reason_code = detail.get("reason_code")
            if reason_code:
                explanation = str(explanation) + " Reason: " + str(reason_code)
            lines.append(
                f"| {_report_cell(function)} | {_report_cell(family)} | {_report_cell(outcome)} | {_report_cell(explanation, limit=500)} |"
            )
        if len(results) > 30:
            lines.append(f"| … | … | … | {len(results) - 30} more probe result(s) are in the linked JSON evidence. |")
        lines.append("")
        if str(campaign_data.get("mode") or "").lower() == "interrupted":
            lines.append("**Campaign note:** This run was interrupted. Its partial probe results do not support a safety conclusion.")
            lines.append("")
        elif any(isinstance(item, dict) and item.get("break_condition") for item in results):
            lines.append("**Campaign note:** A local break condition was observed. It still needs matched-control, fidelity, and independent reproof before being called confirmed.")
            lines.append("")

    lines.extend(["## 3. Findings to investigate", ""])
    if not findings:
        lines.extend([
            "No source-analysis candidate was recorded in this run.",
            "",
            "This does not mean the contract is safe. Check scanner coverage, compiler "
            "configuration, inherited contracts, external dependencies, and protocol-specific "
            "invariants. A clean static scan is not an exploitability proof.",
            "",
        ])
    else:
        lines.append(
            "The items below are candidates, not automatic vulnerability verdicts. "
            "Severity and confidence are triage labels; verify reachability, attacker "
            "control, and impact against the exact deployed code."
        )
        lines.append("")
        for index, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue
            location = finding.get("location") if isinstance(finding.get("location"), dict) else {}
            path = str(location.get("path") or finding.get("file") or "")
            line_no = location.get("line") or finding.get("line")
            symbol = str(location.get("symbol") or finding.get("function") or "")
            location_parts = []
            if path:
                location_parts.append(_report_source_ref(path, line_no, root, out))
            if symbol:
                location_parts.append(_report_code(symbol))
            location_text = " — ".join(location_parts) if location_parts else "Source location not recorded"
            severity = _report_clean(finding.get("severity"), "Needs human triage").upper()
            confidence = _report_clean(finding.get("confidence"), "Not recorded")
            category = _report_clean(finding.get("category"), "General")
            tool = _report_clean(finding.get("tool") or finding.get("check"), "Not recorded")
            verified = finding.get("verified") is True or str(finding.get("status") or "").lower() in {"confirmed", "validated"}
            state = "Confirmed/validated in saved evidence" if verified else "Candidate — not confirmed"

            lines.extend([
                f"### {index}. {_report_clean(finding.get('title'), 'Untitled candidate')}",
                "",
                f"**Triage:** {severity} · {category} · {confidence} confidence  ",
                f"**Evidence state:** {state}  ",
                f"**Where:** {location_text}  ",
                f"**Detector:** {tool}",
                "",
            ])
            optional_fields = (
                ("Severity rationale", "severity_rubric"),
                ("Fork block", "fork_block"),
                ("Gas used", "gas_used"),
                ("Gross profit", "gross_profit"),
                ("Net profit after costs", "net_profit"),
                ("Control evidence", "control_evidence"),
            )
            for label, key in optional_fields:
                if finding.get(key) is not None and str(finding.get(key)).strip():
                    lines.extend(["**" + label + "**", "", _report_clean(finding.get(key), limit=1800), ""])
            for label, keys in (
                ("Why it was flagged", ("reasoning", "meaning", "description")),
                ("Potential impact", ("impact", "why")),
                ("Attacker prerequisites", ("exploit_preconditions", "prerequisites")),
                ("What to do next", ("recommendation", "next")),
            ):
                value = next((finding.get(key) for key in keys if finding.get(key)), None)
                if value:
                    lines.extend(["**" + label + "**", "", _report_clean(value, limit=3000), ""])
            _report_quote(lines, "Relevant source evidence", finding.get("evidence_quote") or finding.get("source_excerpt"))
            quote_status = finding.get("source_quote_status")
            if quote_status:
                lines.extend([
                    f"**Source quote check:** {_report_clean(quote_status)}",
                    "",
                ])
            if finding.get("evidence_path"):
                lines.extend(["**Evidence file:** " + _report_code(finding.get("evidence_path")), ""])
            if finding.get("harness") or finding.get("harness_archive"):
                harness = finding.get("harness_archive") or finding.get("harness")
                lines.extend(["**Generated test harness:** " + _report_code(harness), ""])
            if finding.get("reproduction_steps"):
                lines.extend(["**Reproduction outline**", ""])
                for step_number, step in enumerate(finding["reproduction_steps"], 1):
                    lines.append(f"{step_number}. {_report_clean(step)}")
                lines.append("")

    lines.extend([
        "## 4. What is still needed before a finding is confirmed",
        "",
        "A source match or a successful function call is not enough. The evidence should "
        "show a security property being violated and rule out the normal/control behaviour.",
        "",
    ])
    proof_explanations = {
        "attack must demonstrate a measurable security-property delta": "Show a concrete change to a security property, such as an unauthorized owner change or excess asset withdrawal.",
        "matched sequential control must pass": "Run a paired control under the same setup and show that the vulnerable behaviour is specific to the attack.",
        "target lines must be covered": "Show that the test actually executes the source lines associated with the candidate.",
        "harness mutation score must meet threshold": "Change or repair the suspected vulnerable logic and demonstrate that the test detects the difference.",
        "net profit must remain positive after costs": "For economic attacks, calculate attacker gain after gas, fees, slippage, and financing costs.",
        "reproof must not depend on state-fabricating cheatcodes": "Reproduce the result without cheatcodes that manufacture the vulnerable state.",
    }
    for item in data.get("proof_gate") or []:
        text_item = str(item)
        lines.append("- " + proof_explanations.get(text_item, _report_clean(text_item)))
    lines.append("")

    marker_rows = []
    for group, rows in signals.items():
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            marker_rows.append((str(group), row))
    if marker_rows:
        lines.extend([
            "## 5. Source-navigation markers (not findings)",
            "",
            f"The scanners also recorded {total_markers} navigation/context marker(s). "
            "They are included only to help locate code for manual review; they are not "
            "vulnerability counts.",
            "",
            "| Source location | Marker | Code excerpt |",
            "|---|---|---|",
        ])
        for group, row in marker_rows[:25]:
            where = str(row.get("file") or "unknown")
            if row.get("line"):
                where += ":" + str(row.get("line"))
            marker = row.get("kind") or row.get("function") or group
            excerpt = _report_clean(row.get("text") or row.get("variables"), "No excerpt", limit=180)
            lines.append(
                f"| {_report_code(where)} | {_report_cell(marker)} | {_report_cell(excerpt)} |"
            )
        if len(marker_rows) > 25:
            lines.append(f"| … | … | {len(marker_rows) - 25} additional marker(s) omitted; see the JSON evidence. |")
        lines.append("")

    lines.extend([
        "## 6. Evidence files and limitations",
        "",
        f"- Full machine-readable audit data: {_report_code(src.relative_to(root).as_posix())}",
        f"- Provenance record: {_report_code('.audit/godmode/provenance.json')}",
        "- Static analysis can miss bugs and can also produce false positives.",
        "- An unexecuted, blocked, or skipped probe provides no evidence that the tested path is safe.",
        "- Local Anvil results apply to the local deployment/state used for that run; recheck the intended fork or deployment separately.",
        "- This report does not authorize production transactions or certify the contract as secure.",
        "",
        "---",
        "",
        "*Generated by Lowkey. Treat the report as an evidence-backed workpaper, not a security certificate.*",
        "",
    ])

    out.write_text("\n".join(lines), encoding="utf-8")
    digest = sha(out)
    sidecar = out.with_suffix(out.suffix + ".sha256")
    sidecar.write_text(digest + "  " + out.name + "\n", encoding="utf-8")
    print("Report: " + str(out.relative_to(root)))
    print("SHA-256: " + digest)
    print(f"Findings: {len(candidates)} candidate(s), {len(confirmed)} confirmed/validated")
    return 0

def provenance_cli(args): return provenance(args)

def calldata_mine(args):
    p=LowkeyArgumentParser(prog="lk calldata-mine"); p.add_argument("target"); p.add_argument("hash_file"); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    target=addr(ns.target); url=rpc_url(ns.rpc_url); hashes=[]
    for line in Path(ns.hash_file).expanduser().read_text(encoding="utf-8").splitlines():
        value=line.strip()
        if re.fullmatch(r"0x[0-9a-fA-F]{64}",value): hashes.append(value)
    rows=[]; grouped={}
    for tx_hash in dict.fromkeys(hashes):
        tx=rpc(url,"eth_getTransactionByHash",[tx_hash])
        if not tx or str(tx.get("to") or "").lower()!=target: continue
        data=str(tx.get("input") or "0x"); selector=data[:10] if len(data)>=10 else None
        row={"tx_hash":tx_hash,"selector":selector,"calldata_bytes":max(0,(len(data)-2)//2),
             "from":tx.get("from"),"value":tx.get("value"),"block":tx.get("blockNumber")}
        rows.append(row); grouped.setdefault(selector,[]).append(row)
    return output({"target":target,"supplied_hashes":len(hashes),"matched_transactions":len(rows),
                   "deduplicated_selectors":grouped,
                   "limitation":"The supplied transaction list is the discovery boundary; full address history needs an explorer/indexer adapter."})

def gas_ladder(args):
    p=LowkeyArgumentParser(prog="lk gas-ladder"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Gas-ladder manifest must be inside the project.")
    spec=json.loads(mf.read_text()); template=spec.get("argv")
    if not isinstance(template,list) or not all(isinstance(x,str) for x in template): raise ValueError("manifest.argv must be an argv array containing {n}.")
    if not any("{n}" in x for x in template): raise ValueError("At least one argv entry must contain {n}.")
    low=int(spec.get("min",1)); high=int(spec.get("max",10000))
    if low<0 or high<low or high-low>10_000_000: raise ValueError("Invalid search range (0..10,000,000).")
    marker=re.compile(str(spec.get("oom_regex") or r"(?:out of gas|gas required exceeds allowance|\bOOG\b)"),re.I)
    timeout=int(spec.get("timeout_seconds",300)); trials=[]
    # First establish a non-OOG lower baseline and a failing upper bound.
    def measure(n):
        argv=[x.replace("{n}",str(n)) for x in template]; proc=run(argv,root,timeout); text=proc.stdout+"\n"+proc.stderr
        hit=bool(marker.search(text))
        trials.append({"n":n,"exit_code":proc.returncode,"oom":hit,"tail":text[-1200:]})
        return hit
    if low==high:
        first=measure(low)
        threshold=low if first else None
    else:
        high_hit=measure(high)
        if not high_hit: threshold=None
        else:
            lo_hit=measure(low)
            if lo_hit: threshold=low
            else:
                left,right=low,high
                while right-left>1:
                    mid=(left+right)//2
                    if measure(mid): right=mid
                    else: left=mid
                threshold=right
    payload={"first_reported_oom_size":threshold,"trials":trials,
             "meaning":"First size matching the declared OOG marker, only within this harness and environment.",
             "warning":"A revert, failed build, generic nonzero exit or timeout is not automatically counted as out-of-gas."}
    write_json(safe_out(root,".audit/godmode/gas-ladder.json"),payload); print(json.dumps(payload,indent=2)); return 0 if threshold is not None else 2

def symbolic_path(args):
    p=LowkeyArgumentParser(prog="lk path"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Path manifest must be inside the project.")
    spec=json.loads(mf.read_text()); argv=spec.get("argv")
    if not isinstance(argv,list) or not argv or not all(isinstance(x,str) for x in argv): raise ValueError("Manifest requires explicit argv, e.g. [\"halmos\", \"--function\", \"check_withdraw\"].")
    if not shutil.which(argv[0]): print("BLOCKED: symbolic engine "+argv[0]+" is not installed."); return 2
    proc=run(argv,root,int(spec.get("timeout_seconds",600))); print(proc.stdout,end="")
    if proc.stderr: print(proc.stderr,file=sys.stderr,end="")
    print("Symbolic execution is path-planning evidence, not an exploit proof.")
    return proc.returncode

def watch(args):
    p=LowkeyArgumentParser(prog="lk watch"); p.add_argument("target"); p.add_argument("--rpc-url"); p.add_argument("--count",type=int,default=1); p.add_argument("--interval",type=float,default=3); ns=p.parse_args(args)
    target=addr(ns.target); url=rpc_url(ns.rpc_url)
    if not 1<=ns.count<=100 or not 0<=ns.interval<=60: raise ValueError("Bounded watch accepts count 1..100 and interval 0..60 seconds.")
    checks=[]; previous=None
    for i in range(ns.count):
        code=rpc(url,"eth_getCode",[target,"latest"]); block=rpc(url,"eth_blockNumber",[])
        digest=hashlib.sha256(bytes.fromhex(code[2:])).hexdigest() if code and code!="0x" else None
        checks.append({"block":block,"code_hash":digest,"has_code":bool(digest),"changed":i>0 and digest!=previous})
        previous=digest
        if i+1<ns.count: time.sleep(ns.interval)
    payload={"target":target,"checks":checks,"mode":"bounded-one-shot",
             "note":"Runtime bytecode only. No persistent daemon, TVL feed, deployment indexer or automatic TVL-risk estimate is configured."}
    print(json.dumps(payload,indent=2)); return 0

def upgrade_diff(args):
    p=LowkeyArgumentParser(prog="lk upgrade-diff"); p.add_argument("old_address"); p.add_argument("new_address"); p.add_argument("--rpc-url"); p.add_argument("--old-layout"); p.add_argument("--new-layout"); ns=p.parse_args(args)
    url=rpc_url(ns.rpc_url); old=addr(ns.old_address); new=addr(ns.new_address)
    a=rpc(url,"eth_getCode",[old,"latest"]); b=rpc(url,"eth_getCode",[new,"latest"])
    old_selectors=set(push4(a or "0x")); new_selectors=set(push4(b or "0x")); layout={"status":"not-supplied"}
    if ns.old_layout and ns.new_layout:
        before=json.loads(Path(ns.old_layout).expanduser().read_text()); after=json.loads(Path(ns.new_layout).expanduser().read_text())
        aa=before.get("storageLayout",before).get("storage",[]); bb=after.get("storageLayout",after).get("storage",[])
        am={(str(x.get("slot")),str(x.get("offset"))):x for x in aa}; bm={(str(x.get("slot")),str(x.get("offset"))):x for x in bb}
        layout={"removed":[v for k,v in am.items() if k not in bm],
                "changed":[v for k,v in am.items() if k in bm and (v.get("type")!=bm[k].get("type") or v.get("label")!=bm[k].get("label"))],
                "added":[v for k,v in bm.items() if k not in am],"status":"compare"}
    return output({"old":old,"new":new,"old_code_hash":hashlib.sha256(bytes.fromhex(a[2:])).hexdigest(),
                   "new_code_hash":hashlib.sha256(bytes.fromhex(b[2:])).hexdigest(),
                   "added_selectors":sorted(new_selectors-old_selectors),"removed_selectors":sorted(old_selectors-new_selectors),
                   "storage_layout":layout,"warning":"PUSH4 extraction is a candidate selector set and can include constants. Use compiler storage layout before judging compatibility."})

def verify_hack(args):
    p=LowkeyArgumentParser(prog="lk verify-hack"); p.add_argument("tx_hash"); p.add_argument("--rpc-url",required=True); p.add_argument("--block",type=int,required=True); ns=p.parse_args(args)
    if not re.fullmatch(r"0x[0-9a-fA-F]{64}",ns.tx_hash) or ns.block<1: raise ValueError("Supply a transaction hash and positive attacked block.")
    tx=rpc(rpc_url(ns.rpc_url),"eth_getTransactionByHash",[ns.tx_hash])
    if not tx: raise RuntimeError("Transaction not found on this RPC.")
    actual=int(str(tx.get("blockNumber") or "0x0"),16)
    if actual!=ns.block: raise ValueError(f"Transaction is in block {actual}, not declared block {ns.block}.")
    print(json.dumps({"tx_hash":ns.tx_hash,"attacked_block":ns.block,"required_fork_block":ns.block-1,
                   "from":tx.get("from"),"to":tx.get("to"),"input":tx.get("input"),"value":tx.get("value"),
                   "status":"replay-harness-required",
                   "next":"Fork at block N-1, replay the exact attacker sequence, and compare recipient/target balances. This lookup does not reproduce the hack."}, indent=2))
    return 2

def compose(args):
    p=LowkeyArgumentParser(prog="lk compose"); p.add_argument("--root",default="."); ns=p.parse_args(args); root=root_path(ns.root); m=source_maps(root)
    nodes=[{"id":"attacker","kind":"actor"},{"id":"asset","kind":"asset-impact","status":"not-measured"}]; edges=[]
    signals=[("reentrancy",m["reentrancy_graph"]),("oracle",m["oracle_map"]),("signature",m["signature_map"]),("custody",m["custody_map"]),("initializer",m["initializer_map"])]
    index=0
    for kind,rows in signals:
        for row in rows:
            ident=kind+"-"+str(index); index+=1
            nodes.append({"id":ident,"kind":kind,"source":row})
            edges.append({"from":"attacker","to":ident,"relationship":"candidate reachability"})
            edges.append({"from":ident,"to":"asset","relationship":"impact must be measured"})
    payload={"nodes":nodes,"edges":edges,"candidate_signal_count":index,
             "profitability":"not-computed","warning":"No path is profitable until an executable adapter measures asset gain after gas, fees and slippage."}
    write_json(safe_out(root,".audit/godmode/compose.json"),payload); return output(payload)

def skew_plan(args):
    p=LowkeyArgumentParser(prog="lk skew"); p.add_argument("manifest"); p.add_argument("--root",default="."); ns=p.parse_args(args)
    root=root_path(ns.root); mf=(root/ns.manifest).resolve()
    if not mf.is_relative_to(root) or not mf.is_file(): raise ValueError("Skew manifest must be inside the project.")
    spec=json.loads(mf.read_text()); required=("pool","asset","oracle_read","consumer_call","amounts")
    missing=[x for x in required if x not in spec]
    if missing: raise ValueError("Missing skew manifest fields: "+", ".join(missing))
    plan={"manifest_hash":sha(mf),"pool":spec["pool"],"asset":spec["asset"],"oracle_read":spec["oracle_read"],
          "consumer_call":spec["consumer_call"],"amounts":spec["amounts"],
          "required_assertions":["oracle deviation at the point of consumption","downstream debt/mint/withdraw impact",
            "attacker recipient delta","pool unwind and residual loss","gas, pool fee and slippage deducted"],
          "status":"adapter-and-harness-required"}
    write_json(safe_out(root,".audit/godmode/skew-plan.json"),plan); return output(plan)

def flashmax(args):
    p=LowkeyArgumentParser(prog="lk flashmax"); p.add_argument("venue",choices=("aave","balancer","uniswap-v3")); p.add_argument("asset"); p.add_argument("--adapter",required=True); p.add_argument("--rpc-url"); ns=p.parse_args(args)
    asset=addr(ns.asset); spec=json.loads(Path(ns.adapter).expanduser().read_text())
    if str(spec.get("venue","")).lower()!=ns.venue or str(spec.get("asset","")).lower()!=asset: raise ValueError("Adapter venue/asset must match command.")
    pool=addr(str(spec.get("pool") or "")); calldata=str(spec.get("liquidity_call") or "")
    if not re.fullmatch(r"0x[0-9a-fA-F]*",calldata): raise ValueError("Adapter liquidity_call must be explicit 0x calldata.")
    raw=rpc(rpc_url(ns.rpc_url),"eth_call",[{"to":pool,"data":calldata},"latest"])
    liquidity=int(raw,16) if raw and raw!="0x" else 0
    callback={"aave":"executeOperation","balancer":"receiveFlashLoan","uniswap-v3":"uniswapV3FlashCallback"}[ns.venue]
    return output({"venue":ns.venue,"asset":asset,"pool":pool,"liquidity_raw":liquidity,
                   "fee_bps":spec.get("fee_bps"),"max_borrow_raw":liquidity,
                   "callback":callback,"status":"liquidity-read-only",
                   "warning":"Adapter must encode the right reserve/liquidity read and fee. This does not borrow, deploy a callback, or prove a profitable attack."})

def agent_split(args):
    p=LowkeyArgumentParser(prog="lk agent-split"); p.add_argument("--root",default="."); p.add_argument("--harness"); ns=p.parse_args(args)
    root=root_path(ns.root); m=source_maps(root); cheat=[]
    if ns.harness:
        h=(root/ns.harness).resolve()
        if not h.is_relative_to(root) or not h.is_file(): raise ValueError("Harness must be inside project.")
        rx=re.compile(r"\bvm\.(?:deal|store|etch|mockCall|warp|roll)\s*\(")
        cheat=[{"line":i,"text":line.strip()} for i,line in enumerate(h.read_text(errors="replace").splitlines(),1) if rx.search(line)]
    payload={"planner":{"candidate_reentrancy_paths":len(m["reentrancy_graph"]),"candidate_oracle_reads":len(m["oracle_map"])},
             "attacker":{"families_with_signals":[k for k,v in (("reentrancy",m["reentrancy_graph"]),("oracle",m["oracle_map"]),("signature",m["signature_map"])) if v]},
             "verifier":{"required":["measured attack delta","sequential control","target-line coverage","mutation score","positive net economics","cheatcode-free reproof"],"status":"not-run"},
             "critic":{"harness_cheatcode_hits":cheat,"warnings":["Check actor authority and impersonation.","Check vm.deal/storage writes do not create the claimed exploit state.","Check control executes the same sequential calls."]}}
    write_json(safe_out(root,".audit/godmode/agent-split.json"),payload); return output(payload)

def bundle_simulate(args):
    p=LowkeyArgumentParser(prog="lk bundle"); p.add_argument("--tx",action="append",required=True); p.add_argument("--target-block",type=int,required=True); p.add_argument("--relay-url",required=True); p.add_argument("--auth-signature",required=True); ns=p.parse_args(args)
    if ns.target_block<1: raise ValueError("Target block must be positive.")
    if not all(re.fullmatch(r"0x[0-9a-fA-F]+",x) for x in ns.tx): raise ValueError("Provide raw signed transactions as 0x hex.")
    params={"txs":ns.tx,"blockNumber":hex(ns.target_block),"stateBlockNumber":"latest"}
    body=json.dumps({"jsonrpc":"2.0","id":1,"method":"eth_callBundle","params":[params]}).encode()
    req=Request(ns.relay_url,data=body,headers={"Content-Type":"application/json","X-Flashbots-Signature":ns.auth_signature})
    with urlopen(req,timeout=30) as res: result=json.loads(res.read().decode())
    if result.get("error"): raise RuntimeError(str(result["error"]))
    return output({"simulation":result.get("result"),"broadcast":False,"note":"Simulation only; Lowkey does not call eth_sendBundle."})



# P1 deterministic Step[] renderer. ABIValue is intentionally typed as
# {"type": "...", "value": ...}; the original proposal named ABIValue but did
# not define its wire shape. Unsupported callbacks refuse instead of compiling
# a harness that cannot execute the promised behavior.
STEP_FAMILIES = {
    "reentrancy", "replay", "access", "accounting", "boundary", "time",
    "upgrade", "callback", "oracle", "economic", "erc20", "proxy",
    "storage", "signature", "dos",
}
STEP_KINDS = {
    "call", "flash_borrow", "skew", "warp", "roll", "snapshot",
    "revert", "assert", "unwind", "reenter", "read", "expect",
}
STEP_FIELDS = {"kind", "target", "selector", "args", "value", "optional", "expect"}


class StepPlanError(ValueError):
    def __init__(self, detail, reason_code="unsupported_abi", *, target=None, family=None):
        super().__init__(str(detail))
        self.reason_code = reason_code
        self.target = target
        self.family = family


def _step_uint(value, label, *, minimum=0, maximum=(1 << 256) - 1):
    if isinstance(value, bool):
        raise StepPlanError(f"{label} must be an integer, not a boolean.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", value.strip()):
        number = int(value, 16 if value.strip().lower().startswith("0x") else 10)
    else:
        raise StepPlanError(f"{label} must be a decimal or 0x-prefixed integer.")
    if number < minimum or number > maximum:
        raise StepPlanError(f"{label} is outside its supported integer range.")
    return number


def _step_address(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        raise StepPlanError(f"{label} must be a 20-byte 0x-prefixed address.")
    return "address(uint160(0x00" + value.lower()[2:] + "))"


def _step_selector(value, label):
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{8}", value):
        raise StepPlanError(f"{label} must be exactly four bytes (bytes4).")
    return "bytes4(" + value.lower() + ")"


def _step_scalar_expression(abi_type, value, label):
    abi_type = str(abi_type or "").strip()
    if abi_type == "address":
        return _step_address(value, label)
    if abi_type == "bool":
        if not isinstance(value, bool):
            raise StepPlanError(f"{label} of type bool must be JSON true or false.")
        return "true" if value else "false"
    match = re.fullmatch(r"(u?int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", abi_type)
    if match:
        signed, width_text = match.groups()
        width = int(width_text or "256")
        if signed == "uint":
            number = _step_uint(value, label, maximum=(1 << width) - 1)
        else:
            if isinstance(value, bool):
                raise StepPlanError(f"{label} must be a signed integer.")
            if isinstance(value, int):
                number = value
            elif isinstance(value, str) and re.fullmatch(r"-?(?:0x[0-9a-fA-F]+|[0-9]+)", value.strip()):
                raw = value.strip()
                number = -int(raw[3:], 16) if raw.lower().startswith("-0x") else (
                    int(raw, 16) if raw.lower().startswith("0x") else int(raw, 10)
                )
            else:
                raise StepPlanError(f"{label} must be a signed integer.")
            if number < -(1 << (width - 1)) or number > (1 << (width - 1)) - 1:
                raise StepPlanError(f"{label} does not fit {abi_type}.")
        return f"{abi_type}({number})"
    fixed_bytes = re.fullmatch(r"bytes([1-9]|[12][0-9]|3[0-2])", abi_type)
    if fixed_bytes:
        width = int(fixed_bytes.group(1))
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{%d}" % (width * 2), value):
            raise StepPlanError(f"{label} must be exactly {width} bytes.")
        return f"{abi_type}({value.lower()})"
    if abi_type == "bytes":
        if not isinstance(value, str) or not re.fullmatch(r"0x(?:[0-9a-fA-F]{2})*", value):
            raise StepPlanError(f"{label} bytes value must be even-length 0x-prefixed hex.")
        return 'hex"' + value[2:].lower() + '"'
    if abi_type == "string":
        if not isinstance(value, str) or any(ord(char) < 32 for char in value):
            raise StepPlanError(f"{label} string must contain printable characters only.")
        return json.dumps(value, ensure_ascii=True)
    raise StepPlanError(
        f"Unsupported ABI value type '{abi_type}'. Supported scalar types are address, bool, int/uint, bytes1..bytes32, bytes and string."
    )


def _step_abi_argument(abi_value, prefix):
    if not isinstance(abi_value, dict) or set(abi_value) != {"type", "value"}:
        raise StepPlanError("Each ABIValue must be an object with exactly 'type' and 'value'.")
    abi_type = str(abi_value.get("type") or "").strip()
    value = abi_value.get("value")
    array_match = re.fullmatch(r"(.+)\[([0-9]*)\]", abi_type)
    if not array_match:
        return [], _step_scalar_expression(abi_type, value, prefix)
    base_type, fixed_count = array_match.groups()
    if "[" in base_type or "]" in base_type or base_type.startswith("tuple"):
        raise StepPlanError(f"Nested or tuple ABI array '{abi_type}' requires a specialized generator.")
    if base_type in {"bytes", "string"}:
        raise StepPlanError(f"Dynamic bytes/string arrays '{abi_type}' require a specialized generator.")
    if not isinstance(value, list):
        raise StepPlanError(f"{prefix} array value must be a JSON list.")
    count = len(value)
    if fixed_count and count != int(fixed_count):
        raise StepPlanError(f"{abi_type} requires exactly {fixed_count} values; received {count}.")
    if count > 64:
        raise StepPlanError("Generic ABI arrays are capped at 64 elements.")
    if fixed_count:
        declaration = f"{base_type}[{fixed_count}] memory {prefix};"
    else:
        declaration = f"{base_type}[] memory {prefix} = new {base_type}[]({count});"
    lines = [declaration]
    for index, item in enumerate(value):
        lines.append(f"{prefix}[{index}] = {_step_scalar_expression(base_type, item, prefix + '[' + str(index) + ']')};")
    return lines, prefix


def _step_expectation(value, label):
    if value is None:
        return {"count": None, "must_revert": False}
    if not isinstance(value, dict) or set(value) - {"count", "must_revert"}:
        raise StepPlanError(f"{label}.expect must contain only count and must_revert.")
    count = value.get("count")
    if count is not None:
        count = _step_uint(count, label + ".expect.count", minimum=1, maximum=(1 << 64) - 1)
    must_revert = value.get("must_revert", False)
    if not isinstance(must_revert, bool):
        raise StepPlanError(f"{label}.expect.must_revert must be boolean.")
    return {"count": count, "must_revert": must_revert}


def render_step_harness(spec):
    """Validate a Step[] plan and render a compile-ready Foundry harness."""
    if not isinstance(spec, dict) or set(spec) - {"family", "target_address", "steps"}:
        raise StepPlanError("Step plan must contain only family, target_address and steps.")
    family = str(spec.get("family") or "").strip().lower()
    if family not in STEP_FAMILIES:
        raise StepPlanError("family must be one of: " + ", ".join(sorted(STEP_FAMILIES)), "out_of_scope", family=family or None)
    default_target = spec.get("target_address")
    if default_target is not None:
        default_target = _step_address(default_target, "target_address")
    steps_value = spec.get("steps")
    if not isinstance(steps_value, list) or not steps_value or len(steps_value) > 128:
        raise StepPlanError("steps must be a non-empty array with at most 128 entries.", family=family)
    template_path = Path(__file__).resolve().parent / "templates" / "step_harness.sol.tmpl"
    if not template_path.is_file():
        raise StepPlanError("Installed step_harness.sol.tmpl is missing; reinstall Lowkey from the matching branch.", "no_capability", family=family)
    template = template_path.read_text(encoding="utf-8")
    rendered_steps = []
    pending_expectation = None
    saw_call = False

    def call_identity(target_expr, selector_value, args_value, value_wei):
        return (
            target_expr,
            str(selector_value or "").lower(),
            json.dumps(args_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True),
            value_wei,
        )

    for index, step in enumerate(steps_value):
        label = f"steps[{index}]"
        if not isinstance(step, dict) or set(step) - STEP_FIELDS:
            raise StepPlanError(f"{label} must use only the exact Step fields: " + ", ".join(sorted(STEP_FIELDS)), family=family)
        kind = str(step.get("kind") or "").strip().lower()
        if kind not in STEP_KINDS:
            raise StepPlanError(f"{label}.kind is not a recognized Step kind.", "out_of_scope", family=family)
        if kind in {"flash_borrow", "reenter"}:
            raise StepPlanError(
                f"{label} uses '{kind}', which requires a protocol-specific callback actor. No generic callback was fabricated.",
                "backend_unsupported", target=step.get("target") or spec.get("target_address"), family=family
            )
        optional = step.get("optional", False)
        if not isinstance(optional, bool):
            raise StepPlanError(f"{label}.optional must be boolean.", family=family)
        expect = _step_expectation(step.get("expect"), label)
        raw_args = step.get("args")
        if raw_args is None:
            raw_args = []
        if not isinstance(raw_args, list):
            raise StepPlanError(f"{label}.args must be a list of typed ABIValue objects or null.", family=family)
        target_raw = step.get("target")
        target_expr = default_target if target_raw is None else _step_address(target_raw, label + ".target")
        selector_raw = step.get("selector")
        needs_call = kind in {"call", "read", "unwind", "skew", "expect"}

        if pending_expectation is not None and not needs_call:
            raise StepPlanError(
                f"{label} must immediately consume the previous expect step with a matching call target, selector, args and value.",
                "backend_unsupported", family=family
            )

        if needs_call and (target_expr is None or selector_raw is None):
            raise StepPlanError(f"{label} kind '{kind}' requires target and selector.", family=family)
        if needs_call:
            selector_expr = _step_selector(selector_raw, label + ".selector")
            declarations = []
            arg_exprs = []
            for arg_index, arg in enumerate(raw_args):
                lines, expression = _step_abi_argument(arg, f"step{index}Arg{arg_index}")
                declarations.extend(lines)
                arg_exprs.append(expression)
            data_name = f"step{index}Data"
            calldata_expr = (
                f"abi.encodeWithSelector({selector_expr}, {', '.join(arg_exprs)})"
                if arg_exprs else f"abi.encodeWithSelector({selector_expr})"
            )
            body = []
            if declarations:
                body.extend(declarations)
            body.append(f"bytes memory {data_name} = {calldata_expr};")

            if kind == "expect":
                if pending_expectation is not None:
                    raise StepPlanError(f"{label} cannot arm a second pending call expectation.", family=family)
                if expect["count"] is None:
                    raise StepPlanError(f"{label} kind 'expect' requires expect.count.", family=family)
                expected_value = 0 if step.get("value") is None else _step_uint(step.get("value"), label + ".value")
                body.append(f"vm.expectCall({target_expr}, {data_name}, uint64({expect['count']}));")
                body.append(f"emit LowkeyStep({index}, {json.dumps(kind)}, {target_expr}, true, bytes32(0));")
                pending_expectation = {
                    "identity": call_identity(target_expr, selector_raw, raw_args, expected_value),
                    "must_revert": expect["must_revert"],
                    "source_step": index,
                }
                rendered_steps.append("        {\n            " + "\n            ".join(body) + "\n        }")
                continue

            raw_value = step.get("value")
            value_wei = 0 if raw_value is None else _step_uint(raw_value, label + ".value")
            if kind == "read" and value_wei != 0:
                raise StepPlanError(f"{label} read steps cannot send native value.", family=family)

            pending_revert = False
            if pending_expectation is not None:
                current_identity = call_identity(target_expr, selector_raw, raw_args, value_wei)
                if current_identity != pending_expectation["identity"]:
                    raise StepPlanError(
                        f"{label} does not match the immediately preceding expect step's target, selector, typed args and value.",
                        "backend_unsupported", target=step.get("target") or spec.get("target_address"), family=family
                    )
                if expect["count"] is not None:
                    raise StepPlanError(
                        f"{label} cannot declare a second expect.count while consuming a pending expect step.",
                        "backend_unsupported", family=family
                    )
                pending_revert = pending_expectation["must_revert"]
                pending_expectation = None
            elif expect["count"] is not None:
                body.append(f"vm.expectCall({target_expr}, {data_name}, uint64({expect['count']}));")

            if kind == "read":
                body.append(f"(bool step{index}Success, bytes memory step{index}ReturnData) = {target_expr}.staticcall({data_name});")
            else:
                body.append(f"(bool step{index}Success, bytes memory step{index}ReturnData) = {target_expr}.call{{value: {value_wei}}}({data_name});")
            body.append(f"lastSuccess = step{index}Success;")
            body.append(f"lastReturndata = step{index}ReturnData;")
            body.append(f"emit LowkeyStep({index}, {json.dumps(kind)}, {target_expr}, step{index}Success, keccak256(step{index}ReturnData));")
            if expect["must_revert"] or pending_revert:
                body.append(f'require(!step{index}Success, "STEP_{index}_EXPECTED_REVERT");')
            elif not optional:
                body.append(f'require(step{index}Success, "STEP_{index}_FAILED");')
            saw_call = True
            rendered_steps.append("        {\n            " + "\n            ".join(body) + "\n        }")
            continue

        if kind == "assert":
            if not saw_call:
                raise StepPlanError(f"{label} assert requires a prior call/read step.", family=family)
            if not expect["must_revert"] and expect["count"] is None:
                rendered_steps.append(f'        require(lastSuccess, "STEP_{index}_ASSERT_SUCCESS");')
            elif expect["must_revert"]:
                rendered_steps.append(f'        require(!lastSuccess, "STEP_{index}_ASSERT_REVERT");')
            else:
                raise StepPlanError(f"{label} assert does not accept expect.count.", family=family)
            continue
        if kind in {"warp", "roll"}:
            if step.get("target") is not None or selector_raw is not None or raw_args:
                raise StepPlanError(f"{label} {kind} steps accept only value.", family=family)
            if step.get("value") is None:
                raise StepPlanError(f"{label} {kind} step requires value.", family=family)
            number = _step_uint(step.get("value"), label + ".value")
            cheat = "warp" if kind == "warp" else "roll"
            rendered_steps.append(f"        vm.{cheat}({number});")
            continue
        if kind == "snapshot":
            if target_raw is not None or selector_raw is not None or raw_args or step.get("value") is not None:
                raise StepPlanError(f"{label} snapshot accepts no target, selector, args or value.", family=family)
            rendered_steps.append("        snapshotId = vm.snapshot();\n        snapshotAvailable = true;")
            continue
        if kind == "revert":
            if target_raw is not None or selector_raw is not None or raw_args or step.get("value") is not None:
                raise StepPlanError(f"{label} revert accepts no target, selector, args or value.", family=family)
            rendered_steps.append('        require(snapshotAvailable, "STEP_REVERT_WITHOUT_SNAPSHOT");\n        require(vm.revertTo(snapshotId), "STEP_SNAPSHOT_REVERT_FAILED");\n        snapshotAvailable = false;')
            continue
        raise StepPlanError(f"{label} kind '{kind}' is not yet rendered.", "backend_unsupported", family=family)

    if pending_expectation is not None:
        raise StepPlanError(
            "Step plan ends with an unconsumed expect step.",
            "backend_unsupported", family=family
        )
    if not saw_call:
        raise StepPlanError("Step plan must execute at least one call or read.", family=family)
    contract_name = "LowkeySteps_" + family
    source = template.replace("__LOWKEY_CONTRACT_NAME__", contract_name)
    source = source.replace("__LOWKEY_STEP_CODE__", "\n".join(rendered_steps))
    return source


def steps(args):
    class StepArgumentParser(LowkeyArgumentParser):
        def error(self, message):
            raise StepPlanError(str(message), "unsupported_abi")

    parser = StepArgumentParser(
        prog="lk steps",
        description="Validate and render an execution-checked Step[] Foundry harness.",
    )
    parser.add_argument("manifest", help="JSON file describing the typed Step[] sequence to validate and render.")
    parser.add_argument("--root", default=".", help="Project root; manifest and output paths must remain inside it.")
    parser.add_argument("--output", default=".audit/godmode/steps/step-harness.t.sol", help="Generated Solidity harness path, relative to --root.")
    parser.add_argument("--refusal-output", default=".audit/godmode/steps-refusal.json", help="Machine-readable refusal JSON path for unsupported or invalid plans.")

    ns = None
    root = None
    spec = {}
    try:
        ns = parser.parse_args(args)
        try:
            root = root_path(ns.root)
        except (OSError, ValueError) as error:
            raise StepPlanError(str(error), "out_of_scope") from error

        manifest_path = (root / ns.manifest).resolve()
        if not manifest_path.is_relative_to(root):
            raise StepPlanError("Step manifest must stay inside --root.", "out_of_scope")
        if not manifest_path.is_file():
            raise StepPlanError("Step manifest does not exist or is not a regular file.", "out_of_scope")
        try:
            spec_value = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise StepPlanError(f"Step manifest could not be read as UTF-8 JSON: {error}", "unsupported_abi") from error
        if not isinstance(spec_value, dict):
            raise StepPlanError("Step manifest root must be a JSON object.", "unsupported_abi")
        spec = spec_value

        try:
            source = render_step_harness(spec)
        except StepPlanError:
            raise
        except Exception as error:
            raise StepPlanError(
                f"Step renderer failed closed: {type(error).__name__}: {error}",
                "no_capability",
            ) from error
        try:
            output_path = safe_out(root, ns.output)
            output_path.write_text(source, encoding="utf-8")
        except (OSError, ValueError) as error:
            raise StepPlanError(f"Generated harness could not be written safely: {error}", "no_capability") from error

        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        print(json.dumps({
            "status": "PROPOSED",
            "family": spec.get("family"),
            "steps_rendered": len(spec["steps"]),
            "harness": output_path.relative_to(root).as_posix(),
            "harness_sha256": digest,
        }, sort_keys=True))
        return 0
    except StepPlanError as exc:
        target = exc.target or (spec.get("target_address") if isinstance(spec, dict) else None)
        family = exc.family or (spec.get("family") if isinstance(spec, dict) else None)
        manifest_arg = ns.manifest if ns is not None else (
            str(args[0]) if args and not str(args[0]).startswith("-") else "<manifest>"
        )
        root_arg = ns.root if ns is not None else "."
        refusal = {
            "target": target,
            "family": family,
            "reason": exc.reason_code,
            "detail": str(exc),
            "minimal_cmd": f"lk steps {manifest_arg} --root {root_arg}",
            "backend": "forge_state_diff",
        }
        if root is not None and ns is not None:
            try:
                refusal_path = safe_out(root, ns.refusal_output)
                refusal_path.write_text(json.dumps(refusal, indent=2) + "\n", encoding="utf-8")
            except (OSError, ValueError):
                # The same unsafe or unavailable filesystem path must not hide
                # the refusal; stdout remains the machine-readable fallback.
                pass
        print("REFUSAL " + json.dumps(refusal, sort_keys=True))
        return 2



def main(argv=None):
    a=list(sys.argv[1:] if argv is None else argv)
    if not a or a[0] in HELP_FLAGS:
        print_command_catalog()
        return 0
    cmd,rest=a[0],a[1:]
    if cmd == "archetype" and rest and rest[0] == "classify" and _is_godmode_help_request(rest[1:]):
        return print_godmode_command_help("archetype classify")
    if cmd in ROUTED_COMMANDS and _is_godmode_help_request(rest):
        return print_godmode_command_help(cmd)
    if cmd=="capabilities":
        parser = LowkeyArgumentParser(
            prog="lk capabilities",
            description="Show the central capability registry, including declared inputs, dependencies, outputs and safety requirements.",
        )
        parser.add_argument("--json", action="store_true", help="Print all 44 capability contracts as JSON.")
        parser.add_argument("--detail", help="Print one capability contract and its dependency plan.")
        ns = parser.parse_args(rest)
        if ns.detail:
            plan = capability_registry.dependency_plan(ns.detail)
            if plan is None:
                print(f"Unknown capability: {ns.detail}", file=sys.stderr)
                return 2
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if ns.json:
            print(json.dumps(capability_registry.list_capabilities(), indent=2, sort_keys=True))
            return 0
        for n,name,title,status in CAPABILITIES:
            print(f"{n:02d} {name:20} [{status:16}] {title}")
        print("All 44 capabilities are registered. Partial and adapter-required are explicit.")
        print("Use --json for contracts or --detail NAME for one dependency plan.")
        return 0
    if cmd=="godmode": return godmode(rest)
    if cmd=="control": return control(rest)
    if cmd=="trace-parity": return trace_parity(rest)
    if cmd=="steps": return steps(rest)
    if cmd=="mutation-score": return mutation(rest)
    if cmd=="target-coverage": return coverage(rest)
    if cmd=="provenance": return provenance(rest)
    if cmd=="fidelity":
        p=LowkeyArgumentParser(prog="lk fidelity"); p.add_argument("--root",default="."); p.add_argument("--record",action="store_true"); p.add_argument("--inspect"); p.add_argument("--cheatcode",action="append",default=[]); p.add_argument("--strength",choices=("heuristic","simulated-funds","reproduced-fork"),default="heuristic"); ns=p.parse_args(rest); root=root_path(ns.root)
        try:
            if ns.inspect:
                harness=(root/ns.inspect).resolve()
                if not harness.is_relative_to(root) or not harness.is_file(): raise ValueError("Harness must be an existing file inside the project.")
                return output(analyze_harness_fidelity(harness.read_text(encoding="utf-8",errors="replace"),harness.relative_to(root).as_posix()))
            try: from . import evidence_ledger
            except ImportError: import evidence_ledger
            if ns.record:
                ev=evidence_ledger.append_event(root,"fidelity_record",{"strength":ns.strength,"cheatcodes":ns.cheatcode,"created_at":now()}); print("Recorded "+ev["event_id"]); return 0
            rows=[e for e in evidence_ledger.read_events(root) if e.get("event_type")=="fidelity_record"]; return output(rows)
        except ImportError as exc: raise RuntimeError(str(exc))
    if cmd=="sandbox":
        p=LowkeyArgumentParser(prog="lk sandbox"); p.add_argument("--root",default="."); p.add_argument("--timeout",type=int,default=300); p.add_argument("command",nargs=argparse.REMAINDER); ns=p.parse_args(rest)
        root=root_path(ns.root)
        if not shutil.which("bwrap"): raise RuntimeError("bubblewrap unavailable; refusing unsandboxed execution.")
        if not ns.command or ns.command[0]!="--": raise ValueError("Usage: lk sandbox -- <command> [args]")
        temp=Path(tempfile.mkdtemp(prefix="lk-sandbox-")); work=temp/"project"
        try:
            def ignore_sensitive(directory,names):
                ignored=[]
                for name in names:
                    lower=name.lower()
                    if name in {".git",".audit","node_modules","out","cache","__pycache__",".venv","venv"}:
                        ignored.append(name)
                    elif lower.startswith(".env") or any(token in lower for token in ("credential","keystore","private_key","wallet.json","id_rsa","id_ed25519",".npmrc")):
                        ignored.append(name)
                return ignored
            shutil.copytree(root,work,ignore=ignore_sensitive)
            home=Path.home()
            home_args=[]
            # Build an isolated home path inside the sandbox; do not expose the
            # host home directory. Only Foundry executables and solc versions
            # are selectively mounted read-only.
            if str(home).startswith("/home/"):
                home_args += ["--dir","/home"]
            if str(home)!="/":
                home_args += ["--dir",str(home)]
            foundry_bin=home/".foundry"/"bin"
            if foundry_bin.is_dir():
                home_args += ["--dir",str(home/".foundry"),"--ro-bind",str(foundry_bin),str(foundry_bin)]
            svm=home/".svm"
            if svm.is_dir():
                home_args += ["--dir",str(home/".svm"),"--ro-bind",str(svm),str(svm)]
            path_value=str(foundry_bin)+":/usr/local/bin:/usr/bin:/bin"
            argv=["bwrap","--die-with-parent","--unshare-net","--unshare-pid","--unshare-ipc","--unshare-uts",
                  "--clearenv","--setenv","HOME",str(home), "--setenv","PATH",path_value,
                  "--ro-bind","/usr","/usr","--ro-bind","/etc","/etc","--dev","/dev","--proc","/proc",
                  "--tmpfs","/tmp",*home_args,"--bind",str(work),"/workspace","--chdir","/workspace","--",*ns.command[1:]]
            proc=run(argv,root,ns.timeout)
            print(proc.stdout,end=""); print(proc.stderr,file=sys.stderr,end=""); return proc.returncode
        finally: shutil.rmtree(temp,ignore_errors=True)
    if cmd=="cheat-fingerprint": return fingerprint(rest)
    if cmd in {"fallback-map","oracle-map","reentrancy-graph","sig-matrix","init-frontrun","custody","cross-vm","cfg"}: return source_cmd(cmd,rest)
    if cmd in {"proxy-resolve","storage-infer","selectors-full"}: return rpc_command(cmd,rest)
    if cmd=="unravel": return unravel(rest)
    if cmd=="state-diff": return state_diff(rest)
    if cmd=="economic": return economic(rest)
    if cmd=="attack-forge": return attack_forge(rest)
    if cmd=="invariant-forge": return generate(rest,cmd)
    if cmd=="archetype":
        if rest and rest[0] == "classify":
            return _archetype_index_main(rest[1:])
        return generate(rest,cmd)
    if cmd in {"assumptions", "capability"}:
        if any(str(token).strip().lower() in HELP_FLAGS for token in rest):
            details = _godmode_help_details(cmd)
            help_parser = LowkeyArgumentParser(
                prog="lk " + cmd,
                description=details["summary"],
            )
            help_parser.add_argument("--root", default=".")
            help_parser.add_argument("--report")
            help_parser.parse_args(rest)
            print("When to use: " + details["when"])
            print("Example: " + details["example"])
            print("Limitations: " + details["limits"])
            return 0
        flag = "--assumptions" if cmd == "assumptions" else "--capability"
        return _archetype_index_main([flag, *rest])
    if cmd=="token-weird": return token_weird(rest)
    if cmd=="fork-cache": return fork_cache(rest)
    if cmd=="questions": return questions(rest)
    if cmd=="learn": return learn(rest)
    if cmd=="report": return report(rest)
    if cmd=="reprove": return reprove(rest)
    if cmd=="time":
        p=LowkeyArgumentParser(prog="lk time"); p.add_argument("--root",default="."); p.add_argument("--output",default=".audit/godmode/TimeLadder.template.t.sol"); ns=p.parse_args(rest); root=root_path(ns.root); out=safe_out(root,ns.output)
        offsets=(3600,86400,604800,2592000); body="\n".join(" function test_warp_"+str(x)+"() public { vm.warp(block.timestamp + "+str(x)+"); vm.roll(block.number + "+str(max(1,x//12))+"); /* invoke target and assert invariant */ }" for x in offsets)
        out.write_text("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\nimport \"forge-std/Test.sol\";\ncontract LowkeyTimeLadder is Test {\n"+body+"\n}\n"); print("Time ladder template: "+str(out.relative_to(root))); return 0
    if cmd=="compose": return compose(rest)
    if cmd=="skew": return skew_plan(rest)
    if cmd=="flashmax": return flashmax(rest)
    if cmd=="path": return symbolic_path(rest)
    if cmd=="gas-ladder": return gas_ladder(rest)
    if cmd=="watch": return watch(rest)
    if cmd=="verify-hack": return verify_hack(rest)
    if cmd=="bundle": return bundle_simulate(rest)
    if cmd=="upgrade-diff": return upgrade_diff(rest)
    if cmd=="agent-split": return agent_split(rest)
    if cmd=="calldata-mine": return calldata_mine(rest)
    if cmd in {"sandwich","jit","decompile"}:
        if any(str(token).strip().lower() in HELP_FLAGS for token in rest):
            details = _godmode_help_details(cmd)
            print("LOWKEY GODMODE HELP  •  lk " + cmd)
            print("=" * 72)
            print("What it does: " + details["summary"])
            print("When to use: " + details["when"])
            print("Usage: lk " + cmd + " [adapter-specific options]")
            print("Example: " + details["example"])
            print("Limitations: " + details["limits"])
            print("Help spellings: --h, --help, -h, help")
            return 0
        if cmd=="decompile":
            print("BLOCKED: install and configure a supported Heimdall adapter; no decompiler invocation guessed.")
        else:
            print("BLOCKED: "+cmd+" requires a pending-transaction feed and pool-specific simulation adapter. No transaction was sent.")
        return 2
    if cmd=="flashmax":
        print("BLOCKED: requires Aave/Balancer/Uniswap V3 venue-specific pool and callback adapter."); return 2
    if cmd=="time":
        print("Use: lk time"); return 2
    raise ValueError("Unknown Godmode command: "+cmd)
if __name__=="__main__":
    try: raise SystemExit(main())
    except KeyboardInterrupt: raise SystemExit(130)
    except (ValueError,RuntimeError,OSError,json.JSONDecodeError,subprocess.TimeoutExpired) as exc:
        print("Lowkey: "+str(exc),file=sys.stderr); raise SystemExit(2)
