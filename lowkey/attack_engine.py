#!/usr/bin/env python3
"""Evidence-gated, multi-family EVM attack experiments and attack-chain runner.

A family is an executable strategy contract, not a label. Lowkey discovers
candidate source signals, then requires a target-specific Foundry attack,
matched control, canonical trace evidence, and a mutation that kills the attack
before it reports a verified experiment. It never broadcasts transactions.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable

try:
    from .trace_schema import build_trace_event
except ImportError:
    from trace_schema import build_trace_event


SCHEMA_VERSION = 1
FAMILIES: dict[str, dict[str, Any]] = {
    "reentrancy": {
        "title": "Reentrancy",
        "strategy": "Re-enter a state transition while its prior entitlement or invariant is still live.",
        "preconditions": ["reachable external call", "attacker-controlled callback", "shared state or entitlement"],
        "property": "reentrancy-invariant-violation",
        "signals": [r"\.call\s*(?:\{|\()", r"\b(?:receive|fallback|tokensReceived|onERC721Received)\b", r"\b(?:withdraw|claim|redeem|borrow)\s*\("],
        "min_events": 2, "min_depth": 2, "exact_storage": True, "economic": True,
    },
    "replay": {
        "title": "Replay",
        "strategy": "Repeat a signed, bridged, or claim action and prove a one-time entitlement is consumed exactly once.",
        "preconditions": ["replayable identifier or signed payload", "repeatable entrypoint", "observable consumed-state or duplicate effect"],
        "property": "replayed-action-applied",
        "signals": [r"\b(?:nonce|used|consumed|messageId|digest|claimId)\b", r"\b(?:claim|execute|complete|redeem|fulfill)\s*\(", r"\becrecover\b|\bECDSA\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": True,
    },
    "access": {
        "title": "Access control",
        "strategy": "Compare a privileged action from an unauthorized actor with the same action from an authorized actor.",
        "preconditions": ["sensitive state-changing entrypoint", "intended role or principal", "unauthorized and authorized actors"],
        "property": "unauthorized-state-change",
        "signals": [r"\b(?:onlyOwner|onlyRole|hasRole|_checkRole|owner|admin|guardian)\b", r"\b(?:setOwner|upgradeTo|pause|unpause|setFee|withdrawAdmin)\s*\("],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": True,
    },
    "accounting": {
        "title": "Accounting",
        "strategy": "Exercise deposits, withdrawals, shares, debt, and fees against a stated conservation or solvency invariant.",
        "preconditions": ["explicit accounting invariant", "measurable pre/post balances or liabilities", "attacker-controlled state transition"],
        "property": "accounting-invariant-violation",
        "signals": [r"\b(?:totalAssets|totalSupply|totalDebt|totalShares|borrowed|collateral|reserve|liabilit)\w*\b", r"\b(?:deposit|withdraw|redeem|borrow|repay|liquidate)\s*\("],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": True,
    },
    "boundary": {
        "title": "Boundary conditions",
        "strategy": "Probe exact lower, upper, zero, maximum, rounding, and transition boundaries; require a concrete invariant break.",
        "preconditions": ["declared input or state boundary", "boundary-adjacent values", "observable expected/actual transition"],
        "property": "boundary-invariant-violation",
        "signals": [r"\b(?:min|max|limit|cap|threshold|decimals|amount|deadline|expiry)\b", r"(?:<=|>=|<|>)\s*(?:0|1|type\(|[A-Z_]+)"],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": False,
    },
    "time": {
        "title": "Time and block dependence",
        "strategy": "Test timestamp, block-number, expiry, vesting, and sequencer assumptions at exact transition points.",
        "preconditions": ["time or block dependent decision", "pinned initial timestamp/block", "before/at/after boundary assertions"],
        "property": "time-boundary-bypass",
        "signals": [r"\b(?:block\.timestamp|block\.number|deadline|expiry|vesting|unlock|cooldown|epoch)\b", r"\b(?:warp|roll|timeLock|timelock)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": False, "economic": False,
    },
    "upgrade": {
        "title": "Upgrade authorization and initialization",
        "strategy": "Exercise implementation changes and initialization transitions under authorized and unauthorized principals.",
        "preconditions": ["upgrade or initializer entrypoint", "implementation identity", "upgrade authority and storage invariants"],
        "property": "unauthorized-upgrade-or-initializer",
        "signals": [r"\b(?:upgradeTo|upgradeToAndCall|_authorizeUpgrade|implementation|beacon|proxiableUUID)\b", r"\b(?:initialize|reinitializer|_disableInitializers)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": True,
    },
    "callback": {
        "title": "Callback and hook behavior",
        "strategy": "Drive the protocol through an adversarial callback/hook and prove callback ordering, caller, selector, and state constraints.",
        "preconditions": ["callback or hook entrypoint", "registered or accepted receiver", "adversarial callback actor"],
        "property": "callback-invariant-violation",
        "signals": [r"\b(?:callback|hook|tokensReceived|onERC721Received|onERC1155Received|uniswapV2Call|executeOperation)\b", r"\b(?:receiver|implementer|registry)\b"],
        "min_events": 2, "min_depth": 2, "exact_storage": True, "economic": False,
    },
    "oracle": {
        "title": "Oracle and price integrity",
        "strategy": "Compare manipulated, stale, invalid, and valid price inputs against collateral and settlement invariants.",
        "preconditions": ["identified price source", "freshness/round/decimal assumptions", "independent reference or bounded price range"],
        "property": "oracle-integrity-violation",
        "signals": [r"\b(?:latestRoundData|latestAnswer|priceFeed|oracle|TWAP|twap|consult)\b", r"\b(?:price|exchangeRate|quote|healthFactor|collateralRatio)\b"],
        "min_events": 2, "min_depth": 0, "exact_storage": False, "economic": True,
    },
    "economic": {
        "title": "Economic and compositional",
        "strategy": "Compose protocol actions and calculate realized net value after gas, setup, borrow fees, and unwind costs.",
        "preconditions": ["complete action sequence", "same-unit balance measurement", "all costs and repayment obligations measured"],
        "property": "positive-net-economic-impact",
        "signals": [r"\b(?:swap|borrow|repay|liquidate|flashLoan|flashBorrow|fee|interest|exchangeRate)\b", r"\b(?:profit|balance|reserve|collateral|debt)\b"],
        "min_events": 2, "min_depth": 0, "exact_storage": False, "economic": True,
    },
    "erc20": {
        "title": "ERC-20 and token behavior",
        "strategy": "Compare requested amounts with actual token balance deltas across return-value, fee, rebase, and approval behavior.",
        "preconditions": ["token implementation and decimals identified", "before/after balances", "transfer or approval path"],
        "property": "token-delta-accounting-mismatch",
        "signals": [r"\b(?:transferFrom|safeTransferFrom|transfer|approve|allowance|balanceOf|decimals)\s*\(", r"\b(?:feeOnTransfer|rebasing|permit|nonces)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": False, "economic": True,
    },
    "proxy": {
        "title": "Proxy and delegatecall routing",
        "strategy": "Resolve the actual implementation and verify delegatecall routing, admin separation, and storage-context assumptions.",
        "preconditions": ["proxy type identified", "implementation/admin/beacon resolution", "runtime code hashes pinned"],
        "property": "proxy-routing-or-admin-boundary-violation",
        "signals": [r"\bdelegatecall\b", r"\b(?:implementation|admin|beacon|diamondCut|facet|EIP1967|ERC1967)\b"],
        "min_events": 1, "min_depth": 1, "exact_storage": True, "economic": False,
    },
    "storage": {
        "title": "Storage layout and slot integrity",
        "strategy": "Bind source variables to measured slots and verify unauthorized or colliding writes cannot alter protected state.",
        "preconditions": ["compiler storage layout", "slot/offset mapping", "before/after slot evidence"],
        "property": "protected-slot-corruption",
        "signals": [r"\b(?:sload|sstore|assembly|storage\s+\w+|bytes32\s+constant)\b", r"\b(?:slot|layout|mapping|owner|implementation)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": False,
    },
    "signature": {
        "title": "Signature and typed-data validation",
        "strategy": "Test signer, domain, nonce, expiry, chain, contract, and ERC-1271 semantics with replay controls.",
        "preconditions": ["signature-producing domain", "signer identity", "nonce/deadline/chain binding rules"],
        "property": "signature-domain-or-replay-bypass",
        "signals": [r"\b(?:ecrecover|ECDSA|SignatureChecker|isValidSignature|DOMAIN_SEPARATOR|domainSeparator|permit)\b", r"\b(?:nonce|deadline|chainId|vrs|signature)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": True, "economic": True,
    },
    "dos": {
        "title": "Denial of service and liveness",
        "strategy": "Test progress under hostile recipients, bounded/unbounded loops, gas griefing, and failure recovery.",
        "preconditions": ["explicit liveness property", "bounded resource budget", "recovery or isolation path"],
        "property": "liveness-failure-under-bounded-input",
        "signals": [r"\b(?:for|while)\s*\(", r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{", r"\b(?:payAll|withdrawAll|processAll|claimAll|distribute)\b"],
        "min_events": 1, "min_depth": 0, "exact_storage": False, "economic": False,
    },
}
FAMILY_NAMES = tuple(FAMILIES)


class AttackEngineError(ValueError):
    def __init__(self, message: str, reason: str = "invalid_manifest"):
        super().__init__(message)
        self.reason = reason


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AttackEngineError(f"{label} could not be read as UTF-8 JSON: {exc}", "evidence_missing") from exc
    if not isinstance(value, dict):
        raise AttackEngineError(f"{label} must contain a JSON object.")
    return value


def project_root(value: str | Path = ".") -> Path:
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise AttackEngineError(f"Project root is not a directory: {root}", "out_of_scope")
    return root


def safe_relative_file(root: Path, raw: Any, label: str, *, must_exist: bool = True) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise AttackEngineError(f"{label} must be a non-empty project-relative path.")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise AttackEngineError(f"{label} must not be absolute or traverse outside the project.", "out_of_scope")
    target = (root / relative).resolve()
    if not target.is_relative_to(root):
        raise AttackEngineError(f"{label} resolves outside the project.", "out_of_scope")
    if must_exist and (not target.is_file() or target.is_symlink()):
        raise AttackEngineError(f"{label} is missing or is not a regular file.", "evidence_missing")
    return target


def safe_evidence_file(root: Path, raw: Any, label: str) -> Path:
    target = safe_relative_file(root, raw, label, must_exist=False)
    audit_root = (root / ".audit" / "lowkey").resolve()
    if not target.is_relative_to(audit_root):
        raise AttackEngineError(f"{label} must be stored under .audit/lowkey/.", "out_of_scope")
    if target.exists() and target.is_dir():
        raise AttackEngineError(f"{label} must be a file path.")
    target.parent.mkdir(parents=True, exist_ok=True)
    return target


def _positive_int(value: Any, label: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        raise AttackEngineError(f"{label} must be an {'nonnegative' if allow_zero else 'positive'} integer.")
    return value


def _hex(value: Any, pattern: str, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise AttackEngineError(f"{label} has an invalid hexadecimal format.")
    return value.lower()


def family_inventory() -> list[dict[str, Any]]:
    return [{
        "family": name,
        "title": spec["title"],
        "strategy": spec["strategy"],
        "preconditions": list(spec["preconditions"]),
        "required_property": spec["property"],
        "min_trace_events": spec["min_events"],
        "min_trace_depth": spec["min_depth"],
        "requires_exact_storage": spec["exact_storage"],
        "requires_economic_reproof": spec["economic"],
        "status": "fixture_accepted" if name == "reentrancy" else "adapter_required",
    } for name, spec in FAMILIES.items()]


def discover_candidates(root: str | Path = ".", family: str | None = None, *, max_files: int = 3000) -> dict[str, Any]:
    base = project_root(root)
    selected = [family] if family else list(FAMILY_NAMES)
    unknown = sorted(set(selected) - set(FAMILIES))
    if unknown:
        raise AttackEngineError("Unknown family: " + ", ".join(unknown), "unsupported_family")
    source_dirs = [base / name for name in ("src", "contracts", "sources")]
    source_files: list[Path] = []
    for directory in source_dirs:
        if not directory.is_dir() or directory.is_symlink():
            continue
        for path in directory.rglob("*"):
            if len(source_files) >= max_files:
                raise AttackEngineError(f"Source scan exceeded the {max_files}-file safety limit.", "resource_limit")
            if path.is_symlink() or not path.is_file() or path.suffix.lower() not in {".sol", ".vy"}:
                continue
            if any(part in {".git", "out", "cache", "node_modules", "lib", "vendor"} for part in path.relative_to(base).parts):
                continue
            source_files.append(path)
    candidates: list[dict[str, Any]] = []
    for path in sorted(set(source_files)):
        try:
            if path.stat().st_size > 1_000_000:
                continue
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        lines = source.splitlines()
        rel = path.relative_to(base).as_posix()
        for name in selected:
            spec = FAMILIES[name]
            matches: list[dict[str, Any]] = []
            for pattern in spec["signals"]:
                regex = re.compile(pattern, re.IGNORECASE)
                for index, line in enumerate(lines):
                    if regex.search(line):
                        matches.append({"line": index + 1, "signal": pattern, "excerpt": line.strip()[:240]})
            if matches:
                candidates.append({
                    "family": name, "title": spec["title"], "file": rel,
                    "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    "matches": matches[:30],
                    "status": "CANDIDATE",
                    "interpretation": "Static source signal only. No exploitability or impact is inferred.",
                    "required_preconditions": list(spec["preconditions"]),
                    "required_property": spec["property"],
                })
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "CANDIDATES_ONLY",
        "project": str(base),
        "files_scanned": len(source_files),
        "families_scanned": selected,
        "candidates": candidates,
    }


def _validate_discovery(value: Any, root: Path, family: str, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttackEngineError(f"{label} must declare target-specific source discovery.")
    allowed = {"source_file", "source_sha256", "source_line", "entrypoint"}
    if set(value) != allowed:
        raise AttackEngineError(f"{label} must contain exactly: " + ", ".join(sorted(allowed)))
    source_path = safe_relative_file(root, value.get("source_file"), f"{label}.source_file")
    source_hash = _hex(value.get("source_sha256"), r"[0-9a-fA-F]{64}", f"{label}.source_sha256")
    observed_hash = _sha256_file(source_path)
    if source_hash != observed_hash:
        raise AttackEngineError(f"{label} source hash no longer matches the checked-out target.", "source_identity_mismatch")
    source_line = _positive_int(value.get("source_line"), f"{label}.source_line")
    lines = source_path.read_text(encoding="utf-8").splitlines()
    if source_line > len(lines):
        raise AttackEngineError(f"{label}.source_line is outside the source file.")
    entrypoint = value.get("entrypoint")
    if not isinstance(entrypoint, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\s*\([^;\n{}]*\)", entrypoint.strip()):
        raise AttackEngineError(f"{label}.entrypoint must be an explicit function signature.")
    function_name = re.match(r"([A-Za-z_][A-Za-z0-9_]*)", entrypoint.strip()).group(1)
    source = "\n".join(lines)
    if not re.search(r"\b(?:function|def)\s+" + re.escape(function_name) + r"\s*\(", source):
        raise AttackEngineError(f"{label}.entrypoint was not found in the pinned source file.", "entrypoint_not_found")
    context = "\n".join(lines[max(0, source_line - 3):min(len(lines), source_line + 2)])
    if not re.search(r"\b" + re.escape(function_name) + r"\s*\(", context):
        raise AttackEngineError(f"{label}.source_line does not point to the declared entrypoint.", "entrypoint_line_mismatch")
    if not any(re.search(pattern, source, re.IGNORECASE) for pattern in FAMILIES[family]["signals"]):
        raise AttackEngineError(f"{label} source has no signal for the declared {family} family.", "family_signal_not_found")
    return {"source_file": source_path.relative_to(root).as_posix(),
            "source_sha256": source_hash, "source_line": source_line,
            "entrypoint": " ".join(entrypoint.split()), "family": family}


def _validate_precondition_evidence(value: Any, family: str, label: str) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise AttackEngineError(f"{label} must record every family precondition.")
    expected = set(FAMILIES[family]["preconditions"])
    if set(value) != expected:
        missing, extra = sorted(expected - set(value)), sorted(set(value) - expected)
        raise AttackEngineError(
            f"{label} precondition evidence mismatch; missing={missing}, extra={extra}.",
            "precondition_evidence_incomplete",
        )
    if any(item is not True for item in value.values()):
        raise AttackEngineError(f"{label} did not establish every required precondition.", "preconditions_not_met")
    return {str(key): True for key in sorted(value)}


def _validate_reproof(
    value: Any, *, root: Path, target: dict[str, Any], family: str, impact_mode: str, label: str
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"reproof_file"}:
        raise AttackEngineError(f"{label} must reference the independent lk reproof artifact.", "reproof_missing")
    path = safe_relative_file(root, value.get("reproof_file"), f"{label}.reproof_file")
    payload = _json_file(path, f"{label} reproof")
    source = payload.get("source_fork_verification")
    if not isinstance(source, dict) or source.get("verified") is not True:
        raise AttackEngineError(f"{label} has no independently source-verified fork evidence.", "reproof_not_independent")
    if str(payload.get("target_address") or "").lower() != target["address"]:
        raise AttackEngineError(f"{label} reproof target address differs from the pinned experiment.", "identity_mismatch")
    raw_chain = payload.get("chain_id")
    try:
        same_chain = int(str(raw_chain), 0) == target["chain_id"]
    except (TypeError, ValueError):
        same_chain = str(raw_chain).lower() == hex(target["chain_id"]).lower()
    if not same_chain:
        raise AttackEngineError(f"{label} reproof chain id differs from the pinned experiment.", "identity_mismatch")
    source_chain = source.get("source_chain_id")
    try:
        source_chain_matches = int(str(source_chain), 0) == target["chain_id"]
    except (TypeError, ValueError):
        source_chain_matches = str(source_chain).lower() == hex(target["chain_id"]).lower()
    if not source_chain_matches:
        raise AttackEngineError(f"{label} independent source chain id differs from the pinned target.", "identity_mismatch")
    if str(source.get("target_code_sha256") or "").lower().removeprefix("0x") != target["code_sha256"][2:]:
        raise AttackEngineError(f"{label} target runtime code SHA-256 differs from the independently checked source deployment.", "identity_mismatch")
    if payload.get("fork_parent_block") != target["block_number"]:
        raise AttackEngineError(f"{label} reproof fork block differs from the pinned experiment.", "identity_mismatch")
    if payload.get("command_run") is not True or str(payload.get("receipt_status")).lower() not in {"0x1", "1"}:
        raise AttackEngineError(f"{label} reproof did not execute a mined successful transaction.", "reproof_execution_missing")
    call_trace = payload.get("call_trace")
    if not isinstance(call_trace, list) or not call_trace:
        raise AttackEngineError(f"{label} reproof has no transaction call-trace evidence.", "trace_incomplete")
    if FAMILIES[family]["exact_storage"]:
        storage_trace = payload.get("storage_trace") or {}
        if storage_trace.get("supported") is not True or not payload.get("derived_storage_slots"):
            raise AttackEngineError(f"{label} requires trace-derived changed-storage observations from the independent fork reproof.", "storage_evidence_insufficient")
    tx_hash = _hex(payload.get("tx_hash"), r"0x[0-9a-fA-F]{64}", f"{label}.tx_hash")
    if impact_mode == "economic":
        if payload.get("status") != "PROFITABLE" or payload.get("legacy_status") != "PROFITABLE":
            raise AttackEngineError(f"{label} economic reproof is not independently classified PROFITABLE.", "not_profitable")
        net_profit = _wei(payload.get("net_profit_wei"), f"{label}.net_profit_wei")
        gas_cost = _wei(payload.get("gas_cost_wei"), f"{label}.gas_cost_wei")
        prior_cost = _wei(payload.get("prior_cost_wei"), f"{label}.prior_cost_wei")
        total_cost = _wei(payload.get("total_cost_wei"), f"{label}.total_cost_wei")
        if net_profit <= 0 or total_cost != gas_cost + prior_cost:
            raise AttackEngineError(f"{label} reproof costs do not reconcile to positive net profit.", "economic_cost_mismatch")
    else:
        if payload.get("semantic_invariant_verified") is not True:
            raise AttackEngineError(f"{label} non-economic reproof lacks a passing semantic invariant.", "semantic_reproof_missing")
        if payload.get("status") not in {"SIMULATED_BREAK", "FORK_OBSERVED", "FORK_REPRODUCED", "PROFITABLE"}:
            raise AttackEngineError(f"{label} non-economic reproof status is not an accepted observed state.", "reproof_unproven")
    return {"status": payload.get("status"), "tx_hash": tx_hash,
            "fork_parent_block": target["block_number"],
            "source_verified": True, "reproof_file": path.relative_to(root).as_posix(),
            "reproof_sha256": _sha256_file(path),
            "net_profit_wei": payload.get("net_profit_wei")}


def _validate_target(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttackEngineError("target must be an object.")
    address = _hex(value.get("address"), r"0x[0-9a-fA-F]{40}", "target.address")
    code_hash = _hex(value.get("code_sha256"), r"0x[0-9a-fA-F]{64}", "target.code_sha256")
    chain_id = _positive_int(value.get("chain_id"), "target.chain_id")
    block_number = _positive_int(value.get("block_number"), "target.block_number", allow_zero=True)
    return {"address": address, "code_sha256": code_hash, "chain_id": chain_id, "block_number": block_number}


def _validate_test(value: Any, root: Path, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AttackEngineError(f"{label} must be an object.")
    path = safe_relative_file(root, value.get("test_file"), f"{label}.test_file")
    name = value.get("test_name")
    if not isinstance(name, str) or not re.fullmatch(r"test[A-Za-z0-9_]*", name):
        raise AttackEngineError(f"{label}.test_name must be a Foundry test function name.")
    evidence = safe_evidence_file(root, value.get("evidence_file"), f"{label}.evidence_file")
    return {"test_file": path.relative_to(root).as_posix(), "test_name": name,
            "evidence_file": evidence.relative_to(root).as_posix()}


def _validate_mutants(value: Any, root: Path) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise AttackEngineError("mutation.mutants must contain at least one explicit source mutation.", "mutation_missing")
    rows: list[dict[str, str]] = []
    ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise AttackEngineError(f"mutation.mutants[{index}] must be an object.")
        mutant_id = item.get("id")
        if not isinstance(mutant_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{3,100}", mutant_id):
            raise AttackEngineError(f"mutation.mutants[{index}].id is invalid.")
        if mutant_id in ids:
            raise AttackEngineError(f"Duplicate mutation id: {mutant_id}")
        ids.add(mutant_id)
        relative = item.get("file")
        source = safe_relative_file(root, relative, f"mutation.mutants[{index}].file")
        before, after = item.get("before"), item.get("after")
        if not isinstance(before, str) or not before or not isinstance(after, str) or before == after:
            raise AttackEngineError(f"Mutation {mutant_id} needs distinct non-empty before/after source fragments.")
        if len(before) > 20_000 or len(after) > 20_000:
            raise AttackEngineError(f"Mutation {mutant_id} exceeds the source-fragment limit.", "resource_limit")
        rows.append({"id": mutant_id, "file": source.relative_to(root).as_posix(),
                     "before": before, "after": after})
    return rows


def validate_experiment_manifest(value: Any, root: str | Path = ".") -> dict[str, Any]:
    base = project_root(root)
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise AttackEngineError(f"Experiment manifest schema_version must be {SCHEMA_VERSION}.")
    allowed = {"schema_version", "id", "family", "target", "discovery", "impact_mode", "property_id", "attack", "control", "reproof", "mutation", "timeout_seconds"}
    if set(value) - allowed:
        raise AttackEngineError("Unexpected experiment manifest fields: " + ", ".join(sorted(set(value) - allowed)))
    experiment_id = value.get("id")
    if not isinstance(experiment_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,100}", experiment_id):
        raise AttackEngineError("id must be a stable 3-100 character experiment identifier.")
    family = value.get("family")
    if family not in FAMILIES:
        raise AttackEngineError("family must be one of: " + ", ".join(FAMILY_NAMES), "unsupported_family")
    property_id = value.get("property_id")
    if property_id != FAMILIES[family]["property"]:
        raise AttackEngineError(f"property_id must be '{FAMILIES[family]['property']}' for {family}.")
    timeout = _positive_int(value.get("timeout_seconds", 300), "timeout_seconds")
    if timeout > 3600:
        raise AttackEngineError("timeout_seconds may not exceed 3600.", "resource_limit")
    target = _validate_target(value.get("target"))
    impact_mode = value.get("impact_mode", "economic" if FAMILIES[family]["economic"] else "semantic")
    if impact_mode not in {"economic", "semantic"}:
        raise AttackEngineError("impact_mode must be economic or semantic.")
    discovery = _validate_discovery(value.get("discovery"), base, family, "discovery")
    reproof = value.get("reproof")
    if not isinstance(reproof, dict) or not isinstance(reproof.get("reproof_file"), str):
        raise AttackEngineError("reproof.reproof_file must point to a completed independent lk reproof.", "reproof_missing")
    _validate_reproof(reproof, root=base, target=target, family=family, impact_mode=impact_mode, label="independent reproof")
    attack = _validate_test(value.get("attack"), base, "attack")
    control = _validate_test(value.get("control"), base, "control")
    if attack["evidence_file"] == control["evidence_file"]:
        raise AttackEngineError("Attack and control evidence files must be different.")
    mutation_value = value.get("mutation")
    if not isinstance(mutation_value, dict):
        raise AttackEngineError("mutation must be an object.")
    mutants = _validate_mutants(mutation_value.get("mutants"), base)
    return {
        "schema_version": SCHEMA_VERSION, "id": experiment_id, "family": family,
        "target": target, "discovery": discovery, "reproof": reproof, "impact_mode": impact_mode,
        "property_id": property_id, "attack": attack, "control": control,
        "mutants": mutants, "timeout_seconds": timeout, "project_root": str(base),
    }


def _load_trace_events(value: Any, family: str, label: str) -> list[dict[str, Any]]:
    if not isinstance(value, list) or len(value) < FAMILIES[family]["min_events"]:
        raise AttackEngineError(f"{label} needs at least {FAMILIES[family]['min_events']} canonical trace events.", "trace_incomplete")
    events: list[dict[str, Any]] = []
    for index, event in enumerate(value):
        if not isinstance(event, dict):
            raise AttackEngineError(f"{label}.trace_events[{index}] must be an object.", "trace_invalid")
        try:
            normalized = build_trace_event(**{key: event.get(key) for key in (
                "seq", "backend", "kind", "accessor", "account", "depth", "value",
                "selector", "calldata", "reverted", "storage", "storage_support",
            )})
        except (TypeError, ValueError) as exc:
            raise AttackEngineError(f"{label}.trace_events[{index}] is not valid TraceEvent v2: {exc}", "trace_invalid") from exc
        events.append(normalized)
    required_depth = FAMILIES[family]["min_depth"]
    if max((event["depth"] or 0) for event in events) < required_depth:
        raise AttackEngineError(f"{label} trace depth is below the {family} requirement ({required_depth}).", "trace_incomplete")
    if FAMILIES[family]["exact_storage"] and not any(
        event["backend"] == "forge-state-diff" and event["storage_support"] == "exact"
        and event["storage"] for event in events
    ):
        raise AttackEngineError(f"{label} needs Forge exact per-access storage evidence for {family}.", "storage_evidence_insufficient")
    return events


def _wei(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise AttackEngineError(f"{label} must be a nonnegative integer wei amount.")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)", value):
        number = int(value, 16 if value.lower().startswith("0x") else 10)
    else:
        raise AttackEngineError(f"{label} must be a decimal or 0x-prefixed integer wei amount.")
    if number < 0:
        raise AttackEngineError(f"{label} cannot be negative.")
    return number



def _validate_evidence(
    evidence: Any, *, manifest: dict[str, Any], role: str, label: str
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise AttackEngineError(f"{label} must be an object.", "evidence_invalid")
    required = {"schema_version", "experiment_id", "family", "role", "target",
                "discovery_sha256", "preconditions", "pair_anchor", "predicate", "trace_events"}
    missing = required - set(evidence)
    if missing:
        raise AttackEngineError(f"{label} is missing: " + ", ".join(sorted(missing)), "evidence_invalid")
    if evidence["schema_version"] != SCHEMA_VERSION or evidence["experiment_id"] != manifest["id"]:
        raise AttackEngineError(f"{label} schema or experiment id does not match the manifest.", "evidence_mismatch")
    if evidence["family"] != manifest["family"] or evidence["role"] != role:
        raise AttackEngineError(f"{label} family/role does not match the experiment.", "evidence_mismatch")
    target = _validate_target(evidence["target"])
    if target != manifest["target"]:
        raise AttackEngineError(f"{label} target identity/chain/block does not match the pinned manifest.", "identity_mismatch")
    if _hex(evidence["discovery_sha256"], r"[0-9a-fA-F]{64}", f"{label}.discovery_sha256") != manifest["discovery"]["source_sha256"]:
        raise AttackEngineError(f"{label} source discovery does not match the pinned source.", "source_identity_mismatch")
    preconditions = _validate_precondition_evidence(evidence["preconditions"], manifest["family"], label)
    anchor = evidence["pair_anchor"]
    if not isinstance(anchor, dict):
        raise AttackEngineError(f"{label}.pair_anchor must be an object.", "evidence_invalid")
    normalized_anchor = {
        "entry_selector": _hex(anchor.get("entry_selector"), r"0x[0-9a-fA-F]{8}", f"{label}.pair_anchor.entry_selector"),
        "calldata_sha256": _hex(anchor.get("calldata_sha256"), r"[0-9a-fA-F]{64}", f"{label}.pair_anchor.calldata_sha256"),
        "prestate_sha256": _hex(anchor.get("prestate_sha256"), r"[0-9a-fA-F]{64}", f"{label}.pair_anchor.prestate_sha256"),
        "setup_sha256": _hex(anchor.get("setup_sha256"), r"[0-9a-fA-F]{64}", f"{label}.pair_anchor.setup_sha256"),
    }
    predicate = evidence["predicate"]
    if not isinstance(predicate, dict) or predicate.get("id") != manifest["property_id"] or not isinstance(predicate.get("observed"), bool):
        raise AttackEngineError(f"{label}.predicate must identify {manifest['property_id']} and contain a boolean observed value.", "evidence_invalid")
    events = _load_trace_events(evidence["trace_events"], manifest["family"], label)
    return {"role": role, "target": target, "pair_anchor": normalized_anchor,
            "predicate": {"id": predicate["id"], "observed": predicate["observed"]},
            "trace_events": events, "preconditions": preconditions, "raw": evidence}


def validate_evidence_pair(
    attack: Any, control: Any, manifest: dict[str, Any]
) -> dict[str, Any]:
    left = _validate_evidence(attack, manifest=manifest, role="attack", label="attack evidence")
    right = _validate_evidence(control, manifest=manifest, role="control", label="control evidence")
    reproof = _validate_reproof(manifest["reproof"], root=Path(manifest["project_root"]), target=manifest["target"], family=manifest["family"], impact_mode=manifest["impact_mode"], label="independent reproof")
    if left["target"] != right["target"]:
        raise AttackEngineError("Attack and control targets differ.", "control_mismatch")
    if left["pair_anchor"] != right["pair_anchor"]:
        raise AttackEngineError("Attack and control do not share the same entry call, calldata, setup and prestate anchor.", "control_mismatch")
    if left["predicate"]["observed"] is not True:
        raise AttackEngineError("Attack run did not observe the declared family property violation.", "attack_not_observed")
    if right["predicate"]["observed"] is not False:
        raise AttackEngineError("Control run also observed the declared family property violation.", "control_failed")
    return {
        "status": "PAIRED_OBSERVATION",
        "family": manifest["family"],
        "experiment_id": manifest["id"],
        "attack_trace_events": len(left["trace_events"]),
        "control_trace_events": len(right["trace_events"]),
        "pair_anchor": left["pair_anchor"],
        "target": left["target"], "independent_reproof": reproof,
    }


def _run_forge_test(root: Path, test: dict[str, str], timeout: int, *, role: str, run_id: str, experiment_id: str) -> dict[str, Any]:
    forge = shutil.which("forge")
    if not forge:
        raise AttackEngineError("Foundry forge is unavailable; refusing to substitute another backend.", "backend_unsupported")
    evidence = safe_evidence_file(root, test["evidence_file"], f"{role}.evidence_file")
    if evidence.exists():
        evidence.unlink()
    argv = [forge, "test", "--match-path", test["test_file"], "--match-test", test["test_name"], "-vvvv"]
    environment = os.environ.copy()
    environment.update({
        "LOWKEY_EXPERIMENT_ID": experiment_id,
        "LOWKEY_EXPERIMENT_RUN_ID": run_id,
        "LOWKEY_EXPERIMENT_ROLE": role,
        "LOWKEY_EVIDENCE_PATH": evidence.relative_to(root).as_posix(),
    })
    started = time.monotonic()
    try:
        proc = subprocess.run(argv, cwd=root, env=environment, text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=timeout, check=False)
        execution = {"status": "passed" if proc.returncode == 0 else "failed",
                     "exit_code": proc.returncode, "stdout": proc.stdout[-12000:],
                     "stderr": proc.stderr[-12000:]}
    except subprocess.TimeoutExpired as exc:
        execution = {"status": "timeout", "exit_code": None,
                     "stdout": str(exc.stdout or "")[-12000:],
                     "stderr": str(exc.stderr or "")[-12000:]}
    execution["elapsed_seconds"] = round(time.monotonic() - started, 3)
    execution["evidence_path"] = evidence.relative_to(root).as_posix()
    if execution["status"] != "passed":
        return execution
    execution["evidence"] = _json_file(evidence, f"{role} evidence")
    return execution


def _mutation_gate(root: Path, test: dict[str, str], mutants: list[dict[str, str]], timeout: int, run_id: str, experiment_id: str) -> dict[str, Any]:
    try:
        from .behavioral_validation import validate_mutations
    except ImportError:
        from behavioral_validation import validate_mutations
    forge = shutil.which("forge")
    if not forge:
        raise AttackEngineError("Foundry forge is unavailable for mutation reproof.", "backend_unsupported")
    argv = [forge, "test", "--match-path", test["test_file"], "--match-test", test["test_name"], "-vvvv"]
    mutation_env = os.environ.copy()
    mutation_env.update({
        "LOWKEY_EXPERIMENT_ID": experiment_id,
        "LOWKEY_EXPERIMENT_RUN_ID": run_id,
        "LOWKEY_EXPERIMENT_ROLE": "attack",
        "LOWKEY_EVIDENCE_PATH": ".lowkey-mutation-evidence.json",
    })
    result = validate_mutations(
        root, argv, mutants, timeout_seconds=timeout, env=mutation_env
    )
    summary = result.get("summary") or {}
    killed = int(summary.get("killed") or 0)
    if result.get("status") != "completed" or killed < 1 or summary.get("survived", 0) or summary.get("invalid", 0) or summary.get("timeout", 0) or summary.get("error", 0):
        raise AttackEngineError("Mutation gate did not kill every declared mutant after a passing baseline.", "mutation_not_killed")
    return {"status": "MUTATION_KILLED", "summary": summary, "mutation_score": result.get("mutation_score"),
            "run_id": result.get("run_id")}


def run_experiment(value: Any, root: str | Path = ".", *, output_path: str | None = None) -> dict[str, Any]:
    base = project_root(root)
    manifest = validate_experiment_manifest(value, base)
    run_id = hashlib.sha256((manifest["id"] + str(time.time_ns())).encode()).hexdigest()[:20]
    started = time.monotonic()
    attack_run = _run_forge_test(base, manifest["attack"], manifest["timeout_seconds"], role="attack", run_id=run_id, experiment_id=manifest["id"])
    if attack_run["status"] != "passed":
        raise AttackEngineError(f"Attack Forge test did not pass: {attack_run['status']}.", "attack_execution_failed")
    control_run = _run_forge_test(base, manifest["control"], manifest["timeout_seconds"], role="control", run_id=run_id, experiment_id=manifest["id"])
    if control_run["status"] != "passed":
        raise AttackEngineError(f"Control Forge test did not pass: {control_run['status']}.", "control_execution_failed")
    pair = validate_evidence_pair(attack_run["evidence"], control_run["evidence"], manifest)
    mutation = _mutation_gate(base, manifest["attack"], manifest["mutants"], manifest["timeout_seconds"], run_id, manifest["id"])
    report = {
        "schema_version": SCHEMA_VERSION, "run_id": run_id,
        "status": "VERIFIED_LOCAL_EXPERIMENT",
        "scope": "local_foundry_test",
        "family": manifest["family"], "experiment_id": manifest["id"],
        "target": manifest["target"], "pair": pair,
        "attack_execution": {k: v for k, v in attack_run.items() if k != "evidence"},
        "control_execution": {k: v for k, v in control_run.items() if k != "evidence"},
        "mutation": mutation,
        "profitability": "not_claimed",
        "limitations": [
            "A passing local Foundry experiment is not proof against an authentic deployed target.",
            "A source signal or family label is not a vulnerability verdict.",
            "Profitability requires a separate receipt-backed Anvil reproof with all costs measured.",
        ],
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }
    destination = Path(output_path) if output_path else Path(".audit/lowkey/attack-engine") / f"{run_id}.json"
    if destination.is_absolute():
        out = destination.resolve()
        if not out.is_relative_to(base):
            raise AttackEngineError("Report output must stay inside the project.", "out_of_scope")
    else:
        out = (base / destination).resolve()
        if not out.is_relative_to(base):
            raise AttackEngineError("Report output must stay inside the project.", "out_of_scope")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["report_path"] = out.relative_to(base).as_posix()
    return report


def _validate_chain(value: Any, root: Path) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION:
        raise AttackEngineError(f"Chain manifest schema_version must be {SCHEMA_VERSION}.")
    allowed = {"schema_version", "id", "target", "property_id", "impact_mode", "mode", "timeout_seconds",
               "stages", "attack", "control", "failure", "reproof", "mutation"}
    if set(value) - allowed:
        raise AttackEngineError("Unexpected chain fields: " + ", ".join(sorted(set(value) - allowed)))
    chain_id = value.get("id")
    if not isinstance(chain_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,100}", chain_id):
        raise AttackEngineError("chain id must be a stable 3-100 character identifier.")
    target = _validate_target(value.get("target"))
    reproof = value.get("reproof")
    if not isinstance(reproof, dict) or not isinstance(reproof.get("reproof_file"), str):
        raise AttackEngineError("chain reproof.reproof_file must reference an independent fork reproof.", "reproof_missing")
    stages = value.get("stages")
    if not isinstance(stages, list) or not stages or len(stages) > 32 or any(
        not isinstance(item, dict) or item.get("family") not in FAMILIES for item in stages
    ):
        raise AttackEngineError("stages must be a non-empty list of 1-32 supported family objects.")
    impact_mode = value.get("impact_mode", "economic" if any(FAMILIES[item["family"]]["economic"] for item in stages) else "semantic")
    if impact_mode not in {"economic", "semantic"}:
        raise AttackEngineError("chain impact_mode must be economic or semantic.")
    reproof_family = "economic" if impact_mode == "economic" else str(stages[0]["family"])
    _validate_reproof(reproof, root=root, target=target, family=reproof_family, impact_mode=impact_mode, label="chain independent reproof")
    property_id = value.get("property_id")
    if not isinstance(property_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.:-]{3,120}", property_id):
        raise AttackEngineError("chain property_id is required.")
    mode = value.get("mode")
    if mode not in {"single_transaction", "stateful_fork"}:
        raise AttackEngineError("mode must be single_transaction or stateful_fork.")
    timeout = _positive_int(value.get("timeout_seconds", 600), "timeout_seconds")
    if timeout > 3600:
        raise AttackEngineError("timeout_seconds may not exceed 3600.", "resource_limit")
    stages = value.get("stages")
    if not isinstance(stages, list) or not stages or len(stages) > 32:
        raise AttackEngineError("stages must contain 1-32 attack stages.")
    normalized: list[dict[str, Any]] = []
    ids: set[str] = set()
    producers: dict[str, str] = {}
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            raise AttackEngineError(f"stages[{index}] must be an object.")
        allowed_stage = {"id", "family", "discovery", "preconditions", "depends_on", "consumes", "produces", "on_failure", "rollback"}
        if set(stage) != allowed_stage:
            raise AttackEngineError(f"stages[{index}] must contain exactly: " + ", ".join(sorted(allowed_stage)))
        stage_id, family = stage.get("id"), stage.get("family")
        if not isinstance(stage_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{2,80}", stage_id) or stage_id in ids:
            raise AttackEngineError(f"stages[{index}].id is invalid or duplicated.")
        if family not in FAMILIES:
            raise AttackEngineError(f"stages[{index}].family is unsupported.")
        ids.add(stage_id)
        discovery = _validate_discovery(stage.get("discovery"), root, family, f"stages[{index}].discovery")
        preconditions = stage.get("preconditions")
        expected_preconditions = FAMILIES[family]["preconditions"]
        if not isinstance(preconditions, list) or sorted(preconditions) != sorted(expected_preconditions):
            raise AttackEngineError(f"stages[{index}].preconditions must explicitly enumerate the family preconditions: {expected_preconditions}")
        dependencies = stage.get("depends_on", [])
        consumes = stage.get("consumes", [])
        produces = stage.get("produces", [])
        if not all(isinstance(v, list) and all(isinstance(x, str) and x for x in v) for v in (dependencies, consumes, produces)):
            raise AttackEngineError(f"stages[{index}] depends_on/consumes/produces must be arrays of non-empty strings.")
        if len(set(dependencies)) != len(dependencies) or len(set(consumes)) != len(consumes) or len(set(produces)) != len(produces):
            raise AttackEngineError(f"stages[{index}] contains duplicate dependencies or artifacts.")
        policy = stage.get("on_failure")
        rollback = stage.get("rollback")
        if policy not in {"abort", "revert", "restore"}:
            raise AttackEngineError(f"stages[{index}].on_failure must be abort, revert or restore.")
        if rollback not in {"evm_transaction_revert", "anvil_snapshot_revert", "compensating_action"}:
            raise AttackEngineError(f"stages[{index}].rollback is not an explicit supported rollback strategy.")
        if mode == "single_transaction" and rollback != "evm_transaction_revert":
            raise AttackEngineError("single_transaction chains must use evm_transaction_revert for every stage.")
        if mode == "stateful_fork" and rollback not in {"anvil_snapshot_revert", "compensating_action"}:
            raise AttackEngineError("stateful_fork chains require snapshot revert or an explicit compensating action.")
        for artifact in produces:
            if artifact in producers:
                raise AttackEngineError(f"Artifact '{artifact}' is produced by more than one stage.")
            producers[artifact] = stage_id
        normalized.append({"id": stage_id, "family": family, "discovery": discovery,
                           "preconditions": list(preconditions), "depends_on": list(dependencies),
                           "consumes": list(consumes), "produces": list(produces),
                           "on_failure": policy, "rollback": rollback})
    # Topological ordering is deterministic; manifest order is required to equal the
    # valid execution order so logs and trace ranges cannot be silently reordered.
    known: set[str] = set()
    for stage in normalized:
        if any(dependency not in ids for dependency in stage["depends_on"]):
            raise AttackEngineError(f"Stage {stage['id']} references an unknown dependency.")
        if stage["id"] in stage["depends_on"]:
            raise AttackEngineError(f"Stage {stage['id']} cannot depend on itself.")
        if not set(stage["depends_on"]).issubset(known):
            raise AttackEngineError("Stages must be listed in topological order; a dependency must precede its consumer.")
        for artifact in stage["consumes"]:
            producer = producers.get(artifact)
            if producer is None or producer not in known:
                raise AttackEngineError(f"Stage {stage['id']} consumes '{artifact}' before an upstream stage produces it.")
            if producer not in stage["depends_on"] and not any(
                producer in earlier["depends_on"] or earlier["id"] == producer
                for earlier in normalized if earlier["id"] in stage["depends_on"]
            ):
                raise AttackEngineError(f"Stage {stage['id']} must explicitly depend on producer '{producer}'.")
        known.add(stage["id"])
    attack = _validate_test(value.get("attack"), root, "attack")
    control = _validate_test(value.get("control"), root, "control")
    failure = _validate_test(value.get("failure"), root, "failure")
    if len({attack["evidence_file"], control["evidence_file"], failure["evidence_file"]}) != 3:
        raise AttackEngineError("Attack, control and rollback evidence files must be different.")
    mutation_value = value.get("mutation")
    if not isinstance(mutation_value, dict):
        raise AttackEngineError("mutation must be an object.")
    mutants = _validate_mutants(mutation_value.get("mutants"), root)
    return {"schema_version": SCHEMA_VERSION, "id": chain_id, "target": target, "reproof": reproof,
            "property_id": property_id, "impact_mode": impact_mode, "mode": mode, "timeout_seconds": timeout,
            "stages": normalized, "attack": attack, "control": control,
            "failure": failure, "mutants": mutants, "project_root": str(root)}


def validate_chain_manifest(value: Any, root: str | Path = ".") -> dict[str, Any]:
    return _validate_chain(value, project_root(root))


def _validate_chain_evidence(
    evidence: Any, *, manifest: dict[str, Any], role: str
) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise AttackEngineError(f"{role} chain evidence must be an object.", "evidence_invalid")
    required = {"schema_version", "experiment_id", "role", "target", "pair_anchor",
                "predicate", "execution", "stage_results"}
    missing = required - set(evidence)
    if missing:
        raise AttackEngineError(f"{role} chain evidence missing: " + ", ".join(sorted(missing)), "evidence_invalid")
    if evidence["schema_version"] != SCHEMA_VERSION or evidence["experiment_id"] != manifest["id"] or evidence["role"] != role:
        raise AttackEngineError(f"{role} chain evidence identity does not match.", "evidence_mismatch")
    if _validate_target(evidence["target"]) != manifest["target"]:
        raise AttackEngineError(f"{role} chain target does not match the pinned manifest.", "identity_mismatch")
    anchor = evidence["pair_anchor"]
    if not isinstance(anchor, dict):
        raise AttackEngineError(f"{role} pair_anchor must be an object.")
    normalized_anchor = {
        "entry_selector": _hex(anchor.get("entry_selector"), r"0x[0-9a-fA-F]{8}", "entry_selector"),
        "calldata_sha256": _hex(anchor.get("calldata_sha256"), r"[0-9a-fA-F]{64}", "calldata_sha256"),
        "prestate_sha256": _hex(anchor.get("prestate_sha256"), r"[0-9a-fA-F]{64}", "prestate_sha256"),
        "setup_sha256": _hex(anchor.get("setup_sha256"), r"[0-9a-fA-F]{64}", "setup_sha256"),
    }
    predicate = evidence["predicate"]
    if not isinstance(predicate, dict) or predicate.get("id") != manifest["property_id"] or not isinstance(predicate.get("observed"), bool):
        raise AttackEngineError(f"{role} chain predicate is invalid.")
    execution = evidence["execution"]
    if not isinstance(execution, dict) or execution.get("mode") != manifest["mode"] or execution.get("status") != "passed":
        raise AttackEngineError(f"{role} chain execution mode/status is invalid.")
    if manifest["mode"] == "single_transaction" and execution.get("atomic") is not True:
        raise AttackEngineError("single_transaction evidence must explicitly prove atomic execution.")
    tx_hash = _hex(execution.get("tx_hash"), r"0x[0-9a-fA-F]{64}", f"{role}.execution.tx_hash")
    if execution.get("receipt_status") != 1:
        raise AttackEngineError(f"{role} chain receipt did not succeed.", "execution_failed")
    block_number = _positive_int(execution.get("block_number"), f"{role}.execution.block_number", allow_zero=True)
    rows = evidence["stage_results"]
    if not isinstance(rows, list) or len(rows) != len(manifest["stages"]):
        raise AttackEngineError(f"{role} stage_results count does not match the manifest.")
    previous_post = normalized_anchor["prestate_sha256"]
    normalized_stages = []
    for index, (raw, spec) in enumerate(zip(rows, manifest["stages"])):
        if not isinstance(raw, dict) or raw.get("id") != spec["id"] or raw.get("family") != spec["family"] or raw.get("status") != "completed":
            raise AttackEngineError(f"{role} stage {spec['id']} is missing, out of order, or incomplete.")
        pre = _hex(raw.get("prestate_sha256"), r"[0-9a-fA-F]{64}", f"{role}.{spec['id']}.prestate_sha256")
        post = _hex(raw.get("poststate_sha256"), r"[0-9a-fA-F]{64}", f"{role}.{spec['id']}.poststate_sha256")
        if pre != previous_post:
            raise AttackEngineError(f"{role} chain state continuity breaks before stage {spec['id']}.", "chain_state_discontinuity")
        consumed, produced = raw.get("consumed"), raw.get("produced")
        if not isinstance(consumed, list) or not isinstance(produced, list):
            raise AttackEngineError(f"{role} stage {spec['id']} must record consumed and produced artifact names.")
        if sorted(consumed) != sorted(spec["consumes"]) or sorted(produced) != sorted(spec["produces"]):
            raise AttackEngineError(f"{role} stage {spec['id']} artifact flow differs from the manifest.")
        if _hex(raw.get("discovery_sha256"), r"[0-9a-fA-F]{64}", f"{role}.{spec['id']}.discovery_sha256") != spec["discovery"]["source_sha256"]:
            raise AttackEngineError(f"{role} stage {spec['id']} discovery digest differs from the pinned source.", "source_identity_mismatch")
        preconditions = _validate_precondition_evidence(raw.get("preconditions"), spec["family"], f"{role}.{spec['id']}")
        stage_events = _load_trace_events(raw.get("trace_events"), spec["family"], f"{role}.{spec['id']}")
        stage_predicate = raw.get("predicate")
        expected_property = FAMILIES[spec["family"]]["property"]
        if not isinstance(stage_predicate, dict) or stage_predicate.get("id") != expected_property or not isinstance(stage_predicate.get("observed"), bool):
            raise AttackEngineError(f"{role} stage {spec['id']} must record its family-specific predicate.", "stage_predicate_missing")
        if stage_predicate["observed"] is not (role == "attack"):
            raise AttackEngineError(f"{role} stage {spec['id']} has the wrong attack/control predicate outcome.", "stage_predicate_mismatch")
        stage_tx = _hex(raw.get("tx_hash"), r"0x[0-9a-fA-F]{64}", f"{role}.{spec['id']}.tx_hash")
        stage_block = _positive_int(raw.get("block_number"), f"{role}.{spec['id']}.block_number", allow_zero=True)
        if manifest["mode"] == "single_transaction" and (stage_tx != tx_hash or stage_block != block_number):
            raise AttackEngineError("single_transaction stage evidence spans multiple transactions or blocks.")
        if manifest["mode"] == "stateful_fork" and stage_block < block_number:
            raise AttackEngineError("stateful_fork stage block precedes its chain transaction.")
        if FAMILIES[spec["family"]]["economic"] and role == "attack":
            _validate_economic_data(evidence.get("economic"), f"{role} chain economic stage {spec['id']}")
        normalized_stages.append({"id": spec["id"], "family": spec["family"],
                                  "discovery": spec["discovery"], "preconditions": preconditions,
                                  "predicate": stage_predicate,
                                  "prestate_sha256": pre, "poststate_sha256": post,
                                  "trace_events": len(stage_events)})
        previous_post = post
    return {"role": role, "target": manifest["target"], "pair_anchor": normalized_anchor,
            "predicate": predicate, "execution": {"tx_hash": tx_hash, "block_number": block_number,
            "mode": manifest["mode"], "atomic": execution.get("atomic")}, "stages": normalized_stages,
            "raw": evidence}


def validate_chain_evidence_pair(attack: Any, control: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    left = _validate_chain_evidence(attack, manifest=manifest, role="attack")
    right = _validate_chain_evidence(control, manifest=manifest, role="control")
    reproof_family = "economic" if manifest["impact_mode"] == "economic" else manifest["stages"][0]["family"]
    reproof = _validate_reproof(manifest["reproof"], root=Path(manifest["project_root"]), target=manifest["target"], family=reproof_family, impact_mode=manifest["impact_mode"], label="chain independent reproof")
    if left["pair_anchor"] != right["pair_anchor"]:
        raise AttackEngineError("Attack/control chains do not share the same pinned starting state and entry call.", "control_mismatch")
    if left["predicate"].get("observed") is not True:
        raise AttackEngineError("Attack chain did not observe the declared impact.", "attack_not_observed")
    if right["predicate"].get("observed") is not False:
        raise AttackEngineError("Control chain also observed the declared impact.", "control_failed")
    return {"status": "CHAIN_PAIRED", "mode": manifest["mode"], "stage_count": len(manifest["stages"]),
            "attack_stages": left["stages"], "control_stages": right["stages"],
            "target": manifest["target"], "pair_anchor": left["pair_anchor"], "independent_reproof": reproof}


def validate_failure_rollback(evidence: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(evidence, dict) or evidence.get("schema_version") != SCHEMA_VERSION:
        raise AttackEngineError("Rollback evidence schema is invalid.")
    if evidence.get("experiment_id") != manifest["id"] or evidence.get("role") != "failure":
        raise AttackEngineError("Rollback evidence identity/role does not match.")
    if _validate_target(evidence.get("target")) != manifest["target"]:
        raise AttackEngineError("Rollback target identity does not match.", "identity_mismatch")
    failure = evidence.get("failure_injection")
    if not isinstance(failure, dict) or failure.get("executed") is not True:
        raise AttackEngineError("Failure-injection test was not executed.")
    stage = next((item for item in manifest["stages"] if item["id"] == failure.get("failed_stage")), None)
    if stage is None:
        raise AttackEngineError("Failure-injection evidence names an unknown stage.")
    if failure.get("on_failure") != stage["on_failure"] or failure.get("rollback_strategy") != stage["rollback"]:
        raise AttackEngineError("Failure-injection evidence does not match the failed stage policy/rollback declaration.")
    before = _hex(failure.get("prestate_sha256"), r"[0-9a-fA-F]{64}", "failure.prestate_sha256")
    after = _hex(failure.get("poststate_sha256"), r"[0-9a-fA-F]{64}", "failure.poststate_sha256")
    if failure.get("rollback_strategy") == "evm_transaction_revert":
        if failure.get("transaction_reverted") is not True or before != after:
            raise AttackEngineError("Atomic EVM failure did not revert all prior stage effects.", "rollback_failed")
    elif failure.get("rollback_strategy") == "anvil_snapshot_revert":
        if failure.get("snapshot_reverted") is not True or before != after:
            raise AttackEngineError("Anvil snapshot rollback did not restore the original state.", "rollback_failed")
    elif failure.get("rollback_strategy") == "compensating_action":
        if failure.get("compensation_verified") is not True or failure.get("residual_delta") not in (0, "0", "0x0"):
            raise AttackEngineError("Compensating action left an unverified residual state delta.", "rollback_failed")
    return {"status": "ROLLBACK_VERIFIED", "failed_stage": failure["failed_stage"],
            "strategy": failure["rollback_strategy"]}


def run_chain(value: Any, root: str | Path = ".", *, output_path: str | None = None) -> dict[str, Any]:
    base = project_root(root)
    manifest = validate_chain_manifest(value, base)
    run_id = hashlib.sha256((manifest["id"] + str(time.time_ns())).encode()).hexdigest()[:20]
    attack_run = _run_forge_test(base, manifest["attack"], manifest["timeout_seconds"], role="attack", run_id=run_id, experiment_id=manifest["id"])
    if attack_run["status"] != "passed":
        raise AttackEngineError("Attack chain test did not pass.", "attack_execution_failed")
    control_run = _run_forge_test(base, manifest["control"], manifest["timeout_seconds"], role="control", run_id=run_id, experiment_id=manifest["id"])
    if control_run["status"] != "passed":
        raise AttackEngineError("Control chain test did not pass.", "control_execution_failed")
    failure_run = _run_forge_test(base, manifest["failure"], manifest["timeout_seconds"], role="failure", run_id=run_id, experiment_id=manifest["id"])
    if failure_run["status"] != "passed":
        raise AttackEngineError("Failure-injection/rollback test did not pass.", "rollback_failed")
    pair = validate_chain_evidence_pair(attack_run["evidence"], control_run["evidence"], manifest)
    rollback = validate_failure_rollback(failure_run["evidence"], manifest)
    mutation = _mutation_gate(base, manifest["attack"], manifest["mutants"], manifest["timeout_seconds"], run_id, manifest["id"])
    report = {"schema_version": SCHEMA_VERSION, "run_id": run_id,
              "status": "VERIFIED_LOCAL_ATTACK_CHAIN", "scope": "local_foundry_test",
              "chain_id": manifest["id"], "mode": manifest["mode"],
              "target": manifest["target"], "pair": pair, "rollback": rollback,
              "mutation": mutation,
              "limitations": [
                  "The chain is executable only through its explicit target-specific Foundry adapter.",
                  "A local/fork test is not a broadcast transaction or a mined exploit reproduction.",
                  "Only measured, receipt-backed net profit may be called profitable.",
              ]}
    destination = Path(output_path) if output_path else Path(".audit/lowkey/attack-chains") / f"{run_id}.json"
    out = (base / destination).resolve() if not destination.is_absolute() else destination.resolve()
    if not out.is_relative_to(base):
        raise AttackEngineError("Chain report output must stay inside the project.", "out_of_scope")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["report_path"] = out.relative_to(base).as_posix()
    return report


def _load_manifest(path: str, root: Path) -> dict[str, Any]:
    manifest_path = safe_relative_file(root, path, "manifest")
    return _json_file(manifest_path, "manifest")


def _emit(value: Any) -> int:
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="lk attack", description="Evidence-gated attack-family and attack-chain engine.")
    sub = parser.add_subparsers(dest="command")
    inventory = sub.add_parser("engines", help="List executable family strategy contracts and acceptance requirements.")
    inventory.add_argument("--json", action="store_true")
    discover = sub.add_parser("discover", help="Find source-level family leads; never returns a vulnerability verdict.")
    discover.add_argument("--root", default=".")
    discover.add_argument("--family", choices=FAMILY_NAMES)
    discover.add_argument("--json", action="store_true")
    verify = sub.add_parser("verify", help="Run a paired attack/control Foundry experiment, evidence checks and mutation gate.")
    verify.add_argument("manifest")
    verify.add_argument("--root", default=".")
    verify.add_argument("--output")
    chain = sub.add_parser("chain", help="Validate or execute a multi-stage attack-chain specification.")
    chain.add_argument("action", choices=("validate", "run"))
    chain.add_argument("manifest")
    chain.add_argument("--root", default=".")
    chain.add_argument("--output")
    if not args or args[0] in {"-h", "--help", "help"}:
        parser.print_help()
        return 0
    try:
        ns = parser.parse_args(args)
        if ns.command == "engines":
            return _emit({"schema_version": SCHEMA_VERSION, "families": family_inventory()}) if ns.json else _print_inventory()
        if ns.command == "discover":
            result = discover_candidates(ns.root, ns.family)
            return _emit(result) if ns.json else _print_discovery(result)
        if ns.command == "verify":
            root = project_root(ns.root)
            value = _load_manifest(ns.manifest, root)
            return _emit(run_experiment(value, root, output_path=ns.output))
        if ns.command == "chain":
            root = project_root(ns.root)
            value = _load_manifest(ns.manifest, root)
            if ns.action == "validate":
                result = validate_chain_manifest(value, root)
                return _emit({"status": "VALIDATED_NOT_EXECUTED", "chain_id": result["id"],
                              "mode": result["mode"], "stages": result["stages"],
                              "execution": "No commands, RPC calls or transactions were run."})
            return _emit(run_chain(value, root, output_path=ns.output))
        parser.print_help()
        return 0
    except AttackEngineError as exc:
        print(json.dumps({"status": "REFUSED", "reason": exc.reason, "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    except (OSError, RuntimeError, ValueError) as exc:
        print(json.dumps({"status": "ERROR", "reason": "execution_error", "detail": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


def _print_inventory() -> int:
    rows = family_inventory()
    print("LOWKEY ATTACK STRATEGY ENGINE")
    print("=============================")
    for row in rows:
        print(f"{row['family']:14} [{row['status']:17}] {row['title']}")
        print(f"  {row['strategy']}")
    print("\nFamily status is not an exploit verdict; target adapters still need paired acceptance.")
    return 0


def _print_discovery(result: dict[str, Any]) -> int:
    print("LOWKEY ATTACK DISCOVERY — CANDIDATES ONLY")
    print(f"Files scanned: {result['files_scanned']}")
    for candidate in result["candidates"]:
        print(f"\n[{candidate['family']}] {candidate['file']} — CANDIDATE")
        for match in candidate["matches"][:8]:
            print(f"  L{match['line']}: {match['excerpt']}")
    print("\nStatic signals are leads, not proof of exploitability.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
