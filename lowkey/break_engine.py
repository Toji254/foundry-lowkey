"""
Lowkey adversarial red-team engine.

Mission:
    Do not declare findings from static patterns alone. Build and execute isolated
    local attack experiments, stop on a concrete break condition, and leave an
    auditable evidence trail.

Research profile:
    The attack-family taxonomy is informed by public Immunefi common-vulnerability
    guidance, Immunefi bug-fix reviews, Cyfrin/CodeHawks contest submissions, and
    Solodit's public finding taxonomy. These sources describe recurring classes,
    not a guarantee that every protocol can be attacked generically.

Safety boundary:
    This engine requires Lowkey to detect an Anvil RPC. It never sends transactions
    to an arbitrary production RPC through this command. Users can attack a fork
    by running Anvil locally and pointing Lowkey at that local node.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

try:
    from break_playbook import (
        FINDING_PATTERNS,
        backend_for_project,
        catalog_summary,
        family_names,
        language_label,
        patterns_for,
        native_probe_commands,
    )
except ImportError:
    FINDING_PATTERNS = ()
    def backend_for_project(info):
        return "generic"
    def catalog_summary(project=None):
        return {"total_patterns": 0, "relevant_patterns": [], "families": []}
    def family_names(patterns):
        return []
    def language_label(info):
        return "unknown"
    def patterns_for(*, project=None, function_name="", source_text=""):
        return []
    def native_probe_commands(info):
        return []


ATTACK_FAMILIES = {
    "reentrancy": {
        "title": "Reentrancy / callback abuse",
        "basis": "external calls, ETH transfer, token/NFT callbacks",
        "priority": 1,
    },
    "replay": {
        "title": "Replay / repeat-claim abuse",
        "basis": "claim, withdraw, redeem, release, payout and state-transition paths",
        "priority": 2,
    },
    "access": {
        "title": "Access-control bypass",
        "basis": "privileged operations callable by an untrusted actor",
        "priority": 3,
    },
    "accounting": {
        "title": "Accounting / value extraction",
        "basis": "asset conservation, duplicate payout, unexpected ETH movement",
        "priority": 4,
    },
    "boundary": {
        "title": "Boundary / input abuse",
        "basis": "zero, one, max integers, empty bytes/strings, false/zero addresses",
        "priority": 5,
    },
    "time": {
        "title": "Time / block-dependence",
        "basis": "timestamp, block number/hash, prevrandao and deadline assumptions",
        "priority": 6,
    },
    "upgrade": {
        "title": "Initialization / upgrade abuse",
        "basis": "initialize, proxy, admin, implementation, upgrade and setup paths",
        "priority": 7,
    },
    "callback": {
        "title": "External callback / return-value abuse",
        "basis": "arbitrary recipients, low-level calls and callback surfaces",
        "priority": 8,
    },
    "oracle": {
        "title": "Oracle / price manipulation",
        "basis": "staleness, manipulable spot prices, feed assumptions and price-dependent accounting",
        "priority": 10,
    },
    "economic": {
        "title": "Economic / flash-loan-shaped abuse",
        "basis": "temporary capital, invariant breaks across pools, fees, rewards and collateral",
        "priority": 11,
    },
    "erc20": {
        "title": "Non-standard token integration abuse",
        "basis": "fee-on-transfer, rebasing, false-returning, callback and allowance assumptions",
        "priority": 12,
    },
    "proxy": {
        "title": "Proxy / implementation / storage abuse",
        "basis": "delegatecall context, initialization, upgrade authority and storage assumptions",
        "priority": 13,
    },
    "storage": {
        "title": "Storage corruption / invariant drift",
        "basis": "state-slot assumptions, packed storage, mappings and cross-contract state",
        "priority": 14,
    },
    "signature": {
        "title": "Signature / nonce / authorization replay",
        "basis": "permit/execute/meta-tx style surfaces and replayable calldata",
        "priority": 9,
    },
    "dos": {
        "title": "Denial-of-service / griefing",
        "basis": "repeated execution, pathological inputs and lockup surfaces",
        "priority": 10,
    },
}

SENSITIVE_RE = re.compile(
    r"(?i)(^|_)(owner|admin|upgrade|implementation|initialize|init|"
    r"pause|unpause|set|configure|config|grant|revoke|renounce|"
    r"rescue|sweep|emergency|withdraw|claim|redeem|release|unlock|"
    r"payout|collect|harvest|mint|burn|execute|delegate|oracle|"
    r"price|fee|limit|guardian)(_|$)"
)

CLAIM_RE = re.compile(
    r"(?i)(withdraw|claim|redeem|release|unlock|payout|collect|harvest|"
    r"refund|rescue|sweep|emergency|execute)"
)

UPGRADE_RE = re.compile(
    r"(?i)(initialize|upgrade|implementation|admin|beacon|proxy|"
    r"proxiable|setimplementation|upgradeToAndCall)"
)

TIME_RE = re.compile(r"(?i)(timestamp|deadline|expiry|expiration|epoch|blocknumber|random|seed)")

SIGNATURE_RE = re.compile(
    r"(?i)(permit|signature|sig|execute|meta|nonce|authorization|auth)"
)

CALLBACK_RE = re.compile(r"(?i)(callback|hook|receiver|fallback|receive|on[A-Z])")
PRIVILEGED_RE = re.compile(
    r"(?i)(owner|admin|guardian|pause|unpause|upgrade|initialize|grant|revoke|"
    r"renounce|setOwner|transferOwnership|acceptOwnership|rescue|sweep|"
    r"emergency|configure|set[A-Za-z]+|upgradeToAndCall|proxiable|"
    r"withdraw|claim|redeem|release|unlock|payout|collect|harvest)"
)
SETUP_RE = re.compile(r"(?i)^(deposit|seed|fund|topUp|top_up|stake|credit)$")


@dataclass
class Target:
    contract: str
    address: str
    artifact: str | None = None
    source: str = "current target"


@dataclass
class AttackResult:
    family: str
    contract: str
    address: str
    function: str | None
    status: str
    summary: str
    evidence_path: str | None = None
    break_condition: bool = False
    detail: dict[str, Any] | None = None


def _slug(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_]+", "_", str(value or "target"))
    safe = safe.strip("_") or "target"
    return safe[:100]


def _root(host) -> Path:
    return Path(host.audit_context.foundry_project_root()).expanduser().resolve()


def _effective_source_languages(root: Path, detected: dict[str, Any]) -> dict[str, int]:
    """Count first-party source languages while excluding generated/dependency trees."""
    counts: dict[str, int] = {}
    excluded = {".git", ".audit", "out", "build", "cache", "node_modules", "lib", "script", "scripts", "test", "tests", "mock", "mocks", "fixtures"}
    extensions = {
        ".sol": "solidity",
        ".vy": "vyper",
        ".cairo": "cairo",
        ".move": "move",
        ".rs": "rust",
        ".huff": "huff",
        ".yul": "yul",
    }
    try:
        for path in root.rglob("*"):
            if not path.is_file() or any(part in excluded for part in path.relative_to(root).parts[:-1]):
                continue
            language = extensions.get(path.suffix.lower())
            if language:
                counts[language] = counts.get(language, 0) + 1
    except OSError:
        pass
    return counts or {
        str(key): int(value)
        for key, value in ((detected.get("languages") or {}) if isinstance(detected.get("languages"), dict) else {}).items()
    }


def _project_break_context(host) -> dict[str, Any]:
    """Detect the active project/workspace and derive its breaker backend."""
    root = _root(host)
    try:
        from project_detection import detect_project
        info = detect_project(root)
    except Exception as exc:
        info = {
            "root": str(root),
            "kind": "unknown",
            "backend": "generic",
            "stacks": [],
            "languages": {},
            "native": {},
            "detection_error": str(exc),
        }
    info["effective_languages"] = _effective_source_languages(root, info)
    info["break_backend"] = backend_for_project(info)
    info["break_catalog"] = catalog_summary(info)
    return info


def _language_features(root: Path, info: dict[str, Any]) -> list[str]:
    """Collect language-specific source cues without assuming Solidity syntax."""
    features: list[str] = []
    languages = set(str(x).lower() for x in (info.get("languages") or {}).keys())
    if "vyper" in languages:
        patterns = {
            "@external": "external entry points",
            "@internal": "internal entry points",
            "@view": "view functions",
            "@pure": "pure functions",
            "@nonreentrant": "reentrancy guard",
            "raw_call": "raw_call external interaction",
            "extcall": "extcall external interaction",
            "send(": "native ETH send",
            "raw_log": "low-level event logging",
        }
        for path in root.rglob("*.vy"):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for needle, label in patterns.items():
                if needle in text and label not in features:
                    features.append(label)
            if len(features) >= 12:
                break
    if "cairo" in languages:
        features.append("Cairo entrypoints/storage are language-native; use Starknet tooling")
    if "move" in languages:
        features.append("Move entry functions/resources are language-native; use chain-native tests")
    if "rust" in languages and any("anchor" in str(x).lower() for x in (info.get("stacks") or [])):
        features.append("Anchor program instructions/accounts are language-native; use local-validator tests")
    return features


def _break_root(host) -> Path:
    path = _root(host) / ".audit" / "break"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _runs_root(host) -> Path:
    path = _break_root(host) / "runs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _write_json(host, name: str, payload: dict[str, Any]) -> Path:
    stamp = time.strftime("%Y%m%d_%H%M%S")
    digest = hashlib.sha1(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:10]
    path = _runs_root(host) / f"{stamp}_{_slug(name)}_{digest}.json"
    path.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")
    return path


def _emit(host, event: str, summary: str, data: dict[str, Any] | None = None):
    try:
        host.audit_context.emit(
            event,
            _root(host),
            tool="break",
            status="completed",
            summary=summary,
            data=data or {},
        )
    except Exception:
        pass


def _require_anvil(host, config) -> str:
    info = host.anvil_rpc_info(config)
    if not info:
        raise RuntimeError(
            "lk break is local-red-team mode and requires a detected Anvil node. "
            "Start 'anvil' or run 'lk fork <RPC>' first."
        )
    rpc = info.get("url") or host.effective_rpc(config)
    if not rpc:
        raise RuntimeError("Anvil was detected but no RPC URL is available.")
    return str(rpc)


def _is_state_changing(fn: dict[str, Any]) -> bool:
    return str(fn.get("stateMutability") or "").lower() not in {"view", "pure"}


def _function_name(signature: str) -> str:
    return str(signature).split("(", 1)[0]


def _function_matches(fn: dict[str, Any], query: str) -> bool:
    name = str(fn.get("name") or "")
    signature = str(query or "")
    if "(" in signature:
        return _format_signature(fn) == signature
    return name.lower() == signature.lower()


def _format_signature(fn: dict[str, Any], host=None) -> str:
    if host is not None:
        try:
            return host.format_signature(fn)
        except Exception:
            pass
    inputs = fn.get("inputs") or []
    types = ",".join(str(item.get("type") or "") for item in inputs)
    return f"{fn.get('name') or 'unknown'}({types})"


def _abi_for(host, config, address: str):
    probe_cfg = dict(config)
    probe_cfg["target"] = address
    try:
        abi = host.load_abi(address, probe_cfg)
    except Exception:
        abi = None
    return abi or []


def _target_from_config(host, config) -> list[Target]:
    result: list[Target] = []
    seen: set[str] = set()

    current = config.get("target")
    current_contract = config.get("target_contract") or "Target"
    if host.is_address(current):
        artifact = (config.get("abi_paths") or {}).get(current)
        result.append(Target(str(current_contract), current, artifact, "current target"))
        seen.add(str(current).lower())

    def add(contract, address, artifact=None, source="saved target"):
        if not host.is_address(address):
            return
        key = str(address).lower()
        if key in seen:
            return
        seen.add(key)
        result.append(Target(str(contract or "Target"), str(address), artifact, source))

    for key, entry in (config.get("targets") or {}).items():
        if isinstance(entry, dict):
            add(
                entry.get("contract") or entry.get("name") or key,
                entry.get("address"),
                entry.get("artifact"),
                "saved target",
            )
        elif host.is_address(entry):
            add(key, entry, None, "saved target")

    # Project audit targets and deployments are useful when --system is requested.
    try:
        system = getattr(host, "system_model", None)
        if system is not None:
            manifest, _ = system.refresh_manifest(
                _root(host),
                rpc=host.effective_rpc(config),
                config=config,
                reason="lk break target discovery",
            )
            for item in manifest.get("deployments") or []:
                if isinstance(item, dict) and item.get("live"):
                    add(
                        item.get("contract"),
                        item.get("address"),
                        item.get("artifact"),
                        "system deployment",
                    )
            for item in manifest.get("audit_targets") or []:
                if isinstance(item, dict):
                    add(
                        item.get("contract") or item.get("name") or "Target",
                        item.get("target") or item.get("address"),
                        item.get("artifact"),
                        "system audit target",
                    )
    except Exception:
        pass

    return result


def _discover_functions(host, config, target: Target) -> list[dict[str, Any]]:
    probe_cfg = dict(config)
    probe_cfg["target"] = target.address
    if target.artifact:
        probe_cfg.setdefault("abi_paths", {})
        probe_cfg["abi_paths"] = dict(probe_cfg["abi_paths"])
        probe_cfg["abi_paths"][target.address] = target.artifact
    abi = _abi_for(host, probe_cfg, target.address)
    functions = [fn for fn in abi if isinstance(fn, dict) and fn.get("type") == "function"]
    return functions


def _score_function(fn: dict[str, Any]) -> tuple[int, str]:
    name = str(fn.get("name") or "")
    signature = _format_signature(fn)
    score = 100
    if CLAIM_RE.search(name):
        score -= 45
    if SENSITIVE_RE.search(name):
        score -= 30
    if UPGRADE_RE.search(name):
        score -= 30
    if CALLBACK_RE.search(name):
        score -= 10
    if SIGNATURE_RE.search(name):
        score -= 10
    if TIME_RE.search(name):
        score -= 8
    if str(fn.get("stateMutability") or "") in {"view", "pure"}:
        score += 100
    return score, signature


def _ordered_functions(functions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    unique = {}
    for fn in functions:
        unique[_format_signature(fn)] = fn
    return sorted(unique.values(), key=_score_function)


def _parse_args(args: list[str]):
    opts = {
        "function": None,
        "family": None,
        "pattern": None,
        "catalog": False,
        "system": False,
        "auto": False,
        "until_found": False,
        "max_rounds": 1,
        "fund_target": None,
        "depth": 3,
        "seed": 1337,
        "quiet": False,
    }
    positionals = []
    i = 0
    while i < len(args):
        item = str(args[i])
        low = item.lower()
        if low in {"--help", "-h", "--h", "help"}:
            opts["help"] = True
            i += 1
            continue
        if low in {"--system", "system"}:
            opts["system"] = True
            i += 1
            continue
        if low in {"--auto"}:
            opts["auto"] = True
            i += 1
            continue
        if low in {"--until-found", "--indefinite", "-u"}:
            opts["until_found"] = True
            i += 1
            continue
        if low in {"--function", "--fn"}:
            if i + 1 >= len(args):
                raise ValueError(f"{item} needs a function name/signature.")
            opts["function"] = str(args[i + 1])
            i += 2
            continue
        if low in {"--catalog", "--patterns"}:
            opts["catalog"] = True
            i += 1
            continue
        if low in {"--pattern", "--finding"}:
            if i + 1 >= len(args):
                raise ValueError(f"{item} needs a finding-pattern id.")
            opts["pattern"] = str(args[i + 1]).upper()
            i += 2
            continue
        if low == "--family":
            if i + 1 >= len(args):
                raise ValueError("--family needs a family name.")
            opts["family"] = str(args[i + 1]).lower()
            i += 2
            continue
        if low in {"--rounds", "--iterations", "--max-rounds"}:
            if i + 1 >= len(args):
                raise ValueError(f"{item} needs a number.")
            opts["max_rounds"] = max(1, int(args[i + 1]))
            i += 2
            continue
        if low == "--fund-target":
            if i + 1 >= len(args):
                raise ValueError("--fund-target needs an amount such as 10ether.")
            opts["fund_target"] = str(args[i + 1])
            i += 2
            continue
        if low == "--depth":
            if i + 1 >= len(args):
                raise ValueError("--depth needs a number.")
            opts["depth"] = max(1, min(10, int(args[i + 1])))
            i += 2
            continue
        if low == "--seed":
            if i + 1 >= len(args):
                raise ValueError("--seed needs an integer.")
            opts["seed"] = int(args[i + 1])
            i += 2
            continue
        if low == "--quiet":
            opts["quiet"] = True
            i += 1
            continue
        if item.startswith("-"):
            raise ValueError(f"Unknown lk break option: {item}")
        positionals.append(item)
        i += 1

    if opts["function"] is None and positionals:
        # Friendly shorthand: lk break withdraw
        opts["function"] = positionals[0]
    if opts["family"] is None and len(positionals) > 1:
        opts["family"] = positionals[1].lower()
    return opts


def help_text() -> str:
    return """LOWKEY HELP  •  lk break
========================================================================
What it does: Runs local adversarial experiments whose sole mission is to
              make the selected contract/system violate a concrete property.
              A static warning is never treated as a break.

WHEN TO USE
  Use it after lk lab / lk audit when you want Lowkey to attack assumptions
  instead of merely listing them.

USAGE
  lk break
  lk break <function>
  lk break --function '<signature>'
  lk break --family reentrancy
  lk break --pattern REENT-001
  lk break --system
  lk break --until-found
  lk break --function withdraw --until-found
  lk break --system --until-found

ATTACK FAMILIES
  reentrancy    callbacks, recipient contracts, nested calls
  replay        repeated claim/withdraw/redeem/release execution
  access        untrusted caller against privileged-looking functions
  accounting    ETH conservation and unexpected value extraction
  boundary      zero/one/max and empty/malformed edge inputs
  time          timestamp/block/deadline sensitivity
  upgrade       initializer/admin/implementation paths
  callback      hostile external-call behavior and return handling
  signature     permit/meta-tx/nonce/replay-shaped surfaces
  dos           repeated/pathological execution and griefing probes
  oracle        oracle/price dependency probes
  economic      economic and flash-loan-shaped probes
  erc20         non-standard token assumption probes
  proxy         proxy/initialization/implementation probes
  storage       storage/invariant probes

MODES
  --pattern ID  Attack using the family mapped from a recurring finding pattern.
                IDs come from Lowkey's cross-language public-finding playbook.
  --catalog      Print the public-finding logic catalog and exit.
  --system      Attack every live target Lowkey knows for this project/system.
  --until-found Continue rounds until a concrete break condition is reached
                or you stop the process with Ctrl-C.
  --rounds N    Bound the number of rounds when not using --until-found.
  --depth N     Maximum reentrant callback depth for the local harness.
  --fund-target 10ether
                Fund the target only inside the disposable Forge fork.
                This is useful for withdrawal/reserve experiments.

SAFETY
  lk break requires a detected Anvil node. It does not send production
  transactions. The engine executes generated Forge experiments against the
  local node state and keeps experiments isolated with Forge fork snapshots.

OUTPUT
  WHAT / ATTACK / RESULT / BREAK CONDITION / EVIDENCE
  A concrete break stops --until-found immediately and is recorded under
  .audit/break/. Non-EVM projects are routed to their native test toolchain;
  Lowkey never pretends a generic EVM harness proves a Cairo/Move/Anchor bug.
"""


def _anvil_accounts(host, config) -> list[str]:
    try:
        info = host.anvil_rpc_info(config)
        accounts = info.get("accounts", []) if isinstance(info, dict) else []
        return [x for x in accounts if host.is_address(x)]
    except Exception:
        return []


def _make_value(host, fn: dict[str, Any], rng: random.Random, mode: str, config=None) -> list[str]:
    args = []
    accounts = _anvil_accounts(host, config or {})
    fallback = accounts[0] if accounts else "0x" + "11" * 20
    for item in fn.get("inputs") or []:
        ptype = str(item.get("type") or "").lower()
        if ptype == "address":
            if mode == "zero":
                args.append("0x0000000000000000000000000000000000000000")
            elif mode == "one" and len(accounts) > 1:
                args.append(accounts[1])
            else:
                args.append(fallback)
        elif ptype == "bool":
            args.append("true" if mode == "one" else "false")
        elif ptype.startswith("uint"):
            bits = 256
            m = re.match(r"uint(\d+)", ptype)
            if m:
                bits = int(m.group(1))
            if mode == "zero":
                args.append("0")
            elif mode == "max":
                args.append(str((1 << bits) - 1))
            elif mode == "one":
                args.append("1")
            else:
                choices = [0, 1, 2, 10]
                args.append(str(rng.choice(choices)))
        elif ptype.startswith("int"):
            bits = 256
            m = re.match(r"int(\d+)", ptype)
            if m:
                bits = int(m.group(1))
            if mode == "zero":
                args.append("0")
            elif mode == "max":
                args.append(str((1 << (bits - 1)) - 1))
            elif mode == "one":
                args.append("1")
            else:
                args.append(str(rng.choice([-1, 0, 1, 2])))
        elif ptype == "bytes":
            args.append("0x" if mode != "one" else "0x01")
        elif ptype.startswith("bytes"):
            n = int(ptype[5:] or "1")
            args.append("0x" + ("00" * n if mode != "one" else ("01" * n)))
        elif ptype == "string":
            args.append("lowkey" if mode == "one" else "")
        elif ptype.endswith("[]"):
            # Empty dynamic arrays are valid ABI values and are intentionally useful
            # for probing missing non-empty constraints.
            args.append("[]")
        elif ptype.startswith("tuple"):
            # Generic tuple/struct values are protocol-specific; do not fabricate
            # an apparently valid tuple that could produce misleading evidence.
            raise ValueError("tuple/struct argument requires a protocol-specific generator")
        else:
            args.append("0")
    return args


def _encode_call(host, config, target: Target, fn: dict[str, Any], values: list[str]):
    signature = _format_signature(fn, host)
    probe_cfg = dict(config)
    probe_cfg["target"] = target.address
    if target.artifact:
        probe_cfg.setdefault("abi_paths", {})
        probe_cfg["abi_paths"] = dict(probe_cfg["abi_paths"])
        probe_cfg["abi_paths"][target.address] = target.artifact
    try:
        _, calldata = host.encode_target_call(probe_cfg, signature, values)
    except Exception as error:
        return None, str(error)
    return calldata, None


def _solidity_amount_literal(value: str) -> str:
    """Normalize Lowkey's compact amount syntax into a Solidity amount literal."""
    raw = str(value or "").strip()
    match = re.fullmatch(
        r"([0-9]+(?:\.[0-9]+)?)\s*(wei|gwei|szabo|finney|ether)",
        raw,
        flags=re.I,
    )
    if not match:
        raise ValueError(
            "Invalid --fund-target amount. Use a numeric Solidity unit such as "
            "1ether, 10ether, 500gwei, or 1000000wei."
        )
    number, unit = match.groups()
    return f"{number} {unit.lower()}"

def _payable_value(fn: dict[str, Any], opts, mode="normal") -> str:
    if str(fn.get("stateMutability") or "") != "payable":
        return "0"
    if mode == "zero":
        return "0"
    if mode == "small":
        return "1wei"
    if opts.get("fund_target"):
        # Keep call value separate from optional target reserve funding.
        return "1wei"
    return "1wei"


def _evm_runner(project_info: dict[str, Any], root: Path) -> str:
    """Select an execution runner instead of equating EVM with Foundry."""
    stacks = {str(x).lower() for x in (project_info.get("stacks") or [])}
    manifests = project_info.get("manifests") or {}
    native = project_info.get("native") or {}
    if "foundry" in stacks and native.get("forge"):
        return "foundry"
    if "hardhat" in stacks and native.get("hardhat"):
        return "hardhat"
    if "vyper" in stacks:
        # A Vyper project may be driven by pytest/Boa/Titanoboa/Ape rather than Foundry.
        if native.get("pytest") or native.get("boa") or native.get("ape"):
            return "vyper-native"
        if native.get("forge") and manifests.get("foundry"):
            return "foundry"
        return "vyper-native"
    return "evm-native"


def _forge_run(host, config, source_path: str, rpc: str, project_info: dict[str, Any] | None = None):
    root = _root(host)
    project_info = project_info or {}
    if _evm_runner(project_info, root) != "foundry":
        raise RuntimeError(
            "This EVM project is not configured for a Forge breaker. "
            "Lowkey routed it to its native runner instead of inventing a Forge project."
        )
    forge = host.tool_path("forge") if hasattr(host, "tool_path") else "forge"
    if not forge:
        raise RuntimeError("forge was not found on PATH.")
    try:
        match_path = Path(source_path).resolve().relative_to(root).as_posix()
    except ValueError:
        match_path = Path(source_path).as_posix()

    # Forge's --match-path is evaluated against project-relative paths. Passing
    # the absolute temporary harness path can make Forge execute zero tests,
    # which then gets misclassified as a generic BLOCKED result.
    cmd = [
        forge,
        "test",
        "--match-path",
        match_path,
        "--fork-url",
        rpc,
        "-vvv",
    ]
    completed = subprocess.run(
        cmd,
        cwd=str(root),
        capture_output=True,
        text=True,
    )

    # Generated adversarial harnesses can accumulate enough local observables to
    # trigger Solidity's legacy stack-depth limit. Retry only that compiler failure
    # through Foundry's IR pipeline; never alter the user's project config.
    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    if completed.returncode != 0 and "Stack too deep" in output:
        ir_cmd = [
            forge,
            "test",
            "--match-path",
            match_path,
            "--fork-url",
            rpc,
            "--via-ir",
            "--optimize",
            "-vvv",
        ]
        ir_completed = subprocess.run(
            ir_cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        return ir_completed

    return completed


def _cast_binary(host) -> str:
    cast = host.tool_path("cast") if hasattr(host, "tool_path") else None
    if cast:
        return cast
    return "cast"


def _cast_exec(host, args: list[str], rpc: str):
    cmd = [_cast_binary(host), *args, "--rpc-url", rpc]
    return subprocess.run(cmd, cwd=str(_root(host)), capture_output=True, text=True)


def _cast_int(text_value: str) -> int:
    raw = str(text_value or "").strip()
    match = re.search(r"0x[0-9a-fA-F]+|\\d+", raw)
    if not match:
        return 0
    token = match.group(0)
    return int(token, 16) if token.lower().startswith("0x") else int(token)


def _cast_snapshot(host, rpc: str):
    result = _cast_exec(host, ["rpc", "evm_snapshot"], rpc)
    if result.returncode != 0:
        result = _cast_exec(host, ["rpc", "anvil_snapshot"], rpc)
    if result.returncode != 0:
        return None
    return (result.stdout or "").strip().splitlines()[-1] if result.stdout else None


def _cast_revert(host, rpc: str, snapshot: str | None):
    if not snapshot:
        return
    _cast_exec(host, ["rpc", "evm_revert", snapshot], rpc)


def _cast_balance(host, rpc: str, address: str) -> int:
    result = _cast_exec(host, ["balance", address], rpc)
    return _cast_int(result.stdout)


def _cast_send(
    host,
    rpc: str,
    target: Target,
    calldata: str,
    value: str,
    actor: str,
):
    value_arg = value if value not in {"0", "0wei"} else "0"
    args = [
        "send",
        target.address,
        "--data", calldata,
        "--unlocked",
        "--from", actor,
        "--value", value_arg,
    ]
    return _cast_exec(host, args, rpc)


def _run_simple_evm_family(
    host,
    config,
    rpc: str,
    target: Target,
    fn: dict[str, Any],
    family: str,
    opts,
    rng,
) -> AttackResult:
    """Execute families that only require local JSON-RPC + ABI calldata.

    This path is the cross-framework bridge: Vyper and Hardhat projects can use
    it without a Forge test tree. It is still strictly local because the caller
    must already have a detected Anvil-compatible RPC.
    """
    signature = _format_signature(fn, host)
    actor_accounts = _anvil_accounts(host, config)
    if not actor_accounts:
        return AttackResult(family, target.contract, target.address, signature, "BLOCKED", "No unlocked local Anvil accounts were detected.")
    actor = actor_accounts[1] if len(actor_accounts) > 1 else actor_accounts[0]
    mode = "one" if family in {"replay", "accounting", "access"} else "zero"
    values = _make_value(host, fn, rng, mode, config)
    calldata, error = _encode_call(host, config, target, fn, values)
    if not calldata:
        return AttackResult(family, target.contract, target.address, signature, "BLOCKED", f"Could not encode a generic call: {error}")
    value = _payable_value(fn, opts, "small")

    snapshot = _cast_snapshot(host, rpc)
    if not snapshot:
        return AttackResult(family, target.contract, target.address, signature, "BLOCKED", "Local RPC does not expose evm_snapshot/anvil_snapshot.")

    try:
        before_target = _cast_balance(host, rpc, target.address)
        before_actor = _cast_balance(host, rpc, actor)
        first = _cast_send(host, rpc, target, calldata, value, actor)
        mid_target = _cast_balance(host, rpc, target.address)
        mid_actor = _cast_balance(host, rpc, actor)

        second = None
        after_target = mid_target
        after_actor = mid_actor
        second_gain = 0
        second_outflow = 0
        zero_success = False
        max_success = False

        if family in {"replay", "accounting"}:
            second = _cast_send(host, rpc, target, calldata, value, actor)
            after_target = _cast_balance(host, rpc, target.address)
            after_actor = _cast_balance(host, rpc, actor)
            second_outflow = max(0, mid_target - after_target)
            # Gas means an actor's raw balance can decrease even when they receive
            # funds, so target-side outflow is the safer generic signal here.
            second_gain = max(0, after_actor - mid_actor)
        elif family == "boundary":
            zero_values = _make_value(host, fn, rng, "zero", config)
            max_values = _make_value(host, fn, rng, "max", config)
            zero_data, zero_error = _encode_call(host, config, target, fn, zero_values)
            max_data, max_error = _encode_call(host, config, target, fn, max_values)
            if not zero_data or not max_data:
                reason = zero_error or max_error or "could not encode edge values"
                return AttackResult(family, target.contract, target.address, signature, "BLOCKED", reason)
            _cast_revert(host, rpc, snapshot)
            zero = _cast_send(host, rpc, target, zero_data, value, actor)
            zero_success = zero.returncode == 0
            _cast_revert(host, rpc, snapshot)
            maximum = _cast_send(host, rpc, target, max_data, value, actor)
            max_success = maximum.returncode == 0
        elif family == "time":
            # Timestamp manipulation is intentionally observational here: without a
            # protocol-specific invariant, changed return/output is a lead, not BREAK.
            _cast_exec(host, ["rpc", "evm_setNextBlockTimestamp", "100000"], rpc)
            first = _cast_send(host, rpc, target, calldata, value, actor)
            _cast_exec(host, ["rpc", "evm_setNextBlockTimestamp", "200000"], rpc)
            second = _cast_send(host, rpc, target, calldata, value, actor)

        first_success = first.returncode == 0 if first is not None else False
        second_success = second.returncode == 0 if second is not None else False
        is_break = (
            family in {"replay", "accounting"}
            and second_success
            and second_outflow > 1
            and second_gain > 0
        ) or (
            family == "access"
            and first_success
            and bool(PRIVILEGED_RE.search(str(fn.get("name") or "")))
        )

        lines = [
            f"LOWKEY_BREAK_FAMILY {family}",
            f"FIRST_SUCCESS {str(first_success).lower()}",
            f"SECOND_SUCCESS {str(second_success).lower()}",
            f"SECOND_ATTACKER_GAIN {second_gain}",
            f"SECOND_TARGET_OUTFLOW {second_outflow}",
            f"ZERO_SUCCESS {str(zero_success).lower()}",
            f"MAX_SUCCESS {str(max_success).lower()}",
            f"TARGET_BEFORE {before_target}",
            f"TARGET_AFTER {after_target}",
            f"LOWKEY_BREAK {str(is_break).lower()}",
        ]
        evidence = _write_json(host, f"cast_{target.contract}_{_function_name(signature)}_{family}", {
            "backend": "evm-cast",
            "family": family,
            "target": asdict(target),
            "function": signature,
            "actor": actor,
            "calldata": calldata,
            "value": value,
            "output": lines,
        })
        result = _result_from_output(
            host,
            family=family,
            target=target,
            function=signature,
            output="\\n".join(lines),
            evidence_path=str(evidence),
        )
        result.detail = result.detail or {}
        result.detail.update({"backend": "evm-cast", "actor": actor, "before_actor": before_actor, "after_actor": after_actor})
        return result
    finally:
        _cast_revert(host, rpc, snapshot)


def _render_common_header() -> str:
    return """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
"""


def _render_repeat_test(
    target: Target,
    fn: dict[str, Any],
    signature: str,
    values: list[str],
    value: str,
    label: str,
    seed_fund: str | None,
    setup_signature: str | None = None,
    entitlement_signature: str | None = None,
):
    target_lit = f"address(uint160(0x00{target.address[2:].lower()}))"
    params = list(fn.get("inputs") or [])
    expressions = []
    for item, raw_value in zip(params, values):
        ptype = str(item.get("type") or "").lower()
        if ptype == "address":
            expressions.append("address(ATTACKER)")
        else:
            expressions.append(_basic_solidity_expr(ptype, str(raw_value)))
    payload_expr = (
        f'abi.encodeWithSignature("{signature}", {", ".join(expressions)})'
        if expressions else f'abi.encodeWithSignature("{signature}")'
    )

    setup_block = ""
    if seed_fund:
        seed_amount = _solidity_amount_literal(seed_fund)
        if setup_signature:
            setup_block += f"""
        bytes memory setupData = abi.encodeWithSignature("{setup_signature}");
        vm.prank(ATTACKER);
        (bool setupSuccess, bytes memory setupReturndata) = TARGET.call{{value: {seed_amount}}}(setupData);
        console2.log("SETUP_SUCCESS", setupSuccess);
        console2.log("SETUP_RETURNDATA_LENGTH", setupReturndata.length);
        console2.logBytes(setupReturndata);
        console2.logBytes(setupReturndata);
        """
        else:
            setup_block += f'        vm.deal(TARGET, {seed_amount});\n'
    elif setup_signature:
        setup_block += """
        bytes memory setupData = abi.encodeWithSignature("%s");
        vm.prank(ATTACKER);
        (bool setupSuccess, bytes memory setupReturndata) = TARGET.call{value: 2 wei}(setupData);
        console2.log("SETUP_SUCCESS", setupSuccess);
        console2.log("SETUP_RETURNDATA_LENGTH", setupReturndata.length);
        """ % setup_signature

    entitlement_before = """
        uint256 entitlementBefore = 0;
        bool entitlementReadOk = false;
"""
    entitlement_after_first = """
        uint256 entitlementAfterFirst = 0;
"""
    entitlement_after_second = """
        uint256 entitlementAfterSecond = 0;
"""
    if entitlement_signature:
        entitlement_before = f"""
        uint256 entitlementBefore = 0;
        bool entitlementReadOk = false;
        {{
            (bool ok, bytes memory data) = TARGET.staticcall(
                abi.encodeWithSignature("{entitlement_signature}", address(ATTACKER))
            );
            entitlementReadOk = ok && data.length >= 32;
            if (entitlementReadOk) entitlementBefore = abi.decode(data, (uint256));
        }}
"""
        entitlement_after_first = f"""
        uint256 entitlementAfterFirst = 0;
        {{
            (bool ok, bytes memory data) = TARGET.staticcall(
                abi.encodeWithSignature("{entitlement_signature}", address(ATTACKER))
            );
            if (ok && data.length >= 32) entitlementAfterFirst = abi.decode(data, (uint256));
        }}
"""
        entitlement_after_second = f"""
        uint256 entitlementAfterSecond = 0;
        {{
            (bool ok, bytes memory data) = TARGET.staticcall(
                abi.encodeWithSignature("{entitlement_signature}", address(ATTACKER))
            );
            if (ok && data.length >= 32) entitlementAfterSecond = abi.decode(data, (uint256));
        }}
"""

    return _render_common_header() + f"""
contract LowkeyBreakRepeat is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(uint160(0x00BEEF000000000000000000000000000000000042));

    function test_break_repeat() public {{
        // Fund the attacker before any payable setup call. Otherwise a seeded
        // deposit/credit path can revert for lack of ETH and masquerade as a
        // protocol-level accounting observation.
        vm.deal(ATTACKER, 100 ether);
{setup_block}
{entitlement_before}
        bytes memory data = {payload_expr};

        // Measure withdrawal gains only after setup has established the attacker's entitlement.
        uint256 targetBefore = TARGET.balance;
        uint256 attackerBefore = ATTACKER.balance;

        vm.prank(ATTACKER);
        (bool first, bytes memory firstReturndata) = TARGET.call{{value: {value}}}(data);

        uint256 targetMid = TARGET.balance;
        uint256 attackerMid = ATTACKER.balance;
{entitlement_after_first}
        vm.prank(ATTACKER);
        (bool second, bytes memory secondReturndata) = TARGET.call{{value: {value}}}(data);

        uint256 targetAfter = TARGET.balance;
        uint256 attackerAfter = ATTACKER.balance;
{entitlement_after_second}
        uint256 totalGain = attackerAfter > attackerBefore ? attackerAfter - attackerBefore : 0;
        uint256 totalTargetOutflow = targetBefore > targetAfter ? targetBefore - targetAfter : 0;

        console2.log("LOWKEY_BREAK_FAMILY", "{label}");
        console2.log("FIRST_SUCCESS", first);
        console2.log("SECOND_SUCCESS", second);
        console2.log("FIRST_RETURNDATA_LENGTH", firstReturndata.length);
        console2.logBytes(firstReturndata);
        console2.log("SECOND_RETURNDATA_LENGTH", secondReturndata.length);
        console2.logBytes(secondReturndata);
        console2.log("TOTAL_ATTACKER_GAIN", totalGain);
        console2.log("TOTAL_TARGET_OUTFLOW", totalTargetOutflow);
        console2.log("ENTITLEMENT_READ_OK", entitlementReadOk);
        console2.log("ENTITLEMENT_BEFORE", entitlementBefore);
        console2.log("ENTITLEMENT_AFTER_FIRST", entitlementAfterFirst);
        console2.log("ENTITLEMENT_AFTER_SECOND", entitlementAfterSecond);

        // A second successful withdrawal is normal when the attacker still has entitlement.
        // BREAK requires demonstrated payout greater than the entitlement recorded before attack.
        bool breakByEntitlement = entitlementReadOk
            && totalGain > entitlementBefore;
        // Without an entitlement baseline, repeated value movement is only an
        // observation. Do not label a normal second payout as an accounting BREAK.
        if (breakByEntitlement) {{
            console2.log("LOWKEY_BREAK", true);
        }} else {{
            console2.log("LOWKEY_BREAK", false);
        }}

        targetMid; attackerMid;
    }}
}}
"""


def _render_access_test(target: Target, signature: str, calldata: str, value: str, break_on_success: bool = True):
    target_lit = f"address(uint160(0x00{target.address[2:].lower()}))"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakAccess is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(uint160(0x00BEEF000000000000000000000000000000000042));

    function test_break_access() public {{
        bytes memory data = hex"{calldata[2:]}";
        vm.deal(ATTACKER, 100 ether);

        vm.prank(ATTACKER);
        (bool success, bytes memory returndata) = TARGET.call{{value: {value_lit}}}(data);

        console2.log("LOWKEY_BREAK_FAMILY", "access");
        console2.log("SUCCESS", success);
        console2.log("RETURNDATA_LENGTH", returndata.length);
        console2.log("LOWKEY_BREAK", {str(break_on_success).lower()} && success);
    }}
}}
"""


def _render_boundary_test(target: Target, signature: str, call_zero: str, call_max: str, value: str):
    target_lit = f"address(uint160(0x00{target.address[2:].lower()}))"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakBoundary is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(uint160(0x00BEEF000000000000000000000000000000000042));

    function test_break_boundary() public {{
        vm.deal(ATTACKER, 100 ether);
        bytes memory zeroData = hex"{call_zero[2:]}";
        bytes memory maxData = hex"{call_max[2:]}";

        vm.prank(ATTACKER);
        (bool zeroSuccess, ) = TARGET.call{{value: {value_lit}}}(zeroData);

        vm.prank(ATTACKER);
        (bool maxSuccess, ) = TARGET.call{{value: {value_lit}}}(maxData);

        console2.log("LOWKEY_BREAK_FAMILY", "boundary");
        console2.log("ZERO_SUCCESS", zeroSuccess);
        console2.log("MAX_SUCCESS", maxSuccess);

        // A successful edge call is a lead; Lowkey only turns it into BREAK when
        // the call also produces an observable value/state condition outside its
        // normal entitlement.
        console2.log("LOWKEY_BREAK", false);
    }}
}}
"""


def _render_time_test(target: Target, signature: str, calldata: str, value: str):
    target_lit = f"address(uint160(0x00{target.address[2:].lower()}))"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakTime is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(uint160(0x00BEEF000000000000000000000000000000000042));

    function test_time_dependence() public {{
        bytes memory data = hex"{calldata[2:]}";
        vm.deal(ATTACKER, 100 ether);

        vm.warp(100000);
        vm.prank(ATTACKER);
        (bool first, bytes memory a) = TARGET.call{{value: {value_lit}}}(data);

        vm.warp(200000);
        vm.prank(ATTACKER);
        (bool second, bytes memory b) = TARGET.call{{value: {value_lit}}}(data);

        console2.log("LOWKEY_BREAK_FAMILY", "time");
        console2.log("FIRST_SUCCESS", first);
        console2.log("SECOND_SUCCESS", second);
        console2.log("RETURN_DATA_CHANGED", keccak256(a) != keccak256(b));
        console2.log("LOWKEY_BREAK", false);
    }}
}}
"""


def _basic_solidity_expr(ptype: str, value: str) -> str:
    """Render a safe generic Solidity expression for generated attack calldata."""
    raw = str(value)
    lower = ptype.lower().strip()

    if lower == "address":
        return f"address({raw})"
    if lower == "bool":
        return "true" if raw.lower() == "true" else "false"
    if lower == "string":
        # _make_value only emits simple ASCII values, so repr via JSON is sufficient
        # and avoids accidentally producing invalid Solidity string literals.
        import json as _json
        return _json.dumps(raw)
    if lower == "bytes":
        return raw if raw.startswith("0x") else "0x"
    if lower.startswith(("uint", "int", "bytes")):
        return raw

    if lower.endswith("[]"):
        base = lower[:-2]
        if base.startswith("tuple") or base.startswith("("):
            raise ValueError(
                f"dynamic array element type '{ptype}' requires a protocol-specific generator"
            )
        if raw.strip() != "[]":
            raise ValueError(
                f"generic dynamic array '{ptype}' accepts only an empty array in this attack mode"
            )
        return f"new {base}[](0)"

    if re.fullmatch(r"(?:address|bool|u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)|bytes(?:1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32))\[[0-9]+\]", lower):
        raise ValueError(f"fixed-size array '{ptype}' requires a specialized attack generator")

    if lower.startswith("tuple") or lower.startswith("("):
        raise ValueError(f"tuple/struct argument '{ptype}' requires a specialized attack generator")

    raise ValueError(f"complex ABI type '{ptype}' needs a specialized attack generator")


def _find_setup_signature(functions: list[dict[str, Any]]) -> str | None:
    for item in functions:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "")
        inputs = item.get("inputs") or []
        if SETUP_RE.search(name) and len(inputs) == 0 and str(item.get("stateMutability") or "") == "payable":
            return _format_signature(item)
    return None


def _find_entitlement_getter_signature(functions: list[dict[str, Any]]) -> str | None:
    """Find an address-keyed uint view that can expose an attacker's entitlement."""
    candidates: list[tuple[int, str]] = []
    preferred = re.compile(r"(?i)(^|_)(balances?|credit|amount|entitlement|debt|shares?|position)(_|$)")
    widths = {"uint8", "uint16", "uint32", "uint64", "uint96", "uint128", "uint256"}
    for item in functions:
        if not isinstance(item, dict):
            continue
        if str(item.get("stateMutability") or "").lower() not in {"view", "pure"}:
            continue
        inputs = item.get("inputs") or []
        outputs = item.get("outputs") or []
        if len(inputs) != 1 or len(outputs) != 1:
            continue
        if str(inputs[0].get("type") or "").lower() != "address":
            continue
        if str(outputs[0].get("type") or "").lower() not in widths:
            continue
        name = str(item.get("name") or "")
        score = 100
        if name.lower() == "balances":
            score -= 60
        elif name.lower() == "balance":
            score -= 50
        elif preferred.search(name):
            score -= 25
        candidates.append((score, _format_signature(item)))
    if not candidates:
        return None
    candidates.sort(key=lambda value: (value[0], value[1]))
    return candidates[0][1]

def _render_reentrancy_test(
    target: Target,
    fn: dict[str, Any],
    signature: str,
    values: list[str],
    depth: int,
    setup_signature: str | None = None,
    seed_fund: str | None = None,
    entitlement_signature: str | None = None,
):
    target_lit = f"address(uint160(0x00{target.address[2:].lower()}))"
    params = list(fn.get("inputs") or [])
    expressions = [
        _basic_solidity_expr(str(item.get("type") or ""), str(value))
        for item, value in zip(params, values)
    ]
    encoded_args = [
        "address(hostile)" if str(item.get("type") or "").lower() == "address" else expr
        for item, expr in zip(params, expressions)
    ]
    payload_expr = (
        f'abi.encodeWithSignature("{signature}", {", ".join(encoded_args)})'
        if encoded_args else f'abi.encodeWithSignature("{signature}")'
    )
    setup_block = """        uint256 targetBalanceBeforeFunding = TARGET.balance;
"""
    if seed_fund:
        seed_amount = _solidity_amount_literal(seed_fund)
        setup_block += f'        vm.deal(TARGET, {seed_amount});\n'
    setup_block += """        uint256 targetBalanceBeforeSetup = TARGET.balance;
"""
    if setup_signature:
        seed_value = _solidity_amount_literal(seed_fund) if seed_fund else "2 wei"
        setup_block += f"""
        bytes memory setupData = abi.encodeWithSignature("{setup_signature}");
        (bool seeded, ) = address(hostile).call{{value: {seed_value}}}(
            abi.encodeWithSignature("seed(bytes)", setupData)
        );
        console2.log("SETUP_WRAPPER_SUCCESS", seeded);
        console2.log("SETUP_VALUE_WEI", uint256({seed_value}));
"""
    setup_block += """        uint256 targetBalanceAfterSetup = TARGET.balance;
"""
    if entitlement_signature:
        setup_block += f"""
        (bool entitlementSetupOk, bytes memory entitlementSetupData) = TARGET.staticcall(
            abi.encodeWithSignature("{entitlement_signature}", address(hostile))
        );
        uint256 entitlementAfterSetup = 0;
        if (entitlementSetupOk && entitlementSetupData.length >= 32) {{
            entitlementAfterSetup = abi.decode(entitlementSetupData, (uint256));
        }}
        console2.log("ENTITLEMENT_SETUP_READ_OK", entitlementSetupOk);
        console2.log("ENTITLEMENT_AFTER_SETUP", entitlementAfterSetup);
"""

    entitlement_before_attack_block = ""
    entitlement_after_attack_block = ""
    if entitlement_signature:
        entitlement_before_attack_block = f"""
        {{
            (bool ok, bytes memory data) = TARGET.staticcall(
                abi.encodeWithSignature("{entitlement_signature}", address(hostile))
            );
            entitlementBeforeAttackOk = ok && data.length >= 32;
            if (entitlementBeforeAttackOk) {{
                entitlementBeforeAttack = abi.decode(data, (uint256));
            }}
        }}
"""
        entitlement_after_attack_block = f"""
        {{
            (bool ok, bytes memory data) = TARGET.staticcall(
                abi.encodeWithSignature("{entitlement_signature}", address(hostile))
            );
            if (ok && data.length >= 32) {{
                entitlementAfterAttack = abi.decode(data, (uint256));
            }}
        }}
"""

    return _render_common_header() + f"""
contract LowkeyBreakReentrant {{
    address public immutable target;
    bytes public payload;
    uint256 public attempts;
    uint256 public successes;
    bool public lastSeedSuccess;
    bool public lastAttackSuccess;
    bytes public lastSeedReturndata;
    bytes public lastAttackReturndata;

    constructor(address _target) {{
        target = _target;
    }}

    function setPayload(bytes calldata _payload) external {{
        payload = _payload;
    }}

    function seed(bytes calldata data) external payable {{
        (bool ok, bytes memory returndata) = target.call{{value: msg.value}}(data);
        lastSeedSuccess = ok;
        lastSeedReturndata = returndata;
        emit TargetCall("SEED", ok, returndata);
    }}

    function attack() external payable {{
        (bool ok, bytes memory returndata) = target.call{{value: msg.value}}(payload);
        lastAttackSuccess = ok;
        lastAttackReturndata = returndata;
        emit TargetCall("OUTER", ok, returndata);
    }}

    event TargetCall(string phase, bool success, bytes returndata);

    receive() external payable {{
        _reenter();
    }}

    fallback() external payable {{
        _reenter();
    }}

    function _reenter() internal {{
        if (attempts >= {max(1, depth)}) return;
        attempts++;
        (bool ok, ) = target.call(payload);
        if (ok) successes++;
    }}
}}

contract LowkeyBreakReentrancy is Test {{
    address constant TARGET = {target_lit};

    function test_break_reentrancy() public {{
        LowkeyBreakReentrant hostile = new LowkeyBreakReentrant(TARGET);
        bytes memory payload = {payload_expr};
        hostile.setPayload(payload);
        vm.deal(address(this), 100 ether);
        vm.deal(address(hostile), 100 ether);
{setup_block}
        uint256 beforeHostile = address(hostile).balance;
        uint256 beforeTarget = TARGET.balance;
        uint256 entitlementBeforeAttack = 0;
        bool entitlementBeforeAttackOk = false;

{entitlement_before_attack_block}

        (bool outer, ) = address(hostile).call{{value: 1 wei}}(
            abi.encodeWithSignature("attack()")
        );

        uint256 afterHostile = address(hostile).balance;
        uint256 afterTarget = TARGET.balance;
        uint256 entitlementAfterAttack = 0;
{entitlement_after_attack_block}

        uint256 outerInput = 1 wei;
        uint256 received = afterHostile > beforeHostile + outerInput
            ? afterHostile - beforeHostile - outerInput
            : 0;
        uint256 targetLoss = beforeTarget > afterTarget ? beforeTarget - afterTarget : 0;

        console2.log("LOWKEY_BREAK_FAMILY", "reentrancy");
        console2.log("HOSTILE_WRAPPER_SUCCESS", outer);
        console2.log("TARGET_SETUP_SUCCESS", hostile.lastSeedSuccess());
        console2.log("TARGET_SETUP_RETURNDATA_LENGTH", hostile.lastSeedReturndata().length);
        console2.log("TARGET_BALANCE_BEFORE_FUNDING", targetBalanceBeforeFunding);
        console2.log("TARGET_BALANCE_BEFORE_SETUP", targetBalanceBeforeSetup);
        console2.log("TARGET_BALANCE_AFTER_SETUP", targetBalanceAfterSetup);
        console2.logBytes(hostile.lastSeedReturndata());
        console2.log("TARGET_OUTER_SUCCESS", hostile.lastAttackSuccess());
        console2.log("TARGET_OUTER_RETURNDATA_LENGTH", hostile.lastAttackReturndata().length);
        console2.logBytes(hostile.lastAttackReturndata());
        console2.log("TARGET_REJECTED_ATTACK", !hostile.lastAttackSuccess());
        console2.log("TARGET_REVERT_DATA_PRESENT", hostile.lastAttackReturndata().length > 0);
        console2.log("REENTRY_REACHED", hostile.attempts() > 0);
        console2.log("TARGET_CODE_LENGTH", TARGET.code.length);
        console2.log("TARGET_BALANCE_AFTER_SETUP", TARGET.balance);
        console2.log("REENTRY_ATTEMPTS", hostile.attempts());
        console2.log("REENTRY_SUCCESSES", hostile.successes());
        console2.log("ATTACKER_WITHDRAW_RECEIVED", received);
        console2.log("ENTITLEMENT_BEFORE_ATTACK", entitlementBeforeAttack);
        console2.log("ENTITLEMENT_BEFORE_ATTACK_READ_OK", entitlementBeforeAttackOk);
        console2.log("ENTITLEMENT_AFTER_ATTACK", entitlementAfterAttack);
        console2.log("TARGET_LOSS", targetLoss);

        bool exceededEntitlement = entitlementBeforeAttackOk
            && hostile.successes() > 0
            && received > entitlementBeforeAttack;
        bool genericValueBreak = !entitlementBeforeAttackOk
            && hostile.successes() > 0
            && received > 1 wei
            && targetLoss > 1 wei;

        if (exceededEntitlement || genericValueBreak) {{
            console2.log("LOWKEY_BREAK", true);
        }} else {{
            console2.log("LOWKEY_BREAK", false);
        }}
    }}
}}
"""

def _extract_console_bytes(text_output: str, marker: str) -> str | None:
    """Return the first raw 0x-prefixed bytes line immediately after a telemetry marker."""
    lines = str(text_output or "").splitlines()
    for index, line in enumerate(lines):
        if marker not in line:
            continue
        for candidate in lines[index + 1:index + 5]:
            value = candidate.strip()
            if re.fullmatch(r"0x[0-9a-fA-F]*", value):
                return value
    return None


def _read_telemetry_bool(text_output: str, marker: str) -> bool | None:
    match = re.search(
        rf"{re.escape(marker)}\s+(true|false)",
        str(text_output or ""),
        flags=re.I,
    )
    if not match:
        return None
    return match.group(1).lower() == "true"


def _read_telemetry_uint(text_output: str, marker: str) -> int | None:
    match = re.search(
        rf"{re.escape(marker)}\s+(\d+)",
        str(text_output or ""),
        flags=re.I,
    )
    return int(match.group(1)) if match else None


def _keccak256(data: bytes) -> bytes | None:
    """Use Ethereum Keccak when available; never substitute NIST SHA3-256."""
    try:
        from Crypto.Hash import keccak
        digest = keccak.new(digest_bits=256)
        digest.update(data)
        return digest.digest()
    except Exception:
        pass
    try:
        from eth_hash.auto import keccak
        return keccak(data)
    except Exception:
        return None


def _canonical_abi_type(item: dict[str, Any]) -> str:
    type_name = str(item.get("type") or "")
    if not type_name.startswith("tuple"):
        return type_name
    suffix = type_name[len("tuple"):]
    components = item.get("components") or []
    inner = ",".join(_canonical_abi_type(component) for component in components)
    return f"({inner}){suffix}"


def _error_signature(item: dict[str, Any]) -> str | None:
    name = str(item.get("name") or "")
    if not name:
        return None
    return f"{name}({','.join(_canonical_abi_type(x) for x in (item.get('inputs') or []))})"


def _selector_for_signature(host, signature: str) -> str | None:
    """Resolve an ABI selector using Python Keccak or Foundry's cast as a fallback."""
    digest = _keccak256(signature.encode())
    if digest is not None:
        return digest[:4].hex()

    try:
        cast = host.tool_path("cast") if hasattr(host, "tool_path") else "cast"
        completed = subprocess.run(
            [str(cast), "sig", signature],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        match = re.search(r"0x([0-9a-fA-F]{8})", completed.stdout or "")
        if match:
            return match.group(1).lower()
    except Exception:
        pass
    return None


def _decode_revert_data(host, config, target: Target, raw_hex: str | None) -> str | None:
    """Decode standard/custom ABI errors without assuming a specific protocol."""
    if not raw_hex or raw_hex == "0x":
        return None
    try:
        raw = bytes.fromhex(raw_hex[2:])
    except ValueError:
        return None
    if len(raw) < 4:
        return f"raw revert ({len(raw)} bytes): {raw_hex}"

    selector = raw[:4].hex()
    payload = raw[4:]

    # Solidity's standard revert formats.
    if selector == "08c379a0":
        try:
            if len(payload) >= 64:
                offset = int.from_bytes(payload[:32], "big")
                if offset + 32 <= len(payload):
                    length = int.from_bytes(payload[offset:offset + 32], "big")
                    start = offset + 32
                    end = min(start + length, len(payload))
                    message = payload[start:end].decode("utf-8", errors="replace")
                    return f"Error(string): {message}"
        except Exception:
            pass
        return "Error(string) [malformed payload]"
    if selector == "4e487b71":
        code = int.from_bytes(payload[:32], "big") if len(payload) >= 32 else None
        return f"Panic({code})" if code is not None else "Panic(uint256) [malformed payload]"

    abi = []
    try:
        probe_cfg = dict(config or {})
        probe_cfg["target"] = target.address
        abi = _abi_for(host, probe_cfg, target.address)
    except Exception:
        abi = []

    for item in abi:
        if not isinstance(item, dict) or item.get("type") != "error":
            continue
        expected = None
        item_selector = item.get("selector")
        if isinstance(item_selector, str) and re.fullmatch(r"0x[0-9a-fA-F]{8}", item_selector):
            expected = item_selector[2:].lower()
        else:
            signature = _error_signature(item)
            expected = _selector_for_signature(host, signature) if signature else None
        if expected != selector:
            continue

        signature = _error_signature(item) or str(item.get("name") or "custom error")
        # eth_abi is optional. The error name/selector remains useful even when
        # a deployment uses complex tuple/custom types that aren't installed here.
        inputs = item.get("inputs") or []
        if inputs:
            try:
                from eth_abi import decode
                values = decode(
                    [_canonical_abi_type(x) for x in inputs],
                    payload,
                )
                rendered = ", ".join(repr(value) for value in values)
                return f"{signature}: {rendered}"
            except Exception:
                return f"{signature} [selector 0x{selector}]"
        return signature

    return f"Unknown custom error [selector 0x{selector}]"


def _result_from_output(
    host,
    *,
    family: str,
    target: Target,
    function: str | None,
    output: str,
    evidence_path: str | None,
    config: dict[str, Any] | None = None,
) -> AttackResult:
    text_output = str(output or "")
    found = re.search(r"LOWKEY_BREAK\s+(true|false)", text_output, flags=re.I)
    is_break = bool(found and found.group(1).lower() == "true")
    structured = "LOWKEY_BREAK_FAMILY" in text_output
    status = "BREAK" if is_break else ("OBSERVED" if structured else "BLOCKED")
    summary = {
        "BREAK": "Concrete break condition reached.",
        "OBSERVED": "Attack executed; no concrete break condition reached.",
        "BLOCKED": "Attack harness did not produce a usable execution result.",
    }[status]
    raw_tail = "\n".join(text_output.splitlines()[-80:])
    target_rejected = bool(re.search(r"TARGET_REJECTED_ATTACK\s+true", text_output, flags=re.I))
    reentry_reached = bool(re.search(r"REENTRY_REACHED\s+true", text_output, flags=re.I))
    target_revert_data = bool(re.search(r"TARGET_REVERT_DATA_PRESENT\s+true", text_output, flags=re.I))
    if structured and family in {"replay", "accounting"}:
        setup_success = _read_telemetry_bool(text_output, "SETUP_SUCCESS")
        first_success = _read_telemetry_bool(text_output, "FIRST_SUCCESS")
        second_success = _read_telemetry_bool(text_output, "SECOND_SUCCESS")
        setup_len = _read_telemetry_uint(text_output, "SETUP_RETURNDATA_LENGTH") or 0
        first_len = _read_telemetry_uint(text_output, "FIRST_RETURNDATA_LENGTH") or 0
        second_len = _read_telemetry_uint(text_output, "SECOND_RETURNDATA_LENGTH") or 0
        target_outflow = _read_telemetry_uint(text_output, "TOTAL_TARGET_OUTFLOW")
        decoded_setup = _decode_revert_data(
            host, config, target,
            _extract_console_bytes(text_output, "SETUP_RETURNDATA_LENGTH"),
        )
        decoded_first = _decode_revert_data(
            host, config, target,
            _extract_console_bytes(text_output, "FIRST_RETURNDATA_LENGTH"),
        )
        decoded_second = _decode_revert_data(
            host, config, target,
            _extract_console_bytes(text_output, "SECOND_RETURNDATA_LENGTH"),
        )
        function_name = _function_name(function or "target call")
        if setup_success is False:
            reason = decoded_setup or (
                "No revert data was returned."
                if not setup_len
                else f"Revert data length: {setup_len} bytes."
            )
            summary = (
                f"Target rejected the setup call before the {family} probe could establish its intended state. "
                f"{reason}"
            )
        elif first_success is False:
            reason = decoded_first or (
                "No revert data was returned."
                if not first_len
                else f"Revert data length: {first_len} bytes."
            )
            flow = (
                f"Target rejected the first {function_name} attempt before value movement."
                if target_outflow in {None, 0}
                else f"Target rejected the first {function_name} attempt."
            )
            summary = f"{flow} {reason}"
        elif second_success is False:
            reason = decoded_second or (
                "No revert data was returned."
                if not second_len
                else f"Revert data length: {second_len} bytes."
            )
            summary = (
                f"First {function_name} attempt succeeded; the repeat attempt was rejected. "
                f"No repeat break was demonstrated. {reason}"
            )
    elif structured and target_rejected and not reentry_reached:
        summary = (
            "Target rejected the attack before the callback boundary. "
            + ("Revert data was returned; inspect the ABI/reason." if target_revert_data
               else "No revert data was returned; inspect withdraw's guards/preconditions.")
        )
    elif not structured and raw_tail:
        # A generated harness can fail to compile or execute before emitting
        # Lowkey markers. Preserve the real tool error instead of hiding it behind
        # a generic "BLOCKED" message.
        summary = f"Forge produced no Lowkey telemetry. Last output: {raw_tail}"
    detail = {
        "raw_tail": raw_tail,
    }
    if structured and family in {"replay", "accounting"}:
        detail.update({
            "setup_revert": _decode_revert_data(
                host, config, target,
                _extract_console_bytes(text_output, "SETUP_RETURNDATA_LENGTH"),
            ),
            "first_revert": _decode_revert_data(
                host, config, target,
                _extract_console_bytes(text_output, "FIRST_RETURNDATA_LENGTH"),
            ),
            "second_revert": _decode_revert_data(
                host, config, target,
                _extract_console_bytes(text_output, "SECOND_RETURNDATA_LENGTH"),
            ),
        })
    return AttackResult(
        family=family,
        contract=target.contract,
        address=target.address,
        function=function,
        status=status,
        summary=summary,
        evidence_path=evidence_path,
        break_condition=is_break,
        detail=detail,
    )


def _write_harness(host, name: str, body: str) -> str:
    path = _root(host) / "test" / f"Lowkey_Break_{_slug(name)}_{hashlib.sha1(body.encode()).hexdigest()[:10]}.t.sol"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return str(path)


def _record_break(host, result: AttackResult):
    payload = asdict(result)
    path = _write_json(
        host,
        f"break_{result.family}_{result.contract}_{result.function or 'system'}",
        payload,
    )
    payload["evidence_path"] = str(path)
    _emit(host, "break-found" if result.break_condition else "break-observation", result.summary, payload)

    if result.break_condition:
        # A concrete behavioral break is stronger than a source heuristic, but the
        # tool deliberately does not assign economic severity.
        try:
            signal = {
                "category": "break",
                "tool": "break",
                "check": f"BREAK-{result.family.upper()}",
                "title": f"Break condition: {ATTACK_FAMILIES.get(result.family, {}).get('title', result.family)}",
                "impact": "Unknown",
                "confidence": "Reproduced locally",
                "file": "",
                "line": None,
                "function": result.function,
                "description": result.summary,
                "meaning": ATTACK_FAMILIES.get(result.family, {}).get("basis", ""),
                "why": "A generated adversarial harness reached an explicit behavioral break condition on the isolated local execution.",
                "next": "Inspect the generated harness and prove the exact invariant/impact manually.",
                "provenance": [
                    "Immunefi common vulnerability taxonomy",
                    "Immunefi public bug-fix reviews",
                    "Cyfrin CodeHawks public contest submissions",
                    "Solodit public finding taxonomy",
                ],
                "verification_status": "CONFIRMED",
                "verification": {
                    "status": "CONFIRMED",
                    "mode": "stateful-break",
                    "evidence": [str(path)],
                },
                "status": "open",
            }
            host.audit_context.add_signal(signal, _root(host))
        except Exception:
            pass
    return str(path)


def _run_family(host, config, rpc: str, target: Target, fn: dict[str, Any], family: str, opts, rng, project_info: dict[str, Any] | None = None) -> AttackResult:
    signature = _format_signature(fn, host)
    name = _function_name(signature)
    runner = _evm_runner(project_info or {}, _root(host)) if project_info is not None else "foundry"
    if runner != "foundry" and family in {"replay", "accounting", "access", "boundary", "time"}:
        return _run_simple_evm_family(host, config, rpc, target, fn, family, opts, rng)

    modes = ["normal", "one", "zero", "max"]
    mode = "one" if family in {"reentrancy", "replay", "accounting"} else modes[rng.randrange(len(modes))]
    values = _make_value(host, fn, rng, mode, config)
    calldata, error = _encode_call(host, config, target, fn, values)
    if not calldata:
        return AttackResult(
            family=family,
            contract=target.contract,
            address=target.address,
            function=signature,
            status="BLOCKED",
            summary=f"Could not encode a generic call: {error}",
        )

    value = _payable_value(fn, opts, "small")
    seed_fund = opts.get("fund_target")

    if family in {"replay", "accounting"}:
        try:
            all_functions = _discover_functions(host, config, target)
            setup_signature = _find_setup_signature(all_functions)
            entitlement_signature = _find_entitlement_getter_signature(all_functions)
        except Exception:
            setup_signature = None
            entitlement_signature = None
        body = _render_repeat_test(
            target,
            fn,
            signature,
            values,
            value,
            family,
            seed_fund,
            setup_signature=setup_signature,
            entitlement_signature=entitlement_signature,
        )
    elif family == "access":
        body = _render_access_test(
            target,
            signature,
            calldata,
            value,
            break_on_success=bool(PRIVILEGED_RE.search(name)),
        )
    elif family == "boundary":
        zero_values = _make_value(host, fn, rng, "zero")
        max_values = _make_value(host, fn, rng, "max")
        zero_data, zero_error = _encode_call(host, config, target, fn, zero_values)
        max_data, max_error = _encode_call(host, config, target, fn, max_values)
        if not zero_data or not max_data:
            reason = zero_error or max_error or "could not encode edge values"
            return AttackResult(family, target.contract, target.address, signature, "BLOCKED", reason)
        body = _render_boundary_test(target, signature, zero_data, max_data, value)
    elif family == "time":
        body = _render_time_test(target, signature, calldata, value)
    elif family == "reentrancy":
        if any(
            str(item.get("type") or "").lower().startswith(("tuple", "bytes", "string"))
            or str(item.get("type") or "").lower().endswith("[]")
            for item in (fn.get("inputs") or [])
        ):
            return AttackResult(
                family, target.contract, target.address, signature, "BLOCKED",
                "Generic reentrancy generation needs only simple ABI types.",
            )
        try:
            all_functions = _discover_functions(host, config, target)
            setup_signature = _find_setup_signature(all_functions)
            entitlement_signature = _find_entitlement_getter_signature(all_functions)
            body = _render_reentrancy_test(
                target,
                fn,
                signature,
                values,
                opts.get("depth", 3),
                setup_signature,
                seed_fund=seed_fund,
                entitlement_signature=entitlement_signature,
            )
        except ValueError as error:
            return AttackResult(
                family, target.contract, target.address, signature, "BLOCKED", str(error)
            )
    elif family == "upgrade":
        body = _render_access_test(
            target,
            signature,
            calldata,
            value,
            break_on_success=bool(UPGRADE_RE.search(name)),
        )
    elif family in {"callback", "signature", "dos", "oracle", "economic", "erc20", "proxy", "storage"}:
        # Generic success is only an observation. These families need a
        # protocol-specific invariant before Lowkey may call it a BREAK.
        body = _render_access_test(target, signature, calldata, value, break_on_success=False)
    else:
        return AttackResult(family, target.contract, target.address, signature, "BLOCKED", "Unknown family.")

    harness = _write_harness(host, f"{target.contract}_{name}_{family}", body)

    # The optional target funding is scoped to the Forge fork and therefore cannot
    # persist into the user's Anvil node.
    try:
        completed = _forge_run(host, config, harness, rpc, project_info)
        output = "\n".join(
            x for x in (completed.stdout or "", completed.stderr or "") if x
        )
    except Exception as exc:
        return AttackResult(
            family, target.contract, target.address, signature, "BLOCKED",
            f"Forge execution failed to start: {exc}",
            detail={"harness": harness},
        )

    evidence = {
        "family": family,
        "target": asdict(target),
        "function": signature,
        "values": values,
        "calldata": calldata,
        "call_value": value,
        "forge_returncode": completed.returncode,
        "harness": harness,
        "output_tail": "\n".join(output.splitlines()[-160:]),
        "generated_at": time.time(),
        "research_basis": ATTACK_FAMILIES.get(family, {}),
        "project_detection": {
            "kind": (project_info or {}).get("kind"),
            "break_backend": (project_info or {}).get("break_backend"),
            "languages": (project_info or {}).get("languages", {}),
            "stacks": (project_info or {}).get("stacks", []),
            "language_features": _language_features(_root(host), project_info or {}),
        },
    }
    evidence_path = _write_json(host, f"experiment_{target.contract}_{name}_{family}", evidence)

    result = _result_from_output(
        host,
        family=family,
        target=target,
        function=signature,
        output=output,
        evidence_path=str(evidence_path),
        config=config,
    )
    result.detail = result.detail or {}
    result.detail["harness"] = harness
    result.detail["forge_returncode"] = completed.returncode
    return result


def _safe_run_family(host, config, rpc, target, fn, family, opts, rng, project_info=None) -> AttackResult:
    """Run one attack family without allowing a generator failure to abort the campaign."""
    try:
        return _run_family(host, config, rpc, target, fn, family, opts, rng, project_info)
    except Exception as exc:
        signature = _format_signature(fn, host)
        return AttackResult(
            family=family,
            contract=target.contract,
            address=target.address,
            function=signature,
            status="BLOCKED",
            summary=f"Attack generator failed safely: {exc}",
            detail={
                "error_type": type(exc).__name__,
                "error": str(exc),
            },
        )


def _families_for_function(
    fn: dict[str, Any],
    requested: str | None,
    project_info: dict[str, Any] | None = None,
    pattern_hint: str | None = None,
) -> list[str]:
    if requested:
        requested = requested.lower()
        if requested not in ATTACK_FAMILIES:
            raise ValueError(
                "Unknown attack family '%s'. Choose: %s"
                % (requested, ", ".join(ATTACK_FAMILIES))
            )
        return [requested]

    name = str(fn.get("name") or "")
    signature = _format_signature(fn)
    patterns = patterns_for(project=project_info, function_name=name)
    if pattern_hint:
        wanted = [item for item in FINDING_PATTERNS if str(item.id).upper() == str(pattern_hint).upper()]
        if not wanted:
            raise ValueError(f"Unknown finding pattern '{pattern_hint}'.")
        mapped = family_names(wanted)
        if mapped and mapped[0] in ATTACK_FAMILIES:
            return [mapped[0]]
        raise ValueError(f"Finding pattern '{pattern_hint}' has no executable attack family.")

    families = ["reentrancy", "replay", "accounting", "boundary"]
    if PRIVILEGED_RE.search(name):
        families.append("access")
    if UPGRADE_RE.search(name):
        families.append("upgrade")
    if TIME_RE.search(name) or TIME_RE.search(signature):
        families.append("time")
    if SIGNATURE_RE.search(name) or SIGNATURE_RE.search(signature):
        families.append("signature")
    if CALLBACK_RE.search(name) or CALLBACK_RE.search(signature):
        families.append("callback")
    for family in family_names(patterns):
        if family in ATTACK_FAMILIES and family not in families:
            families.append(family)
    return families or ["dos"]


def _select_functions(functions: list[dict[str, Any]], opts: dict[str, Any]) -> list[dict[str, Any]]:
    funcs = _ordered_functions([fn for fn in functions if _is_state_changing(fn)])
    query = opts.get("function")
    if query:
        matched = [fn for fn in funcs if _function_matches(fn, query)]
        if not matched and "(" not in str(query):
            matched = [fn for fn in funcs if str(fn.get("name") or "").lower() == str(query).lower()]
        if not matched:
            raise ValueError(f"No state-changing function matched '{query}'.")
        return matched
    # Start with the most attack-relevant surface, but expand outward in rounds.
    return funcs


def _print_banner(host, targets: list[Target], opts: dict[str, Any], rpc: str | None, project_info: dict[str, Any]):
    print()
    print("LOWKEY // BREAK MODE")
    print("====================")
    print("Mission : actively try to make the selected system violate a concrete property.")
    print("Rule    : static warnings are leads; BREAK requires stateful execution evidence.")
    print(f"Backend : {project_info.get('break_backend', 'generic')}")
    print(f"Language: {language_label(project_info)}")
    if rpc:
        print(f"Runtime : {rpc}")
    print(f"Targets : {len(targets)}")
    if opts.get("system"):
        print("Scope   : WHOLE SYSTEM")
    elif opts.get("function"):
        print(f"Scope   : FUNCTION {opts['function']}")
    elif opts.get("pattern"):
        print(f"Scope   : FINDING PATTERN {opts['pattern']}")
    else:
        print("Scope   : CURRENT TARGET")
    mode_label = "INDEFINITE / STOP ON BREAK" if opts.get("until_found") else f"ROUND-LIMITED ({opts.get('max_rounds', 1)})"
    print(f"Mode    : {mode_label}")
    features = _language_features(_root(host), project_info)
    if features:
        print("LANGUAGE CUES")
        print("-------------")
        for item in features[:10]:
            print(f"  {item}")
    print()
    print("ATTACK LIBRARY")
    print("--------------")
    for key, info in sorted(ATTACK_FAMILIES.items(), key=lambda item: item[1]["priority"]):
        print(f"  {key:<12} {info['title']}")
    print(f"Public-finding playbook: {len(FINDING_PATTERNS)} recurring logic patterns")
    print()


def _run_native_backend(host, project_info: dict[str, Any], opts: dict[str, Any]) -> int:
    """Route non-EVM projects to their own toolchain without faking exploit proof."""
    root = Path(str(project_info.get("root") or _root(host)))
    backend = str(project_info.get("break_backend") or "generic")
    commands = native_probe_commands(project_info)
    summary = {
        "mode": "native-backend",
        "backend": backend,
        "kind": project_info.get("kind"),
        "languages": project_info.get("languages", {}),
        "stacks": project_info.get("stacks", []),
        "native": project_info.get("native", {}),
        "pattern_catalog": project_info.get("break_catalog", {}),
        "commands": [],
        "status": "PLAN_ONLY",
    }
    print()
    print(f"LOWKEY // NATIVE {backend.upper()} BREAKER")
    print("=====================================")
    print(f"Project : {root}")
    print(f"Language: {language_label(project_info)}")
    print("Rule    : native execution is allowed; a test pass/fail is not itself a vulnerability verdict.")
    if commands:
        for command in commands:
            print(f"Native  : {' '.join(command)}")
            try:
                completed = subprocess.run(command, cwd=str(root), capture_output=True, text=True, timeout=900)
                output = (completed.stdout or "") + ("\\n" + completed.stderr if completed.stderr else "")
                summary["commands"].append({"command": command, "returncode": completed.returncode, "output_tail": "\\n".join(output.splitlines()[-120:])})
                status = "PASS" if completed.returncode == 0 else "FAIL"
                print(f"{status:<7} native test execution")
            except (OSError, subprocess.TimeoutExpired) as exc:
                summary["commands"].append({"command": command, "error": str(exc)})
                print(f"BLOCKED native test execution: {exc}")
    else:
        print("Native  : no supported local test runner detected yet.")
    evidence = _write_json(host, f"native_{backend}_break", summary)
    summary["evidence_path"] = str(evidence)
    _emit(host, "break-native", "Native breaker routed without a fabricated EVM verdict.", summary)
    print()
    print(f"Finding logic mapped: {len(FINDING_PATTERNS)} recurring public-audit patterns")
    print(f"Evidence: {evidence}")
    print("Status  : native attack generation is deliberately adapter-specific; no BREAK was claimed.")
    return 0


def run(config, args=None, host=None):
    host = host or __import__("lowkey.lk", fromlist=["*"])
    args = list(args or [])
    opts = _parse_args(args)

    if opts.get("help"):
        print(help_text())
        return 0

    if opts.get("catalog"):
        print("LOWKEY // BREAK FINDING CATALOG")
        print("===============================")
        for item in FINDING_PATTERNS:
            print(f"  {item.id:<12} [{item.family}] {item.title}")
            print(f"               LOGIC: {item.logic}")
        print()
        print(f"Total: {len(FINDING_PATTERNS)} recurring logic patterns")
        return 0

    project_info = _project_break_context(host)
    if project_info.get("break_backend") != "evm":
        return _run_native_backend(host, project_info, opts)

    try:
        rpc = _require_anvil(host, config)
    except Exception as exc:
        return host.fail(f"Error: {exc}")

    rng = random.Random(opts.get("seed", 1337))

    try:
        known_targets = _target_from_config(host, config)
        if opts.get("system"):
            targets = known_targets
        else:
            current = [item for item in known_targets if str(item.address).lower() == str(config.get("target") or "").lower()]
            targets = current[:1]
            if not targets and host.is_address(config.get("target")):
                targets = [Target(config.get("target_contract") or "Target", config["target"])]
        if not targets:
            if opts.get("auto"):
                print("No target is selected. Running the existing local lab setup...")
                host.run_lab(config, [])
                known_targets = _target_from_config(host, config)
                targets = known_targets[:1]
            if not targets:
                return host.fail(
                    "No live target selected. Run 'lk lab' or 'lk target <address>' first."
                )
    except Exception as exc:
        return host.fail(f"Target discovery failed: {exc}")

    _print_banner(host, targets, opts, rpc, project_info)

    rounds = 0
    campaign_results: list[AttackResult] = []
    try:
        while True:
            rounds += 1
            print(f"=== BREAK ROUND {rounds} ===")
            made_progress = False

            for target in targets:
                functions = _discover_functions(host, config, target)
                selected = _select_functions(functions, opts)
                if not selected:
                    print(f"[{target.contract}] No state-changing ABI functions found.")
                    continue

                if opts.get("function"):
                    display_functions = selected
                else:
                    # Keep one round focused: prioritize likely claims and privileged
                    # paths before expanding into the complete ABI surface on later rounds.
                    display_functions = selected if rounds > 1 else selected[:12]

                for fn in display_functions:
                    families = _families_for_function(
                        fn,
                        opts.get("family"),
                        project_info=project_info,
                        pattern_hint=opts.get("pattern"),
                    )
                    for family in families:
                        made_progress = True
                        result = _safe_run_family(
                            host, config, rpc, target, fn, family, opts, rng, project_info
                        )
                        campaign_results.append(result)

                        marker = "!!! BREAK !!!" if result.break_condition else result.status
                        print(
                            f"[{marker}] {target.contract}::{result.function or '-'} "
                            f"| {family:<12} | {result.summary}"
                        )
                        if result.evidence_path:
                            print(f"            Evidence: {result.evidence_path}")

                        if result.break_condition:
                            evidence = _record_break(host, result)
                            print()
                            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                            print("LOWKEY // CONCRETE BREAK CONDITION REACHED")
                            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
                            print(f"Family   : {family}")
                            print(f"Function : {result.function}")
                            print(f"Evidence : {result.evidence_path or evidence}")
                            print("Status   : campaign stopped; inspect the harness and prove impact.")
                            return 0

            if not opts.get("until_found") and rounds >= max(1, opts.get("max_rounds", 1)):
                break

            if not made_progress:
                break

        summary = {
            "mode": "indefinite" if opts.get("until_found") else "round-limited",
            "rounds": rounds,
            "targets": [asdict(x) for x in targets],
            "results": [asdict(x) for x in campaign_results],
            "started_at": time.time(),
        }
        report = _write_json(host, "campaign", summary)
        _emit(host, "break-campaign", "Break campaign completed without a concrete break.", summary)
        observed = sum(1 for item in campaign_results if item.status == "OBSERVED")
        blocked = sum(1 for item in campaign_results if item.status == "BLOCKED")
        print()
        print("LOWKEY // BREAK CAMPAIGN COMPLETE")
        print("=================================")
        print(f"Rounds   : {rounds}")
        print(f"Executed : {len(campaign_results) - blocked}")
        print(f"Blocked  : {blocked}")
        print(f"Observed : {observed}")
        print("Breaks   : 0")
        print(f"Report   : {report}")
        print("No concrete break condition was reached in this campaign.")
        return 0
    except KeyboardInterrupt:
        summary = {
            "mode": "interrupted",
            "rounds": rounds,
            "targets": [asdict(x) for x in targets],
            "results": [asdict(x) for x in campaign_results],
            "stopped_by": "Ctrl-C",
            "started_at": time.time(),
        }
        report = _write_json(host, "campaign_interrupted", summary)
        _emit(host, "break-stop", "Break campaign stopped by user.", summary)
        print()
        print()
        print("LOWKEY // BREAK CAMPAIGN STOPPED")
        print("================================")
        print("Reason   : Ctrl-C")
        print(f"Rounds   : {rounds}")
        print(f"Report   : {report}")
        print("No conclusion is implied by an interrupted campaign.")
        return 130
    except Exception as exc:
        _emit(host, "break-error", str(exc), {"error": str(exc)})
        return host.fail(f"Break engine failed: {exc}", 1)
