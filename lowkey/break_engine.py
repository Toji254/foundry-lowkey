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
    r"emergency|configure|set[A-Za-z]+|upgradeToAndCall|proxiable)"
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


def _forge_run(host, config, source_path: str, rpc: str):
    root = _root(host)
    forge = host.tool_path("forge") if hasattr(host, "tool_path") else "forge"
    if not forge:
        raise RuntimeError("forge was not found on PATH.")
    cmd = [
        forge,
        "test",
        "--match-path",
        str(Path(source_path).as_posix()),
        "--fork-url",
        rpc,
        "-vvv",
    ]
    return subprocess.run(
        cmd,
        cwd=str(root),
        capture_output=True,
        text=True,
    )


def _render_common_header() -> str:
    return """// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";
"""


def _render_repeat_test(target: Target, signature: str, calldata: str, value: str, label: str, seed_fund: str | None):
    target_lit = f"address(0x{target.address[2:]})"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    fund_line = ""
    if seed_fund:
        fund_line = f'        vm.deal(TARGET, {seed_fund});\n'
    return _render_common_header() + f"""
contract LowkeyBreakRepeat is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(0xBEEF000000000000000000000000000000000042);

    function test_break_repeat() public {{
{fund_line}        bytes memory data = hex"{calldata[2:]}";
        vm.deal(ATTACKER, 100 ether);

        uint256 targetBefore = TARGET.balance;
        uint256 attackerBefore = ATTACKER.balance;

        vm.prank(ATTACKER);
        (bool first, ) = TARGET.call{{value: {value_lit}}}(data);

        uint256 targetMid = TARGET.balance;
        uint256 attackerMid = ATTACKER.balance;

        vm.prank(ATTACKER);
        (bool second, ) = TARGET.call{{value: {value_lit}}}(data);

        uint256 targetAfter = TARGET.balance;
        uint256 attackerAfter = ATTACKER.balance;

        uint256 secondGain = attackerAfter > attackerMid ? attackerAfter - attackerMid : 0;
        uint256 secondOutflow = targetMid > targetAfter ? targetMid - targetAfter : 0;

        console2.log("LOWKEY_BREAK_FAMILY", "{label}");
        console2.log("FIRST_SUCCESS", first);
        console2.log("SECOND_SUCCESS", second);
        console2.log("SECOND_ATTACKER_GAIN", secondGain);
        console2.log("SECOND_TARGET_OUTFLOW", secondOutflow);

        if (second && secondGain > 0 && secondOutflow > 0) {{
            console2.log("LOWKEY_BREAK", true);
        }} else {{
            console2.log("LOWKEY_BREAK", false);
        }}

        // Never make the test itself fail on a mere candidate: Lowkey parses the
        // observations and decides whether the behavioral break condition is met.
        targetBefore; attackerBefore;
    }}
}}
"""


def _render_access_test(target: Target, signature: str, calldata: str, value: str, break_on_success: bool = True):
    target_lit = f"address(0x{target.address[2:]})"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakAccess is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(0xBEEF000000000000000000000000000000000042);

    function test_break_access() public {{
        bytes memory data = hex"{calldata[2:]}";
        vm.deal(ATTACKER, 100 ether);

        vm.prank(ATTACKER);
        (bool success, bytes memory returndata) = TARGET.call{{value: {value_lit}}}(data);

        console2.log("LOWKEY_BREAK_FAMILY", "access");
        console2.log("SUCCESS", success);
        console2.log("RETURNDATA_LENGTH", returndata.length);
        console2.log("LOWKEY_BREAK", break_on_success && success);
    }}
}}
"""


def _render_boundary_test(target: Target, signature: str, call_zero: str, call_max: str, value: str):
    target_lit = f"address(0x{target.address[2:]})"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakBoundary is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(0xBEEF000000000000000000000000000000000042);

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
    target_lit = f"address(0x{target.address[2:]})"
    value_lit = "0" if value in {"0", "0wei"} else "1"
    return _render_common_header() + f"""
contract LowkeyBreakTime is Test {{
    address constant TARGET = {target_lit};
    address constant ATTACKER = address(0xBEEF000000000000000000000000000000000042);

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
    raw = str(value)
    lower = ptype.lower()
    if lower == "address":
        return f"address({raw})"
    if lower == "bool":
        return "true" if raw.lower() == "true" else "false"
    if lower.startswith(("uint", "int", "bytes")):
        return raw
    raise ValueError(f"complex ABI type '{ptype}' needs a specialized attack generator")


def _basic_solidity_expr(ptype: str, value: str) -> str:
    raw = str(value)
    lower = ptype.lower()
    if lower == "address":
        return f"address({raw})"
    if lower == "bool":
        return "true" if raw.lower() == "true" else "false"
    if lower.startswith(("uint", "int", "bytes")):
        return raw
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


def _render_reentrancy_test(
    target: Target,
    fn: dict[str, Any],
    signature: str,
    values: list[str],
    depth: int,
    setup_signature: str | None = None,
):
    target_lit = f"address(0x{target.address[2:]})"
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
    setup_block = ""
    if setup_signature:
        setup_block = f"""
        bytes memory setupData = abi.encodeWithSignature("{setup_signature}");
        (bool seeded, ) = address(hostile).call{{value: 2 wei}}(
            abi.encodeWithSignature("seed(bytes)", setupData)
        );
        console2.log("SETUP_SEEDED", seeded);
"""

    return _render_common_header() + f"""
contract LowkeyBreakReentrant {{
    address public immutable target;
    bytes public payload;
    uint256 public attempts;
    uint256 public successes;

    constructor(address _target) {{
        target = _target;
    }}

    function setPayload(bytes calldata _payload) external {{
        payload = _payload;
    }}

    function seed(bytes calldata data) external payable {{
        (bool ok, ) = target.call{{value: msg.value}}(data);
        require(ok, "seed call reverted");
    }}

    function attack() external payable {{
        (bool ok, ) = target.call{{value: msg.value}}(payload);
        require(ok, "outer attack reverted");
    }}

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

        (bool outer, ) = address(hostile).call{{value: 1 wei}}(
            abi.encodeWithSignature("attack()")
        );

        uint256 afterHostile = address(hostile).balance;
        uint256 afterTarget = TARGET.balance;
        uint256 received = afterHostile > beforeHostile ? afterHostile - beforeHostile : 0;
        uint256 targetLoss = beforeTarget > afterTarget ? beforeTarget - afterTarget : 0;

        console2.log("LOWKEY_BREAK_FAMILY", "reentrancy");
        console2.log("OUTER_SUCCESS", outer);
        console2.log("REENTRY_ATTEMPTS", hostile.attempts());
        console2.log("REENTRY_SUCCESSES", hostile.successes());
        console2.log("ATTACKER_RECEIVED", received);
        console2.log("TARGET_LOSS", targetLoss);

        if (hostile.successes() > 0 && received > 1 wei && targetLoss > 1 wei) {{
            console2.log("LOWKEY_BREAK", true);
        }} else {{
            console2.log("LOWKEY_BREAK", false);
        }}
    }}
}}
"""

def _result_from_output(
    host,
    *,
    family: str,
    target: Target,
    function: str | None,
    output: str,
    evidence_path: str | None,
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
    detail = {"raw_tail": "\n".join(text_output.splitlines()[-80:])}
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
        body = _render_repeat_test(
            target, signature, calldata, value, family, seed_fund
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
            body = _render_reentrancy_test(
                target, fn, signature, values, opts.get("depth", 3), setup_signature
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
        completed = _forge_run(host, config, harness, rpc)
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
    )
    result.detail = result.detail or {}
    result.detail["harness"] = harness
    result.detail["forge_returncode"] = completed.returncode
    return result


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
                        result = _run_family(
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
