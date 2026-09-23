from __future__ import annotations

import json
import re
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any


@dataclass
class Request:
    kind: str
    target: str | None = None
    contract: str | None = None
    function: str | None = None
    args: list[str] | None = None
    value: str = "0"
    calldata: str | None = None
    output: Path | None = None
    force: bool = False


def _is_address(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"0x[0-9a-fA-F]{40}", value))


def _id(value: str, fallback: str = "Generated") -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", value or "") or fallback
    return value if not value[0].isdigit() else "_" + value


def _canonical_type(param: dict[str, Any]) -> str:
    raw = str(param.get("type", ""))
    if raw.startswith("tuple"):
        return f"({','.join(_canonical_type(x) for x in param.get('components', []))}){raw[len('tuple'):]}"
    return raw


def _run(root: Path, binary: str, args: list[str]) -> tuple[int, str, str]:
    try:
        result = subprocess.run([binary, *args], cwd=root, capture_output=True, text=True)
    except OSError as exc:
        return 127, "", str(exc)
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def artifact_files(root: Path) -> list[Path]:
    out = root / "out"
    if not out.is_dir():
        return []
    return [p for p in out.rglob("*.json") if "build-info" not in p.parts and p.name != "solc-input.json"]


def find_artifact(root: Path, contract_name: str | None = None) -> tuple[Path, dict[str, Any]] | None:
    matches = []
    for path in artifact_files(root):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(payload, dict) or not isinstance(payload.get("abi"), list):
            continue
        matches.append((path, payload))
    if not matches:
        return None

    def source_for_artifact(path: Path) -> Path | None:
        try:
            relative = path.relative_to(root / "out")
            parts = list(relative.parts)[:-1]
            if not parts:
                return None
            source = root / "src" / Path(*parts)
            return source if source.exists() else None
        except (ValueError, OSError):
            return None

    if contract_name:
        # Prefer an exact source filename match. A user-facing request such as
        # "EthEscrow" naturally refers to src/EthEscrow.sol, while the Solidity
        # symbol inside that file may be "Escrow".
        requested_source = root / "src" / f"{contract_name}.sol"
        source_file_matches = []

        if requested_source.exists():
            try:
                source_text = requested_source.read_text(encoding="utf-8")
            except OSError:
                source_text = ""

            # Do not trust artifact filenames alone. Read the actual Solidity
            # declarations so stale artifacts from an older contract name cannot
            # cause a wrong import in the generated script.
            declared_symbols = {
                match.group(2)
                for match in re.finditer(
                    r"\b(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)\b",
                    source_text,
                )
            }

            for path, payload in matches:
                source = source_for_artifact(path)
                # Foundry artifact JSON does not always include a top-level
                # contractName field. In that case the artifact filename is the
                # contract symbol (for example Escrow.json -> Escrow).
                artifact_symbol = str(payload.get("contractName") or path.stem or "")
                if (
                    source == requested_source
                    and artifact_symbol in declared_symbols
                ):
                    source_file_matches.append((path, payload))

        if source_file_matches:
            matches = source_file_matches
        elif requested_source.exists():
            # The requested source exists, but none of its artifacts match a
            # declaration in that source. Do not fall back to a stale artifact
            # from another compilation/source tree with the requested filename.
            return None
        else:
            # No matching source file exists, so a direct Solidity symbol match
            # is still useful as a fallback for contracts supplied by artifact name.
            exact = [
                item for item in matches
                if item[1].get("contractName") == contract_name
                and item[1].get("bytecode", {}).get("object")
            ]
            if exact:
                matches = exact
            else:
                stem_matches = [
                    item for item in matches
                    if item[0].stem == contract_name
                    and item[1].get("bytecode", {}).get("object")
                ]
                if not stem_matches:
                    return None
                matches = stem_matches

    # Deployment generation needs an actual deployable source artifact where possible.
    deployable = [
        item for item in matches
        if item[1].get("bytecode", {}).get("object")
    ]
    if deployable:
        matches = deployable

    # When no contract was specified, prefer source-backed artifacts over test/script artifacts.
    if contract_name is None:
        source_matches = []
        for path, payload in matches:
            if source_for_artifact(path):
                source_matches.append((path, payload))
        if source_matches:
            matches = source_matches

    matches.sort(key=lambda x: x[0].stat().st_mtime, reverse=True)
    return matches[0]


def _source_import(root: Path, artifact: Path, contract: str) -> str:
    # Foundry artifacts normally live under out/<source-path>/<Contract>.sol/Contract.json.
    try:
        relative = artifact.relative_to(root / "out")
        parts = list(relative.parts)[:-1]
        if parts:
            candidate = root / "src" / Path(*parts)
            if candidate.exists():
                return "../" + candidate.relative_to(root).as_posix()
    except ValueError:
        pass

    src = root / "src"
    if src.is_dir():
        for candidate in src.rglob(f"{contract}.sol"):
            return "../" + candidate.relative_to(root).as_posix()
    return f"../src/{contract}.sol"


def _functions(abi: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [x for x in abi if x.get("type") == "function" and x.get("name")]


def _constructor(abi: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next((x for x in abi if x.get("type") == "constructor"), None)


def _env_expression(param: dict[str, Any], index: int) -> str:
    abi_type = _canonical_type(param)
    env = f"LOWKEY_CONSTRUCTOR_ARG_{index}"
    simple = abi_type.lower()
    if simple == "address":
        return f'vm.envAddress("{env}")'
    if simple == "bool":
        return f'vm.envBool("{env}")'
    if simple == "string":
        return f'vm.envString("{env}")'
    if simple == "bytes32":
        return f'vm.envBytes32("{env}")'
    if simple == "bytes":
        return f'vm.envBytes("{env}")'
    if re.fullmatch(r"u?int(?:8|16|32|64|128|256)?", simple):
        return f'vm.envUint("{env}")'
    # Arrays and tuples are supplied as ABI-encoded bytes, then decoded in Solidity.
    return f'abi.decode(vm.envBytes("{env}"), ({abi_type}))'


def _constructor_code(abi: list[dict[str, Any]], contract: str) -> tuple[str, list[str]]:
    item = _constructor(abi)
    if not item or not item.get("inputs"):
        return f"        instance = new {contract}();", []

    expressions = [_env_expression(p, i) for i, p in enumerate(item["inputs"], 1)]
    code = "\n".join([
        "        // Constructor inputs live in environment variables so this file can be reused",
        "        // across Anvil, testnets, and production without hard-coding deployment config.",
        "        // Complex arrays/tuples should be ABI-encoded in their matching env variable.",
        f"        instance = new {contract}({', '.join(expressions)});",
    ])
    help_lines = [
        f"LOWKEY_CONSTRUCTOR_ARG_{i} -> {_canonical_type(p)} ({p.get('name') or 'unnamed'})"
        for i, p in enumerate(item["inputs"], 1)
    ]
    return code, help_lines


def _post_checks(abi: list[dict[str, Any]]) -> str:
    funcs = {x.get("name"): x for x in _functions(abi)}
    lines = [
        "        // Confirms deployment left runtime bytecode at the returned address.",
        "        // This is a deployment sanity check, not a security proof.",
        '        require(address(instance).code.length > 0, "Lowkey: no runtime bytecode");',
        '        console2.log("Deployed:", address(instance));',
        '        console2.log("Chain ID:", block.chainid);',
        '        console2.log("Code bytes:", address(instance).code.length);',
    ]
    for name, label, expected in [
        ("owner", "owner()", "address"),
        ("paused", "paused()", "bool"),
        ("name", "name()", "string"),
        ("symbol", "symbol()", "string"),
    ]:
        item = funcs.get(name)
        if item and not item.get("inputs") and len(item.get("outputs", [])) == 1:
            if _canonical_type(item["outputs"][0]) == expected:
                lines += [
                    f"        // Read {label} after deployment to catch an obvious configuration mistake.",
                    f'        console2.log("{label}:", instance.{name}());',
                ]
    names = {x.get("name") for x in _functions(abi)}
    if "initialize" in names:
        lines += [
            "        // SECURITY PROMPT: initialize(...) exists. It is intentionally not called automatically;",
            "        // initializer arguments and ownership semantics are protocol-specific.",
        ]
    if "transferOwnership" in names or any(n and n.startswith("grantRole") for n in names):
        lines += [
            "        // SECURITY PROMPT: privileged-role management exists. Verify the intended admin separately.",
        ]
    if "upgradeTo" in names or "upgradeToAndCall" in names:
        lines += [
            "        // SECURITY PROMPT: an upgrade path exists. Check proxy and authorization assumptions.",
        ]
    return "\n".join(lines)


def render_deployment(root: Path, contract: str, artifact_path: Path, artifact: dict[str, Any]) -> tuple[str, list[str]]:
    abi = artifact["abi"]
    constructor, help_lines = _constructor_code(abi, contract)
    ident = _id(contract, "Contract")
    source = _source_import(root, artifact_path, contract)
    created = datetime.now().isoformat(timespec="seconds")

    text = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{Script, console2}} from "forge-std/Script.sol";
import {{Vm}} from "forge-std/Vm.sol";
import {{ {contract} }} from "{source}";

/// @title Lowkey-generated deployment for {contract}
/// @notice Reusable Foundry deployment plus post-deployment audit hooks.
contract LowkeyDeploy_{ident} is Script {{
    string internal constant DEPLOYMENT_DIR = "deployments";

    function run() external returns ({contract} instance) {{
        // Keep private keys in Forge CLI flags or environment variables, never in this source file.
        // startBroadcast tells Foundry that the following deployment transaction is the one to broadcast.
        vm.startBroadcast();

{constructor}

        vm.stopBroadcast();

        _postDeployChecks(instance);
        _writeDeploymentRecord(instance);
        return instance;
    }}

    function _postDeployChecks({contract} instance) internal view {{
{_post_checks(abi)}
    }}

    function _writeDeploymentRecord({contract} instance) internal {{
        // serialize* + writeJson creates machine-readable evidence for later scripts and audits.
        string memory json = vm.serializeAddress("lowkey", "address", address(instance));
        json = vm.serializeUint("lowkey", "chainId", block.chainid);
        json = vm.serializeString("lowkey", "contract", "{contract}");
        json = vm.serializeString("lowkey", "generatedAt", "{created}");
        vm.writeJson(
            json,
            string.concat(DEPLOYMENT_DIR, "/{ident}-", vm.toString(block.chainid), ".json")
        );
    }}
}}
'''
    return text, help_lines


def _latest_send(root: Path) -> str | None:
    for path in [root / ".audit" / "history" / "session.log",
                 Path.home() / ".lowkey" / "audit" / "session_log.txt"]:
        if not path.exists():
            continue
        try:
            for line in reversed(path.read_text(encoding="utf-8").splitlines()):
                if "CMD: cast send " in line:
                    return line.split("CMD: ", 1)[1].strip()
        except OSError:
            pass
    return None


def _parse_send(command: str) -> tuple[str, str, list[str], str] | None:
    try:
        parts = shlex.split(command)
        i = parts.index("send")
        target, function = parts[i + 1], parts[i + 2]
    except (ValueError, IndexError):
        return None

    args: list[str] = []
    value = "0"
    i += 3
    while i < len(parts):
        if parts[i] in {"--value", "-v"} and i + 1 < len(parts):
            value = parts[i + 1]
            i += 2
        elif parts[i].startswith("--"):
            # Skip option values so private keys and RPC arguments never become generated Solidity.
            i += 2 if i + 1 < len(parts) and not parts[i + 1].startswith("--") else 1
        else:
            args.append(parts[i])
            i += 1
    return target, function, args, value


def _request_from_latest(root: Path) -> Request | None:
    command = _latest_send(root)
    if not command:
        return None
    parsed = _parse_send(command)
    if not parsed:
        return None
    target, function, args, value = parsed
    code, calldata, error = _run(root, "cast", ["calldata", function, *args])
    if code != 0:
        raise ValueError(error or "cast calldata failed")
    return Request("latest", target, function=function, args=args, value=value,
                   calldata=calldata.removeprefix("0x"))


def _value(value: str) -> str:
    value = (value or "0").strip()
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(ether|gwei|wei)", value, re.IGNORECASE)
    if not match:
        return re.sub(r"(?i)(\d)(ether|gwei|wei)\b", r"\\1 \\2", value)
    amount, unit = match.groups()
    unit = unit.lower()
    if "." not in amount:
        return f"{amount} {unit}"
    try:
        multiplier = {"ether": Decimal(10) ** 18, "gwei": Decimal(10) ** 9, "wei": Decimal(1)}[unit]
        wei = Decimal(amount) * multiplier
        if wei == wei.to_integral_value():
            return str(int(wei))
    except (InvalidOperation, KeyError):
        pass
    return value


def _parse_request(kind: str, root: Path, config: dict[str, Any], raw: list[str]) -> Request:
    request = Request(kind, args=[])
    positional: list[str] = []
    i = 0
    while i < len(raw):
        token = raw[i]
        if token == "--force":
            request.force = True
        elif token in {"--output", "-o"} and i + 1 < len(raw):
            request.output = Path(raw[i + 1])
            i += 1
        elif token == "--value" and i + 1 < len(raw):
            request.value = raw[i + 1]
            i += 1
        elif token == "--calldata" and i + 1 < len(raw):
            request.calldata = raw[i + 1].removeprefix("0x")
            i += 1
        else:
            positional.append(token)
        i += 1

    if kind == "deployment":
        request.contract = positional[0] if positional else None
        return request

    request.target = config.get("target") if _is_address(config.get("target")) else None
    if positional:
        request.function, request.args = positional[0], positional[1:]
    else:
        latest = _request_from_latest(root)
        if latest:
            latest.output = request.output
            latest.force = request.force
            if request.value != "0":
                latest.value = request.value
            if request.calldata:
                latest.calldata = request.calldata
            return latest
    return request


def _write(root: Path, requested: Path | None, default: Path, content: str, force: bool) -> Path:
    path = requested or default
    path = path if path.is_absolute() else root / path
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and not force:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        path = path.with_name(f"{path.stem}_{stamp}{path.suffix}")
    path.write_text(content, encoding="utf-8")
    return path


def _template_poc(contract: str, target: str, function: str, value: str, calldata: str) -> str:
    ident = _id(contract, "Target")
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{Script, console2}} from "forge-std/Script.sol";

/// @title Lowkey-generated proof of concept
/// @notice Replays one concrete call and exposes the measurements needed for a security property.
contract LowkeyPoC_{ident} is Script {{
    address internal constant TARGET = {target};

    function run() external {{
        // SAFETY: start with Anvil or a local fork. A broadcasted script changes real chain state.
        // The private key stays outside source code and is loaded from the environment here.
        uint256 attackerKey = vm.envUint("LOWKEY_ATTACKER_KEY");
        address attacker = vm.addr(attackerKey);

        vm.startBroadcast(attackerKey);

        // recordLogs captures emitted events so you can inspect behavior, not just balances.
        vm.recordLogs();
        vm.record();

        uint256 attackerBefore = attacker.balance;
        uint256 targetBefore = TARGET.balance;

        // Raw call is intentional: it replays exact calldata while you are still learning the ABI.
        // Later, replace this with a typed interface call once the contract behavior is understood.
        (bool success, bytes memory returndata) =
            TARGET.call{{value: {_value(value)}}}(hex"{calldata}");

        uint256 attackerAfter = attacker.balance;

        // accesses exposes storage slots this transaction read/wrote.
        // This is the Solidity-side counterpart to Lowkey's transaction state-diff workflow.
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(TARGET);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 targetAfter = TARGET.balance;

        vm.stopBroadcast();

        console2.log("Function:", "{function}");
        console2.log("Success:", success);
        console2.log("Target before:", targetBefore);
        console2.log("Target after:", targetAfter);
        console2.log("Attacker before:", attackerBefore);
        console2.log("Attacker after:", attackerAfter);
        console2.log("Storage reads:", reads.length);
        console2.log("Storage writes:", writes.length);
        console2.log("Events emitted:", logs.length);
        console2.logBytes(returndata);

        // Raw write-slot addresses are useful first evidence. Decode mapping/struct slots after that.
        for (uint256 i = 0; i < writes.length; i++) {{
            console2.logBytes32(writes[i]);
        }}

        // A successful call only means it did not revert. It is NOT proof of a vulnerability.
        require(success, "Lowkey PoC: target call reverted");

        // Put the actual security property here:
        // require(attackerAfter > attackerBefore, "exploit condition not met");
        // require(TARGET.balance < targetBefore, "expected loss did not occur");
    }}
}}
'''


def _template_test(contract: str, target: str, function: str, value: str, calldata: str) -> str:
    ident = _id(contract, "Target")
    test_name = _id(function or "reproduction").lower()
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {{Test, console2}} from "forge-std/Test.sol";
import {{Vm}} from "forge-std/Vm.sol";

/// @title Lowkey-generated reproduction test for {contract}
/// @notice Deterministic setup + concrete call + obvious places for security assertions.
contract LowkeyTest_{ident} is Test {{
    address internal constant TARGET = {target};
    address internal attacker;
    address internal victim;

    function setUp() public {{
        // makeAddr creates local test accounts; no real wallet keys are needed.
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");

        // deal mutates balances inside Foundry's test EVM. It is a cheatcode, not production logic.
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);

        // Fail early if the selected target address has no deployed runtime code.
        assertGt(TARGET.code.length, 0, "Lowkey: TARGET has no runtime code");
    }}

    function test_{test_name}() public {{
        // ARRANGE: capture the values that define the property you are investigating.
        uint256 targetBefore = TARGET.balance;
        uint256 attackerBefore = attacker.balance;

        // snapshot creates a rollback point so experiments do not contaminate one another.
        uint256 snapshot = vm.snapshot();

        // prank changes msg.sender for the next external call only.
        // Use startPrank when several calls must originate from the same actor.
        vm.prank(attacker);

        // Record storage and event evidence around the exact call.
        // This connects the generated test to Lowkey's state-diff/transaction-inspection workflow.
        vm.recordLogs();
        vm.record();

        // ACT: replay the exact calldata discovered/generated by Lowkey.
        (bool success, bytes memory returndata) =
            TARGET.call{{value: {_value(value)}}}(hex"{calldata}");

        // Revert data often identifies the guard or custom error that blocked the path.
        if (!success) {{
            console2.logBytes(returndata);
        }}
        assertTrue(success, "Lowkey reproduction: target call reverted");

        uint256 targetAfter = TARGET.balance;
        uint256 attackerAfter = attacker.balance;

        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(TARGET);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        // ASSERT: execution success and security impact are separate questions.
        console2.log("Function:", "{function}");
        console2.log("Target before:", targetBefore);
        console2.log("Target after:", targetAfter);
        console2.log("Attacker before:", attackerBefore);
        console2.log("Attacker after:", attackerAfter);
        console2.log("Storage reads:", reads.length);
        console2.log("Storage writes:", writes.length);
        console2.log("Events emitted:", logs.length);

        // Replace these placeholders with the protocol property you actually proved.
        // assertEq(...);          // exact state transition
        // assertGt(...);          // unexpected value increase
        // vm.expectRevert(...);   // unauthorized path should fail
        // vm.expectEmit(...);     // event should be emitted

        assertTrue(vm.revertTo(snapshot), "Lowkey: snapshot rollback failed");
    }}

    // Next step: turn a concrete reproduction into a fuzz test once the invariant is clear.
    // bound(...) constrains fuzzed numbers; assume(...) rules out impossible states.
}}
'''


def run_generate(config: dict[str, Any], args: list[str]) -> int:
    if not args or args[0] in {"help", "--help", "-h"}:
        print("""Lowkey generator

Usage:
  lk generate deployment <ContractName> [--output script/File.s.sol] [--force]
  lk generate poc [<function> [args...]] [--value <value>] [--calldata 0x...] [--output script/File.s.sol]
  lk generate test [<function> [args...]] [--value <value>] [--calldata 0x...] [--output test/File.t.sol]

poc/test use the latest recorded cast send when no function is supplied.
Generated Solidity contains teaching comments beside the Foundry primitives you need to understand.
""")
        return 0

    kind = args[0].lower()
    if kind not in {"deployment", "poc", "test"}:
        print("Usage: lk generate deployment | poc | test")
        return 2

    root = Path.cwd()
    try:
        request = _parse_request(kind, root, config, args[1:])
    except ValueError as exc:
        print(f"Error: {exc}")
        return 2

    if kind == "deployment":
        # Deployment generation only needs source artifacts; don't let an old/broken audit test
        # block artifact discovery. Foundry supports --skip test for this workflow.
        code, _, error = _run(root, "forge", ["build", "--skip", "test", "--skip", "script"])
        if code:
            print(error or "forge build failed")
            return code or 2

        result = find_artifact(root, request.contract)
        if not result:
            print(f"Error: compiled artifact not found for {request.contract or '<contract>'}.")
            return 2

        artifact_path, artifact = result
        # Foundry artifacts may omit contractName; the artifact filename is then the Solidity symbol.
        contract = str(artifact.get("contractName") or artifact_path.stem or request.contract or "Contract")
        content, env_help = render_deployment(root, contract, artifact_path, artifact)
        output = _write(
            root,
            request.output,
            Path("script") / f"LowkeyDeploy_{_id(contract)}.s.sol",
            content,
            request.force,
        )
        print(f"Deployment script generated: {output}")
        for line in env_help:
            print(f"  {line}")
        print("Dry-run with forge script first; add --broadcast only when you intentionally want chain state changed.")
        return 0

    if not request.target:
        print("Error: set a target with lk target <address> or generate from a recorded send.")
        return 2
    if not request.function and not request.calldata:
        print("Error: no function supplied and no recorded cast send was found.")
        return 2
    if not request.calldata:
        code, encoded, error = _run(
            root,
            "cast",
            ["calldata", request.function or "", *(request.args or [])],
        )
        if code != 0 or not encoded:
            print(f"Error generating calldata: {error or 'cast calldata failed'}")
            return code or 2
        request.calldata = encoded.removeprefix("0x")

    artifact = find_artifact(root)
    contract = str(artifact[1].get("contractName")) if artifact else "Target"
    ident = _id(contract, "Target")
    if kind == "poc":
        content = _template_poc(contract, request.target, request.function or "raw-call", request.value, request.calldata)
        default = Path("script") / f"LowkeyPoC_{ident}.s.sol"
    else:
        content = _template_test(contract, request.target, request.function or "raw-call", request.value, request.calldata)
        default = Path("test") / f"LowkeyTest_{ident}.t.sol"

    output = _write(root, request.output, default, content, request.force)
    print(f"{kind.upper()} generated: {output}")
    print("Read the comments before running it; they are intentionally part of the learning workflow.")
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(run_generate({}, sys.argv[1:]))
