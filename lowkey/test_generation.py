"""Project-aware Solidity test-scaffold generation for LowkeyCast.

Generated drafts live outside Foundry's configured test directory by default.
Lowkey deliberately does not invent protocol assertions from names or ABI alone.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from test_generation_analysis import analyse_contract, render_test_plan, unit_access_control_tests, mask_solidity
except ImportError:  # keep partial installs diagnosable
    analyse_contract = render_test_plan = unit_access_control_tests = mask_solidity = None

TEST_TYPES = ("unit", "fuzz", "invariant", "integration", "fork", "poc", "regression", "formal")


def parse_types(raw: str | None) -> list[str]:
    if not raw or raw.strip().lower() == "all":
        return list(TEST_TYPES)
    values = []
    for item in raw.split(","):
        value = item.strip().lower()
        if value and value not in values:
            if value not in TEST_TYPES:
                raise ValueError(
                    f"Unknown test type '{value}'. Choose: {', '.join(TEST_TYPES)}."
                )
            values.append(value)
    if not values:
        raise ValueError(f"Choose one or more types: {', '.join(TEST_TYPES)}.")
    return values


def _foundry_config_path(root: Path) -> Path:
    """Resolve the Foundry config selected for this invocation."""
    configured = Path(os.environ.get("FOUNDRY_CONFIG", "foundry.toml")).expanduser()
    return (configured if configured.is_absolute() else root / configured).resolve()
def _source_root(root: Path) -> Path:
    """Resolve the active Foundry source directory without guessing a different profile."""
    config_path = _foundry_config_path(root)
    src = os.environ.get("FOUNDRY_SRC") or "src"
    if config_path.exists():
        try:
            import tomllib
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            profiles = config.get("profile", {})
            active_profile = os.environ.get("FOUNDRY_PROFILE", "default")
            profile_config = profiles.get(active_profile, {})
            default_config = profiles.get("default", {})
            src = (
                os.environ.get("FOUNDRY_SRC")
                or profile_config.get("src")
                or default_config.get("src")
                or config.get("src")
                or src
            )
        except (OSError, ValueError, ImportError, AttributeError):
            pass
    return (root / str(src)).resolve()

def _contract_source(root: Path, name: str) -> tuple[Path, str] | None:
    source_root = _source_root(root)
    if not source_root.exists():
        return None
    pattern = re.compile(
        r"\b(?:abstract\s+)?contract\s+" + re.escape(name) + r"\b"
    )
    for path in sorted(source_root.rglob("*.sol")):
        try:
            source = path.read_text(encoding="utf-8")
        except OSError:
            continue
        searchable = mask_solidity(source) if mask_solidity else source
        if pattern.search(searchable):
            return path, source
    return None


def _contract_body(source: str, name: str) -> str | None:
    searchable = mask_solidity(source) if mask_solidity else source
    match = re.search(
        r"\b(?:abstract\s+)?contract\s+" + re.escape(name) + r"\b[^\{]*\{",
        searchable,
    )
    if not match:
        return None
    start = match.end()
    closing = _matching_brace(searchable, start - 1)
    if closing is None:
        return None
    return source[start:closing]


def _constructor_args(source: str, name: str) -> str | None:
    body = _contract_body(source, name)
    if body is None:
        return None
    searchable = mask_solidity(body) if mask_solidity else body
    constructor = re.search(r"\bconstructor\s*\(([^)]*)\)", searchable)
    if not constructor:
        return ""
    return constructor.group(1).strip()


def _normalise_integer_type(solidity_type: str) -> str:
    if solidity_type == "uint":
        return "uint256"
    if solidity_type == "int":
        return "int256"
    return solidity_type


def _matching_brace(source: str, open_index: int) -> int | None:
    depth = 0
    for index in range(open_index, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _find_simple_fuzz_property(source: str, name: str) -> dict[str, str] | None:
    """Recognize a public integer state variable with a one-statement setter.

    This deliberately narrow source pattern gives us direct evidence for the
    generated property: calling the setter with x should make the public getter
    return x. Anything more complex stays a TODO rather than an invented claim.
    """
    body = _contract_body(source, name)
    if body is None:
        return None
    searchable = mask_solidity(body) if mask_solidity else body

    integer_type = r"(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?)"
    states: dict[str, str] = {}
    for match in re.finditer(
        rf"(?m)^\s*({integer_type})\s+public\s+([A-Za-z_]\w*)\s*;",
        searchable,
    ):
        states[match.group(2)] = match.group(1)

    if not states:
        return None

    function_pattern = re.compile(
        r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
        r"(?:external|public)\b[^{}]*\{"
    )
    for match in function_pattern.finditer(searchable):
        parameters = _split_parameters(match.group(2))
        if len(parameters) != 1:
            continue
        # Do not infer a property through custom modifiers such as onlyOwner.
        # Those can change whether a generated test call is valid.
        if not re.fullmatch(
            r"function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*(?:external|public)\s*"
            r"(?:(?:virtual|override(?:\([^)]*\))?)\s*)*\{",
            match.group(0),
        ):
            continue
        parameter_tokens = parameters[0].split()
        if len(parameter_tokens) != 2:
            continue
        parameter_type, parameter_name = parameter_tokens
        if not re.fullmatch(integer_type, parameter_type):
            continue

        opening = match.end() - 1
        closing = _matching_brace(searchable, opening)
        if closing is None:
            continue
        function_body = searchable[opening + 1:closing].strip()

        for state_name, state_type in states.items():
            if _normalise_integer_type(parameter_type) != _normalise_integer_type(state_type):
                continue
            assignment = re.fullmatch(
                rf"{re.escape(state_name)}\s*=\s*{re.escape(parameter_name)}\s*;",
                function_body,
            )
            if assignment:
                return {
                    "setter": match.group(1),
                    "parameter": parameter_name,
                    "type": parameter_type,
                    "state": state_name,
                }
    return None


def _split_parameters(raw: str) -> list[str]:
    """Split a Solidity parameter list on top-level commas."""
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(raw):
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            parts.append(raw[start:index].strip())
            start = index + 1
    tail = raw[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _constructor_values(raw: str | None) -> list[str] | None:
    """Return conservative, compile-safe placeholders for simple constructor types.

    Unknown/user-defined types intentionally return None instead of guessing.
    These defaults only make a draft deployable; they do not model valid protocol
    setup or prove that zero values are meaningful.
    """
    if raw is None:
        return None
    if not raw.strip():
        return []

    values: list[str] = []
    for declaration in _split_parameters(raw):
        tokens = declaration.split()
        if not tokens:
            return None
        solidity_type = tokens[0]

        if solidity_type == "address" and len(tokens) > 1 and tokens[1] == "payable":
            values.append("payable(address(0))")
        elif solidity_type == "address":
            values.append("address(0)")
        elif re.fullmatch(r"u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?", solidity_type):
            values.append("0")
        elif solidity_type == "bool":
            values.append("false")
        elif solidity_type == "string":
            values.append('""')
        elif solidity_type == "bytes":
            values.append('bytes("")')
        elif re.fullmatch(r"bytes(?:[1-9]|[12][0-9]|3[0-2])", solidity_type):
            values.append(f"{solidity_type}(0)")
        else:
            return None
    return values


def _foundry_test_dir(root: Path) -> Path:
    """Read the active Foundry profile's configured test directory."""
    config_path = _foundry_config_path(root)
    test_dir = "test"
    if config_path.exists():
        try:
            import tomllib
            config = tomllib.loads(config_path.read_text(encoding="utf-8"))
            profiles = config.get("profile", {})
            active_profile = os.environ.get("FOUNDRY_PROFILE", "default")
            profile_config = profiles.get(active_profile, {})
            default_config = profiles.get("default", {})
            test_dir = (
                os.environ.get("FOUNDRY_TEST")
                or os.environ.get("DAPP_TEST")
                or profile_config.get("test")
                or default_config.get("test")
                or config.get("test")
                or test_dir
            )
        except (OSError, ValueError, ImportError, AttributeError):
            pass
    if not isinstance(test_dir, str) or not test_dir.strip():
        test_dir = "test"
    path = Path(test_dir).expanduser()
    return (path if path.is_absolute() else root / path).resolve()


def _solidity_pragma(source: str) -> str:
    """Reuse the target source's compiler range when available."""
    searchable = mask_solidity(source) if mask_solidity else source
    match = re.search(r"\bpragma\s+solidity\s+([^;]+);", searchable)
    if not match:
        return "^0.8.20"
    pragma = source[match.start(1):match.end(1)].strip()
    return pragma if re.fullmatch(r"[0-9A-Za-z.^<>=+*~|()\s-]+", pragma) else "^0.8.20"


def _rel_import(root: Path, source_path: Path) -> str:
    # Drafts are meant to be moved into lowkey-generated under the configured test directory.
    destination = _foundry_test_dir(root) / "lowkey-generated"
    return PurePosixPath(os.path.relpath(source_path, destination)).as_posix()


def _validate_generated(root: Path, generated: list[str]) -> dict[str, Any]:
    """Compile only drafts written for this invocation; never validate unrelated stale files."""
    solidity_files: list[Path] = []
    for raw_path in generated:
        path = Path(raw_path)
        if not path.is_absolute():
            path = root / path
        if path.name.endswith(".t.sol") and path.is_file():
            solidity_files.append(path.resolve())
    solidity_files = sorted(set(solidity_files))
    result: dict[str, Any] = {
        "requested": True,
        "status": "not-applicable" if not solidity_files else "pending",
        "command": ["forge", "build"],
        "baseline_exit_code": None,
        "exit_code": None,
        "detail": "",
    }
    if not solidity_files:
        result["detail"] = "No generated Solidity drafts were available to compile. Formal specs are not validated by Forge."
        return result
    forge_bin = shutil.which("forge")
    if not forge_bin:
        result["status"] = "unavailable"
        result["detail"] = "forge was not found on PATH; drafts were written but not compile-validated."
        return result

    try:
        baseline = subprocess.run(
            [forge_bin, "build"], cwd=root, capture_output=True, text=True,
            timeout=180, check=False,
        )
    except subprocess.TimeoutExpired as exc:
        result["status"] = "baseline-failed"
        result["detail"] = "Baseline forge build timed out before generated drafts were added."
        result["stdout_tail"] = str(exc.stdout or "")[-4000:]
        result["stderr_tail"] = str(exc.stderr or "")[-4000:]
        return result
    except OSError as exc:
        result["status"] = "unavailable"
        result["detail"] = "Could not run baseline forge build: " + str(exc)
        return result
    result["baseline_exit_code"] = baseline.returncode
    if baseline.returncode != 0:
        result["status"] = "baseline-failed"
        result["exit_code"] = baseline.returncode
        result["detail"] = "The project fails to build before generated drafts are added; draft compilation was not evaluated."
        result["stdout_tail"] = (baseline.stdout or "")[-4000:]
        result["stderr_tail"] = (baseline.stderr or "")[-4000:]
        return result

    destination = _foundry_test_dir(root) / "lowkey-generated"
    created_dirs: list[Path] = []
    cursor = destination
    while not cursor.exists():
        created_dirs.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    try:
        destination.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        result["status"] = "unavailable"
        result["detail"] = "Cannot create temporary validation directory: " + str(exc)
        for directory in created_dirs:
            try:
                directory.rmdir()
            except OSError:
                pass
        return result

    token = uuid.uuid4().hex[:12]
    temporary_files: list[Path] = []
    try:
        for source_path in solidity_files:
            content = source_path.read_text(encoding="utf-8")
            searchable = mask_solidity(content) if mask_solidity else content
            declarations = re.findall(r"\b(?:abstract\s+)?contract\s+([A-Za-z_]\w*)", searchable)
            for declaration in declarations:
                unique_name = "LowkeyValidation_" + token + "_" + declaration
                content = re.sub(r"\b" + re.escape(declaration) + r"\b", unique_name, content)
            temp_path = destination / ("LowkeyValidation_" + token + "_" + source_path.name)
            temp_path.write_text(content, encoding="utf-8")
            temporary_files.append(temp_path)

        completed = subprocess.run(
            [forge_bin, "build"], cwd=root, capture_output=True, text=True,
            timeout=180, check=False,
        )
        result["exit_code"] = completed.returncode
        result["stdout_tail"] = (completed.stdout or "")[-4000:]
        result["stderr_tail"] = (completed.stderr or "")[-4000:]
        result["status"] = "passed" if completed.returncode == 0 else "failed"
        result["detail"] = (
            "Generated Solidity drafts compiled successfully; test functions were not executed."
            if completed.returncode == 0 else
            "The project built before staging drafts but failed to compile with temporary generated drafts."
        )
    except subprocess.TimeoutExpired as exc:
        result["status"] = "failed"
        result["detail"] = "forge build timed out after 180 seconds."
        result["stdout_tail"] = str(exc.stdout or "")[-4000:]
        result["stderr_tail"] = str(exc.stderr or "")[-4000:]
    except OSError as exc:
        result["status"] = "unavailable"
        result["detail"] = "Could not stage or compile generated drafts: " + str(exc)
    finally:
        for path in temporary_files:
            try:
                path.unlink()
            except OSError:
                pass
        for directory in created_dirs:
            try:
                directory.rmdir()
            except OSError:
                pass
    return result


def _solidity_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not clean or clean[0].isdigit():
        clean = "Contract_" + clean
    return clean


def _local_template(kind: str, name: str, import_path: str, constructor_values: list[str],
                    fuzz_property: dict[str, str] | None = None,
                    analysis: dict[str, Any] | None = None,
                    source_pragma: str = "^0.8.20") -> str:
    ident = _solidity_name(name)
    generated = f"LowkeyGenerated{kind.title()}_{ident}"
    constructor_arguments = ", ".join(constructor_values)
    deploy_expression = f"new {name}({constructor_arguments})"
    common = f'''// SPDX-License-Identifier: MIT
pragma solidity {source_pragma};

// LowkeyCast-generated STARTER, not proof of protocol correctness.
// Move into lowkey-generated under the configured Foundry test directory.
import {{Test}} from "forge-std/Test.sol";
import {{ {name} }} from "{import_path}";

'''
    if constructor_values:
        common += "// TODO: Review the compile-safe constructor placeholder values before relying on generated tests.\n\n"
    setter_unit_test = ""
    if fuzz_property:
        setter = fuzz_property["setter"]
        parameter_type = fuzz_property["type"]
        state = fuzz_property["state"]
        setter_unit_test = f"""
    function test_{setter}_updatesPublicState() public {{
        {parameter_type} expected = {parameter_type}(1);
        target.{setter}(expected);
        assertEq(target.{state}(), expected);
    }}
"""
    extra_access_tests = "\n".join(unit_access_control_tests(analysis or {}, (analysis or {}).get("_source_text", "")) if unit_access_control_tests else [])
    if extra_access_tests:
        extra_access_tests = "\n" + extra_access_tests + "\n"
    if kind == "unit":
        body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    function test_deployment_has_runtime_code() public view {{
        address deployed = address(target);
        uint256 codeSize;
        assembly {{ codeSize := extcodesize(deployed) }}
        assertGt(codeSize, 0);
    }}

    // TODO: Add unit tests for expected state changes, access control,
    // boundary values, revert reasons, emitted events, and accounting.
{setter_unit_test}{extra_access_tests}}}
'''
    elif kind == "fuzz":
        if fuzz_property:
            setter = fuzz_property["setter"]
            parameter_type = fuzz_property["type"]
            state = fuzz_property["state"]
            body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    function testFuzz_{setter}_preservesStoredValue({parameter_type} fuzzValue) public {{
        target.{setter}(fuzzValue);
        assertEq(target.{state}(), fuzzValue);
    }}

    // Generated only because the source has a public integer state variable
    // and a setter whose body assigns its sole parameter directly.
    // TODO: Add caller/access-control cases and boundary-specific properties.
}}
'''
        else:
            body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    // TODO: No safe direct-setter/public-integer-getter property was recognized.
    // Add an executable testFuzz_ function for a property you can state precisely.
    // Do not mistake a fuzzed call for a tested property.
}}
'''
    elif kind == "invariant":
        if fuzz_property:
            setter = fuzz_property["setter"]
            parameter_type = fuzz_property["type"]
            state = fuzz_property["state"]
            handler = f"LowkeyInvariantHandler_{ident}"
            body = f'''contract {handler} {{
    {name} internal immutable target;
    {parameter_type} public expectedValue;

    constructor({name} target_) {{
        target = target_;
        expectedValue = target_.{state}();
    }}

    function {setter}({parameter_type} nextValue) external {{
        target.{setter}(nextValue);
        expectedValue = nextValue;
    }}
}}

contract {generated} is Test {{
    {name} internal target;
    {handler} internal handler;

    function setUp() public {{
        target = {deploy_expression};
        handler = new {handler}(target);
        targetContract(address(handler));
    }}

    function invariant_{state}_matchesLastSuccessfulSetterCall() public view {{
        assertEq(target.{state}(), handler.expectedValue());
    }}
}}
'''
        else:
            body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    // TODO: Write a Handler that performs valid protocol actions, then target
    // it with targetContract(address(handler)). Add invariant_ functions for
    // real properties (for example, sum of user balances == total liabilities).
    // No protocol invariant can be safely inferred from the ABI alone.
}}
'''
    elif kind == "integration":
        body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    // TODO: Deploy or configure the real peer contracts (tokens, oracle, router,
    // vault, etc.), wire their addresses, and test cross-contract behavior.
    // This starter intentionally does not invent dependency addresses.
}}
'''
    else:  # regression
        body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    // TODO: Preserve a specific previously failing behavior here.
    // Add the old bug's preconditions, trigger, and expected post-fix assertion.
    // A smoke test alone is not a regression test.
}}
'''
    return common + body


def _formal_template(name: str, fuzz_property: dict[str, str] | None) -> tuple[str, str]:
    """Return a Certora CVL rule for a narrow recognized property or a worksheet."""
    if fuzz_property:
        setter = fuzz_property["setter"]
        parameter_type = fuzz_property["type"]
        state = fuzz_property["state"]
        content = f'''// Certora CVL starter generated by LowkeyCast.
// Review the contract configuration and run with a compatible Certora Prover setup.
// This rule models only the directly observed setter/getter relationship.

using {name} as target;

methods {{
    function {setter}({parameter_type}) external;
    function {state}() external returns ({parameter_type}) envfree;
}}

rule {setter}_round_trip({parameter_type} fuzzValue) {{
    env e;
    target.{setter}(e, fuzzValue);
    assert target.{state}() == fuzzValue;
}}
'''
        return ".spec", content

    content = f'''# Formal verification worksheet: {name}

Generated by LowkeyCast. This is **not a proof** and is not an executable CVL spec yet.

## Scope and required decisions
- [ ] Choose and pin a verifier/tool version (for example, Certora Prover with CVL).
- [ ] State each security property as precise preconditions and postconditions.
- [ ] Identify privileged actors and authorization invariants.
- [ ] Specify accounting conservation and solvency properties where relevant.
- [ ] Specify state-machine transitions and invalid transitions.
- [ ] Model external calls, tokens, oracles, and environmental assumptions.
- [ ] Review assumptions for vacuity; rules must not pass because preconditions are impossible.
- [ ] Run the verifier, inspect counterexamples, and record the exact configuration.

## Why no rule was generated
Lowkey could not confidently identify a direct public-integer setter/getter property for {name}.
A guessed assertion could be incorrect or vacuous. Add a formal rule only after the intended behavior and assumptions are understood.
'''
    return ".md", content


def _fork_template(kind: str, name: str, target: str | None, import_path: str,
                   fuzz_property: dict[str, str] | None,
                   analysis: dict[str, Any] | None = None,
                   source_pragma: str = "^0.8.20") -> str:
    """Generate fork diagnostics without mutating a deployed protocol by default."""
    ident = _solidity_name(name)
    addr = target.lower() if isinstance(target, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", target) else "address(0)"
    target_literal = addr if addr == "address(0)" else f"address({addr})"
    generated = f"LowkeyGenerated{kind.title()}_{ident}"
    version_match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", source_pragma)
    chainid_supported = not version_match or (int(version_match.group(1)), int(version_match.group(2))) >= (0, 8)
    chain_id_check = (
        '        uint256 expectedChainId = vm.envOr("LOWKEY_EXPECTED_CHAIN_ID", uint256(0));'
        '\n        if (expectedChainId != 0) assertEq(block.chainid, expectedChainId, "Unexpected fork chain ID");'
        if chainid_supported else
        '        // Solidity before 0.8.0 has no block.chainid builtin; pin the chain externally.'
    )
    body = f'''// SPDX-License-Identifier: MIT
pragma solidity {source_pragma};

// LowkeyCast-generated fork diagnostic. Set LOWKEY_RPC_URL; pin LOWKEY_FORK_BLOCK and
// LOWKEY_EXPECTED_CHAIN_ID for reproducible, chain-checked audit evidence.
// Tests run against a local Foundry fork; they do not send transactions to mainnet.
import {{Test}} from "forge-std/Test.sol";
import {{ {name} }} from "{import_path}";

contract {generated} is Test {{
    address internal constant TARGET = {target_literal};
    {name} internal target;

    function _codeSize(address account) internal view returns (uint256 size) {{
        assembly {{ size := extcodesize(account) }}
    }}

    function setUp() public {{
        string memory rpcUrl = vm.envString("LOWKEY_RPC_URL");
        uint256 requestedBlock = vm.envOr("LOWKEY_FORK_BLOCK", uint256(0));
        if (requestedBlock == 0) {{
            vm.createSelectFork(rpcUrl);
        }} else {{
            vm.createSelectFork(rpcUrl, requestedBlock);
        }}
        require(TARGET != address(0), "Set a real target address before running");
        assertGt(_codeSize(TARGET), 0, "Target has no code on selected fork");
        {chain_id_check}
        target = {name}(TARGET);
    }}

    function test_fork_target_has_runtime_code() public view {{
        assertGt(_codeSize(TARGET), 0, "Target has no runtime code");
    }}

'''
    if kind == "fork":
        state_variables = (analysis or {}).get("state_variables", [])
        generated_getters = 0
        for state in state_variables:
            if state.get("visibility") != "public":
                continue
            getter = str(state.get("name") or "")
            if not re.fullmatch(r"[A-Za-z_]\w*", getter):
                continue
            body += f'''    function testFork_{getter}_publicGetterIsCallable() public view {{
        (bool ok, bytes memory result) = TARGET.staticcall(
            abi.encodeWithSignature("{getter}()")
        );
        assertTrue(ok, "Public getter reverted on selected fork");
        assertGt(result.length, 0, "Public getter returned no encoded data");
    }}

'''
            generated_getters += 1
        if generated_getters == 0:
            body += '''    // TODO: Add a read-only assertion against a known deployment invariant,
    // such as an expected owner, implementation address, oracle configuration,
    // or a block-pinned accounting value. No expected value was inferred.
'''
        body += '''    // Writes are deliberately not generated from a local source pattern:
    // authorization, proxy routing, and live state may differ from local source.
}
'''
    else:
        body += '''    // TODO: Add a concrete exploit precondition, trigger, and measurable
    // security-impact assertion backed by a finding or recorded execution.
    // No suspected vulnerability was supplied, so a generic PoC would be fiction.
}
'''
    return body

def _render(kind: str, name: str, import_path: str, target: str | None,
            local_deploy: bool, constructor_values: list[str] | None,
            is_abstract: bool, fuzz_property: dict[str, str] | None,
            analysis: dict[str, Any] | None = None,
            source_pragma: str = "^0.8.20") -> str:
    if kind == "formal":
        return _formal_template(name, fuzz_property)[1]
    if kind in {"unit", "fuzz", "invariant", "integration", "regression"}:
        if is_abstract:
            raise ValueError(f"{kind} cannot automatically deploy an abstract contract")
        if not local_deploy or constructor_values is None:
            raise ValueError(
                f"{kind} needs constructor argument types with supported placeholder values; "
                "this constructor contains an unsupported or unrecognized type"
            )
        return _local_template(kind, name, import_path, constructor_values, fuzz_property if kind in {"unit", "fuzz", "invariant"} else None, analysis, source_pragma)
    return _fork_template(kind, name, target, import_path, fuzz_property, analysis, source_pragma)


def _recorded_call_poc(
    root: Path,
    contract_name: str,
    target: str | None,
    source_pragma: str,
) -> tuple[str, dict[str, Any]] | None:
    """Create a replay-only fork test from a concrete call for the configured target."""
    if not isinstance(target, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", target):
        return None
    version = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)", source_pragma)
    if version and (int(version.group(1)), int(version.group(2))) < (0, 8):
        return None
    try:
        import generator as existing_generator
        request = existing_generator._request_from_latest(root, expected_target=target)
    except (ImportError, OSError, ValueError, RuntimeError):
        return None
    if not request or str(getattr(request, "target", "")).lower() != target.lower():
        return None
    calldata = str(getattr(request, "calldata", "") or "").removeprefix("0x")
    if not calldata or len(calldata) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", calldata):
        return None
    value = str(getattr(request, "value", "0") or "0")
    function = str(getattr(request, "function", "") or "recordedCall")
    try:
        content = existing_generator._template_test(
            contract_name,
            target,
            function,
            value,
            calldata,
            source_import=None,
            deploy_locally=False,
        )
    except (AttributeError, TypeError, ValueError):
        return None
    content = content.replace("pragma solidity ^0.8.20;", f"pragma solidity {source_pragma};", 1)
    content = content.replace(
        "vm.createSelectFork(rpcUrl);",
        """uint256 requestedBlock = vm.envOr("LOWKEY_FORK_BLOCK", uint256(0));
        if (requestedBlock == 0) {
            vm.createSelectFork(rpcUrl);
        } else {
            vm.createSelectFork(rpcUrl, requestedBlock);
        }
        uint256 expectedChainId = vm.envOr("LOWKEY_EXPECTED_CHAIN_ID", uint256(0));
        if (expectedChainId != 0) {
            assertEq(block.chainid, expectedChainId, "Unexpected fork chain ID");
        }""",
        1,
    )
    content = content.replace("contract LowkeyTest_", "contract LowkeyGeneratedPoc_", 1)
    content = (
        "// Lowkey test-gen replay candidate: this replays recorded calldata; it does NOT establish exploitability.\\n"
        "// Pin LOWKEY_FORK_BLOCK and LOWKEY_EXPECTED_CHAIN_ID for reproducibility.\\n"
        + content
    )
    return content, {
        "mode": "recorded-call-replay",
        "target": target,
        "function": function,
        "value": value,
        "calldata_sha256": hashlib.sha256(bytes.fromhex(calldata)).hexdigest(),
        "security_impact_assertion": False,
        "note": "Replay only. The fork executes the configured target address, not the local source; verify implementation/source identity and add exploit preconditions plus a security-impact assertion before calling this a PoC.",
    }


def _generation_assessment(
    selected: list[str],
    *,
    local_deploy: bool,
    is_abstract: bool,
    fuzz_property: dict[str, str] | None,
    target: str | None,
    constructor_values: list[str] | None = None,
    recorded_poc: bool = False,
) -> dict[str, dict[str, Any]]:
    """Describe what each artifact actually contains, without equating scaffolds with tests."""
    result: dict[str, dict[str, Any]] = {}
    valid_target = isinstance(target, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", target) is not None
    for kind in selected:
        if kind == "unit":
            if local_deploy and not is_abstract and fuzz_property:
                if constructor_values:
                    level, note = "requires-setup-review", "A narrow setter/getter assertion is generated, but constructor placeholders must be checked before execution."
                else:
                    level, note = "executable-candidate", "Deployment smoke test and a narrow setter/getter assertion; not broad unit coverage."
            elif local_deploy and not is_abstract:
                if constructor_values:
                    level, note = "requires-setup-review", "Smoke test only; constructor placeholders may violate deployment preconditions."
                else:
                    level, note = "smoke-only", "Deployment smoke test plus TODOs; no business-behavior assertion was inferred."
            else:
                level, note = "blocked", "No safe automatic local deployment was inferred."
        elif kind == "fuzz":
            if local_deploy and not is_abstract and fuzz_property:
                level = "requires-setup-review" if constructor_values else "executable-candidate"
                note = "Fuzzes only the recognized direct setter/getter relation; review constructor placeholders first." if constructor_values else "Fuzzes only the recognized direct setter/getter relation."
            else:
                level, note = "scaffold", "No executable property was inferred; add a property and valid input domain."
        elif kind == "invariant":
            if local_deploy and not is_abstract and fuzz_property:
                level = "requires-setup-review" if constructor_values else "executable-candidate"
                note = "Checks the last successful direct setter write, but constructor placeholders must be reviewed first." if constructor_values else "Checks the last successful direct setter write; this is not a protocol-wide invariant."
            else:
                level, note = "scaffold", "A handler and protocol invariant must be designed from intended behavior."
        elif kind == "integration":
            level, note = "scaffold", "Peer deployment, configuration, and cross-contract assertions are not inferred automatically."
        elif kind == "fork":
            level = "diagnostic-candidate" if valid_target else "requires-target"
            note = "Read-only fork diagnostics; add deployment-specific expected values and proxy/implementation checks." if valid_target else "Set a deployed target address before the fork draft can run."
        elif kind == "poc":
            if recorded_poc:
                level, note = "recorded-call-replay", "Replays a recorded call on a fork; it is not an exploit proof until impact assertions are added."
            else:
                level, note = "scaffold", "A concrete exploit precondition, trigger, and impact assertion are required."
        elif kind == "regression":
            level, note = "scaffold", "A known bug's trigger and post-fix expectation must be supplied."
        elif kind == "formal":
            level = "candidate-rule" if fuzz_property else "worksheet"
            note = "Narrow setter/getter CVL candidate only; it is not proof until the verifier runs and assumptions are reviewed." if level == "candidate-rule" else "No executable formal rule was inferred."
        else:
            level, note = "unknown", "No assessment is available for this type."
        result[kind] = {
            "level": level,
            "protocol_security_established": False,
            "note": note,
        }
    return result


def run_test_gen(config: dict[str, Any], args: list[str]) -> int:
    if any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        print("""Lowkey test generator

Usage:
  lk test-gen [ContractName] [--types all|unit,fuzz,invariant,integration,fork,poc,regression,formal]
              [--output-dir .audit/test-gen] [--force] [--validate]

Types:
  unit         Local deployment smoke test + unit-test TODOs
  fuzz         Executable setter/getter fuzz property when safely recognized; otherwise a TODO
  invariant    Handler/property scaffold; protocol invariants must be supplied
  integration  Local peer-contract wiring scaffold
  fork         Read-only fork checks against the configured target
  poc          Fork-based reproduction scaffold
  regression   Starter for locking in a previously fixed bug
  formal       Certora CVL rule for recognized properties, or a formal-spec worksheet

Generated drafts are saved outside Foundry's test directory by default, so they
will not silently affect the project's existing test suite. Review the report,
complete TODOs, and move approved files into the configured Foundry test directory before running Forge.
The generator does not claim coverage or invent protocol-specific assertions.
--validate compiles temporary generated drafts with forge build; it never executes tests.
""")
        return 0

    name = str(config.get("target_contract") or "").strip()
    types_raw: str | None = None
    output_dir = Path(".audit/test-gen")
    force = False
    validate = False
    positionals: list[str] = []
    index = 0
    while index < len(args):
        value = str(args[index])
        if value == "--types":
            index += 1
            if index >= len(args):
                return _error("--types needs a comma-separated list or 'all'")
            types_raw = str(args[index])
        elif value.startswith("--types="):
            types_raw = value.split("=", 1)[1]
        elif value == "--output-dir":
            index += 1
            if index >= len(args):
                return _error("--output-dir needs a path")
            output_dir = Path(args[index]).expanduser()
        elif value.startswith("--output-dir="):
            output_dir = Path(value.split("=", 1)[1]).expanduser()
        elif value == "--force":
            force = True
        elif value == "--validate":
            validate = True
        elif value.startswith("-"):
            return _error(f"Unknown option: {value}")
        else:
            positionals.append(value)
        index += 1
    if positionals:
        name = positionals[0]
    if not name:
        return _error("Provide <ContractName> or set the active project target first.")
    try:
        selected = parse_types(types_raw)
    except ValueError as exc:
        return _error(str(exc))

    root = Path.cwd().resolve()
    config_path = _foundry_config_path(root)
    if not config_path.is_file():
        return _error(f"No Foundry config found at {config_path}. Run this from a Foundry project.")
    found = _contract_source(root, name)
    if not found:
        return _error(f"Could not find contract '{name}' under {_source_root(root)}.")
    source_path, source = found
    source_label = source_path.relative_to(root).as_posix() if source_path.is_relative_to(root) else str(source_path)
    source_sha256 = hashlib.sha256(source.encode("utf-8")).hexdigest()
    constructor_args = _constructor_args(source, name)
    constructor_values = _constructor_values(constructor_args)
    is_abstract = bool(re.search(r"\babstract\s+contract\s+" + re.escape(name) + r"\b", source))
    local_deploy = constructor_values is not None and not is_abstract
    fuzz_property = _find_simple_fuzz_property(source, name)
    analysis = analyse_contract(root, name, source_path, source, _foundry_test_dir(root)) if analyse_contract else {
        "contract": name, "source": str(source_path), "functions": [], "state_variables": [],
        "security_surfaces": {}, "profiles": [], "imports": [], "existing_tests": {},
        "audit_evidence": {"files": [], "signals": [], "note": "Analysis module unavailable."},
        "limitations": ["Evidence analysis module unavailable; reinstall LowkeyCast."],
    }
    analysis["_source_text"] = source
    import_path = _rel_import(root, source_path)
    source_pragma = _solidity_pragma(source)
    output_dir = output_dir if output_dir.is_absolute() else root / output_dir
    output_dir = output_dir / _solidity_name(name)
    output_dir.mkdir(parents=True, exist_ok=True)

    target = config.get("target")
    generated: list[str] = []
    skipped: list[dict[str, str]] = []
    poc_replay: dict[str, Any] | None = None
    for kind in selected:
        suffix = ".t.sol"
        if kind == "formal":
            suffix, _ = _formal_template(name, fuzz_property)
        filename = output_dir / f"LowkeyGenerated{kind.title()}_{_solidity_name(name)}{suffix}"
        try:
            if kind == "poc":
                replay = _recorded_call_poc(root, name, target, source_pragma)
                if replay is not None:
                    content, poc_replay = replay
                else:
                    content = _render(kind, name, import_path, target, local_deploy, constructor_values, is_abstract, fuzz_property, analysis, source_pragma)
            else:
                content = _render(kind, name, import_path, target, local_deploy, constructor_values, is_abstract, fuzz_property, analysis, source_pragma)
        except ValueError as exc:
            skipped.append({"type": kind, "reason": str(exc)})
            continue
        if filename.exists() and not force:
            label = filename.relative_to(root) if filename.is_relative_to(root) else filename
            skipped.append({"type": kind, "reason": f"{label} already exists (use --force to replace)"})
            continue
        filename.write_text(content, encoding="utf-8")
        label = filename.relative_to(root) if filename.is_relative_to(root) else filename
        generated.append(str(label))

    generation_assessment = _generation_assessment(
        selected,
        local_deploy=local_deploy,
        is_abstract=is_abstract,
        fuzz_property=fuzz_property,
        target=target,
        constructor_values=constructor_values,
        recorded_poc=poc_replay is not None,
    )
    for skipped_item in skipped:
        generation_assessment[skipped_item["type"]] = {
            "level": "not-generated",
            "protocol_security_established": False,
            "note": skipped_item["reason"],
        }

    report = {
        "contract": name,
        "source": source_label,
        "source_sha256": source_sha256,
        "constructor": "abstract-contract" if is_abstract else ("unknown" if constructor_args is None else ("zero-argument" if not constructor_args.strip() else ("arguments-required" if constructor_values is not None else "unsupported-arguments"))),
        "constructor_parameters": constructor_args,
        "constructor_placeholders": constructor_values,
        "solidity_pragma": source_pragma,
        "fuzz_property": fuzz_property,
        "analysis": {key: value for key, value in analysis.items() if not key.startswith("_")},
        "requested_types": selected,
        "generation_assessment": generation_assessment,
        "poc_replay": poc_replay,
        "generated": generated,
        "skipped": skipped,
        "warning": "Scaffolds are not protocol proofs. Complete TODO assertions before relying on them.",
        "validation": {"requested": False, "status": "not-requested"},
    }
    if validate:
        validation = _validate_generated(root, generated)
        if "formal" in selected:
            validation["unvalidated_types"] = ["formal"]
            if validation.get("status") == "passed":
                validation["status"] = "partial"
                validation["detail"] += " Solidity drafts compiled, but the generated formal specification was not checked by Forge."
            elif validation.get("status") == "not-applicable":
                validation["detail"] += " Formal specifications require their configured verifier; Forge cannot validate them."
        report["validation"] = validation
    plan_path = output_dir / "test-plan.md"
    if plan_path.exists() and not force:
        plan_path = output_dir / "test-plan.latest.md"
    plan_content = render_test_plan({key: value for key, value in analysis.items() if not key.startswith("_")}, selected) if render_test_plan else "# Test plan unavailable\n\nReinstall LowkeyCast to restore the analysis module.\n"
    plan_path.write_text(plan_content, encoding="utf-8")

    report_path = output_dir / "report.json"
    if report_path.exists() and not force:
        report_path = output_dir / "report.latest.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"Test-generation drafts for {name}")
    print(f"Source: {source_label}")
    print(f"Output: {output_dir.relative_to(root) if output_dir.is_relative_to(root) else output_dir}")
    for path in generated:
        print(f"  generated  {path}")
    for item in skipped:
        print(f"  skipped    {item['type']}: {item['reason']}")
    print("Generation assessment:")
    for kind, assessment in report["generation_assessment"].items():
        print(f"  {kind}: {assessment['level']} — {assessment['note']}")
    print("No generated artifact establishes protocol security; validation is compile-only.")
    validation = report["validation"]
    if validation.get("requested"):
        print(f"Validation: {validation.get('status')} - {validation.get('detail', '')}")
    print(f"Plan: {plan_path.relative_to(root) if plan_path.is_relative_to(root) else plan_path}")
    print(f"Report: {report_path.relative_to(root) if report_path.is_relative_to(root) else report_path}")
    if validate and report["validation"].get("status") != "passed":
        # A requested validation that could not compile any Solidity draft is not a pass.
        # In particular, Forge cannot validate Certora CVL/worksheet output.
        return 1
    return 0


def _error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 2
