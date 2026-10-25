"""Project-aware Solidity test-scaffold generation for LowkeyCast.

Generated drafts live outside Foundry's configured test directory by default.
Lowkey deliberately does not invent protocol assertions from names or ABI alone.
"""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

TEST_TYPES = ("unit", "fuzz", "invariant", "integration", "fork", "poc", "regression")


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


def _source_root(root: Path) -> Path:
    src = "src"
    config = root / "foundry.toml"
    if config.exists():
        try:
            import tomllib
            data = tomllib.loads(config.read_text(encoding="utf-8"))
            src = (
                data.get("profile", {}).get("default", {}).get("src")
                or data.get("src")
                or src
            )
        except (OSError, ValueError, ImportError):
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
        if pattern.search(source):
            return path, source
    return None


def _contract_body(source: str, name: str) -> str | None:
    match = re.search(
        r"\b(?:abstract\s+)?contract\s+" + re.escape(name) + r"\b[^\{]*\{",
        source,
    )
    if not match:
        return None
    start = match.end()
    depth = 1
    end = start
    while end < len(source) and depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    if depth:
        return None
    return source[start:end - 1]


def _constructor_args(source: str, name: str) -> str | None:
    body = _contract_body(source, name)
    if body is None:
        return None
    constructor = re.search(r"\bconstructor\s*\(([^)]*)\)", body)
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

    integer_type = r"(?:u?int(?:8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?)"
    states: dict[str, str] = {}
    for match in re.finditer(
        rf"(?m)^\s*({integer_type})\s+public\s+([A-Za-z_]\w*)\s*;",
        body,
    ):
        states[match.group(2)] = match.group(1)

    if not states:
        return None

    function_pattern = re.compile(
        r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*"
        r"(?:external|public)\b[^{}]*\{"
    )
    for match in function_pattern.finditer(body):
        parameters = _split_parameters(match.group(2))
        if len(parameters) != 1:
            continue
        parameter_tokens = parameters[0].split()
        if len(parameter_tokens) != 2:
            continue
        parameter_type, parameter_name = parameter_tokens
        if not re.fullmatch(integer_type, parameter_type):
            continue

        opening = match.end() - 1
        closing = _matching_brace(body, opening)
        if closing is None:
            continue
        function_body = body[opening + 1:closing]
        function_body = re.sub(r"/\*.*?\*/|//[^\n]*", "", function_body, flags=re.S).strip()

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


def _rel_import(root: Path, source_path: Path) -> str:
    # Generated source is intended to be moved into test/lowkey-generated.
    relative = Path("test") / "lowkey-generated"
    target = Path(os.path.relpath(source_path, root / relative))
    return PurePosixPath(target).as_posix()


def _solidity_name(name: str) -> str:
    clean = re.sub(r"[^A-Za-z0-9_]", "_", name)
    if not clean or clean[0].isdigit():
        clean = "Contract_" + clean
    return clean


def _local_template(kind: str, name: str, import_path: str, constructor_values: list[str],
                    fuzz_property: dict[str, str] | None = None) -> str:
    ident = _solidity_name(name)
    generated = f"LowkeyGenerated{kind.title()}_{ident}"
    constructor_arguments = ", ".join(constructor_values)
    deploy_expression = f"new {name}({constructor_arguments})"
    common = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// LowkeyCast-generated STARTER, not proof of protocol correctness.
// Move to test/lowkey-generated and review all TODOs before relying on it.
import {{Test}} from "forge-std/Test.sol";
import {{ {name} }} from "{import_path}";

'''
    if constructor_values:
        common += "// TODO: Review the compile-safe constructor placeholder values before relying on generated tests.\n\n"
    if kind == "unit":
        body = f'''contract {generated} is Test {{
    {name} internal target;

    function setUp() public {{
        target = {deploy_expression};
    }}

    function test_deployment_has_runtime_code() public view {{
        assertGt(address(target).code.length, 0);
    }}

    // TODO: Add unit tests for expected state changes, access control,
    // boundary values, revert reasons, emitted events, and accounting.
}}
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


def _fork_template(kind: str, name: str, target: str | None) -> str:
    ident = _solidity_name(name)
    addr = target.lower() if isinstance(target, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", target) else "address(0)"
    target_literal = addr if addr == "address(0)" else f"address({addr})"
    generated = f"LowkeyGenerated{kind.title()}_{ident}"
    body = f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// LowkeyCast-generated starter. Configure LOWKEY_RPC_URL before running.
import {{Test}} from "forge-std/Test.sol";

contract {generated} is Test {{
    address internal constant TARGET = {target_literal};

    function setUp() public {{
        string memory rpcUrl = vm.envString("LOWKEY_RPC_URL");
        vm.createSelectFork(rpcUrl);
        require(TARGET != address(0), "Set a real target address before running");
        assertGt(TARGET.code.length, 0, "Target has no code on selected fork");
    }}

'''
    if kind == "fork":
        body += '''    function test_fork_target_has_code() public view {
        assertGt(TARGET.code.length, 0);
    }

    // TODO: Assert the expected behavior against this chain's actual state.
}
'''
    else:
        body += '''    // TODO: Add the concrete call/preconditions and the security property
    // that demonstrates impact. A successful low-level call is not a finding.
    // For call-specific recorded evidence, use the existing lk generate test.
}
'''
    return body


def _render(kind: str, name: str, import_path: str, target: str | None,
            local_deploy: bool, constructor_values: list[str] | None,
            is_abstract: bool, fuzz_property: dict[str, str] | None) -> str:
    if kind in {"unit", "fuzz", "invariant", "integration", "regression"}:
        if is_abstract:
            raise ValueError(f"{kind} cannot automatically deploy an abstract contract")
        if not local_deploy or constructor_values is None:
            raise ValueError(
                f"{kind} needs constructor argument types with supported placeholder values; "
                "this constructor contains an unsupported or unrecognized type"
            )
        return _local_template(kind, name, import_path, constructor_values, fuzz_property if kind == "fuzz" else None)
    return _fork_template(kind, name, target)


def run_test_gen(config: dict[str, Any], args: list[str]) -> int:
    if any(str(arg).lower() in {"-h", "--help", "help"} for arg in args):
        print("""Lowkey test generator

Usage:
  lk test-gen [ContractName] [--types all|unit,fuzz,invariant,integration,fork,poc,regression]
              [--output-dir .audit/test-gen] [--force]

Types:
  unit         Local deployment smoke test + unit-test TODOs
  fuzz         Fuzz-test scaffold; the property and valid input range are TODOs
  invariant    Handler/property scaffold; protocol invariants must be supplied
  integration  Local peer-contract wiring scaffold
  fork         Fork smoke test against the configured target
  poc          Fork-based reproduction scaffold
  regression   Starter for locking in a previously fixed bug

Generated drafts are saved outside Foundry's test directory by default, so they
will not silently affect the project's existing test suite. Review the report,
complete TODOs, and move approved files into test/ before running Forge.
The generator does not claim coverage or invent protocol-specific assertions.
""")
        return 0

    name = str(config.get("target_contract") or "").strip()
    types_raw: str | None = None
    output_dir = Path(".audit/test-gen")
    force = False
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
    if not (root / "foundry.toml").exists():
        return _error("No foundry.toml found in the current directory. Run this from a Foundry project.")
    found = _contract_source(root, name)
    if not found:
        return _error(f"Could not find contract '{name}' under {_source_root(root)}.")
    source_path, source = found
    constructor_args = _constructor_args(source, name)
    constructor_values = _constructor_values(constructor_args)
    is_abstract = bool(re.search(r"\babstract\s+contract\s+" + re.escape(name) + r"\b", source))
    local_deploy = constructor_values is not None and not is_abstract
    fuzz_property = _find_simple_fuzz_property(source, name)
    import_path = _rel_import(root, source_path)
    output_dir = output_dir if output_dir.is_absolute() else root / output_dir
    output_dir = output_dir / _solidity_name(name)
    output_dir.mkdir(parents=True, exist_ok=True)

    target = config.get("target")
    generated: list[str] = []
    skipped: list[dict[str, str]] = []
    for kind in selected:
        filename = output_dir / f"LowkeyGenerated{kind.title()}_{_solidity_name(name)}.t.sol"
        try:
            content = _render(kind, name, import_path, target, local_deploy, constructor_values, is_abstract, fuzz_property)
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

    report = {
        "contract": name,
        "source": str(source_path.relative_to(root)),
        "constructor": "abstract-contract" if is_abstract else ("unknown" if constructor_args is None else ("zero-argument" if not constructor_args.strip() else ("arguments-required" if constructor_values is not None else "unsupported-arguments"))),
        "constructor_parameters": constructor_args,
        "constructor_placeholders": constructor_values,
        "fuzz_property": fuzz_property,
        "requested_types": selected,
        "generated": generated,
        "skipped": skipped,
        "warning": "Scaffolds are not protocol proofs. Complete TODO assertions before relying on them.",
    }
    report_path = output_dir / "report.json"
    if report_path.exists() and not force:
        report_path = output_dir / "report.latest.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(f"Test-generation drafts for {name}")
    print(f"Source: {source_path.relative_to(root)}")
    print(f"Output: {output_dir.relative_to(root) if output_dir.is_relative_to(root) else output_dir}")
    for path in generated:
        print(f"  generated  {path}")
    for item in skipped:
        print(f"  skipped    {item['type']}: {item['reason']}")
    print("Review TODOs: no protocol-specific behavior or invariant is inferred automatically.")
    print(f"Report: {report_path.relative_to(root) if report_path.is_relative_to(root) else report_path}")
    return 0


def _error(message: str) -> int:
    print(f"Error: {message}", file=sys.stderr)
    return 2
