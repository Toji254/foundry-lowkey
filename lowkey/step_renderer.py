#!/usr/bin/env python3
"""Fail-closed typed Step[] renderer for Lowkey acceptance/reproduction harnesses."""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}\Z")
SELECTOR_RE = re.compile(r"0x[0-9a-fA-F]{8}\Z")
CONTRACT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
INT_RE = re.compile(r"(u?int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)\Z")
BYTES_RE = re.compile(r"bytes([1-9]|[12][0-9]|3[0-2])\Z")
TOP_LEVEL_FIELDS = {"schema_version", "target_address", "family", "contract_name", "steps"}
STEP_FIELDS = {"kind", "target", "selector", "args", "value", "optional", "expect"}
SUPPORTED_CALL_KINDS = {"call", "unwind", "reenter"}
SUPPORTED_KINDS = SUPPORTED_CALL_KINDS | {"read", "expect"}


class RefusalError(ValueError):
    def __init__(self, refusal: dict[str, Any]):
        self.refusal = refusal
        super().__init__(str(refusal.get("detail") or refusal.get("reason")))


def _refusal(target: str | None, family: str | None, reason: str, detail: str,
             minimal_cmd: str | None = None, backend: str | None = None) -> dict[str, Any]:
    return {
        "target": target,
        "family": family,
        "reason": reason,
        "detail": detail,
        "minimal_cmd": minimal_cmd,
        "backend": backend,
    }


def _fail(target: str | None, family: str | None, reason: str, detail: str) -> None:
    raise RefusalError(_refusal(target, family, reason, detail))


def _address(value: Any, *, label: str, target: str | None, family: str | None) -> str:
    if not isinstance(value, str) or not ADDRESS_RE.fullmatch(value):
        _fail(target, family, "unsupported_abi", f"{label} must be a 20-byte 0x-prefixed address.")
    return value.lower()


def _integer(value: Any, *, signed: bool, target: str | None, family: str | None) -> int:
    if isinstance(value, bool):
        _fail(target, family, "unsupported_abi", "Boolean is not an integer ABI literal.")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str):
        try:
            result = int(value, 16) if value.lower().startswith("0x") else int(value, 10)
        except ValueError:
            _fail(target, family, f"ABI integer literal is invalid: {value!r}.")
    else:
        _fail(target, family, "unsupported_abi", "Integer ABI values must be JSON integers or decimal/hex strings.")
    if not signed and result < 0:
        _fail(target, family, "unsupported_abi", "Unsigned ABI values cannot be negative.")
    return result


def _typed_value(item: Any, *, target: str | None, family: str | None) -> tuple[str, str]:
    if not isinstance(item, dict) or set(item) != {"type", "value"}:
        _fail(target, family, "unsupported_abi", "Each ABI argument must be exactly {type, value}.")
    abi_type = item.get("type")
    value = item.get("value")
    if not isinstance(abi_type, str):
        _fail(target, family, "unsupported_abi", "ABI argument type must be a string.")
    abi_type = abi_type.strip()
    if abi_type == "address":
        literal = _address(value, label="ABI address value", target=target, family=family)
        return abi_type, f"address({literal})"
    if abi_type == "bool":
        if not isinstance(value, bool):
            _fail(target, family, "unsupported_abi", "bool ABI values must be JSON true or false.")
        return abi_type, "true" if value else "false"
    integer_match = INT_RE.fullmatch(abi_type)
    if integer_match:
        signed = integer_match.group(1) == "int"
        bits = int(integer_match.group(2))
        number = _integer(value, signed=signed, target=target, family=family)
        minimum = -(1 << (bits - 1)) if signed else 0
        maximum = (1 << (bits - (1 if signed else 0))) - 1
        if not minimum <= number <= maximum:
            _fail(target, family, "unsupported_abi", f"{abi_type} value is outside its declared range.")
        return abi_type, f"{abi_type}({number})"
    bytes_match = BYTES_RE.fullmatch(abi_type)
    if bytes_match:
        size = int(bytes_match.group(1))
        if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]{" + str(size * 2) + r"}", value):
            _fail(target, family, "unsupported_abi", f"{abi_type} requires exactly {size} bytes of 0x-prefixed hex.")
        return abi_type, f"{abi_type}({value.lower()})"
    _fail(
        target, family, "unsupported_abi",
        f"ABI type {abi_type!r} is not supported by the P1 scalar renderer; dynamic bytes/string, arrays, tuples and structs are refused.",
    )
    raise AssertionError("unreachable")


def _wei(value: Any, *, target: str | None, family: str | None) -> int:
    if value is None:
        return 0
    result = _integer(value, signed=False, target=target, family=family)
    if result > (1 << 256) - 1:
        _fail(target, family, "unsupported_abi", "Step.value exceeds uint256 wei.")
    return result


def _expectation(value: Any, *, target: str | None, family: str | None) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"count", "must_revert"}:
        _fail(target, family, "no_capability", "expect must be exactly {count, must_revert}.")
    count = value.get("count")
    must_revert = value.get("must_revert")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        _fail(target, family, "no_capability", "expect.count must be a non-negative integer.")
    if not isinstance(must_revert, bool):
        _fail(target, family, "no_capability", "expect.must_revert must be a JSON boolean.")
    return {"count": count, "must_revert": must_revert}


def _normalize_step(raw: Any, index: int, default_target: str | None,
                    family: str | None) -> dict[str, Any]:
    target_for_error = default_target
    if not isinstance(raw, dict):
        _fail(target_for_error, family, "unsupported_abi", f"Step #{index} must be a JSON object.")
    unknown = set(raw) - STEP_FIELDS
    if unknown:
        _fail(target_for_error, family, "unsupported_abi",
              f"Step #{index} has unknown field(s): {', '.join(sorted(unknown))}.")
    kind = raw.get("kind")
    if not isinstance(kind, str):
        _fail(target_for_error, family, "no_capability", f"Step #{index} requires a string kind.")
    kind = kind.strip().lower()
    if kind not in SUPPORTED_KINDS:
        reason = "no_capability" if kind in {"flash_borrow", "skew", "assert"} else "backend_unsupported"
        _fail(target_for_error, family, reason,
              f"Step kind {kind!r} is not executable in P1. Supported kinds: call, read, unwind, reenter, expect.")
    optional = raw.get("optional", False)
    if not isinstance(optional, bool):
        _fail(target_for_error, family, "no_capability", f"Step #{index} optional must be a boolean.")
    expectation = _expectation(raw.get("expect"), target=target_for_error, family=family)
    if kind == "expect":
        if any(raw.get(key) is not None for key in ("target", "selector", "args", "value")):
            _fail(target_for_error, family, "no_capability",
                  f"Step #{index} kind=expect cannot also supply target, selector, args or value.")
        if expectation is None:
            _fail(target_for_error, family, "no_capability", f"Step #{index} kind=expect requires an expect object.")
        return {"kind": kind, "optional": False, "expect": expectation}

    target_value = raw.get("target")
    if target_value is None:
        target_value = default_target
    step_target = _address(target_value, label=f"Step #{index} target", target=target_for_error, family=family)
    selector = raw.get("selector")
    if not isinstance(selector, str) or not SELECTOR_RE.fullmatch(selector):
        _fail(target_for_error, family, "unsupported_abi",
              f"Step #{index} selector must be exactly four bytes (0x plus eight hex characters).")
    args = raw.get("args") or []
    if not isinstance(args, list):
        _fail(target_for_error, family, "unsupported_abi", f"Step #{index} args must be an array or null.")
    typed_args = [_typed_value(arg, target=target_for_error, family=family) for arg in args]
    value = _wei(raw.get("value"), target=target_for_error, family=family)
    if kind == "read" and value != 0:
        _fail(target_for_error, family, "unsupported_abi", f"Step #{index} read cannot transfer ETH.")
    if expectation and expectation["must_revert"] and not optional:
        _fail(target_for_error, family, "no_capability",
              f"Step #{index} expects a revert but optional=true is required so the harness can observe it.")
    return {
        "kind": kind,
        "target": step_target,
        "selector": selector.lower(),
        "args": typed_args,
        "value": value,
        "optional": optional,
        "expect": expectation,
    }


def normalize_manifest(manifest: Any) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        _fail(None, None, "unsupported_abi", "Step manifest must be a JSON object.")
    unknown = set(manifest) - TOP_LEVEL_FIELDS
    if unknown:
        _fail(None, manifest.get("family"), "unsupported_abi",
              "Step manifest has unknown field(s): " + ", ".join(sorted(unknown)) + ".")
    family = manifest.get("family")
    if family is not None and (not isinstance(family, str) or not family.strip()):
        _fail(None, None, "unsupported_abi", "family must be a non-empty string or null.")
    family = family.strip().lower().replace("-", "_").replace(" ", "_") if family else None
    default_target = manifest.get("target_address")
    if default_target is not None:
        default_target = _address(default_target, label="target_address", target=None, family=family)
    steps = manifest.get("steps")
    if not isinstance(steps, list) or not steps:
        _fail(default_target, family, "no_capability", "steps must be a non-empty array.")
    if manifest.get("schema_version", 1) != 1:
        _fail(default_target, family, "unsupported_abi", "Only Step manifest schema_version 1 is supported.")
    contract_name = manifest.get("contract_name") or "LowkeyStepHarness"
    if not isinstance(contract_name, str) or not CONTRACT_RE.fullmatch(contract_name):
        _fail(default_target, family, "unsupported_abi", "contract_name must be a Solidity identifier.")
    normalized_steps = [
        _normalize_step(item, index, default_target, family)
        for index, item in enumerate(steps, 1)
    ]
    if not any(step["kind"] != "expect" for step in normalized_steps):
        _fail(default_target, family, "no_capability", "At least one call or read step is required.")
    return {
        "schema_version": 1,
        "family": family,
        "target_address": default_target,
        "contract_name": contract_name,
        "steps": normalized_steps,
    }


def _step_body(steps: list[dict[str, Any]]) -> str:
    rendered: list[str] = []
    for index, step in enumerate(steps):
        kind = step["kind"]
        if kind == "expect":
            expected = step["expect"]
            rendered.append(
                f"        require(_stepCallCount == {expected['count']}, \"LOWKEY_STEP_COUNT_{index}\");"
            )
            rendered.append(
                f"        require(_lastCallReverted == {'true' if expected['must_revert'] else 'false'}, \"LOWKEY_STEP_REVERT_{index}\");"
            )
            continue
        target = step["target"]
        selector = step["selector"]
        expressions = ", ".join(value for _, value in step["args"])
        encoded = f"abi.encode({expressions})" if expressions else "abi.encode()"
        calldata_name = f"stepCalldata{index}"
        target_name = f"stepTarget{index}"
        result_name = f"stepResult{index}"
        success_name = f"stepOk{index}"
        rendered.append("        {")
        rendered.append(f"            address {target_name} = address({target});")
        rendered.append(
            f"            bytes memory {calldata_name} = abi.encodePacked(bytes4({selector}), {encoded});"
        )
        if kind == "read":
            rendered.append(
                f"            (bool {success_name}, bytes memory {result_name}) = {target_name}.staticcall({calldata_name});"
            )
        else:
            rendered.append(
                f"            require(address(this).balance >= {step['value']}, \"LOWKEY_STEP_VALUE_{index}\");"
            )
            rendered.append(
                f"            (bool {success_name}, bytes memory {result_name}) = {target_name}.call{{value: {step['value']}}}({calldata_name});"
            )
        rendered.append("            _stepCallCount += 1;")
        rendered.append(f"            _lastCallReverted = !{success_name};")
        rendered.append(f"            _lastReturnData = {result_name};")
        rendered.append(f"            results[{index}] = {result_name};")
        if not step["optional"]:
            rendered.append(
                f"            if (!{success_name}) assembly {{ revert(add({result_name}, 0x20), mload({result_name})) }}"
            )
        expectation = step.get("expect")
        if expectation:
            rendered.append(
                f"            require(_stepCallCount == {expectation['count']}, \"LOWKEY_STEP_COUNT_{index}\");"
            )
            rendered.append(
                f"            require(_lastCallReverted == {'true' if expectation['must_revert'] else 'false'}, \"LOWKEY_STEP_REVERT_{index}\");"
            )
        rendered.append("        }")
    return "\n".join(rendered)


def render_source(manifest: dict[str, Any], template_text: str) -> str:
    steps = manifest["steps"]
    replacements = {
        "{{CONTRACT_NAME}}": manifest["contract_name"],
        "{{STEP_COUNT}}": str(len(steps)),
        "{{STEP_BODY}}": _step_body(steps),
        "{{TARGET_ADDRESS}}": manifest.get("target_address") or "0x0000000000000000000000000000000000000000",
    }
    output = template_text
    for token, value in replacements.items():
        output = output.replace(token, value)
    leftovers = re.findall(r"\{\{[A-Z_]+\}\}", output)
    if leftovers:
        _fail(manifest.get("target_address"), manifest.get("family"), "no_capability",
              "Template contains unresolved placeholders: " + ", ".join(leftovers))
    return output


def render_manifest(root: Path, manifest_path: Path, output_path: Path | None = None,
                    *, force: bool = False) -> tuple[Path, dict[str, Any]]:
    root = root.resolve()
    manifest_path = manifest_path if manifest_path.is_absolute() else root / manifest_path
    manifest_path = manifest_path.resolve()
    if not manifest_path.is_relative_to(root) or not manifest_path.is_file():
        _fail(None, None, "out_of_scope", "Step manifest must be an existing file inside the project.")
    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _fail(None, None, "unsupported_abi", f"Could not read a valid JSON step manifest: {exc}")
    normalized = normalize_manifest(raw)
    template_path = Path(__file__).resolve().parent / "templates" / "StepHarness.sol"
    if not template_path.is_file():
        _fail(normalized["target_address"], normalized["family"], "no_capability",
              f"Installed StepHarness template is missing: {template_path}")
    source = render_source(normalized, template_path.read_text(encoding="utf-8"))
    output_path = output_path or Path("test/lowkey") / f"{normalized['contract_name']}.sol"
    output_path = output_path if output_path.is_absolute() else root / output_path
    output_path = output_path.resolve()
    if not output_path.is_relative_to(root):
        _fail(normalized["target_address"], normalized["family"], "out_of_scope",
              "Generated harness output must remain inside the active project.")
    if output_path.exists() and not force:
        _fail(normalized["target_address"], normalized["family"], "out_of_scope",
              f"Refusing to overwrite {output_path.relative_to(root)}; pass --force explicitly.")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(source, encoding="utf-8")
    return output_path, normalized


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lk steps")
    parser.add_argument("manifest", help="Project-relative JSON manifest containing the ordered Step[] list.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output")
    parser.add_argument("--force", action="store_true")
    ns = parser.parse_args(argv)
    root = Path(ns.root).expanduser().resolve()
    manifest_path = Path(ns.manifest).expanduser()
    output_path = Path(ns.output).expanduser() if ns.output else None
    try:
        output, normalized = render_manifest(root, manifest_path, output_path, force=ns.force)
    except RefusalError as exc:
        refusal_dir = root / ".audit" / "steps"
        refusal_dir.mkdir(parents=True, exist_ok=True)
        refusal_path = refusal_dir / "refusal.json"
        refusal_path.write_text(json.dumps(exc.refusal, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(exc.refusal, sort_keys=True), file=sys.stderr)
        print(f"Refusal: .audit/steps/refusal.json", file=sys.stderr)
        return 2
    print("STEP HARNESS GENERATED")
    print(f"  file: {output.relative_to(root).as_posix()}")
    print(f"  family: {normalized['family'] or 'unspecified'}")
    print(f"  steps: {len(normalized['steps'])}")
    print("  execution: not run; compile and execute separately, then validate trace evidence with lk control.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
