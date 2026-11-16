"""Recursive ABI type handling for deterministic setup and probe inputs.

Values produced here are candidate inputs, not claims that a setup is valid.
The caller must still ABI-encode them and execute the resulting call in its
isolated test environment before using the result as evidence.
"""
from __future__ import annotations

import random
import re
from typing import Any, Sequence


_MAX_ARRAY_ITEMS = 64
_MAX_TOTAL_ELEMENTS = 4096
_MAX_ABI_DEPTH = 10


def _split_array_type(value: str) -> tuple[str, list[int | None]]:
    raw = str(value or "").strip().lower()
    match = re.fullmatch(r"(?P<base>.+?)(?P<dims>(?:\[\d*\])*)", raw)
    if not match:
        raise ValueError(f"invalid ABI type '{value}'")
    # Solidity writes array suffixes from the innermost dimension outward;
    # the right-most suffix is the outer-most dimension at call time.
    dimensions = [
        int(item) if item else None
        for item in reversed(re.findall(r"\[(\d*)\]", match.group("dims")))
    ]
    return match.group("base"), dimensions


def canonical_abi_type(item: dict[str, Any], *, depth: int = 0) -> str:
    """Return the canonical Solidity ABI type, expanding tuple components."""
    if depth > _MAX_ABI_DEPTH:
        raise ValueError("ABI tuple nesting exceeds the generic depth limit")
    if not isinstance(item, dict):
        raise ValueError("ABI input must be an object")
    raw = item.get("type")
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("ABI input is missing its type")
    raw_lower = raw.lower()
    base, _ = _split_array_type(raw_lower)
    if base == "tuple":
        components = item.get("components")
        if not isinstance(components, list) or not components:
            raise ValueError("tuple ABI input is missing component definitions")
        suffix = raw_lower[len("tuple"):]
        return "(" + ",".join(
            canonical_abi_type(component, depth=depth + 1)
            for component in components
        ) + ")" + suffix
    if base in {"uint", "int"}:
        return base + "256" + raw_lower[len(base):]
    if base == "byte":
        return "bytes1" + raw_lower[len(base):]
    return raw_lower


def _sample_scalar(base: str, mode: str, rng: random.Random, fallback: str) -> str:
    if base == "address":
        return "0x" + "00" * 20 if mode == "zero" else fallback
    if base == "bool":
        return "false" if mode == "zero" else "true"
    match = re.fullmatch(r"(u?int)(\d*)", base)
    if match:
        family, width_text = match.groups()
        width = int(width_text or "256")
        if width not in range(8, 257, 8):
            raise ValueError(f"unsupported ABI integer width '{base}'")
        if family == "uint":
            maximum = (1 << width) - 1
            if mode == "zero":
                return "0"
            if mode == "max":
                return str(maximum)
            if mode == "one":
                return "1"
            return str(rng.choice([0, 1, 2, 10]))
        minimum = -(1 << (width - 1))
        maximum = (1 << (width - 1)) - 1
        if mode == "zero":
            return "0"
        if mode == "max":
            return str(maximum)
        if mode == "one":
            return "1"
        return str(rng.choice([minimum, -1, 0, 1, maximum]))
    if base == "bytes":
        return "0x" if mode == "zero" else "0x01"
    match = re.fullmatch(r"bytes(\d+)", base)
    if match:
        width = int(match.group(1))
        if width < 1 or width > 32:
            raise ValueError(f"unsupported ABI fixed-bytes width '{base}'")
        octet = "00" if mode == "zero" else "01"
        return "0x" + octet * width
    if base == "string":
        return "" if mode == "zero" else "lowkey"
    if base == "function":
        return "0x" + "00" * 24
    raise ValueError(f"unsupported ABI type '{base}'")


def sample_abi_value(
    item: dict[str, Any],
    mode: str = "one",
    *,
    rng: random.Random | None = None,
    fallback_address: str = "0x" + "11" * 20,
    depth: int = 0,
    _budget: list[int] | None = None,
) -> str:
    """Create a conservative Cast-compatible value for scalar, tuple and array ABI inputs.

    Dynamic arrays are empty in 'zero' mode and contain one element otherwise.
    Fixed arrays always retain their declared length. Nested tuples and arrays
    are recursively represented as Cast tuple/array literals.
    """
    if mode not in {"zero", "one", "max", "normal"}:
        raise ValueError("ABI sample mode must be zero, one, max or normal")
    if depth > _MAX_ABI_DEPTH:
        raise ValueError("ABI value nesting exceeds the generic depth limit")
    generator = rng or random.Random(1337)
    budget = _budget if _budget is not None else [0]
    if not isinstance(item, dict):
        raise ValueError("ABI input must be an object")
    raw = item.get("type")
    if not isinstance(raw, str):
        raise ValueError("ABI input is missing its type")
    base, dimensions = _split_array_type(raw)

    def build(level: int, current_depth: int) -> str:
        if current_depth > _MAX_ABI_DEPTH:
            raise ValueError("ABI value nesting exceeds the generic depth limit")
        if level < len(dimensions):
            fixed_length = dimensions[level]
            count = fixed_length if fixed_length is not None else (
                0 if mode == "zero" else 1
            )
            if count > _MAX_ARRAY_ITEMS:
                raise ValueError(
                    f"ABI array dimension exceeds the generic {_MAX_ARRAY_ITEMS}-element safety limit"
                )
            return "[" + ",".join(
                build(level + 1, current_depth + 1) for _ in range(count)
            ) + "]"
        if base == "tuple":
            components = item.get("components")
            if not isinstance(components, list) or not components:
                raise ValueError("tuple ABI input is missing component definitions")
            return "(" + ",".join(
                sample_abi_value(
                    component,
                    mode,
                    rng=generator,
                    fallback_address=fallback_address,
                    depth=current_depth + 1,
                    _budget=budget,
                )
                for component in components
            ) + ")"
        budget[0] += 1
        if budget[0] > _MAX_TOTAL_ELEMENTS:
            raise ValueError(
                f"ABI sample exceeds the generic {_MAX_TOTAL_ELEMENTS}-element safety limit"
            )
        return _sample_scalar(base, mode, generator, fallback_address)

    return build(0, depth)


def sample_abi_inputs(
    inputs: Sequence[dict[str, Any]] | None,
    mode: str = "one",
    *,
    rng: random.Random | None = None,
    fallback_address: str = "0x" + "11" * 20,
) -> list[str]:
    """Sample all ABI arguments while preserving their recursive shapes."""
    if inputs is None:
        return []
    if not isinstance(inputs, (list, tuple)):
        raise ValueError("ABI function inputs must be an array")
    generator = rng or random.Random(1337)
    budget = [0]
    values = []
    for item in inputs:
        canonical_abi_type(item)
        values.append(sample_abi_value(
            item, mode, rng=generator, fallback_address=fallback_address,
            _budget=budget,
        ))
    return values
