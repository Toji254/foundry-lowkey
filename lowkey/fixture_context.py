"""EVM block-context capture and restoration helpers for promoted test fixtures."""

from __future__ import annotations

import re
from typing import Any

_FIELDS = {
    "timestamp": "LOWKEY_CONTEXT_TIMESTAMP",
    "blockNumber": "LOWKEY_CONTEXT_BLOCK_NUMBER",
    "chainId": "LOWKEY_CONTEXT_CHAIN_ID",
    "baseFeePerGas": "LOWKEY_CONTEXT_BASE_FEE_PER_GAS",
    "gasLimit": "LOWKEY_CONTEXT_GAS_LIMIT",
}


def solidity_capture() -> str:
    """Return console2 markers for the EVM context active after fixture setup."""
    values = (
        ("LOWKEY_CONTEXT_TIMESTAMP", "block.timestamp"),
        ("LOWKEY_CONTEXT_BLOCK_NUMBER", "block.number"),
        ("LOWKEY_CONTEXT_CHAIN_ID", "block.chainid"),
        ("LOWKEY_CONTEXT_BASE_FEE_PER_GAS", "block.basefee"),
        ("LOWKEY_CONTEXT_GAS_LIMIT", "block.gaslimit"),
    )
    return "\n".join(
        f'        console2.log("{label}:", {expression});'
        for label, expression in values
    )


def parse_context(output: str) -> tuple[dict[str, int] | None, str | None]:
    """Parse the context emitted by the generated Solidity harness."""
    text = str(output or "")
    values: dict[str, int] = {}
    for field, label in _FIELDS.items():
        match = re.search(
            rf"(?m){re.escape(label)}\s*:\s*(?:0x([0-9a-fA-F]+)|(\d+))",
            text,
        )
        if not match:
            return None, f"missing {label} marker in Forge output"
        raw = match.group(1) or match.group(2)
        values[field] = int(raw, 16) if match.group(1) else int(raw, 10)
        if values[field] < 0:
            return None, f"invalid negative value for {label}"

    for field in _FIELDS:
        if values[field] > 2**64 - 1:
            return None, f"{field} exceeds Anvil's supported 64-bit configuration range"
    if values["timestamp"] == 0:
        return None, "fixture timestamp is zero; refusing to invent a replacement"
    if values["gasLimit"] == 0:
        return None, "fixture block gas limit is zero"
    return values, None


def _quantity(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 10)
    except ValueError:
        return None


def matches(block: Any, chain_id: Any, context: dict[str, int]) -> bool:
    """Verify the current header and chain ID match captured fixture context."""
    if not isinstance(block, dict):
        return False
    actual = {
        "timestamp": _quantity(block.get("timestamp")),
        "blockNumber": _quantity(block.get("number")),
        "chainId": _quantity(chain_id),
        "baseFeePerGas": _quantity(block.get("baseFeePerGas")),
        "gasLimit": _quantity(block.get("gasLimit")),
    }
    return all(actual.get(field) == context.get(field) for field in _FIELDS)


def anvil_command(binary: str, port: int, context: dict[str, int]) -> list[str]:
    """Build an Anvil command with explicit fixture-aligned genesis parameters."""
    return [
        str(binary),
        "--port", str(int(port)),
        "--silent",
        "--timestamp", str(context["timestamp"]),
        "--number", str(context["blockNumber"]),
        "--chain-id", str(context["chainId"]),
        "--block-base-fee-per-gas", str(context["baseFeePerGas"]),
        "--gas-limit", str(context["gasLimit"]),
    ]
