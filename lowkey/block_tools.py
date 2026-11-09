#!/usr/bin/env python3
"""Read-only EVM block and block-hash inspection for LowkeyCast."""

from __future__ import annotations

import argparse
import importlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


BLOCK_TAGS = {"latest", "earliest", "pending", "safe", "finalized"}
RPC_TIMEOUT_SECONDS = 12


class BlockLookupError(RuntimeError):
    """A user-facing block lookup or RPC failure."""


def parse_block_reference(value: str) -> str:
    """Convert decimal/hex block numbers to canonical JSON-RPC quantities."""
    raw = str(value).strip()
    lowered = raw.lower()
    if lowered in BLOCK_TAGS:
        return lowered
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", raw):
        number = int(raw[2:], 16)
    elif re.fullmatch(r"[0-9]+", raw):
        number = int(raw, 10)
    else:
        raise BlockLookupError(
            f"invalid block reference '{value}'; use a decimal number, 0x-prefixed "
            "hex number, or latest/earliest/pending/safe/finalized"
        )
    return hex(number)


def _valid_rpc_url(value: str) -> str:
    url = str(value).strip()
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise BlockLookupError("RPC URL must be an http:// or https:// endpoint")
    return url


def resolve_rpc(explicit_url: str | None = None) -> str:
    """Resolve the same active Lowkey RPC used by the main CLI where possible."""
    if explicit_url:
        return _valid_rpc_url(explicit_url)

    # Reuse Lowkey's project-aware RPC selection. This preserves configured
    # endpoints and scoped local-fixture RPCs instead of inventing a second
    # connection-selection policy in this command.
    try:
        module_dir = str(Path(__file__).resolve().parent)
        if module_dir not in sys.path:
            sys.path.insert(0, module_dir)
        host = importlib.import_module("lk")
        config = host.load_config()
        active = host.effective_rpc(config)
        if active:
            return _valid_rpc_url(str(active))
    except Exception:
        # Keep this standalone command usable if the main router cannot be
        # imported in a minimal install or during a focused unit test.
        pass

    for key in ("LOWKEY_RPC_URL", "ETH_RPC_URL", "FOUNDRY_ETH_RPC_URL", "FOUNDRY_RPC_URL"):
        value = os.environ.get(key)
        if value:
            return _valid_rpc_url(value)

    config_path = Path.home() / ".lowkey" / "config.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        configured = config.get("rpc") or config.get("rpc_url")
        if configured:
            return _valid_rpc_url(str(configured))
    except (OSError, json.JSONDecodeError, AttributeError, TypeError):
        pass

    # Lowkey's default local Anvil endpoint. If it is not running the RPC
    # error below explains how to select/start the intended endpoint.
    return "http://127.0.0.1:8545"


def rpc_request(rpc_url: str, method: str, params: list[Any]) -> Any:
    """Perform one bounded JSON-RPC request without exposing endpoint secrets."""
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    }).encode("utf-8")
    request = Request(
        rpc_url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=RPC_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise BlockLookupError(
            f"RPC returned HTTP {exc.code}; check the endpoint and its access policy"
        ) from None
    except (URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, TimeoutError):
            detail = "request timed out"
        elif reason:
            detail = str(reason)
        else:
            detail = "connection failed"
        raise BlockLookupError(f"could not reach the configured RPC ({detail})") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise BlockLookupError("RPC returned a response that was not valid JSON") from None

    if not isinstance(payload, dict):
        raise BlockLookupError("RPC returned an invalid JSON-RPC response")
    error = payload.get("error")
    if error:
        if isinstance(error, dict):
            message = str(error.get("message") or "unspecified JSON-RPC error")
            code = error.get("code")
            prefix = f"JSON-RPC error {code}: " if code is not None else "JSON-RPC error: "
        else:
            message = str(error)
            prefix = "JSON-RPC error: "
        raise BlockLookupError(prefix + message)
    if "result" not in payload:
        raise BlockLookupError("RPC response did not contain a result field")
    return payload["result"]


def _quantity(value: Any, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise BlockLookupError(f"RPC returned an invalid {field} quantity")
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", value):
        raise BlockLookupError(f"RPC returned an invalid {field} quantity")
    return int(value, 16)


def _hex_quantity(value: Any, field: str) -> str:
    number = _quantity(value, field)
    return "pending" if number is None else str(number)


def _timestamp(value: Any) -> tuple[str, str]:
    number = _quantity(value, "timestamp")
    if number is None:
        return "pending", "pending"
    try:
        rendered = datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        rendered = "out of platform range"
    return str(number), rendered.replace("+00:00", "Z")


def fetch_block(rpc_url: str, block_reference: str) -> dict[str, Any]:
    reference = parse_block_reference(block_reference)
    result = rpc_request(rpc_url, "eth_getBlockByNumber", [reference, False])
    if result is None:
        raise BlockLookupError(f"block {block_reference} was not found by this RPC")
    if not isinstance(result, dict):
        raise BlockLookupError("RPC returned a malformed block object")
    if "number" not in result and reference != "pending":
        raise BlockLookupError("RPC block response is missing its number")
    return result


def render_block(block: dict[str, Any]) -> str:
    number = _quantity(block.get("number"), "number")
    timestamp, timestamp_utc = _timestamp(block.get("timestamp"))
    block_label = str(number) if number is not None else "pending"
    lines = [
        f"BLOCK {block_label}",
        "=" * 64,
        f"Number:          {block_label}" + (f" (0x{number:x})" if number is not None else ""),
        f"Hash:            {block.get('hash') or 'pending / not assigned'}",
        f"Parent hash:     {block.get('parentHash') or 'unavailable'}",
        f"Timestamp:       {timestamp} ({timestamp_utc})",
        f"Miner:           {block.get('miner') or block.get('author') or 'unavailable'}",
        f"Gas used:        {_hex_quantity(block.get('gasUsed'), 'gasUsed')}",
        f"Gas limit:       {_hex_quantity(block.get('gasLimit'), 'gasLimit')}",
        f"Transactions:    {len(block.get('transactions') or [])}",
    ]
    for field, label in (
        ("baseFeePerGas", "Base fee (wei)"),
        ("difficulty", "Difficulty"),
        ("totalDifficulty", "Total difficulty"),
        ("size", "Size (bytes)"),
        ("blobGasUsed", "Blob gas used"),
        ("excessBlobGas", "Excess blob gas"),
    ):
        if field in block and block[field] is not None:
            lines.append(f"{label + ':':<17}{_hex_quantity(block[field], field)}")
    return "\n".join(lines)


def help_text() -> str:
    return """LOWKEY HELP  •  lk block
========================================================================

What it does:
  Read a block header from the currently selected EVM RPC. It can show the
  full header summary or return only the exact block hash.

When to use:
  Inspect block.number, block.timestamp, parentHash, or blockhash(n)
  dependencies while researching contracts. This is read-only and does not
  require a target contract, ABI, wallet, or transaction.

Usage:
  lk block [number|tag] [--hash] [--json] [--rpc-url URL]
  lk block hash <number|tag> [--json] [--rpc-url URL]

Examples:
  lk block                         Show the latest block.
  lk block 5                       Show block 5.
  lk block hash 5                  Print only block 5's hash.
  lk block 0x5 --hash              Same lookup using a hex block number.
  lk block latest --json           Return the raw block object as JSON.
  lk block hash 5 --rpc-url URL    Query a specific EVM endpoint.

Block references:
  Decimal numbers, 0x-prefixed hexadecimal numbers, latest, earliest,
  pending, safe, and finalized (subject to RPC support).

RPC selection:
  Uses Lowkey's active project/RPC selection. --rpc-url overrides it.

Safety:
  Sends only eth_getBlockByNumber. No transactions or state changes.
  EVM blockhash(n) is available to contracts only for the 256 most recent
  completed blocks; an RPC may expose older headers independently.
"""


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if any(arg in {"--h", "--help", "-h", "help"} for arg in args):
        print(help_text())
        return 0

    hash_only = False
    if args and args[0].lower() == "hash":
        hash_only = True
        args = args[1:]

    parser = argparse.ArgumentParser(
        prog="lk block",
        description="Read an EVM block header or block hash.",
        add_help=False,
        allow_abbrev=False,
    )
    parser.add_argument("reference", nargs="?", default="latest")
    parser.add_argument("--hash", action="store_true", dest="hash_only")
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--rpc-url")
    try:
        options = parser.parse_args(args)
        hash_only = hash_only or options.hash_only
        reference = parse_block_reference(options.reference)
        rpc_url = resolve_rpc(options.rpc_url)
        block = fetch_block(rpc_url, reference)
        block_hash = block.get("hash")
        if hash_only:
            if not isinstance(block_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", block_hash):
                raise BlockLookupError(
                    "this block has no finalized hash yet; choose a mined block number or latest"
                )
            print(json.dumps({"number": block.get("number"), "hash": block_hash}) if options.json_output else block_hash)
            return 0
        if options.json_output:
            print(json.dumps(block, indent=2, sort_keys=True))
        else:
            print(render_block(block))
        return 0
    except BlockLookupError as exc:
        print(f"lk block: {exc}", file=sys.stderr)
        return 1
    except SystemExit as exc:
        return int(exc.code or 0)


if __name__ == "__main__":
    raise SystemExit(main())
