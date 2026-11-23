#!/usr/bin/env python3
"""Matched real-transaction control helper for the P0 Fallback access fixture."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

RPC_URL = (
    os.environ.get("LOWKEY_RPC_URL")
    or os.environ.get("ETH_RPC_URL")
    or os.environ.get("FOUNDRY_ETH_RPC_URL")
    or "http://127.0.0.1:8545"
)
GAS_LIMIT = 150_000
GAS_PRICE = 10_000_000_000


def rpc(method: str, params: list) -> object:
    request = Request(
        RPC_URL,
        data=json.dumps({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": params
        }).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=20) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if payload.get("error"):
        raise RuntimeError(f"{method} failed: {payload['error']}")
    return payload.get("result")


def accounts_for(attacker: str) -> tuple[str, str]:
    accounts = rpc("eth_accounts", [])
    if not isinstance(accounts, list) or len(accounts) < 2:
        raise RuntimeError("Anvil must expose at least two unlocked accounts.")
    owner, observed_attacker = str(accounts[0]).lower(), str(accounts[1]).lower()
    if observed_attacker != attacker.lower():
        raise RuntimeError(
            f"Manifest attacker {attacker} is not Anvil account[1] ({observed_attacker})."
        )
    return owner, observed_attacker


def wait_receipt(tx_hash: str, timeout: float = 25.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if isinstance(receipt, dict):
            return receipt
        time.sleep(0.1)
    raise TimeoutError(f"Anvil did not mine transaction {tx_hash} within {timeout:.0f}s.")


def send_and_wait(sender: str, target: str, data: str, value: str = "0x0") -> tuple[str, dict]:
    tx_hash = rpc("eth_sendTransaction", [{
        "from": sender, "to": target, "data": data, "value": value,
        "gas": hex(GAS_LIMIT), "gasPrice": hex(GAS_PRICE),
    }])
    if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
        raise RuntimeError(f"Anvil returned an invalid transaction hash: {tx_hash!r}")
    return tx_hash, wait_receipt(tx_hash)


def cast_binary() -> str:
    found = shutil.which("cast")
    if found:
        return found
    candidate = Path.home() / ".foundry" / "bin" / "cast"
    if candidate.is_file():
        return str(candidate)
    raise RuntimeError("Foundry cast is unavailable in the control helper.")


def prepare(target: str, attacker: str, amount: str) -> None:
    owner, _ = accounts_for(attacker)
    encoded = subprocess.run(
        [cast_binary(), "calldata", "primeUserCredit(address,uint256)", attacker, amount],
        text=True, capture_output=True, timeout=30, check=False,
    )
    if encoded.returncode != 0:
        raise RuntimeError("cast could not encode primeUserCredit: " + encoded.stderr[-1000:])
    calldata = encoded.stdout.strip()
    if not re.fullmatch(r"0x[0-9a-fA-F]+", calldata):
        raise RuntimeError(f"cast returned invalid setup calldata: {calldata!r}")

    # Setup uses an ordinary owner transaction only. The outer P0 fixture
    # configures Anvil's fixed block-timestamp interval once before either
    # matched scenario; this preparation command never overrides EVM time.
    tx_hash, receipt = send_and_wait(owner, target, calldata)
    if str(receipt.get("status") or "").lower() not in {"0x1", "1"}:
        raise RuntimeError(f"Owner-only scenario preparation reverted: {tx_hash}")
    print(f"PREPARED contribution={amount} tx={tx_hash}")


def probe(target: str, attacker: str) -> None:
    _, sender = accounts_for(attacker)
    tx_hash, receipt = send_and_wait(sender, target, "0x", value="0x1")
    print(f"LOWKEY_TRACE_TX_HASH {tx_hash}")
    print(f"LOWKEY_PROBE_RECEIPT_STATUS {str(receipt.get('status') or '').lower()}")


def assert_owner(target: str, attacker: str) -> None:
    result = subprocess.run(
        [cast_binary(), "call", target, "owner()(address)", "--rpc-url", RPC_URL],
        text=True, capture_output=True, timeout=30, check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Could not read post-attack owner: " + result.stderr[-1000:])
    owner = result.stdout.strip().splitlines()[0].strip().lower()
    if owner != attacker.lower():
        raise AssertionError(f"Expected owner {attacker.lower()}, observed {owner}")
    print("LOWKEY_SEMANTIC_INVARIANT_PASS:fallback_owner_takeover")


def main(argv: list[str]) -> int:
    if not argv:
        raise SystemExit("usage: helper prepare|probe|assert-owner TARGET ATTACKER [AMOUNT]")
    mode = argv[0]
    if len(argv) not in {3, 4}:
        raise SystemExit("invalid helper argument count")
    target, attacker = argv[1], argv[2]
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", target):
        raise SystemExit("target must be an EVM address")
    if not re.fullmatch(r"0x[0-9a-fA-F]{40}", attacker):
        raise SystemExit("attacker must be an EVM address")
    if mode == "prepare" and len(argv) == 4:
        prepare(target, attacker, argv[3])
    elif mode == "probe" and len(argv) == 3:
        probe(target, attacker)
    elif mode == "assert-owner" and len(argv) == 3:
        assert_owner(target, attacker)
    else:
        raise SystemExit("invalid helper mode or arguments")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except Exception as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        raise SystemExit(1)
