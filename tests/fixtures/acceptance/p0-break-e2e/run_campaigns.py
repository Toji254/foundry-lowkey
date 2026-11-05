#!/usr/bin/env python3
"""Run installed Lowkey break campaigns against P0 compatibility targets.

This is an isolated, disposable Anvil acceptance fixture. Targets are deliberately
vulnerable and funded only on the local test chain; never point this at production.
"""
from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path

ROOT = Path.cwd()
RPC = "http://127.0.0.1:8545"
ARTIFACT_DIR = ROOT / "out" / "P0BreakCompatibility.sol"
LOG_DIR = Path("/tmp/lowkey-p0-break-e2e")
LOG_DIR.mkdir(parents=True, exist_ok=True)


def rpc(method: str, params: list):
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    request = urllib.request.Request(RPC, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=15) as response:
        body = json.loads(response.read().decode())
    if body.get("error"):
        raise RuntimeError(f"{method}: {body['error']}")
    return body.get("result")


def deploy(contract_name: str, sender: str) -> str:
    artifact_path = ARTIFACT_DIR / f"{contract_name}.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    bytecode = artifact.get("bytecode", {}).get("object", "")
    if not bytecode or bytecode in {"0x", "0x0"}:
        raise RuntimeError(f"{contract_name}: missing creation bytecode in {artifact_path}")
    if not bytecode.startswith("0x"):
        bytecode = "0x" + bytecode
    tx_hash = rpc("eth_sendTransaction", [{
        "from": sender,
        "data": bytecode,
        "value": hex(10**19),
        "gas": hex(12_000_000),
        "gasPrice": hex(1_000_000_000),
    }])
    for _ in range(100):
        receipt = rpc("eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if int(receipt.get("status", "0x0"), 16) != 1:
                raise RuntimeError(f"{contract_name}: deployment reverted: {receipt}")
            address = receipt.get("contractAddress")
            if not address:
                raise RuntimeError(f"{contract_name}: no contractAddress in receipt: {receipt}")
            code = rpc("eth_getCode", [address, "latest"])
            if not code or code == "0x":
                raise RuntimeError(f"{contract_name}: deployed address has no runtime code")
            return address
        time.sleep(0.05)
    raise TimeoutError(f"{contract_name}: receipt did not appear for {tx_hash}")


def run_lk(args: list[str], label: str) -> str:
    completed = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, timeout=900, check=False)
    output = (completed.stdout or "") + (("\n" + completed.stderr) if completed.stderr else "")
    (LOG_DIR / f"{label}.log").write_text(output, encoding="utf-8")
    if completed.returncode != 0:
        raise RuntimeError(f"{label}: exit {completed.returncode}\n{output[-6000:]}")
    return output


def telemetry(raw: str, label: str) -> int:
    match = re.search(rf"(?m)^\s*{re.escape(label)}\s*:?\s*(\d+)\s*$", raw)
    if not match:
        match = re.search(rf"{re.escape(label)}\s*:?\s*(\d+)", raw)
    if not match:
        raise AssertionError(f"Missing numeric telemetry {label!r}:\n{raw[-8000:]}")
    return int(match.group(1))


def campaign(contract_name: str, address: str, function: str, family: str, label: str, checks):
    artifact = f"out/P0BreakCompatibility.sol/{contract_name}.json"
    run_lk(["lk", "target", address], f"{label}-target")
    run_lk(["lk", "abi", artifact], f"{label}-abi")
    output = run_lk([
        "lk", "break", "--function", function, "--family", family,
        "--rounds", "1", "--depth", "2", "--seed", "7",
    ], label)
    if "[OBSERVED]" not in output:
        raise AssertionError(f"{label}: expected conservative [OBSERVED] status:\n{output[-8000:]}")
    evidence_matches = re.findall(r"Evidence:\s+([^\s]+\.json)", output)
    if not evidence_matches:
        raise AssertionError(f"{label}: no machine-readable evidence path:\n{output[-8000:]}")
    evidence_path = Path(evidence_matches[-1])
    if not evidence_path.is_absolute():
        evidence_path = (ROOT / evidence_path).resolve()
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if evidence.get("forge_returncode") != 0:
        raise AssertionError(f"{label}: Forge did not execute successfully: {evidence}")
    raw = str(evidence.get("output_tail") or "")
    if "LOWKEY_BREAK_FAMILY" not in raw:
        raise AssertionError(f"{label}: missing structured harness telemetry:\n{raw[-8000:]}")
    harness_path = Path(str(evidence.get("harness_archive") or evidence.get("harness") or ""))
    if not harness_path.is_absolute():
        harness_path = (ROOT / harness_path).resolve()
    harness = harness_path.read_text(encoding="utf-8")
    checks(raw, harness)
    print(f"PASS {label}: installed lk break emitted OBSERVED and retained executable Forge evidence")
    print(f"  evidence: {evidence_path}")


def main():
    accounts = rpc("eth_accounts", [])
    if len(accounts) < 2:
        raise RuntimeError("Anvil must expose at least two unlocked accounts")
    sender = accounts[0]

    array_target = deploy("P0ArrayBreakTarget", sender)
    usdc_vault = deploy("P0USDCStyleVault", sender)
    usdt_vault = deploy("P0USDTStyleVault", sender)

    def check_array(raw: str, harness: str):
        assert "new address[](1)" in harness, "dynamic address[] not rendered as memory array"
        assert "withdraw(address[])" in harness, "array attack selector missing"
        assert telemetry(raw, "REENTRY_REACHED") >= 1, raw[-6000:]
        assert telemetry(raw, "REENTRY_SUCCESSES") >= 1, raw[-6000:]
        received = telemetry(raw, "ATTACKER_WITHDRAW_RECEIVED")
        entitlement = telemetry(raw, "ENTITLEMENT_BEFORE_ATTACK")
        assert received > entitlement, (received, entitlement, raw[-6000:])

    def check_token(raw: str, harness: str, token_label: str):
        for marker in (
            'abi.encodeWithSignature("decimals()")',
            "reportedDecimals <= 77",
            "tokenSeedAmount = 10 ** tokenDecimals",
            "_lowkeySafeApprove",
            "returndata.length == 0",
        ):
            assert marker in harness, f"{token_label}: missing generator feature {marker!r}"
        assert telemetry(raw, "TOKEN_DECIMALS") == 6, raw[-6000:]
        assert telemetry(raw, "TOKEN_FUNDING_AMOUNT") == 1_000_000, raw[-6000:]
        entitlement = telemetry(raw, "ENTITLEMENT_BEFORE")
        token_gain = telemetry(raw, "TOTAL_ATTACKER_TOKEN_GAIN")
        target_outflow = telemetry(raw, "TOTAL_TARGET_TOKEN_OUTFLOW")
        assert token_gain > entitlement, (token_gain, entitlement, raw[-6000:])
        assert target_outflow >= token_gain, (target_outflow, token_gain, raw[-6000:])

    campaign(
        "P0ArrayBreakTarget", array_target, "withdraw(address[])", "reentrancy",
        "p0-address-array", check_array,
    )
    campaign(
        "P0USDCStyleVault", usdc_vault, "withdraw()", "accounting",
        "p0-usdc-six-decimal", lambda raw, harness: check_token(raw, harness, "USDC-style"),
    )
    campaign(
        "P0USDTStyleVault", usdt_vault, "withdraw()", "accounting",
        "p0-usdt-no-return", lambda raw, harness: check_token(raw, harness, "USDT-style"),
    )
    print("PASS: all three deployed-target lk break campaigns produced OBSERVED, structured, traceable evidence")


if __name__ == "__main__":
    main()
