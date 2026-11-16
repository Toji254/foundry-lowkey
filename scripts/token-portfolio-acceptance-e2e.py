#!/usr/bin/env python3
"""Installed-CLI acceptance for source-safe ERC20/ERC4626 portfolio accounting.

Only a disposable local Anvil chain is used. The result must remain
LOCAL_PROFITABLE and must never be promoted to deployment PROFITABLE.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
PRIVATE_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
ANVIL_MNEMONIC = "test test test test test test test test test test test junk"
SOLIDITY = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockToken {
    string public name;
    string public symbol;
    uint8 public immutable decimals;
    mapping(address => uint256) private balances;

    constructor(string memory n, string memory s, uint8 d) {
        name = n; symbol = s; decimals = d;
    }

    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}

contract MockFeed {
    int256 private immutable answer;
    uint256 private immutable started;
    uint256 private immutable updated;

    constructor(int256 value) {
        answer = value;
        started = block.timestamp;
        updated = block.timestamp;
    }

    function decimals() external pure returns (uint8) { return 8; }

    function latestRoundData() external view returns (
        uint80 roundId, int256 answer_, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound
    ) {
        return (1, answer, started, updated, 1);
    }
}

contract MockVault4626 {
    address public immutable asset;
    uint8 public constant decimals = 18;
    mapping(address => uint256) private shares;

    constructor(address underlying) { asset = underlying; }

    function mintShares(address who, uint256 amount) external {
        shares[who] += amount;
    }

    function balanceOf(address who) external view returns (uint256) {
        return shares[who];
    }

    // One 18-decimal share redeems for two 6-decimal underlying units.
    function previewRedeem(uint256 shareAmount) external pure returns (uint256) {
        return (shareAmount / 1e12) * 2;
    }
}

contract PortfolioTarget {
    function capture(address token, address vault, uint256 tokenAmount, uint256 shareAmount) external {
        MockToken(token).mint(msg.sender, tokenAmount);
        MockVault4626(vault).mintShares(msg.sender, shareAmount);
    }
}
"""


def run(argv: list[str], cwd: Path, *, env: dict[str, str] | None = None, timeout: int = 240) -> str:
    completed = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"Command exited {completed.returncode}: {argv!r}\n"
            f"--- stdout ---\n{completed.stdout[-10000:]}\n"
            f"--- stderr ---\n{completed.stderr[-10000:]}"
        )
    return completed.stdout


def rpc(url: str, method: str, params: list[Any], timeout: int = 10) -> Any:
    request = Request(
        url,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "Lowkey-token-economics-acceptance"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read(4_000_000).decode())
    if not isinstance(payload, dict) or payload.get("error") or "result" not in payload:
        raise AssertionError(f"RPC {method} failed: {payload!r}")
    return payload["result"]


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_anvil(process: subprocess.Popen, url: str, log: Path) -> None:
    for _ in range(60):
        if process.poll() is not None:
            raise AssertionError("Anvil exited:\n" + log.read_text(errors="replace")[-5000:])
        try:
            if int(rpc(url, "eth_chainId", []), 16) == 31337:
                return
        except Exception:
            pass
        time.sleep(0.25)
    raise AssertionError("Anvil did not become ready:\n" + log.read_text(errors="replace")[-5000:])


def deployed_address(output: str) -> str:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError:
        payload = {}
    if isinstance(payload, dict):
        for key in ("deployedTo", "deployed_to", "contractAddress", "address"):
            value = payload.get(key)
            if isinstance(value, str) and re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
                return value.lower()
    match = re.search(r"(?im)^Deployed to:\s*(0x[0-9a-fA-F]{40})\s*$", output)
    if match:
        return match.group(1).lower()
    raise AssertionError("forge create output did not contain a deployed contract address:\n" + output[-5000:])


def deploy(forge: str, project: Path, url: str, contract: str, args: list[str]) -> str:
    command = [
        forge, "create", f"src/PortfolioFixtures.sol:{contract}",
        "--rpc-url", url, "--private-key", PRIVATE_KEY, "--broadcast", "--json",
    ]
    if args:
        command.extend(["--constructor-args", *args])
    output = run(command, project, timeout=300)
    return deployed_address(output)


def main() -> int:
    forge = shutil.which("forge")
    cast = shutil.which("cast")
    anvil = shutil.which("anvil")
    lk = shutil.which("lk") or str(Path.home() / ".foundry/bin/lk")
    if not all((forge, cast, anvil)) or not Path(lk).is_file():
        raise AssertionError("forge, cast, anvil and installed lk are required.")
    env = os.environ.copy()
    env["PATH"] = str(Path.home() / ".foundry/bin") + os.pathsep + env.get("PATH", "")
    port = free_port()
    url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="lowkey-token-portfolio-") as raw:
        project = Path(raw)
        (project / "src").mkdir()
        (project / "scripts").mkdir()
        (project / ".audit").mkdir()
        (project / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\nout = "out"\nsolc_version = "0.8.20"\n',
            encoding="utf-8",
        )
        (project / "src/PortfolioFixtures.sol").write_text(SOLIDITY, encoding="utf-8")
        (project / "scripts/run_attack.py").write_text(
            """import json, subprocess, sys
url, target, token, vault, private_key = sys.argv[1:]
command = [
    "cast", "send", target,
    "capture(address,address,uint256,uint256)", token, vault,
    str(1000 * 10**6), str(10**18),
    "--rpc-url", url, "--private-key", private_key, "--json",
]
completed = subprocess.run(command, text=True, capture_output=True, check=False)
if completed.returncode:
    raise SystemExit(completed.stderr[-3000:])
payload = json.loads(completed.stdout)
tx_hash = payload.get("transactionHash") or payload.get("transaction_hash") or payload.get("txHash")
if not isinstance(tx_hash, str) or len(tx_hash) != 66:
    raise SystemExit("cast send JSON omitted transactionHash: " + completed.stdout[-3000:])
print("LOWKEY_TRACE_TX_HASH " + tx_hash)
""",
            encoding="utf-8",
        )
        (project / ".audit/portfolio.json").write_text(json.dumps({
            "schema_version": 1,
            "quote_currency": "USD",
            "max_price_age_seconds": 3600,
            "native": {"oracle": "0x" + "0" * 40},
            "tokens": [],
        }, indent=2), encoding="utf-8")
        process = None
        log_path = project / "anvil.log"
        try:
            with log_path.open("w", encoding="utf-8") as handle:
                process = subprocess.Popen(
                    [anvil, "--silent", "--host", "127.0.0.1", "--port", str(port),
                     "--chain-id", "31337", "--mnemonic", ANVIL_MNEMONIC,
                     "--accounts", "10", "--balance", "10000",
                     "--gas-price", "1000000000", "--block-base-fee-per-gas", "1000000000",
                     "--timestamp", "1700000000", "--hardfork", "cancun"],
                    cwd=project, env=env, stdout=handle, stderr=subprocess.STDOUT,
                )
            wait_anvil(process, url, log_path)
            underlying = deploy(forge, project, url, "MockToken", ["Underlying", "UND", "6"])
            token = deploy(forge, project, url, "MockToken", ["Mock USD", "mUSD", "6"])
            native_feed = deploy(forge, project, url, "MockFeed", [str(2000 * 10**8)])
            token_feed = deploy(forge, project, url, "MockFeed", [str(1 * 10**8)])
            vault = deploy(forge, project, url, "MockVault4626", [underlying])
            target = deploy(forge, project, url, "PortfolioTarget", [])
            (project / ".audit/portfolio.json").write_text(json.dumps({
                "schema_version": 1,
                "quote_currency": "USD",
                "max_price_age_seconds": 3600,
                "native": {"oracle": native_feed},
                "tokens": [
                    {"kind": "erc20", "address": token, "symbol": "mUSD",
                     "expected_decimals": 6, "oracle": token_feed},
                    {"kind": "erc4626", "address": vault, "asset": underlying,
                     "symbol": "vUND", "oracle": token_feed},
                ],
            }, indent=2), encoding="utf-8")
            fork_block = int(rpc(url, "eth_blockNumber", []), 16)
            argv = ["python3", "scripts/run_attack.py", url, target, token, vault, PRIVATE_KEY]
            command = [
                lk, "reprove", "src/PortfolioFixtures.sol",
                "--root", str(project),
                "--rpc-url", url,
                "--fork-block", str(fork_block),
                "--target-address", target,
                "--profit-address", ACTOR,
                "--prior-cost-wei", str(10**15),
                "--portfolio-manifest", ".audit/portfolio.json",
                "--family", "economic",
                "--argv-json", json.dumps(argv),
            ]
            output = run(command, project, env=env, timeout=900)
            payload = json.loads(output)
            if payload.get("legacy_status") != "LOCAL_PROFITABLE":
                raise AssertionError("Local token portfolio result was not LOCAL_PROFITABLE:\n" + output[-10000:])
            if payload.get("status") == "PROFITABLE":
                raise AssertionError("Local fixture was incorrectly promoted to deployment PROFITABLE.")
            if payload.get("net_profit_unit") != "USD_18":
                raise AssertionError("Reproof did not report USD 1e-18 as the portfolio unit.")
            portfolio = payload.get("token_portfolio") or {}
            assets = portfolio.get("tokens") or []
            if len(assets) != 2:
                raise AssertionError("Both ERC20 and ERC4626 assets must be present in the report.")
            erc20, vault_result = assets
            if erc20.get("share_or_token_delta") != 1000 * 10**6:
                raise AssertionError("ERC20 balanceOf delta did not match the mined transfer/mint.")
            if vault_result.get("underlying_asset_delta") != 2 * 10**6:
                raise AssertionError("ERC4626 previewRedeem delta did not match the underlying amount.")
            if payload.get("net_profit_usd_18", 0) <= 0:
                raise AssertionError("Measured token portfolio was not net positive after native gas and prior setup costs.")
            if payload.get("economic_policy", {}).get("accepted") is not True:
                raise AssertionError("Economic policy refused a positive measured token portfolio.")
            report_dir = ROOT / ".audit/token-portfolio-acceptance"
            report_dir.mkdir(parents=True, exist_ok=True)
            (report_dir / "reprove.json").write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            summary = {
                "status": "PASS",
                "legacy_status": payload["legacy_status"],
                "proof_status": payload["status"],
                "net_profit_unit": payload["net_profit_unit"],
                "net_profit_usd_18": payload["net_profit_usd_18"],
                "token_value_delta_usd_18": portfolio["token_value_delta_usd_18"],
                "assets": [{"kind": item["kind"], "symbol": item["symbol"],
                            "value_delta_usd_18": item["value_delta_usd_18"]} for item in assets],
                "local_only_not_deployment_profit": True,
            }
            (report_dir / "summary.json").write_text(
                json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(json.dumps(summary, indent=2, sort_keys=True))
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
