#!/usr/bin/env python3
"""Installed-CLI P0 acceptance: address[] setup, six-decimal vault, no-return USDT approval."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract AddressArraySetupTarget {
    mapping(address => uint256) public balances;

    function deposit(address[] calldata recipients) external payable {
        require(recipients.length > 0, "NO_RECIPIENTS");
        for (uint256 i; i < recipients.length; ++i) {
            balances[recipients[i]] += msg.value;
        }
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "NO_BALANCE");
        balances[msg.sender] = 0;
        (bool sent,) = payable(msg.sender).call{value: amount}("");
        require(sent, "SEND_FAILED");
    }

    receive() external payable {}
}

contract MockUSDC6 {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "BALANCE");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "BALANCE");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockUSDT6NoReturnReset {
    uint8 public constant decimals = 6;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function primeAllowance(address owner, address spender, uint256 amount) external {
        allowance[owner][spender] = amount;
    }

    function approve(address spender, uint256 amount) external {
        uint256 current = allowance[msg.sender][spender];
        require(amount == 0 || current == 0, "RESET_REQUIRED");
        allowance[msg.sender][spender] = amount;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "BALANCE");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "BALANCE");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract USDCVault {
    MockUSDC6 public immutable asset;
    mapping(address => uint256) public balances;

    constructor(address token) { asset = MockUSDC6(token); }

    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount), "TRANSFER_IN");
        balances[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "NO_BALANCE");
        balances[msg.sender] = 0;
        require(asset.transfer(msg.sender, amount), "TRANSFER_OUT");
    }
}

contract USDTVault {
    MockUSDT6NoReturnReset public immutable asset;
    mapping(address => uint256) public balances;

    constructor(address token) { asset = MockUSDT6NoReturnReset(token); }

    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount), "TRANSFER_IN");
        balances[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "NO_BALANCE");
        balances[msg.sender] = 0;
        require(asset.transfer(msg.sender, amount), "TRANSFER_OUT");
    }
}
contract MockNoMetadataToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "BALANCE");
        require(allowance[from][msg.sender] >= amount, "ALLOWANCE");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        allowance[from][msg.sender] -= amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "BALANCE");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract NoMetadataVault {
    MockNoMetadataToken public immutable asset;
    mapping(address => uint256) public balances;

    constructor(address token) { asset = MockNoMetadataToken(token); }

    function deposit(uint256 amount) external {
        require(asset.transferFrom(msg.sender, address(this), amount), "TRANSFER_IN");
        balances[msg.sender] += amount;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "NO_BALANCE");
        balances[msg.sender] = 0;
        require(asset.transfer(msg.sender, amount), "TRANSFER_OUT");
    }
}
"""


def run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 240) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-12000:]}\n"
            f"--- stderr ---\n{result.stderr[-12000:]}"
        )
    return result


def deploy(forge: str, root: Path, env: dict[str, str], contract: str, *args: str) -> str:
    output = run([
        forge, "create", f"src/P0Targets.sol:{contract}",
        "--rpc-url", RPC, "--private-key", ANVIL_KEY0, "--broadcast", "--json",
        *(["--constructor-args", *args] if args else []),
    ], root, env)
    payload = json.loads(output.stdout)
    address = payload.get("deployedTo")
    if not isinstance(address, str) or not address.startswith("0x"):
        raise AssertionError(f"forge create did not return deployedTo for {contract}: {payload}")
    return address


def exercise(
    lk: str,
    root: Path,
    env: dict[str, str],
    contract: str,
    address: str,
    expected_markers: list[str],
    evidence_root: Path,
) -> None:
    run([lk, "target", "reset"], root, env)
    run([lk, "target", contract, address], root, env)
    runs_dir = root / ".audit" / "break" / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)
    output = run([lk, "break", "--family", "accounting", "--function", "withdraw", "--rounds", "1"], root, env, timeout=360)
    reports = sorted(runs_dir.glob("*_campaign_*.json")) if runs_dir.is_dir() else []
    if not reports:
        raise AssertionError(f"lk break did not write campaign evidence under {runs_dir}\\n{output.stdout[-10000:]}")
    report_path = reports[-1]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    results = report.get("results") or []
    if len(results) != 1:
        raise AssertionError(f"Expected one accounting result for {contract}, got {len(results)}: {report}")
    result = results[0]
    scenario_evidence = evidence_root / contract
    scenario_evidence.mkdir(parents=True, exist_ok=True)
    for evidence_file in runs_dir.glob("*.json"):
        shutil.copy2(evidence_file, scenario_evidence / evidence_file.name)
    harness_archive = (result.get("detail") or {}).get("harness_archive")
    if harness_archive and Path(harness_archive).is_file():
        shutil.copy2(harness_archive, scenario_evidence / Path(harness_archive).name)
    if result.get("status") != "OBSERVED":
        raise AssertionError(f"{contract} did not reach OBSERVED: {json.dumps(result, indent=2)}")
    tail = str((result.get("detail") or {}).get("raw_tail") or "")
    for marker in expected_markers:
        if marker not in tail:
            raise AssertionError(
                f"{contract} evidence missing {marker!r}.\\n"
                f"Raw tail:\\n{tail}\\nCLI output:\\n{output.stdout[-10000:]}"
            )
    print(f"PASS: {contract} reached OBSERVED through installed lk break; evidence: {scenario_evidence}")


def main() -> int:
    forge = shutil.which("forge")
    cast = shutil.which("cast") or str(Path.home() / ".foundry" / "bin" / "cast")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge or not (Path(lk).is_file() or shutil.which(lk)) or not (Path(cast).is_file() or shutil.which(cast)):
        raise AssertionError("forge or installed lk is unavailable")
    forge_std = Path("/tmp/lowkey-fixture/lib/forge-std")
    if not forge_std.is_dir():
        raise AssertionError(f"CI forge-std dependency is unavailable: {forge_std}")

    env = os.environ.copy()
    env["LOWKEY_RPC_URL"] = RPC
    evidence_root = Path.cwd() / ".audit" / "p0-break-acceptance"
    if evidence_root.exists():
        shutil.rmtree(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="lowkey-p0-break-e2e-") as temp:
            root = Path(temp).resolve()
            (root / "src").mkdir()
            (root / "lib").mkdir()
            (root / "lib" / "forge-std").symlink_to(forge_std, target_is_directory=True)
            (root / "foundry.toml").write_text(
                '[profile.default]\n'
                'src = "src"\n'
                'test = "test"\n'
                'out = "out"\n'
                'libs = ["lib"]\n'
                'solc_version = "0.8.20"\n',
                encoding="utf-8",
            )
            (root / "src" / "P0Targets.sol").write_text(SOURCE, encoding="utf-8")
            run([forge, "build"], root, env)

            array_target = deploy(forge, root, env, "AddressArraySetupTarget")
            usdc = deploy(forge, root, env, "MockUSDC6")
            usdc_vault = deploy(forge, root, env, "USDCVault", usdc)
            usdt = deploy(forge, root, env, "MockUSDT6NoReturnReset")
            usdt_vault = deploy(forge, root, env, "USDTVault", usdt)
            no_metadata_token = deploy(forge, root, env, "MockNoMetadataToken")
            no_metadata_vault = deploy(forge, root, env, "NoMetadataVault", no_metadata_token)
            attacker = "0xBEEF000000000000000000000000000000000042"
            run([
                cast, "send", usdt, "primeAllowance(address,address,uint256)",
                attacker, usdt_vault, "1",
                "--rpc-url", RPC, "--private-key", ANVIL_KEY0,
            ], root, env)

            exercise(lk, root, env, "AddressArraySetupTarget", array_target, [
                "SETUP_SUCCESS true",
            ], evidence_root)
            exercise(lk, root, env, "USDCVault", usdc_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED true",
                "ASSET_DECIMALS 6",
                "TOKEN_FUNDING_AMOUNT 1000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root)
            exercise(lk, root, env, "USDTVault", usdt_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED true",
                "ASSET_DECIMALS 6",
                "TOKEN_FUNDING_AMOUNT 1000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_RESET_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root)
            exercise(lk, root, env, "NoMetadataVault", no_metadata_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED false",
                "ASSET_DECIMALS_FALLBACK_18 true",
                "ASSET_DECIMALS 18",
                "TOKEN_FUNDING_AMOUNT 1000000000000000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root)
        print("PASS: all four P0 end-to-end installed-lk acceptance cases reached OBSERVED.")
    finally:
        # Do not leave the CI runner's global target pointed at a temporary deployment.
        subprocess.run([lk, "target", "reset"], env=env, text=True, capture_output=True, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
