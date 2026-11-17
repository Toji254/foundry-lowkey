#!/usr/bin/env python3
"""Installed-CLI P0 acceptance: address[] setup, six-decimal vault, no-return USDT approval."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FallbackAccessTarget {
    mapping(address => uint256) public contributions;
    address payable public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    constructor() payable {
        owner = payable(msg.sender);
        contributions[msg.sender] = 1000 ether;
    }

    // Seed one caller-specific scenario slot through an ordinary owner call.
    function primeUserCredit(address user, uint256 amount) external onlyOwner {
        contributions[user] = amount;
    }

    function contribute() external payable {
        require(msg.value < 0.001 ether, "too much");
        // Lowkey's one-wei automatic setup probe yields two wei of credit here.
        contributions[msg.sender] += msg.value + 1;
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 1, "not a contributor");
        owner = payable(msg.sender);
    }

    function withdraw() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}

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
) -> dict[str, object]:
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
    return {
        "contract": contract,
        "status": result.get("status"),
        "expected_markers": expected_markers,
        "evidence_path": scenario_evidence.as_posix(),
        "campaign_report": report_path.name,
    }


def exercise_fallback_takeover(
    lk: str,
    cast: str,
    forge: str,
    root: Path,
    env: dict[str, str],
    evidence_root: Path,
) -> dict[str, object]:
    """Prove the Fallback receive() authority write with a matched local control."""
    contract = "FallbackAccessTarget"
    address = deploy(forge, root, env, contract)
    run([lk, "target", "reset"], root, env)
    run([lk, "target", contract, address], root, env)

    account_output = run(
        [cast, "rpc", "eth_accounts", "--rpc-url", RPC], root, env
    ).stdout.strip()
    try:
        accounts = json.loads(account_output)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"Anvil did not return a JSON account list: {account_output!r}") from exc
    if not isinstance(accounts, list) or len(accounts) < 2:
        raise AssertionError("Fallback control requires two unlocked Anvil accounts.")
    deployer, attacker = str(accounts[0]).lower(), str(accounts[1]).lower()

    # contributions is the first state variable, so its mapping base slot is 0.
    encoded_slot = run(
        [cast, "abi-encode", "f(address,uint256)", attacker, "0"], root, env
    ).stdout.strip()
    mapping_slot = run([cast, "keccak", encoded_slot], root, env).stdout.strip()
    if not mapping_slot.startswith("0x") or len(mapping_slot) != 66:
        raise AssertionError(f"Could not derive contribution mapping slot: {mapping_slot!r}")

    # The gate copies the project to a clean directory before executing local
    # command inputs, so include the helper in that copied project.
    helper_source = Path(__file__).with_name("p0-fallback-sequential-control.py")
    if not helper_source.is_file():
        raise AssertionError(f"Sequential-control helper is missing: {helper_source}")
    helper_relative = Path("scripts") / helper_source.name
    helper_copy = root / helper_relative
    helper_copy.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(helper_source, helper_copy)
    helper = helper_relative.as_posix()

    manifest_path = root / "p0-fallback-control.json"
    probe_argv = [sys.executable, helper, "probe", address, attacker]

    def prepare_argv(amount: int) -> list[str]:
        return [sys.executable, helper, "prepare", address, attacker, str(amount)]

    manifest = {
        "target_address": address.lower(),
        "function": "receive()",
        "family": "access",
        "same_calls_id": "p0-fallback-receive-access-v1",
        "non_economic": True,
        "prestate_addresses": [address.lower(), deployer, attacker],
        "prestate_slots": [
            {"address": address.lower(), "slot": "0x" + format(1, "064x")},
        ],
        "scenario_parameters": [
            {
                "name": "attacker_contribution",
                "address": address.lower(),
                "slot": mapping_slot.lower(),
                "control_value": 1,
                "attack_value": 2,
                "description": (
                    "Only the attacker contribution mapping value differs; both "
                    "values are checked on-chain before the matched receive() call."
                ),
            }
        ],
        "metric_addresses": [attacker],
        "trace_expectations": [
            {
                "address": address.lower(),
                "description": "Control and attack each execute one identical receive() call.",
                "control_min_calls": 1,
                "control_max_calls": 1,
                "attack_min_calls": 1,
                "attack_max_calls": 1,
            }
        ],
        "prepare_timeout_seconds": 45,
        "timeout_seconds": 45,
        "semantic_timeout_seconds": 30,
        "control": {
            "prepare_argv": prepare_argv(1),
            "argv": probe_argv,
            "expected_receipt_status": "0x0",
        },
        "attack": {
            "prepare_argv": prepare_argv(2),
            "argv": probe_argv,
            "expected_receipt_status": "0x1",
            "semantic_check_argv": [
                sys.executable, helper, "assert-owner", address, attacker
            ],
            "semantic_check_test": "fallback_owner_takeover",
        },
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    run(
        [lk, "control", manifest_path.name, "--root", str(root), "--freeze"],
        root, env, timeout=90,
    )

    output = run(
        [
            lk, "break", "--family", "access", "--function", "receive",
            "--rounds", "1", "--control-manifest", manifest_path.name,
        ],
        root, env, timeout=240,
    )
    if "LOWKEY // SIMULATED BREAK CONDITION REACHED" not in output.stdout:
        raise AssertionError(
            "Fallback takeover did not pass the matched-control gate as SIMULATED_BREAK.\n"
            + output.stdout[-16000:]
        )

    runs_dir = root / ".audit" / "break" / "runs"
    evidence_files = sorted(
        runs_dir.glob(f"*_access_authority_{contract}_receive_*.json")
    )
    if not evidence_files:
        raise AssertionError(
            f"Fallback authority-write evidence was not saved under {runs_dir}.\n"
            + output.stdout[-12000:]
        )
    evidence_path = evidence_files[-1]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    before = str(evidence.get("authority_before") or "").lower()
    after = str(evidence.get("authority_after") or "").lower()
    observed_attacker = str(evidence.get("attacker") or "").lower()
    gate = evidence.get("control_gate") or {}
    fidelity = gate.get("fidelity") or {}
    if not before or not observed_attacker or before == observed_attacker or after != observed_attacker:
        raise AssertionError(
            "Fallback evidence did not prove an unauthorized owner change: "
            + json.dumps(evidence, indent=2)
        )
    if evidence.get("break_condition") is not True:
        raise AssertionError("Fallback evidence omitted break_condition=true.")
    if evidence.get("verdict") != "SIMULATED_BREAK" or gate.get("status") != "passed":
        raise AssertionError(
            "Fallback candidate did not pass matched control with simulation-only cap: "
            + json.dumps({"verdict": evidence.get("verdict"), "control_gate": gate}, indent=2)
        )
    if fidelity.get("confirmation_eligible") is not False:
        raise AssertionError("A local Anvil fixture was incorrectly marked confirmation-eligible.")

    restored_owner = run(
        [cast, "call", address, "owner()(address)", "--rpc-url", RPC], root, env
    ).stdout.strip().lower()
    restored_contribution = run(
        [cast, "call", address, "contributions(address)(uint256)", attacker, "--rpc-url", RPC],
        root, env,
    ).stdout.strip().splitlines()[0]
    if restored_owner != before:
        raise AssertionError(f"Authority probe did not restore owner: before={before}, after={restored_owner}")
    try:
        contribution_value = int(restored_contribution, 0)
    except ValueError as exc:
        raise AssertionError(f"Could not decode restored contribution value: {restored_contribution!r}") from exc
    if contribution_value != 0:
        raise AssertionError(f"Authority probe left contribution state behind: {contribution_value}")

    destination = evidence_root / contract
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(evidence_path, destination / evidence_path.name)
    shutil.copy2(manifest_path, destination / "control-manifest.json")
    freeze_path = root / ".audit" / "godmode" / "control.freeze.json"
    if freeze_path.is_file():
        shutil.copy2(freeze_path, destination / "control.freeze.json")
    return {
        "contract": contract,
        "status": "SIMULATED_BREAK",
        "entry": "receive()",
        "authority_before": before,
        "authority_after": after,
        "attacker": observed_attacker,
        "control_gate": gate.get("status"),
        "confirmation_eligible": False,
        "snapshot_restored": True,
        "attacker_contribution_after_restore": contribution_value,
        "evidence_path": (destination / evidence_path.name).as_posix(),
    }

def main() -> int:
    forge = shutil.which("forge")
    cast = shutil.which("cast") or str(Path.home() / ".foundry" / "bin" / "cast")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge or not (Path(lk).is_file() or shutil.which(lk)) or not (Path(cast).is_file() or shutil.which(cast)):
        raise AssertionError("forge or installed lk is unavailable")
    forge_std = Path("/tmp/lowkey-fixture/lib/forge-std")
    if not forge_std.is_dir():
        raise AssertionError(f"CI forge-std dependency is unavailable: {forge_std}")

    install_manifest_path = Path.home() / ".lowkey" / "install-manifest.json"
    if not install_manifest_path.is_file():
        raise AssertionError(f"Installed Lowkey manifest is missing: {install_manifest_path}")
    install_manifest = json.loads(install_manifest_path.read_text(encoding="utf-8"))
    installed_git_sha = install_manifest.get("git_sha")
    expected_git_sha = os.environ.get("GITHUB_SHA")
    if expected_git_sha and installed_git_sha != expected_git_sha:
        raise AssertionError(
            f"Installed Lowkey SHA does not match this workflow: "
            f"installed={installed_git_sha!r}, expected={expected_git_sha!r}"
        )

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

            cases = []
            cases.append(exercise(lk, root, env, "AddressArraySetupTarget", array_target, [
                "SETUP_SUCCESS true",
            ], evidence_root))
            cases.append(exercise(lk, root, env, "USDCVault", usdc_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED true",
                "ASSET_DECIMALS 6",
                "TOKEN_FUNDING_AMOUNT 1000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root))
            cases.append(exercise(lk, root, env, "USDTVault", usdt_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED true",
                "ASSET_DECIMALS 6",
                "TOKEN_FUNDING_AMOUNT 1000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_RESET_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root))
            cases.append(exercise(lk, root, env, "NoMetadataVault", no_metadata_vault, [
                "SETUP_SUCCESS true",
                "ASSET_GETTER_DISCOVERED true",
                "ASSET_DECIMALS_VERIFIED false",
                "ASSET_DECIMALS_FALLBACK_18 true",
                "ASSET_DECIMALS 18",
                "TOKEN_FUNDING_AMOUNT 1000000000000000000",
                "TOKEN_APPROVAL_ATTEMPTED true",
                "TOKEN_APPROVAL_SUCCESS true",
            ], evidence_root))
            cases.append(exercise_fallback_takeover(
                lk, cast, forge, root, env, evidence_root
            ))
        if (
            len(cases) != 5
            or any(case.get("status") not in {"OBSERVED", "BREAK", "SIMULATED_BREAK"} for case in cases)
            or cases[-1].get("status") != "SIMULATED_BREAK"
            or cases[-1].get("control_gate") != "passed"
            or cases[-1].get("confirmation_eligible") is not False
            or not cases[-1].get("snapshot_restored")
        ):
            raise AssertionError(f"P0 acceptance did not observe all five cases: {cases}")
        report = {
            "gate": "P0 installed-lk break acceptance",
            "status": "PASS",
            "source_sha": expected_git_sha,
            "installed_git_sha": installed_git_sha,
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "expected_case_count": 5,
            "observed_case_count": len(cases),
            "cases": cases,
        }
        (evidence_root / "report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(report, indent=2, sort_keys=True))
        print("PASS: four accounting acceptance cases and the matched-control Fallback takeover simulation passed.")
    finally:
        # Do not leave the CI runner's global target pointed at a temporary deployment.
        subprocess.run([lk, "target", "reset"], env=env, text=True, capture_output=True, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
