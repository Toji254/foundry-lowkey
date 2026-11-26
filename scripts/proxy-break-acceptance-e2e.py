#!/usr/bin/env python3
"""Installed Lowkey UUPS proxy-break E2E acceptance against disposable Anvil.

The vulnerable and secured proxy fixtures are deployed to Anvil. Lowkey's
generated probe executes on Forge forks and must demonstrate both takeover
and rejection, while the upstream Anvil implementation slots remain unchanged.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
FORGE_STD = Path("/tmp/lowkey-fixture/lib/forge-std")

SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUUPSProbe {
    function proxiableUUID() external view returns (bytes32);
}

abstract contract UUPSProbeBase {
    bytes32 internal constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    // Must match the proxy's slot-zero owner declaration.
    address public owner;

    function proxiableUUID() external pure returns (bytes32) {
        return IMPLEMENTATION_SLOT;
    }

    function _installImplementation(address nextImplementation) internal {
        require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
        require(
            IUUPSProbe(nextImplementation).proxiableUUID() == IMPLEMENTATION_SLOT,
            "UNSUPPORTED_PROXIABLE_UUID"
        );
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, nextImplementation)
        }
    }
}

contract VulnerableUUPSImplementation is UUPSProbeBase {
    function upgradeTo(address nextImplementation) external {
        // Deliberate vulnerability: there is no authorization check.
        _installImplementation(nextImplementation);
    }
}

contract SecureUUPSImplementation is UUPSProbeBase {
    function upgradeTo(address nextImplementation) external {
        require(msg.sender == owner, "ONLY_OWNER");
        _installImplementation(nextImplementation);
    }
}

contract UUPSProxyFixture {
    address public owner;

    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address implementation_) {
        require(implementation_.code.length > 0, "NO_IMPLEMENTATION_CODE");
        owner = msg.sender;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, implementation_)
        }
    }

    fallback() external payable {
        _delegate();
    }

    receive() external payable {
        _delegate();
    }

    function _delegate() internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation_ := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

interface ITransparentProxyAdminUpgrade {
    function upgradeToAndCall(address implementation, bytes calldata data) external payable;
}

contract VulnerableProxyAdmin {
    address private immutable _owner;
    constructor(address initialOwner) { _owner = initialOwner; }
    function owner() external view returns (address) { return _owner; }
    function UPGRADE_INTERFACE_VERSION() external pure returns (string memory) { return "5.0.0"; }
    function upgradeAndCall(address proxy, address implementation, bytes calldata data) external payable {
        ITransparentProxyAdminUpgrade(proxy).upgradeToAndCall{value: msg.value}(implementation, data);
    }
}

contract SecureProxyAdmin {
    address private immutable _owner;
    constructor(address initialOwner) { _owner = initialOwner; }
    function owner() external view returns (address) { return _owner; }
    function UPGRADE_INTERFACE_VERSION() external pure returns (string memory) { return "5.0.0"; }
    function upgradeAndCall(address proxy, address implementation, bytes calldata data) external payable {
        require(msg.sender == _owner, "ONLY_PROXY_ADMIN_OWNER");
        ITransparentProxyAdminUpgrade(proxy).upgradeToAndCall{value: msg.value}(implementation, data);
    }
}

contract TransparentProxyFixture {
    address private immutable _admin;
    bytes32 private constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes4 private constant UPGRADE_TO_AND_CALL =
        bytes4(keccak256("upgradeToAndCall(address,bytes)"));

    constructor(address implementation_, address admin_) {
        _admin = admin_;
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly { sstore(slot, implementation_) }
    }

    fallback() external payable {
        if (msg.sender == _admin) {
            require(msg.sig == UPGRADE_TO_AND_CALL, "ADMIN_SELECTOR_ONLY");
            (address nextImplementation, bytes memory data) =
                abi.decode(msg.data[4:], (address, bytes));
            require(nextImplementation.code.length > 0, "NO_IMPLEMENTATION_CODE");
            bytes32 slot = IMPLEMENTATION_SLOT;
            assembly { sstore(slot, nextImplementation) }
            if (data.length > 0) {
                (bool ok, bytes memory returned) = nextImplementation.delegatecall(data);
                if (!ok) {
                    assembly { revert(add(returned, 32), mload(returned)) }
                }
            }
            return;
        }
        _delegate();
    }

    receive() external payable { _delegate(); }

    function _delegate() internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            let implementation_ := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), implementation_, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch ok
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}

"""


def run(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-16000:]}\n"
            f"--- stderr ---\n{result.stderr[-16000:]}"
        )
    return result


def deploy(
    forge: str,
    root: Path,
    env: dict[str, str],
    contract: str,
    *args: str,
) -> str:
    output = run(
        [
            forge, "create", f"src/ProxyTargets.sol:{contract}",
            "--rpc-url", RPC, "--private-key", ANVIL_KEY0, "--broadcast", "--json",
            *(["--constructor-args", *args] if args else []),
        ],
        root,
        env,
    )
    payload = json.loads(output.stdout)
    address = payload.get("deployedTo")
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        raise AssertionError(f"forge create did not return a deployed address for {contract}: {payload}")
    return address.lower()


def campaign_result(
    lk: str,
    root: Path,
    env: dict[str, str],
    contract: str,
    proxy: str,
    expected_status: str,
    evidence_root: Path,
) -> dict[str, Any]:
    run([lk, "target", "reset"], root, env)
    run([lk, "target", contract, proxy], root, env)

    runs_dir = root / ".audit" / "break" / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)

    output = run(
        [
            lk, "break",
            "--family", "proxy",
            "--function", "upgradeTo",
            "--rounds", "1",
        ],
        root,
        env,
        timeout=360,
    )
    reports = sorted(runs_dir.glob("*_campaign_*.json")) if runs_dir.is_dir() else []
    if not reports:
        raise AssertionError(
            f"lk break wrote no campaign report for {contract}.\n{output.stdout[-16000:]}"
        )
    report_path = reports[-1]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    results = report.get("results") or []
    if len(results) != 1:
        raise AssertionError(
            f"Expected one proxy result for {contract}; got {len(results)}: "
            + json.dumps(report, indent=2)
        )
    result = results[0]
    detail = result.get("detail") or {}
    probe = detail.get("proxy_upgrade_probe") or {}
    expected_candidate = expected_status == "CANDIDATE"

    # The Forge harness impersonates an attacker and deploys synthetic replacement
    # code. Without a separately executed sequential-control manifest, Lowkey must
    # preserve OBSERVED rather than promote this simulated candidate to BREAK.
    if result.get("status") != "OBSERVED":
        raise AssertionError(
            f"{contract}: expected fail-closed OBSERVED, got {result.get('status')}.\n"
            + json.dumps(result, indent=2)
            + "\nCLI output:\n" + output.stdout[-16000:]
        )
    required = {
        "upgrade_call_success",
        "implementation_changed",
        "candidate_implementation_installed",
        "delegatecall_route_confirmed",
    }
    missing = required - set(probe)
    if missing:
        raise AssertionError(f"{contract}: missing probe evidence fields: {sorted(missing)}")
    observed_candidate = all(probe.get(name) is True for name in required)
    if observed_candidate != expected_candidate:
        raise AssertionError(
            f"{contract}: proxy candidate telemetry does not match the fixture: "
            + json.dumps(probe, indent=2)
        )
    candidate_flag = bool(detail.get("candidate_break_condition"))
    if candidate_flag != expected_candidate or bool(result.get("break_condition")):
        raise AssertionError(
            f"{contract}: candidate classification or fail-closed verdict mismatch: "
            + json.dumps(result, indent=2)
        )
    if expected_candidate and (detail.get("control_gate") or {}).get("status") != "missing":
        raise AssertionError(
            f"{contract}: expected the explicit missing-control downgrade: "
            + json.dumps(detail.get("control_gate"), indent=2)
        )

    harness_archive = detail.get("harness_archive")
    if not harness_archive or not Path(harness_archive).is_file():
        raise AssertionError(f"{contract}: archived Forge harness is missing: {harness_archive!r}")
    harness = Path(harness_archive).read_text(encoding="utf-8", errors="replace")
    baseline_index = harness.find("markerWasAlreadyReachable")
    upgrade_index = harness.find("TARGET.call")
    if baseline_index < 0 or upgrade_index < 0 or baseline_index > upgrade_index:
        raise AssertionError(f"{contract}: generated harness does not measure route baseline before upgrade.")

    destination = evidence_root / contract
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(report_path, destination / "campaign.json")
    archived_copy = destination / Path(harness_archive).name
    shutil.copy2(harness_archive, archived_copy)
    (destination / "cli-output.txt").write_text(
        output.stdout + (("\n" + output.stderr) if output.stderr else ""),
        encoding="utf-8",
    )

    print(
        f"PASS: {contract} -> OBSERVED ({'candidate break' if expected_candidate else 'authorized control'}); "
        f"upgrade={probe['upgrade_call_success']} slot={probe['implementation_changed']} "
        f"route={probe['delegatecall_route_confirmed']}"
    )
    return {
        "implementation_contract": contract,
        "proxy": proxy,
        "fixture_role": expected_status,
        "observed_status": result.get("status"),
        "candidate_break_condition": candidate_flag,
        "break_condition": result.get("break_condition"),
        "probe": probe,
        "harness_archive": str(archived_copy),
        "evidence_path": str(destination),
    }



def proxy_admin_campaign_result(
    lk: str,
    root: Path,
    env: dict[str, str],
    admin_contract: str,
    admin_address: str,
    proxy_address: str,
    expected_status: str,
    evidence_root: Path,
) -> dict[str, Any]:
    run([lk, "target", "reset"], root, env)
    run([lk, "target", admin_contract, admin_address], root, env)
    runs_dir = root / ".audit" / "break" / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)
    output = run(
        [lk, "break", "--family", "proxy", "--proxy-address", proxy_address,
         "--function", "upgradeAndCall", "--rounds", "1"],
        root, env, timeout=360,
    )
    reports = sorted(runs_dir.glob("*_campaign_*.json")) if runs_dir.is_dir() else []
    if not reports:
        raise AssertionError(f"lk break wrote no ProxyAdmin campaign report for {admin_contract}.")
    report_path = reports[-1]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    results = report.get("results") or []
    if len(results) != 1:
        raise AssertionError(f"Expected one ProxyAdmin result for {admin_contract}; got {len(results)}.")
    result = results[0]
    detail = result.get("detail") or {}
    probe = detail.get("proxy_upgrade_probe") or {}
    expected_candidate = expected_status == "CANDIDATE"
    if result.get("status") != "OBSERVED":
        raise AssertionError(
            f"{admin_contract}: expected fail-closed OBSERVED, got {result.get('status')}."
            + json.dumps(result, indent=2) + "\n" + output.stdout[-16000:]
        )
    if str(detail.get("proxy_address") or "").lower() != proxy_address.lower():
        raise AssertionError(f"{admin_contract}: explicit proxy address is missing from evidence.")
    required = {
        "upgrade_call_success", "implementation_changed",
        "candidate_implementation_installed", "delegatecall_route_confirmed",
    }
    missing = required - set(probe)
    if missing:
        raise AssertionError(f"{admin_contract}: missing ProxyAdmin telemetry: {sorted(missing)}")
    observed_candidate = all(probe.get(name) is True for name in required)
    candidate_flag = bool(detail.get("candidate_break_condition"))
    if observed_candidate != expected_candidate or candidate_flag != expected_candidate:
        raise AssertionError(
            f"{admin_contract}: proxy candidate telemetry mismatch: "
            + json.dumps({"probe": probe, "result": result}, indent=2)
        )
    if bool(result.get("break_condition")):
        raise AssertionError(
            f"{admin_contract}: an unpaired simulated candidate was incorrectly promoted: "
            + json.dumps(result, indent=2)
        )
    if expected_candidate and (detail.get("control_gate") or {}).get("status") != "missing":
        raise AssertionError(
            f"{admin_contract}: expected the explicit missing-control downgrade: "
            + json.dumps(detail.get("control_gate"), indent=2)
        )

    harness_archive = detail.get("harness_archive")
    if not harness_archive or not Path(harness_archive).is_file():
        raise AssertionError(f"{admin_contract}: archived harness is missing.")
    harness = Path(harness_archive).read_text(encoding="utf-8", errors="replace")
    baseline_index = harness.find("markerWasAlreadyReachable")
    upgrade_index = harness.find("ADMIN.call")
    if baseline_index < 0 or upgrade_index < 0 or baseline_index > upgrade_index:
        raise AssertionError(f"{admin_contract}: route baseline was not measured before the upgrade.")
    destination = evidence_root / admin_contract
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(report_path, destination / "campaign.json")
    archived_copy = destination / Path(harness_archive).name
    shutil.copy2(harness_archive, archived_copy)
    (destination / "cli-output.txt").write_text(
        output.stdout + (("\n" + output.stderr) if output.stderr else ""),
        encoding="utf-8",
    )
    print(
        f"PASS: {admin_contract} -> OBSERVED ({'candidate break' if expected_candidate else 'authorized control'}); "
        f"upgrade={probe['upgrade_call_success']} slot={probe['implementation_changed']} "
        f"route={probe['delegatecall_route_confirmed']}"
    )
    return {
        "proxy_admin_contract": admin_contract,
        "proxy_admin": admin_address,
        "proxy": proxy_address,
        "fixture_role": expected_status,
        "observed_status": result.get("status"),
        "candidate_break_condition": candidate_flag,
        "break_condition": result.get("break_condition"),
        "probe": probe,
        "harness_archive": str(archived_copy),
        "evidence_path": str(destination),
    }


def rpc_storage(cast: str, root: Path, env: dict[str, str], proxy: str) -> str:
    raw = run(
        [cast, "storage", proxy, IMPLEMENTATION_SLOT, "--rpc-url", RPC],
        root,
        env,
    ).stdout.strip().lower()
    if not raw.startswith("0x") or len(raw) != 66:
        raise AssertionError(f"cast storage returned a malformed 32-byte word: {raw!r}")
    return "0x" + raw[-40:]


def main() -> int:
    forge = shutil.which("forge") or str(Path.home() / ".foundry" / "bin" / "forge")
    cast = shutil.which("cast") or str(Path.home() / ".foundry" / "bin" / "cast")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not all(Path(binary).is_file() or shutil.which(binary) for binary in (forge, cast, lk)):
        raise AssertionError("forge, cast, or installed lk is unavailable")
    if not FORGE_STD.is_dir():
        raise AssertionError(f"CI forge-std dependency is unavailable: {FORGE_STD}")

    parsed_rpc = urlparse(RPC)
    if parsed_rpc.scheme not in {"http", "https"} or parsed_rpc.hostname not in {
        "127.0.0.1", "localhost", "::1",
    }:
        raise AssertionError(
            "Refusing to broadcast proxy fixtures to a non-loopback RPC. "
            f"Expected localhost Anvil, received {parsed_rpc.hostname!r}."
        )

    install_manifest_path = Path.home() / ".lowkey" / "install-manifest.json"
    if not install_manifest_path.is_file():
        raise AssertionError(f"Installed Lowkey manifest is missing: {install_manifest_path}")
    install_manifest = json.loads(install_manifest_path.read_text(encoding="utf-8"))
    installed_git_sha = install_manifest.get("git_sha")
    expected_git_sha = os.environ.get("GITHUB_SHA")
    if expected_git_sha and installed_git_sha != expected_git_sha:
        raise AssertionError(
            "Installed Lowkey SHA does not match this workflow: "
            f"installed={installed_git_sha!r}, expected={expected_git_sha!r}"
        )

    env = os.environ.copy()
    env["LOWKEY_RPC_URL"] = RPC
    env["FOUNDRY_ETH_RPC_URL"] = RPC
    evidence_root = Path.cwd() / ".audit" / "proxy-break-acceptance"
    if evidence_root.exists():
        shutil.rmtree(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)

    try:
        with tempfile.TemporaryDirectory(prefix="lowkey-proxy-break-e2e-") as temp:
            root = Path(temp).resolve()
            (root / "src").mkdir()
            (root / "lib").mkdir()
            (root / "lib" / "forge-std").symlink_to(FORGE_STD, target_is_directory=True)
            (root / "foundry.toml").write_text(
                '[profile.default]\n'
                'src = "src"\n'
                'test = "test"\n'
                'out = "out"\n'
                'libs = ["lib"]\n'
                'solc_version = "0.8.20"\n'
                'optimizer = true\n'
                'optimizer_runs = 200\n',
                encoding="utf-8",
            )
            (root / "src" / "ProxyTargets.sol").write_text(SOURCE, encoding="utf-8")
            chain_id_raw = run([cast, "chain-id", "--rpc-url", RPC], root, env).stdout.strip()
            try:
                chain_id = int(chain_id_raw, 0)
            except ValueError as exc:
                raise AssertionError(f"Could not decode Anvil chain ID: {chain_id_raw!r}") from exc
            if chain_id != 31337:
                raise AssertionError(
                    f"Refusing to broadcast fixture deployments: expected Anvil chain ID 31337, got {chain_id}."
                )
            run([forge, "build"], root, env)

            vulnerable_impl = deploy(forge, root, env, "VulnerableUUPSImplementation")
            vulnerable_proxy = deploy(
                forge, root, env, "UUPSProxyFixture", vulnerable_impl,
            )
            secure_impl = deploy(forge, root, env, "SecureUUPSImplementation")
            secure_proxy = deploy(forge, root, env, "UUPSProxyFixture", secure_impl)

            deployer = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
            vulnerable_admin = deploy(forge, root, env, "VulnerableProxyAdmin", deployer)
            vulnerable_transparent_proxy = deploy(
                forge, root, env, "TransparentProxyFixture", vulnerable_impl, vulnerable_admin,
            )
            secure_admin = deploy(forge, root, env, "SecureProxyAdmin", deployer)
            secure_transparent_proxy = deploy(
                forge, root, env, "TransparentProxyFixture", secure_impl, secure_admin,
            )

            cases = [
                campaign_result(
                    lk, root, env, "VulnerableUUPSImplementation", vulnerable_proxy,
                    "CANDIDATE", evidence_root,
                ),
                campaign_result(
                    lk, root, env, "SecureUUPSImplementation", secure_proxy,
                    "CONTROL", evidence_root,
                ),
                proxy_admin_campaign_result(
                    lk, root, env, "VulnerableProxyAdmin", vulnerable_admin,
                    vulnerable_transparent_proxy, "BREAK", evidence_root,
                ),
                proxy_admin_campaign_result(
                    lk, root, env, "SecureProxyAdmin", secure_admin,
                    secure_transparent_proxy, "OBSERVED", evidence_root,
                ),
            ]

            source_slots = {
                "vulnerable_uups": (vulnerable_proxy, vulnerable_impl),
                "secure_uups": (secure_proxy, secure_impl),
                "vulnerable_proxy_admin": (vulnerable_transparent_proxy, vulnerable_impl),
                "secure_proxy_admin": (secure_transparent_proxy, secure_impl),
            }
            for label, (proxy_address, expected_implementation) in source_slots.items():
                actual = rpc_storage(cast, root, env, proxy_address)
                if actual != expected_implementation.lower():
                    raise AssertionError(
                        f"{label}: upstream Anvil implementation slot changed or mismatched; "
                        f"expected={expected_implementation.lower()} actual={actual}"
                    )

            report = {
                "gate": "Lowkey UUPS and ProxyAdmin candidate-evidence acceptance",
                "status": "PASS",
                "chain_id": chain_id,
                "source_sha": expected_git_sha,
                "installed_git_sha": installed_git_sha,
                "cases": cases,
                "source_anvil_unchanged": True,
                "scope": (
                    "Local Anvil deployments; Lowkey attack harness executes on Forge forks. "
                    "Vulnerable UUPS and ProxyAdmin fixtures must produce complete candidate telemetry; owner-gated controls must reject the attacker. All results remain OBSERVED until an independent sequential-control manifest passes."
                ),
            }
            (evidence_root / "report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(json.dumps(report, indent=2, sort_keys=True))
            print("PASS: vulnerable UUPS upgrade was reproduced and the authorized control rejected it.")
    finally:
        subprocess.run([lk, "target", "reset"], env=env, text=True, capture_output=True, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
