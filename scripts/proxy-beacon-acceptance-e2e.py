#!/usr/bin/env python3
"""Executable Beacon proxy paired-control acceptance through lk proxy campaign."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER = "0xf39fd6e51aad88f6f4ce6aB8827279cffFb92266"
ATTACKER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"
FORGE_STD = Path("/tmp/lowkey-fixture/lib/forge-std")


def run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 360) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-16000:]}\n--- stderr ---\n{result.stderr[-16000:]}"
        )
    return result


def deploy(forge: str, root: Path, env: dict[str, str], contract: str, *args: str) -> str:
    command = [
        forge, "create", f"src/BeaconFixtures.sol:{contract}",
        "--rpc-url", RPC, "--private-key", ANVIL_KEY0, "--broadcast", "--json",
    ]
    if args:
        command.extend(["--constructor-args", *args])
    result = run(command, root, env)
    address = json.loads(result.stdout).get("deployedTo")
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        raise AssertionError(f"forge create did not return {contract} address: {result.stdout[-4000:]}")
    return address.lower()


def cast_call(cast: str, root: Path, env: dict[str, str], target: str, signature: str, *args: str) -> str:
    return run([cast, "call", target, signature, *args, "--rpc-url", RPC], root, env).stdout.strip()


def cast_send(cast: str, root: Path, env: dict[str, str], target: str, signature: str, *args: str) -> None:
    run([
        cast, "send", target, signature, *args,
        "--private-key", ANVIL_KEY0, "--rpc-url", RPC,
    ], root, env)


def cast_storage(cast: str, root: Path, env: dict[str, str], target: str, slot: str) -> str:
    value = run([cast, "storage", target, slot, "--rpc-url", RPC], root, env).stdout.strip().lower()
    if len(value) != 66 or not value.startswith("0x"):
        raise AssertionError(f"Malformed storage response for {target}:{slot}: {value!r}")
    return value


def word(value: int) -> str:
    return "0x" + f"{value:064x}"


def make_manifest(
    forge: str,
    fork_block: int,
    beacon: str,
    proxy_a: str,
    proxy_b: str,
    actor: str,
    implementation_v1: str,
    implementation_v2: str,
) -> dict:
    argv = [
        forge, "test",
        "--match-path", "test/BeaconControls.t.sol",
        "--match-test", "test_paired_beacon_upgrade",
        "--fork-url", RPC,
        "--fork-block-number", str(fork_block),
        "-vv",
    ]
    return {
        "trace_backend": "forge-state-diff",
        "paired_forge_experiment": True,
        "target_authenticity": "fixture",
        "family": "proxy",
        "proxy_family": "BEACON",
        "non_economic": True,
        "expected_chain_id": 31337,
        "expected_fork_block": fork_block,
        "target_address": beacon,
        "function": "upgradeTo(address)",
        "same_calls_id": "beacon-same-target-same-actor-same-upgrade-v1",
        "metric_name": "successful_unauthorized_beacon_upgrades",
        "prestate_addresses": [beacon, proxy_a, proxy_b, actor, implementation_v1, implementation_v2],
        "prestate_slots": [
            {"address": beacon, "slot": "0x0"},
            {"address": beacon, "slot": "0x1"},
            {"address": beacon, "slot": "0x2"},
            {"address": proxy_a, "slot": BEACON_SLOT},
            {"address": proxy_b, "slot": BEACON_SLOT},
            {"address": proxy_a, "slot": "0x0"},
            {"address": proxy_b, "slot": "0x0"},
            {"address": actor, "slot": "0x0"},
            {"address": actor, "slot": "0x1"},
        ],
        "metric_addresses": [actor],
        "metric_storage": {
            "address": actor,
            "slot": "0x0",
            "kind": "uint256_delta",
            "description": "BeaconUpgradeActor.successfulCalls; increments only if the beacon upgrade call succeeds.",
        },
        "scenario_parameters": [{
            "name": "secureMode",
            "address": beacon,
            "slot": "0x2",
            "control_value": word(1),
            "attack_value": word(0),
            "description": "The only declared scenario difference; the owner toggles the fixture's explicit authorization control.",
        }],
        "trace_expectations": [{
            "address": beacon,
            "selector": "0x3659cfe6",
            "control_min_calls": 1,
            "control_max_calls": 1,
            "attack_min_calls": 1,
            "attack_max_calls": 1,
            "description": "Both branches execute the same upgradeTo(address) selector and calldata through the same actor.",
        }],
        "evidence_requirements": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
        "require_trace_storage": True,
        "control": {
            "harness": "test/BeaconControls.t.sol",
            "support_files": ["src/BeaconFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": ".audit/godmode/control-beacon-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": "test_paired_beacon_upgrade",
        },
        "attack": {
            "harness": "test/BeaconControls.t.sol",
            "support_files": ["src/BeaconFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": ".audit/godmode/attack-beacon-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": "test_paired_beacon_upgrade",
        },
        "fidelity_sources": [
            "test/BeaconControls.t.sol",
            "src/BeaconFixtures.sol",
            "src/LowkeyForgeStateDiffRecorder.sol",
        ],
        "notes": (
            "Local Anvil fixture only. The control and vulnerable branch use the same beacon, "
            "shared proxies, actor, implementation argument and pinned fork snapshot. The harness "
            "uses vm.prank and a synthetic implementation, so confirmation_eligible must remain false."
        ),
    }


def execute_campaign(lk: str, root: Path, env: dict[str, str], manifest: str) -> dict:
    common = [lk, "proxy", "campaign", "--manifest", manifest, "--root", str(root), "--rpc-url", RPC]
    run(common + ["--freeze"], root, env)
    run(common + ["--validate"], root, env)
    report_path = ".audit/godmode/beacon-control-report.json"
    run(common + ["--output", report_path, "--non-economic"], root, env)
    path = root / report_path
    if not path.is_file():
        raise AssertionError("lk proxy campaign did not write its control report.")
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("status") != "SIMULATED_BREAK":
        raise AssertionError(f"Beacon fixture must remain SIMULATED_BREAK, got {report.get('status')!r}: {report}")
    runs = report.get("runs") or {}
    control = runs.get("control") or {}
    attack = runs.get("attack") or {}
    if control.get("metric") != 0 or attack.get("metric") != 1:
        raise AssertionError(f"Beacon paired metrics must be secure=0/vulnerable=1: {runs}")
    if control.get("execution_verified") is not True or attack.get("execution_verified") is not True:
        raise AssertionError(f"Beacon Forge executions were not independently verified: {runs}")
    for field in (
        "state_diff_pair_verified",
        "same_entry_call_verified",
        "same_prestate_verified",
        "same_chain_verified",
        "same_block_verified",
        "same_fork_anchor_verified",
        "trace_delta_verified",
        "evidence_requirements_verified",
        "semantic_invariant_verified",
    ):
        if report.get(field) is not True:
            raise AssertionError(f"Beacon independent control did not verify {field}: {report}")
    fidelity = report.get("proof_axes") or {}
    if fidelity.get("fidelity") not in {"synthetic_state", "fixture"}:
        raise AssertionError(f"Unexpected Beacon fixture fidelity label: {fidelity}")
    return report


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    forge = shutil.which("forge") or str(Path.home() / ".foundry" / "bin" / "forge")
    cast = shutil.which("cast") or str(Path.home() / ".foundry" / "bin" / "cast")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not all(Path(item).is_file() or shutil.which(item) for item in (forge, cast, lk)):
        raise AssertionError("forge, cast or installed lk is unavailable.")
    if not FORGE_STD.is_dir():
        raise AssertionError(f"CI forge-std dependency is missing: {FORGE_STD}")
    install_path = Path.home() / ".lowkey" / "install-manifest.json"
    if not install_path.is_file():
        raise AssertionError(f"Installed Lowkey manifest is missing: {install_path}")
    installed = json.loads(install_path.read_text(encoding="utf-8"))
    expected_sha = os.environ.get("GITHUB_SHA")
    if expected_sha and installed.get("git_sha") != expected_sha:
        raise AssertionError(f"Installed Lowkey SHA mismatch: {installed.get('git_sha')!r} != {expected_sha!r}")

    env = os.environ.copy()
    env["LOWKEY_RPC_URL"] = RPC
    env["FOUNDRY_ETH_RPC_URL"] = RPC
    with tempfile.TemporaryDirectory(prefix="lowkey-beacon-acceptance-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "lib").mkdir()
        (root / ".audit" / "godmode").mkdir(parents=True)
        (root / "lib" / "forge-std").symlink_to(FORGE_STD, target_is_directory=True)
        fixture_root = repo_root / "tests" / "fixtures" / "acceptance" / "proxy-beacon"
        shutil.copy2(fixture_root / "src" / "BeaconFixtures.sol", root / "src" / "BeaconFixtures.sol")
        shutil.copy2(fixture_root / "test" / "BeaconControls.t.sol", root / "test" / "BeaconControls.t.sol")
        shutil.copy2(repo_root / "docs" / "LowkeyForgeStateDiffRecorder.sol", root / "src" / "LowkeyForgeStateDiffRecorder.sol")
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\nlibs = ["lib"]\n'
            'solc_version = "0.8.20"\noptimizer = true\noptimizer_runs = 200\n'
            'fs_permissions = [{ access = "read-write", path = "./.audit/godmode" }]\n',
            encoding="utf-8",
        )

        host = urlparse(RPC).hostname
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise AssertionError(f"Refusing Beacon fixture deployment to non-loopback RPC host {host!r}.")
        client_version = run([cast, "rpc", "web3_clientVersion", "--rpc-url", RPC], root, env).stdout.strip().strip('"')
        if "anvil" not in client_version.lower():
            raise AssertionError(f"Refusing Beacon fixtures on a non-Anvil endpoint: {client_version!r}")
        chain_id = int(run([cast, "chain-id", "--rpc-url", RPC], root, env).stdout.strip(), 0)
        if chain_id != 31337:
            raise AssertionError(f"Refusing Beacon fixture deployment on chain ID {chain_id}; expected local Anvil 31337.")

        run([forge, "build"], root, env, timeout=600)
        implementation_v1 = deploy(forge, root, env, "BeaconLogicV1")
        implementation_v2 = deploy(forge, root, env, "BeaconLogicV2")
        beacon = deploy(forge, root, env, "PairedBeacon", implementation_v1, OWNER)
        proxy_a = deploy(forge, root, env, "BeaconProxyFixture", beacon)
        proxy_b = deploy(forge, root, env, "BeaconProxyFixture", beacon)
        actor = deploy(forge, root, env, "BeaconUpgradeActor")
        cast_send(cast, root, env, proxy_a, "setValue(uint256)", "111")
        cast_send(cast, root, env, proxy_b, "setValue(uint256)", "222")

        fork_block = int(run([cast, "block-number", "--rpc-url", RPC], root, env).stdout.strip(), 0)
        env.update({
            "BEACON_ADDRESS": beacon,
            "BEACON_PROXY_A": proxy_a,
            "BEACON_PROXY_B": proxy_b,
            "BEACON_ACTOR": actor,
            "BEACON_OWNER": OWNER,
            "BEACON_ATTACKER": ATTACKER,
            "BEACON_IMPLEMENTATION_V1": implementation_v1,
            "BEACON_IMPLEMENTATION_V2": implementation_v2,
        })

        # Exercise all Beacon fixtures against an exact Anvil snapshot before
        # asking Lowkey's frozen sequential-control runner to evaluate the pair.
        run([
            forge, "test", "--match-path", "test/BeaconControls.t.sol",
            "--fork-url", RPC, "--fork-block-number", str(fork_block), "-vv",
        ], root, env, timeout=900)

        manifest = make_manifest(
            forge, fork_block, beacon, proxy_a, proxy_b, actor, implementation_v1, implementation_v2,
        )
        (root / "beacon-control.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        control_report = execute_campaign(lk, root, env, "beacon-control.json")

        # The control campaign runs only on a Forge fork. The original Anvil
        # deployments must retain their initial implementation and proxy slots.
        if cast_call(cast, root, env, beacon, "implementation()(address)").lower() != implementation_v1:
            raise AssertionError("Beacon campaign mutated the source Anvil implementation.")
        for proxy, expected_value in ((proxy_a, "111"), (proxy_b, "222")):
            if cast_call(cast, root, env, proxy, "beacon()(address)").lower() != beacon:
                raise AssertionError(f"Beacon campaign changed {proxy}'s beacon address.")
            if cast_call(cast, root, env, proxy, "value()(uint256)") != expected_value:
                raise AssertionError(f"Beacon campaign changed source proxy storage at {proxy}.")
            if cast_call(cast, root, env, proxy, "version()(uint256)") != "1":
                raise AssertionError(f"Beacon campaign changed source proxy implementation at {proxy}.")
        if cast_storage(cast, root, env, actor, "0x0") != word(0):
            raise AssertionError("Beacon campaign changed the source Anvil actor metric.")

        evidence_root = repo_root / ".audit" / "proxy-beacon-acceptance"
        if evidence_root.exists():
            shutil.rmtree(evidence_root)
        evidence_root.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / "beacon-control.json", evidence_root / "control-manifest.json")
        shutil.copy2(root / ".audit" / "godmode" / "beacon-control-report.json", evidence_root / "control-report.json")
        for name in ("control-beacon-state-diff.json", "attack-beacon-state-diff.json"):
            artifact = root / ".audit" / "godmode" / name
            if not artifact.is_file():
                raise AssertionError(f"Beacon state-diff evidence missing: {artifact}")
            shutil.copy2(artifact, evidence_root / name)
        final = {
            "gate": "Lowkey Beacon paired-control acceptance",
            "status": "PASS",
            "chain_id": chain_id,
            "fork_block": fork_block,
            "beacon": beacon,
            "implementation_before": implementation_v1,
            "implementation_after_fork_attack": implementation_v2,
            "shared_proxies": [proxy_a, proxy_b],
            "proxy_storage_before": {"proxy_a": 111, "proxy_b": 222},
            "proxy_storage_after_fork_attack": {"proxy_a": 111, "proxy_b": 222},
            "source_anvil_implementation_unchanged": True,
            "control_report": control_report,
            "classification_policy": (
                "Fixture-only execution. Secure control rejected the matching unauthorized beacon upgrade; "
                "vulnerable branch upgraded the shared beacon and changed both proxy routes while preserving "
                "their storage. The result remains SIMULATED_BREAK with confirmation_eligible=false."
            ),
        }
        (evidence_root / "report.json").write_text(json.dumps(final, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(final, indent=2, sort_keys=True))
        print("PASS: secure Beacon control rejected; vulnerable Beacon changed both shared-proxy routes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
