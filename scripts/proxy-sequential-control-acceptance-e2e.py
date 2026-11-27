#!/usr/bin/env python3
"""P0 acceptance: paired vulnerable/secure proxy execution through lk's frozen control gate."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER = "0xf39fd6e51aad88f6f4ce6aB8827279cffFb92266"
ATTACKER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
IMPLEMENTATION_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
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
    command = [forge, "create", f"src/ProxySequentialFixtures.sol:{contract}",
               "--rpc-url", RPC, "--private-key", ANVIL_KEY0, "--broadcast", "--json"]
    if args:
        command.extend(["--constructor-args", *args])
    result = run(command, root, env)
    address = json.loads(result.stdout).get("deployedTo")
    if not isinstance(address, str) or len(address) != 42 or not address.startswith("0x"):
        raise AssertionError(f"forge create did not return {contract} address: {result.stdout[-4000:]}")
    return address.lower()


def rpc_storage(cast: str, root: Path, env: dict[str, str], address: str, slot: str) -> str:
    value = run([cast, "storage", address, slot, "--rpc-url", RPC], root, env).stdout.strip().lower()
    if not value.startswith("0x") or len(value) != 66:
        raise AssertionError(f"Malformed storage response for {address}:{slot}: {value!r}")
    return value


def address_word(address: str) -> str:
    return "0x" + ("0" * 24) + address[2:].lower()


def make_manifest(target: str, function_signature: str, actor: str, proxy: str, scenario_address: str, scenario_slot: str,
                  control_value: str, attack_value: str, prefix: str, test_name: str,
                  fork_block: int, forge: str) -> dict[str, Any]:
    selector_by_signature = {
        "upgradeTo(address)": "0x3659cfe6",
        "upgradeAndCall(address,address,bytes)": "0x9623609d",
    }
    selector = selector_by_signature.get(function_signature)
    if selector is None:
        raise AssertionError(f"Unsupported P0 proxy upgrade selector: {function_signature}")
    argv = [forge, "test", "--match-path", "test/ProxySequentialControls.t.sol",
            "--match-test", test_name, "--fork-url", RPC, "-vv"]
    return {
        "trace_backend": "forge-state-diff",
        "paired_forge_experiment": True,
        "target_authenticity": "fixture",
        "family": "proxy",
        "non_economic": True,
        "expected_chain_id": 31337,
        "expected_fork_block": fork_block,
        "target_address": target,
        "function": function_signature,
        "same_calls_id": f"p0-{prefix}-same-target-same-call-v1",
        "metric_name": "successful_unauthorized_upgrade_calls",
        "prestate_addresses": list(dict.fromkeys(x.lower() for x in (target, proxy, actor, scenario_address))),
        # Compare the same concrete storage locations in both traces. UUPS
        # owner slot zero is explicitly read in both branches because only the
        # secure implementation naturally reads it during authorization.
        "prestate_slots": [
            {"address": scenario_address, "slot": scenario_slot},
            {"address": proxy, "slot": IMPLEMENTATION_SLOT},
            {"address": actor, "slot": "0x0"},
        ] + ([{"address": proxy, "slot": "0x0"}] if target.lower() == proxy.lower() else []),
        "metric_addresses": [actor],
        "metric_storage": {
            "address": actor, "slot": "0x0", "kind": "uint256_delta",
            "description": "ProxyUpgradeActor.successfulCalls; increments only when the attempted upgrade call succeeds.",
        },
        "scenario_parameters": [{
            "name": "authorization_scenario", "address": scenario_address, "slot": scenario_slot,
            "control_value": control_value, "attack_value": attack_value,
            "description": "The only declared scenario difference; selected through the fixture owner's gated configuration method before tracing.",
        }],
        "trace_expectations": [{
            "address": target, "selector": selector,
            "control_min_calls": 1, "control_max_calls": 1,
            "attack_min_calls": 1, "attack_max_calls": 1,
            "description": "Count the actual upgrade selector only; read-only implementation getters remain in the full trace but do not inflate the upgrade-call count.",
        }],
        "evidence_requirements": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
        "require_trace_storage": True,
        "control": {
            "harness": "test/ProxySequentialControls.t.sol",
            "support_files": ["src/ProxySequentialFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": f".audit/godmode/control-{prefix}-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": test_name,
        },
        "attack": {
            "harness": "test/ProxySequentialControls.t.sol",
            "support_files": ["src/ProxySequentialFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": f".audit/godmode/attack-{prefix}-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": test_name,
        },
        "fidelity_sources": ["test/ProxySequentialControls.t.sol", "src/ProxySequentialFixtures.sol",
                             "src/LowkeyForgeStateDiffRecorder.sol"],
        "notes": "Fixture-only paired control. vm.prank and a synthetic replacement are lab mechanisms; this evidence is simulated and cannot confirm a real deployment vulnerability.",
    }


def make_transparent_hybrid_manifest(
    forge: str,
    fork_block: int,
    proxy: str,
    actor: str,
    secure_implementation: str,
    vulnerable_implementation: str,
) -> dict[str, Any]:
    """Freeze a same-proxy/same-actor UUPS second-surface experiment.

    The only declared scenario variable is the proxy implementation slot:
    secure UUPS logic rejects the non-admin actor, while vulnerable UUPS logic
    allows the same upgradeTo(address) calldata through the Transparent proxy.
    """
    selector = "0x3659cfe6"  # upgradeTo(address)
    argv = [
        forge, "test",
        "--match-path", "test/ProxySequentialControls.t.sol",
        "--match-test", "test_paired_transparent_uups_second_surface",
        "--fork-url", RPC,
        "--fork-block-number", str(fork_block),
        "-vv",
    ]
    return {
        "trace_backend": "forge-state-diff",
        "paired_forge_experiment": True,
        "target_authenticity": "fixture",
        "family": "proxy",
        "proxy_family": "TRANSPARENT",
        "non_economic": True,
        "expected_chain_id": 31337,
        "expected_fork_block": fork_block,
        "target_address": proxy,
        "function": "upgradeTo(address)",
        "same_calls_id": "p0-transparent-uups-second-surface-v1",
        "metric_name": "successful_non_admin_uups_upgrade_calls",
        "prestate_addresses": [proxy.lower(), actor.lower()],
        "prestate_slots": [
            {"address": proxy, "slot": "0x0"},
            {"address": proxy, "slot": IMPLEMENTATION_SLOT},
            {"address": actor, "slot": "0x0"},
        ],
        "metric_addresses": [actor],
        "metric_storage": {
            "address": actor,
            "slot": "0x0",
            "kind": "uint256_delta",
            "description": "ProxyUpgradeActor.successfulCalls; increments only when the non-admin UUPS call through the Transparent fallback succeeds.",
        },
        "scenario_parameters": [{
            "name": "transparent_implementation",
            "address": proxy,
            "slot": IMPLEMENTATION_SLOT,
            "control_value": address_word(secure_implementation),
            "attack_value": address_word(vulnerable_implementation),
            "description": "The sole declared scenario difference: the owner-installed UUPS implementation behind the same Transparent proxy.",
        }],
        "trace_expectations": [{
            "address": proxy,
            "selector": selector,
            "control_min_calls": 1,
            "control_max_calls": 1,
            "attack_min_calls": 1,
            "attack_max_calls": 1,
            "description": "Both scenarios send identical upgradeTo(address) calldata through the same Transparent proxy from the same ProxyUpgradeActor; only the delegated UUPS implementation differs.",
        }],
        "evidence_requirements": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
        "require_trace_storage": True,
        "control": {
            "harness": "test/ProxySequentialControls.t.sol",
            "support_files": ["src/ProxySequentialFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": ".audit/godmode/control-transparent-hybrid-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": "test_paired_transparent_uups_second_surface",
        },
        "attack": {
            "harness": "test/ProxySequentialControls.t.sol",
            "support_files": ["src/ProxySequentialFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": ".audit/godmode/attack-transparent-hybrid-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": "test_paired_transparent_uups_second_surface",
        },
        "fidelity_sources": [
            "test/ProxySequentialControls.t.sol",
            "src/ProxySequentialFixtures.sol",
            "src/LowkeyForgeStateDiffRecorder.sol",
        ],
        "notes": (
            "Fixture-only Transparent proxy hybrid experiment. The immutable ProxyAdmin address "
            "is denied implementation-facing selectors, an ordinary caller is delegated, and the "
            "paired attack checks whether a UUPS upgradeTo(address) route remains reachable through "
            "the Transparent fallback. Fixture and caller simulation cap the result at SIMULATED_BREAK."
        ),
    }


def run_transparent_hybrid_campaign(
    lk: str,
    root: Path,
    env: dict[str, str],
    manifest_name: str,
    evidence_root: Path,
) -> dict[str, Any]:
    campaign_name = "transparent-hybrid"
    freeze_path = f".audit/godmode/{campaign_name}.freeze.json"
    common = [
        lk, "proxy", "campaign",
        "--manifest", manifest_name,
        "--root", str(root),
        "--rpc-url", RPC,
        "--freeze-file", freeze_path,
    ]
    run(common + ["--freeze"], root, env, timeout=360)
    run(common + ["--validate"], root, env, timeout=360)

    report_path = f".audit/godmode/{campaign_name}-control.json"
    run(common + ["--output", report_path, "--non-economic"], root, env, timeout=900)
    report_file = root / report_path
    if not report_file.is_file():
        raise AssertionError("Lowkey proxy campaign did not write the Transparent hybrid report.")
    report = json.loads(report_file.read_text(encoding="utf-8"))
    if report.get("status") != "SIMULATED_BREAK" or report.get("legacy_status") != "SIMULATED_BREAK":
        raise AssertionError(f"Transparent hybrid fixture must remain SIMULATED_BREAK: {report}")
    if report.get("target_authenticity") != "fixture" or report.get("control_delta") != 1:
        raise AssertionError(f"Transparent hybrid campaign lacks fixture fidelity or the expected metric delta: {report}")
    runs = report.get("runs") or {}
    control, attack = runs.get("control") or {}, runs.get("attack") or {}
    if control.get("trace_error") or attack.get("trace_error"):
        raise AssertionError(f"Transparent hybrid campaign has a trace error: {runs}")
    if control.get("metric") != 0 or attack.get("metric") != 1:
        raise AssertionError(f"Transparent hybrid metrics must be secure=0/vulnerable=1: {runs}")
    if control.get("execution_verified") is not True or attack.get("execution_verified") is not True:
        raise AssertionError(f"Transparent hybrid Forge executions were not independently verified: {runs}")
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
            raise AssertionError(f"Transparent hybrid pair did not verify {field}: {report}")
    proof_axes = report.get("proof_axes") or {}
    if proof_axes.get("fidelity") not in {"synthetic_state", "fixture"}:
        raise AssertionError(f"Transparent hybrid fidelity was not simulation-specific: {proof_axes}")

    destination = evidence_root / campaign_name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / manifest_name, destination / "control-manifest.json")
    shutil.copy2(report_file, destination / "control-report.json")
    freeze_file = root / freeze_path
    if freeze_file.is_file():
        shutil.copy2(freeze_file, destination / "freeze.json")
    for scenario in ("control", "attack"):
        raw_path = root / ".audit" / "godmode" / f"{scenario}-transparent-hybrid-state-diff.json"
        if not raw_path.is_file():
            raise AssertionError(f"Transparent hybrid {scenario} state-diff is missing: {raw_path}")
        shutil.copy2(raw_path, destination / f"{scenario}-state-diff.json")
    return report


def check_pair_result(root: Path, report_prefix: str, evidence_dir: Path) -> dict[str, Any]:
    control_report = root / ".audit" / "godmode" / "control.json"
    if not control_report.is_file():
        raise AssertionError("Independent control runner did not write .audit/godmode/control.json.")
    payload = json.loads(control_report.read_text(encoding="utf-8"))
    destination = evidence_dir / report_prefix
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(control_report, destination / "control-report.json")
    runs = payload.get("runs") or {}
    for scenario_name in ("control", "attack"):
        row = runs.get(scenario_name) or {}
        artifact_name = row.get("state_diff_file")
        if isinstance(artifact_name, str) and artifact_name:
            artifact_path = (root / artifact_name).resolve()
            if artifact_path.is_relative_to(root.resolve()) and artifact_path.is_file():
                shutil.copy2(artifact_path, destination / f"{scenario_name}-state-diff.json")
    control_metric = (runs.get("control") or {}).get("metric")
    attack_metric = (runs.get("attack") or {}).get("metric")
    if control_metric != 0 or attack_metric != 1 or payload.get("control_delta") != 1:
        raise AssertionError(
            f"Paired proxy metrics do not show secure=0/vulnerable=1: "
            f"control={control_metric}, attack={attack_metric}, report={payload}"
        )
    if (runs.get("control") or {}).get("execution_verified") is not True or (runs.get("attack") or {}).get("execution_verified") is not True:
        raise AssertionError(f"Independent runner did not verify both Forge executions: {runs}")
    if payload.get("status") != "SIMULATED_BREAK" or payload.get("legacy_status") != "SIMULATED_BREAK":
        raise AssertionError(f"Fixture-only paired report must remain SIMULATED_BREAK: {payload}")
    for field in ("state_diff_pair_verified", "same_entry_call_verified", "same_prestate_verified",
                  "same_chain_verified", "same_block_verified", "same_fork_anchor_verified",
                  "trace_delta_verified", "evidence_requirements_verified", "semantic_invariant_verified"):
        if payload.get(field) is not True:
            raise AssertionError(f"Independent paired control did not verify {field}: {payload}")
    return payload


def run_controlled_break(lk: str, root: Path, env: dict[str, str], contract: str, target: str,
                         function: str, manifest_name: str, proxy: str, cast: str,
                         expected_slot: str, evidence_root: Path) -> dict[str, Any]:
    run([lk, "control", manifest_name, "--freeze", "--root", str(root), "--rpc-url", RPC], root, env)
    validate_path = root / ".audit" / "godmode" / "freeze-validation.json"
    run([lk, "control", manifest_name, "--validate", "--root", str(root), "--rpc-url", RPC,
         "--output", ".audit/godmode/freeze-validation.json"], root, env)
    if not validate_path.is_file():
        raise AssertionError("Frozen manifest validation report is missing.")
    validation = json.loads(validate_path.read_text(encoding="utf-8"))
    if validation.get("status") != "PROPOSED" or validation.get("freeze_valid") is not True or validation.get("execution_attempted") is not False:
        raise AssertionError(f"Control manifest did not validate without execution: {validation}")

    run([lk, "target", "reset"], root, env)
    run([lk, "target", contract, target], root, env)
    runs_dir = root / ".audit" / "break" / "runs"
    if runs_dir.exists():
        shutil.rmtree(runs_dir)
    command = [lk, "break", "--family", "proxy", "--function", function, "--rounds", "1",
               "--control-manifest", manifest_name]
    if contract == "PairedProxyAdmin":
        command.extend(["--proxy-address", proxy])
    output = run(command, root, env, timeout=900)
    reports = sorted(runs_dir.glob("*_campaign_*.json")) if runs_dir.is_dir() else []
    if not reports:
        raise AssertionError(f"lk break wrote no report for {contract}: {output.stdout[-12000:]}")
    campaign = json.loads(reports[-1].read_text(encoding="utf-8"))
    results = campaign.get("results") or []
    if len(results) != 1:
        raise AssertionError(f"Expected one {contract} result, observed {len(results)}: {campaign}")
    result = results[0]
    destination = evidence_root / contract
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(reports[-1], destination / "break-campaign.json")
    paired_report = check_pair_result(root, contract, evidence_root)
    detail = result.get("detail") or {}
    gate = detail.get("control_gate") or {}
    fidelity = gate.get("fidelity") or {}
    if result.get("status") != "SIMULATED_BREAK":
        raise AssertionError(
            f"{contract}: expected paired candidate to remain SIMULATED_BREAK, got {result.get('status')}. "
            f"Evidence: {json.dumps(result, indent=2)}\n{output.stdout[-12000:]}"
        )
    if str(result.get("address") or "").lower() != target.lower():
        raise AssertionError(f"{contract}: finding target does not match independent manifest target.")
    if detail.get("candidate_break_condition") is not True or result.get("break_condition") is not True:
        raise AssertionError(f"{contract}: candidate break telemetry was lost after the control gate.")
    if gate.get("status") != "passed" or gate.get("promotion_stage") != "SIMULATED_ONLY":
        raise AssertionError(f"{contract}: independent gate did not pass at simulated-only stage: {gate}")
    if fidelity.get("confirmation_eligible") is not False:
        raise AssertionError(f"{contract}: fixture/caller-impersonation fidelity was incorrectly confirmation eligible: {fidelity}")

    source_slot = rpc_storage(cast, root, env, proxy, IMPLEMENTATION_SLOT)
    if source_slot != expected_slot.lower():
        raise AssertionError(f"{contract}: source Anvil implementation slot changed: expected={expected_slot} actual={source_slot}")

    destination = evidence_root / contract
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / manifest_name, destination / "control-manifest.json")
    shutil.copy2(validate_path, destination / "freeze-validation.json")
    evidence_path = result.get("evidence_path")
    evidence_file = Path(evidence_path) if evidence_path else None
    if evidence_file is not None and not evidence_file.is_absolute():
        evidence_file = root / evidence_file
    if evidence_file is None or not evidence_file.is_file():
        raise AssertionError(f"{contract}: break evidence archive is missing: {evidence_path!r}")
    shutil.copy2(evidence_file, destination / "break-evidence.json")
    (destination / "cli-output.txt").write_text(output.stdout + (("\n" + output.stderr) if output.stderr else ""), encoding="utf-8")
    return {
        "contract": contract, "target": target, "function": result.get("function"),
        "status": result.get("status"), "break_condition": result.get("break_condition"),
        "control_gate": gate, "paired_control": paired_report,
        "source_anvil_implementation_unchanged": True, "evidence_path": str(destination),
    }


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
    with tempfile.TemporaryDirectory(prefix="lowkey-proxy-sequential-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "lib").mkdir()
        (root / ".audit" / "godmode").mkdir(parents=True)
        (root / "lib" / "forge-std").symlink_to(FORGE_STD, target_is_directory=True)
        fixture_root = repo_root / "tests" / "fixtures" / "acceptance" / "proxy-sequential"
        shutil.copy2(fixture_root / "src" / "ProxySequentialFixtures.sol", root / "src" / "ProxySequentialFixtures.sol")
        shutil.copy2(fixture_root / "test" / "ProxySequentialControls.t.sol", root / "test" / "ProxySequentialControls.t.sol")
        shutil.copy2(repo_root / "docs" / "LowkeyForgeStateDiffRecorder.sol", root / "src" / "LowkeyForgeStateDiffRecorder.sol")
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\nlibs = ["lib"]\n'
            'solc_version = "0.8.20"\noptimizer = true\noptimizer_runs = 200\n'
            'fs_permissions = [{ access = "read-write", path = "./.audit/godmode" }]\n',
            encoding="utf-8",
        )

        chain_id = int(run([cast, "chain-id", "--rpc-url", RPC], root, env).stdout.strip(), 0)
        if chain_id != 31337:
            raise AssertionError(f"Refusing to execute proxy campaign on chain ID {chain_id}; expected loopback Anvil 31337.")
        run([forge, "build"], root, env, timeout=600)
        secure_impl = deploy(forge, root, env, "SecureUUPSImplementation")
        vulnerable_impl = deploy(forge, root, env, "VulnerableUUPSImplementation")
        uups_proxy = deploy(forge, root, env, "LowkeyUUPSProxy", vulnerable_impl)
        actor = deploy(forge, root, env, "ProxyUpgradeActor")
        admin = deploy(forge, root, env, "PairedProxyAdmin", OWNER)
        transparent_proxy = deploy(forge, root, env, "LowkeyTransparentProxy", secure_impl, admin, OWNER)
        fork_block = int(run([cast, "block-number", "--rpc-url", RPC], root, env).stdout.strip(), 0)

        env.update({
            "P0_OWNER": OWNER, "P0_UUPS_PROXY": uups_proxy,
            "P0_SECURE_IMPLEMENTATION": secure_impl, "P0_VULNERABLE_IMPLEMENTATION": vulnerable_impl,
            "P0_PROXY_ADMIN": admin, "P0_TRANSPARENT_PROXY": transparent_proxy, "P0_ACTOR": actor,
        })
        evidence_root = repo_root / ".audit" / "proxy-sequential-acceptance"
        if evidence_root.exists():
            shutil.rmtree(evidence_root)
        evidence_root.mkdir(parents=True, exist_ok=True)

        uups_manifest = make_manifest(
            target=uups_proxy, function_signature="upgradeTo(address)", actor=actor,
            proxy=uups_proxy, scenario_address=uups_proxy,
            scenario_slot=IMPLEMENTATION_SLOT, control_value=address_word(secure_impl),
            attack_value=address_word(vulnerable_impl), prefix="uups",
            test_name="test_paired_uups_upgrade", fork_block=fork_block, forge=forge,
        )
        (root / "uups-control.json").write_text(json.dumps(uups_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        initial_uups_slot = rpc_storage(cast, root, env, uups_proxy, IMPLEMENTATION_SLOT)
        if initial_uups_slot != address_word(vulnerable_impl):
            raise AssertionError("UUPS proxy did not begin with vulnerable implementation.")
        uups_case = run_controlled_break(
            lk, root, env, "SecureUUPSImplementation", uups_proxy, "upgradeTo", "uups-control.json",
            uups_proxy, cast, initial_uups_slot, evidence_root,
        )

        admin_manifest = make_manifest(
            target=admin, function_signature="upgradeAndCall(address,address,bytes)", actor=actor,
            proxy=transparent_proxy, scenario_address=admin,
            scenario_slot="0x0", control_value="0x" + ("0" * 63) + "1",
            attack_value="0x" + ("0" * 64), prefix="proxy-admin",
            test_name="test_paired_proxy_admin_upgrade", fork_block=fork_block, forge=forge,
        )
        (root / "proxy-admin-control.json").write_text(json.dumps(admin_manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        initial_proxy_slot = rpc_storage(cast, root, env, transparent_proxy, IMPLEMENTATION_SLOT)
        initial_mode = rpc_storage(cast, root, env, admin, "0x0")
        if initial_proxy_slot != address_word(secure_impl) or initial_mode != "0x" + ("0" * 64):
            raise AssertionError("ProxyAdmin fixture did not start in the declared vulnerable baseline.")
        admin_case = run_controlled_break(
            lk, root, env, "PairedProxyAdmin", admin, "upgradeAndCall", "proxy-admin-control.json",
            transparent_proxy, cast, initial_proxy_slot, evidence_root,
        )

        # Independently exercise the Transparent selector split:
        # the immutable ProxyAdmin cannot call implementation getters or the
        # implementation's UUPS selector, while an ordinary caller is delegated.
        dispatch_result = run([
            forge, "test", "--match-path", "test/ProxySequentialControls.t.sol",
            "--match-test", "test_transparent_admin_non_admin_selector_routing",
            "--fork-url", RPC, "--fork-block-number", str(fork_block), "-vv",
        ], root, env, timeout=600)
        if "[PASS] test_transparent_admin_non_admin_selector_routing()" not in dispatch_result.stdout:
            raise AssertionError(
                "Transparent admin/non-admin selector routing test did not execute and pass: "
                + dispatch_result.stdout[-12000:]
            )

        hybrid_manifest = make_transparent_hybrid_manifest(
            forge=forge,
            fork_block=fork_block,
            proxy=transparent_proxy,
            actor=actor,
            secure_implementation=secure_impl,
            vulnerable_implementation=vulnerable_impl,
        )
        hybrid_manifest_name = "transparent-hybrid-control.json"
        (root / hybrid_manifest_name).write_text(
            json.dumps(hybrid_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        hybrid_initial_slot = rpc_storage(cast, root, env, transparent_proxy, IMPLEMENTATION_SLOT)
        if hybrid_initial_slot != address_word(secure_impl):
            raise AssertionError("Transparent proxy did not begin with the secure UUPS-compatible implementation.")
        hybrid_case = run_transparent_hybrid_campaign(
            lk, root, env, hybrid_manifest_name, evidence_root,
        )
        # Forge campaigns execute on a pinned fork; the source Anvil must retain
        # its original secure implementation after both paired scenarios.
        if rpc_storage(cast, root, env, transparent_proxy, IMPLEMENTATION_SLOT) != address_word(secure_impl):
            raise AssertionError("Transparent hybrid campaign mutated the source Anvil implementation slot.")

        report = {
            "gate": "Lowkey independent P0 UUPS and ProxyAdmin sequential-control acceptance",
            "status": "PASS",
            "source_sha": expected_sha,
            "installed_git_sha": installed.get("git_sha"),
            "chain_id": chain_id,
            "fork_block": fork_block,
            "cases": [uups_case, admin_case],
            "transparent_dispatch": {
                "status": "PASS",
                "test": "test_transparent_admin_non_admin_selector_routing",
                "evidence": (
                    "The immutable ProxyAdmin caller is rejected for owner() and upgradeTo(address), "
                    "while an ordinary caller reaches the delegated owner() getter."
                ),
            },
            "transparent_uups_second_surface": hybrid_case,
            "classification_policy": (
                "UUPS, ProxyAdmin and Transparent hybrid results are fixture-only paired experiments. "
                "The secure and vulnerable paths use equivalent fork snapshots, the same proxy, actor and "
                "encoded upgrade calldata where paired. Transparent routing and a non-admin UUPS second "
                "upgrade surface are demonstrated only for this fixture. Results remain SIMULATED_BREAK "
                "with confirmation_eligible=false; this is not production exploit confirmation."
            ),
        }
        (evidence_root / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
        print("PASS: UUPS, ProxyAdmin, Transparent admin routing and UUPS-behind-Transparent paired controls verified.")
        run([lk, "target", "reset"], root, env)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
