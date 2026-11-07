#!/usr/bin/env python3
"""P1 acceptance: paired Forge state diff, freeze validation, and funded Anvil reproof."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478bfe5bfffa3618b3b1c6b0c"

# The canonical Anvil test mnemonic's first key.
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478bfe5bfffa3618b3b1c6b0"


def run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 360) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command exited {result.returncode}: {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-12000:]}\n"
            f"--- stderr ---\n{result.stderr[-12000:]}"
        )
    return result


def run_expected(argv: list[str], cwd: Path, env: dict[str, str], expected: int, timeout: int = 120):
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"Expected exit {expected}, received {result.returncode}: {argv!r}\n"
            f"stdout={result.stdout[-8000:]}\nstderr={result.stderr[-8000:]}"
        )
    return result


def find_tool(name: str, fallback: Path) -> str:
    found = shutil.which(name)
    if found:
        return found
    if fallback.is_file():
        return str(fallback)
    raise AssertionError(f"Required tool is unavailable: {name}")


def deploy(forge: str, root: Path, env: dict[str, str], contract: str, *args: str) -> str:
    command = [
        forge, "create", f"src/ReentrancyFixture.sol:{contract}",
        "--rpc-url", RPC, "--private-key", ANVIL_KEY0, "--broadcast", "--json",
    ]
    if args:
        command.extend(["--constructor-args", *args])
    result = run(command, root, env)
    payload = json.loads(result.stdout)
    address = payload.get("deployedTo")
    if not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]{40}", address):
        raise AssertionError(f"forge create did not return {contract} address: {payload}")
    return address


def send(cast: str, root: Path, env: dict[str, str], to: str, signature: str, *args: str, value: str | None = None):
    command = [cast, "send", to, signature, *args, "--rpc-url", RPC, "--private-key", ANVIL_KEY0]
    if value is not None:
        command.extend(["--value", value])
    return run(command, root, env)


def read_json(path: Path) -> dict:
    if not path.is_file():
        raise AssertionError(f"Expected machine-readable evidence file is missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    fixture = repo_root / "tests" / "fixtures" / "acceptance" / "p1-reentrancy"
    forge = find_tool("forge", Path.home() / ".foundry" / "bin" / "forge")
    cast = find_tool("cast", Path.home() / ".foundry" / "bin" / "cast")
    lk = find_tool("lk", Path.home() / ".foundry" / "bin" / "lk")
    forge_std_value = os.environ.get("LOWKEY_FORGE_STD")
    forge_std = Path(forge_std_value).resolve() if forge_std_value else None
    if forge_std is None or not (forge_std / "src" / "Vm.sol").is_file():
        raise AssertionError("LOWKEY_FORGE_STD must point to the installed forge-std source tree.")
    if not fixture.is_dir():
        raise AssertionError(f"P1 reentrancy fixture directory is missing: {fixture}")

    evidence_root = Path.cwd() / ".audit" / "p1-reentrancy-acceptance"
    if evidence_root.exists():
        shutil.rmtree(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env.update({
        "LOWKEY_RPC_URL": RPC,
        "ETH_RPC_URL": RPC,
        "FOUNDRY_ETH_RPC_URL": RPC,
    })
    source_sha = env.get("GITHUB_SHA")
    install_manifest_path = Path.home() / ".lowkey" / "install-manifest.json"
    if not install_manifest_path.is_file():
        raise AssertionError(f"Installed Lowkey manifest is missing: {install_manifest_path}")
    installed_sha = json.loads(install_manifest_path.read_text(encoding="utf-8")).get("git_sha")
    if source_sha and installed_sha != source_sha:
        raise AssertionError(f"Installed Lowkey SHA {installed_sha!r} differs from workflow SHA {source_sha!r}")

    with tempfile.TemporaryDirectory(prefix="lowkey-p1-reentrancy-") as temp:
        root = Path(temp).resolve()
        shutil.copytree(fixture, root, dirs_exist_ok=True)
        (root / "src" / "LowkeyForgeStateDiffRecorder.sol").write_text(
            (repo_root / "docs" / "LowkeyForgeStateDiffRecorder.sol").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (root / "lib").mkdir(exist_ok=True)
        (root / "lib" / "forge-std").symlink_to(forge_std, target_is_directory=True)

        run([forge, "build"], root, env, timeout=360)
        vault = deploy(forge, root, env, "ReentrancyVault")
        actor = deploy(forge, root, env, "ReentrancyActor", vault)

        # One ETH is withdrawable; one ETH is reserve liquidity for the second,
        # reentrant withdrawal. No balance/storage state is fabricated.
        send(cast, root, env, vault, "seed()", value="1ether")
        send(cast, root, env, actor, "deposit()", value="1ether")
        owner_result = run([cast, "wallet", "address", "--private-key", ANVIL_KEY0], root, env)
        owner = owner_result.stdout.strip().splitlines()[-1]
        if not re.fullmatch(r"0x[0-9a-fA-F]{40}", owner):
            raise AssertionError(f"cast wallet address returned an invalid owner address: {owner!r}")
        fork_block_text = run([cast, "block-number", "--rpc-url", RPC], root, env).stdout.strip()
        fork_block = int(fork_block_text)

        env.update({"P1_VAULT": vault, "P1_ACTOR": actor, "P1_OWNER": owner})
        shared_argv = [
            forge, "test",
            "--match-path", "test/P1ReentrancyPaired.t.sol",
            "--match-test", "test_paired_reentrancy",
            "--fork-url", RPC,
            "-vv",
        ]
        manifest = {
            "trace_backend": "forge-state-diff",
            "paired_forge_experiment": True,
            "target_authenticity": "fixture",
            "family": "reentrancy",
            "expected_chain_id": 31337,
            "expected_fork_block": fork_block,
            "target_address": vault,
            "same_calls_id": "p1-same-vault-withdraw-control-vs-reentrancy-v1",
            "metric_name": "attacker_contract_gross_balance_delta_wei",
            "prestate_addresses": [vault, actor],
            "metric_addresses": [actor],
            "scenario_parameters": [{
                "name": "callback_mode",
                "address": actor,
                "slot": "0x0",
                "control_value": "1",
                "attack_value": "2",
                "description": "1 is sequential-only; 2 enables the reentrant receive callback.",
            }],
            "trace_expectations": [{
                "address": vault,
                "control_min_calls": 1,
                "control_max_calls": 1,
                "attack_min_calls": 2,
                "attack_max_calls": 2,
                "description": "The callback attack adds exactly one nested withdraw call.",
            }],
            "evidence_requirements": {
                "call_tree": "exact",
                "calldata": "exact",
                "storage": "derived",
            },
            "require_trace_storage": True,
            "control": {
                "harness": "test/P1ReentrancyPaired.t.sol",
                "support_files": [
                    "src/ReentrancyFixture.sol",
                    "src/LowkeyForgeStateDiffRecorder.sol",
                ],
                "state_diff_file": ".audit/godmode/control-state-diff.json",
                "argv": shared_argv,
            },
            "attack": {
                "harness": "test/P1ReentrancyPaired.t.sol",
                "support_files": [
                    "src/ReentrancyFixture.sol",
                    "src/LowkeyForgeStateDiffRecorder.sol",
                ],
                "state_diff_file": ".audit/godmode/attack-state-diff.json",
                "argv": shared_argv,
            },
        }
        manifest_path = root / "control.json"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        common = [lk, "control", "control.json", "--root", str(root), "--rpc-url", RPC]
        run(common + ["--freeze"], root, env)
        validation = run(
            common + ["--validate", "--output", ".audit/p1-reentrancy-acceptance/freeze-validation.json"],
            root, env,
        )
        valid_report = read_json(root / ".audit" / "p1-reentrancy-acceptance" / "freeze-validation.json")
        if validation.returncode != 0 or valid_report.get("status") != "PROPOSED" or not valid_report.get("freeze_valid"):
            raise AssertionError(f"Freeze validation did not pass without execution: {valid_report}")
        if valid_report.get("execution_attempted") is not False:
            raise AssertionError("Standalone --validate unexpectedly claims experiment execution.")

        paired = run(
            common + [
                "--require-frozen",
                "--output", ".audit/p1-reentrancy-acceptance/paired-control.json",
            ],
            root, env, timeout=900,
        )
        paired_report = read_json(root / ".audit" / "p1-reentrancy-acceptance" / "paired-control.json")
        if paired.returncode != 0:
            raise AssertionError(f"Paired control did not pass: {paired_report}")
        for field in (
            "state_diff_pair_verified",
            "same_entry_call_verified",
            "same_prestate_verified",
            "same_chain_verified",
            "same_block_verified",
            "same_fork_anchor_verified",
            "trace_delta_verified",
            "evidence_requirements_verified",
            "economic_reproof_required",
        ):
            if paired_report.get(field) is not True:
                raise AssertionError(f"Paired state-diff evidence did not verify {field}: {paired_report}")
        if paired_report.get("status") != "SIMULATED_BREAK" or paired_report.get("legacy_status") != "SIMULATED_BREAK":
            raise AssertionError(f"Forge state-diff must remain capped at SIMULATED_BREAK: {paired_report}")
        if paired_report.get("economic_policy", {}).get("accepted") is not False:
            raise AssertionError("Forge gross balances were incorrectly promoted to net profitability.")
        rows = paired_report.get("runs") or {}
        for scenario, expected_calls, expected_mode in (("control", 1, "0x1"), ("attack", 2, "0x2")):
            row = rows.get(scenario) or {}
            calls = [
                item for item in (row.get("call_trace") or [])
                if str(item.get("to") or "").lower() == vault.lower()
            ]
            if len(calls) != expected_calls:
                raise AssertionError(f"{scenario} expected {expected_calls} vault calls, observed {len(calls)}.")
            accesses = row.get("derived_storage_accesses") or []
            if not accesses:
                raise AssertionError(f"{scenario} has no trace-derived storage accesses.")
            params = row.get("scenario_parameters") or []
            if len(params) != 1 or str(params[0].get("observed_value") or "").lower()[-1:] != expected_mode[-1:]:
                raise AssertionError(f"{scenario} callback-mode prestate was not independently observed: {params}")

        freeze_path = root / ".audit" / "godmode" / "control.freeze.json"
        original_freeze = freeze_path.read_text(encoding="utf-8")
        tampered = json.loads(original_freeze)
        tampered["freeze_sha256"] = "0" * 64
        freeze_path.write_text(json.dumps(tampered, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tamper = run_expected(
            common + [
                "--validate",
                "--output", ".audit/p1-reentrancy-acceptance/tampered-validation.json",
            ],
            root, env, expected=2,
        )
        tamper_report = read_json(root / ".audit" / "p1-reentrancy-acceptance" / "tampered-validation.json")
        if tamper_report.get("status") != "REJECTED" or tamper_report.get("rejection_codes") != ["digest_mismatch"]:
            raise AssertionError(f"Tampered frozen digest was not REJECTED/digest_mismatch: {tamper_report}")
        if tamper_report.get("execution_attempted") is not False:
            raise AssertionError("Tampered frozen digest reached experiment execution.")
        freeze_path.write_text(original_freeze, encoding="utf-8")

        # A separate signed transaction proves local net profitability after
        # actual receipt gas. The proof axis stays OBSERVED because this target
        # is a fixture, not an independently authenticated real deployment.
        replay_argv = [
            sys.executable, "scripts/p1_replay_attack.py", actor, RPC, ANVIL_KEY0,
        ]
        reprove_command = [
            lk, "reprove", "src/ReentrancyFixture.sol",
            "--root", str(root),
            "--rpc-url", RPC,
            "--fork-block", str(fork_block),
            "--target-address", vault,
            "--profit-address", owner,
            "--profit-address", actor,
            "--family", "reentrancy",
            "--require-trace-storage",
            "--argv-json", json.dumps(replay_argv),
            "--support-file", "scripts/p1_replay_attack.py",
        ]
        reprove = run(reprove_command, root, env, timeout=900)
        reprove_report = read_json(root / ".audit" / "godmode" / "reprove.json")
        if reprove.returncode != 0:
            raise AssertionError(f"Funded local reproof failed: {reprove_report}\n{reprove.stdout[-8000:]}")
        if reprove_report.get("legacy_status") != "LOCAL_PROFITABLE":
            raise AssertionError(f"Funded reproof did not reach LOCAL_PROFITABLE: {reprove_report}")
        if int(reprove_report.get("net_profit_wei") or 0) <= 0 or int(reprove_report.get("gas_cost_wei") or 0) <= 0:
            raise AssertionError("Local reproof did not record positive net profit after nonzero gas cost.")
        if not (reprove_report.get("storage_trace") or {}).get("slots"):
            raise AssertionError("Local reproof did not include prestateTracer-derived storage slots.")
        if reprove_report.get("target_authenticity") != "unknown" or reprove_report.get("status") != "OBSERVED":
            raise AssertionError("Fixture reproof must remain OBSERVED on the authenticity axis.")

        shutil.copy2(manifest_path, evidence_root / "control.json")
        shutil.copy2(freeze_path, evidence_root / "control.freeze.json")
        shutil.copy2(root / ".audit" / "godmode" / "control-state-diff.json", evidence_root / "control-state-diff.json")
        shutil.copy2(root / ".audit" / "godmode" / "attack-state-diff.json", evidence_root / "attack-state-diff.json")
        shutil.copy2(root / ".audit" / "godmode" / "reprove.json", evidence_root / "reprove.json")
        shutil.copy2(root / ".audit" / "p1-reentrancy-acceptance" / "paired-control.json", evidence_root / "paired-control.json")
        shutil.copy2(root / ".audit" / "p1-reentrancy-acceptance" / "freeze-validation.json", evidence_root / "freeze-validation.json")
        shutil.copy2(root / ".audit" / "p1-reentrancy-acceptance" / "tampered-validation.json", evidence_root / "tampered-validation.json")

        report = {
            "status": "PASS",
            "source_sha": source_sha,
            "installed_git_sha": installed_sha,
            "workflow_run_id": os.environ.get("GITHUB_RUN_ID"),
            "vault": vault,
            "attacker": actor,
            "fork_block": fork_block,
            "forge_pair": {
                "status": paired_report.get("status"),
                "state_diff_pair_verified": paired_report.get("state_diff_pair_verified"),
                "control_delta": paired_report.get("control_delta"),
                "call_counts": {"control": 1, "attack": 2},
                "control_storage_accesses": len(rows["control"]["derived_storage_accesses"]),
                "attack_storage_accesses": len(rows["attack"]["derived_storage_accesses"]),
                "economic_reproof_required": paired_report.get("economic_reproof_required"),
            },
            "freeze_validation": {
                "valid_status": valid_report.get("status"),
                "tampered_status": tamper_report.get("status"),
                "tampered_reason_codes": tamper_report.get("rejection_codes"),
                "execution_attempted_after_tamper": tamper_report.get("execution_attempted"),
            },
            "anvil_reproof": {
                "legacy_status": reprove_report.get("legacy_status"),
                "proof_status": reprove_report.get("status"),
                "net_profit_wei": reprove_report.get("net_profit_wei"),
                "gas_cost_wei": reprove_report.get("gas_cost_wei"),
                "trace_storage_slots": len((reprove_report.get("storage_trace") or {}).get("slots") or []),
                "target_authenticity": reprove_report.get("target_authenticity"),
            },
        }
        (evidence_root / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
