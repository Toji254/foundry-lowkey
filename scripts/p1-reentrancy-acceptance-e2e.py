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
ANVIL_KEY0 = None


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
    global ANVIL_KEY0

    repo_root = Path(__file__).resolve().parents[1]
    p0_source = (repo_root / "scripts" / "p0-break-acceptance-e2e.py").read_text(encoding="utf-8")
    key_match = re.search(r'^ANVIL_KEY0 = "([^"]+)"$', p0_source, flags=re.MULTILINE)
    if not key_match:
        raise AssertionError("Could not load the shared deterministic Anvil test key from the P0 acceptance source.")
    ANVIL_KEY0 = key_match.group(1)

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

        env.update({
            "P1_VAULT": vault,
            "P1_ACTOR": actor,
            "P1_OWNER": owner,
            "P1_EXPECT_ATTACK_REENTRIES": "1",
        })
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
            "metric_name": "successful_reentrant_withdrawals",
            "prestate_addresses": [vault, actor],
            "metric_addresses": [actor],
            "metric_storage": {
                "address": actor,
                "slot": "0x2",
                "kind": "uint256_delta",
                "description": "Successful nested withdrawals recorded by ReentrancyActor.",
            },
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
        if paired_report.get("attack_metric_kind") != "forge_trace_storage_uint256_delta":
            raise AssertionError(f"Paired Forge metric was not trace-derived storage: {paired_report.get('attack_metric_kind')}")
        if paired_report.get("runs", {}).get("control", {}).get("metric") != 0:
            raise AssertionError("Sequential control unexpectedly recorded a successful nested withdrawal.")
        if paired_report.get("runs", {}).get("attack", {}).get("metric") != 1 or paired_report.get("control_delta") != 1:
            raise AssertionError(f"Vulnerable attack did not record exactly one successful nested withdrawal: {paired_report}")
        paired_metrics = paired_report.get("metric_evidence") or {}
        if (paired_metrics.get("control") or {}).get("delta") != 0:
            raise AssertionError(f"Control storage metric was not a verified zero: {paired_metrics}")
        if (paired_metrics.get("attack") or {}).get("delta") != 1:
            raise AssertionError(f"Attack storage metric was not a verified one: {paired_metrics}")
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
        run_expected(
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

        # Mutation acceptance: move the credit write before the untrusted
        # external call (checks-effects-interactions). A surviving exploit is
        # a BLOCKED/mutation_not_killed result, never a silent pass.
        mutation_root = Path(temp) / "mutation"
        shutil.copytree(fixture, mutation_root, dirs_exist_ok=True)
        (mutation_root / "src" / "LowkeyForgeStateDiffRecorder.sol").write_text(
            (repo_root / "docs" / "LowkeyForgeStateDiffRecorder.sol").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (mutation_root / "lib").mkdir(exist_ok=True)
        (mutation_root / "lib" / "forge-std").symlink_to(forge_std, target_is_directory=True)
        mutation_source_path = mutation_root / "src" / "ReentrancyFixture.sol"
        mutation_source = mutation_source_path.read_text(encoding="utf-8")
        vulnerable_order = "\n".join([
            '        (bool ok,) = msg.sender.call{value: amount}("");',
            '        require(ok, "PAYOUT_FAILED");',
            "",
            '        // Vulnerability: this write happens after the untrusted external call.',
            '        credit[msg.sender] = 0;',
        ])
        protected_order = "\n".join([
            '        // Mutation: checks-effects-interactions clears credit before callback.',
            '        credit[msg.sender] = 0;',
            '        (bool ok,) = msg.sender.call{value: amount}("");',
            '        require(ok, "PAYOUT_FAILED");',
        ])
        if mutation_source.count(vulnerable_order) != 1:
            raise AssertionError("P1 mutation target line was absent or ambiguous; do not claim mutation coverage.")
        mutation_source_path.write_text(
            mutation_source.replace(vulnerable_order, protected_order, 1),
            encoding="utf-8",
        )
        run([forge, "build"], mutation_root, env, timeout=360)
        mutation_vault = deploy(forge, mutation_root, env, "ReentrancyVault")
        mutation_actor = deploy(forge, mutation_root, env, "ReentrancyActor", mutation_vault)
        send(cast, mutation_root, env, mutation_vault, "seed()", value="1ether")
        send(cast, mutation_root, env, mutation_actor, "deposit()", value="1ether")
        mutation_block = int(run(
            [cast, "block-number", "--rpc-url", RPC], mutation_root, env
        ).stdout.strip())
        mutation_env = dict(env)
        mutation_env.update({
            "P1_VAULT": mutation_vault,
            "P1_ACTOR": mutation_actor,
            "P1_OWNER": owner,
            "P1_EXPECT_ATTACK_REENTRIES": "0",
        })

        mutation_manifest = json.loads(json.dumps(manifest))
        mutation_manifest["target_address"] = mutation_vault
        mutation_manifest["expected_fork_block"] = mutation_block
        mutation_manifest["same_calls_id"] = "p1-reentrancy-cei-mutation-v1"
        mutation_manifest["metric_name"] = "successful_reentrant_withdrawals_after_cei_mutation"
        mutation_manifest["prestate_addresses"] = [mutation_vault, mutation_actor]
        mutation_manifest["metric_addresses"] = [mutation_actor]
        mutation_manifest["metric_storage"]["address"] = mutation_actor
        mutation_manifest["scenario_parameters"][0]["address"] = mutation_actor
        mutation_manifest["trace_expectations"][0]["address"] = mutation_vault
        mutation_manifest["control"]["state_diff_file"] = ".audit/godmode/mutation-control-state-diff.json"
        mutation_manifest["attack"]["state_diff_file"] = ".audit/godmode/mutation-attack-state-diff.json"
        mutation_manifest_path = mutation_root / "mutation-control.json"
        mutation_manifest_path.write_text(
            json.dumps(mutation_manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        mutation_common = [
            lk, "control", "mutation-control.json", "--root", str(mutation_root),
            "--rpc-url", RPC, "--freeze-file", ".audit/godmode/mutation.freeze.json",
        ]
        run(mutation_common + ["--freeze"], mutation_root, mutation_env)
        run(mutation_common + [
            "--validate",
            "--output", ".audit/p1-reentrancy-acceptance/mutation-freeze-validation.json",
        ], mutation_root, mutation_env)
        mutation_validation = read_json(
            mutation_root / ".audit" / "p1-reentrancy-acceptance" / "mutation-freeze-validation.json"
        )
        if mutation_validation.get("status") != "PROPOSED" or not mutation_validation.get("freeze_valid"):
            raise AssertionError(f"Mutated experiment did not validate its frozen spec: {mutation_validation}")
        mutation_command = mutation_common + [
            "--require-frozen",
            "--output", ".audit/p1-reentrancy-acceptance/mutation-control.json",
        ]
        mutation_execution = subprocess.run(
            mutation_command,
            cwd=mutation_root,
            env=mutation_env,
            text=True,
            capture_output=True,
            timeout=900,
            check=False,
        )
        mutation_log = (
            "--- stdout ---\\n" + (mutation_execution.stdout or "") +
            "\\n--- stderr ---\\n" + (mutation_execution.stderr or "")
        )
        (evidence_root / "mutation-command.log").write_text(
            mutation_log, encoding="utf-8"
        )
        mutation_report_path = (
            mutation_root / ".audit" / "p1-reentrancy-acceptance" / "mutation-control.json"
        )
        if not mutation_report_path.is_file():
            mutation_failure = {
                "status": "BLOCKED",
                "reason_code": "mutation_report_missing",
                "family": "reentrancy",
                "cli_exit_code": mutation_execution.returncode,
                "cli_output_tail": mutation_log[-12000:],
            }
            (evidence_root / "mutation-failure.json").write_text(
                json.dumps(mutation_failure, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            raise AssertionError(
                "Mutation control did not produce a machine-readable report; see mutation-failure.json."
            )
        mutation_report = read_json(mutation_report_path)
        # Preserve the complete evidence before asserting, even when the gate
        # fails. The temporary mutation workspace is deleted on context exit.
        diagnostic_files = [
            (
                mutation_manifest_path,
                evidence_root / "mutation-control.json",
            ),
            (
                mutation_root / ".audit" / "godmode" / "mutation.freeze.json",
                evidence_root / "mutation.freeze.json",
            ),
            (
                mutation_root / ".audit" / "p1-reentrancy-acceptance" / "mutation-freeze-validation.json",
                evidence_root / "mutation-freeze-validation.json",
            ),
            (
                mutation_root / ".audit" / "p1-reentrancy-acceptance" / "mutation-control.json",
                evidence_root / "mutation-control-report.json",
            ),
            (
                mutation_root / ".audit" / "godmode" / "mutation-control-state-diff.json",
                evidence_root / "mutation-control-state-diff.json",
            ),
            (
                mutation_root / ".audit" / "godmode" / "mutation-attack-state-diff.json",
                evidence_root / "mutation-attack-state-diff.json",
            ),
        ]
        for source, destination in diagnostic_files:
            if source.is_file():
                shutil.copy2(source, destination)

        mutation_rows = mutation_report.get("runs") or {}
        control_metric = (mutation_rows.get("control") or {}).get("metric")
        attack_metric = (mutation_rows.get("attack") or {}).get("metric")
        mutation_killed = (
            mutation_execution.returncode == 1
            and mutation_report.get("status") == "REJECTED"
            and mutation_report.get("reason_code") == "control_passed"
            and mutation_report.get("control_delta") == 0
            and mutation_report.get("execution_attempted") is True
            and mutation_report.get("attack_metric_kind") == "forge_trace_storage_uint256_delta"
            and control_metric == 0
            and attack_metric == 0
            and (mutation_report.get("metric_evidence") or {}).get("control", {}).get("delta") == 0
            and (mutation_report.get("metric_evidence") or {}).get("attack", {}).get("delta") == 0
        )
        mutation_rows = mutation_report.get("runs") or {}
        for scenario, expected_calls in (("control", 1), ("attack", 2)):
            row = mutation_rows.get(scenario) or {}
            observed_calls = [
                item for item in (row.get("call_trace") or [])
                if str(item.get("to") or "").lower() == mutation_vault.lower()
            ]
            if len(observed_calls) != expected_calls:
                mutation_killed = False
        if not mutation_killed:
            mutation_failure = {
                "status": "BLOCKED",
                "reason_code": "mutation_not_killed",
                "family": "reentrancy",
                "mutation": "move credit[msg.sender] = 0 before the external payout call",
                "cli_exit_code": mutation_execution.returncode,
                "observed_status": mutation_report.get("status"),
                "observed_reason_code": mutation_report.get("reason_code"),
                "rejection_codes": mutation_report.get("rejection_codes"),
                "control_delta": mutation_report.get("control_delta"),
                "attack_metric": mutation_report.get("attack_metric"),
                "attack_metric_kind": mutation_report.get("attack_metric_kind"),
                "metric_evidence": mutation_report.get("metric_evidence"),
                "control_metric": control_metric,
                "attack_metric_value": attack_metric,
                "reasons": mutation_report.get("reasons"),
                "scenario_errors": {
                    scenario: (mutation_rows.get(scenario) or {}).get("trace_error")
                    for scenario in ("control", "attack")
                },
            }
            print(json.dumps({"mutation_failure": mutation_failure}, indent=2, sort_keys=True))
            (evidence_root / "mutation-failure.json").write_text(
                json.dumps(mutation_failure, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            raise AssertionError("The checks-effects-interactions mutation survived; see mutation-failure.json.")
        # A separate signed transaction proves local net profitability after
        # actual receipt gas. The proof axis stays OBSERVED because this target
        # is a fixture, not an independently authenticated real deployment.
        reprove_fork_block = int(run(
            [cast, "block-number", "--rpc-url", RPC], root, env
        ).stdout.strip())
        replay_argv = [
            sys.executable, "scripts/p1_replay_attack.py", actor, RPC, ANVIL_KEY0,
        ]
        reprove_command = [
            lk, "reprove", "src/ReentrancyFixture.sol",
            "--root", str(root),
            "--rpc-url", RPC,
            "--fork-block", str(reprove_fork_block),
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
            "reprove_fork_block": reprove_fork_block,
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
            "mutation": {
                "status": mutation_report.get("status"),
                "reason_code": mutation_report.get("reason_code"),
                "control_delta": mutation_report.get("control_delta"),
                "execution_verified": mutation_killed,
                "mutation": "checks-effects-interactions: credit cleared before external call",
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
