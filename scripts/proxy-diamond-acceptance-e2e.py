#!/usr/bin/env python3
"""Executable EIP-2535 Diamond paired-control acceptance through Lowkey."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlparse

RPC = os.environ.get("LOWKEY_RPC_URL", "http://127.0.0.1:8545")
ANVIL_KEY0 = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
OWNER = "0xf39fd6e51aad88f6f4ce6aB8827279cffFb92266"
ATTACKER = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
FORGE_STD = Path("/tmp/lowkey-fixture/lib/forge-std")


def run(
    argv: list[str],
    cwd: Path,
    env: dict[str, str],
    timeout: int = 360,
    diagnostic_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    if diagnostic_path is not None:
        diagnostic_path.parent.mkdir(parents=True, exist_ok=True)
        diagnostic_path.write_text(
            json.dumps({
                "argv": [str(item) for item in argv],
                "cwd": str(cwd),
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-16000:]}\n--- stderr ---\n{result.stderr[-16000:]}"
        )
    return result


def deploy(forge: str, root: Path, env: dict[str, str], contract: str, *args: str) -> str:
    command = [
        forge, "create", f"src/DiamondFixtures.sol:{contract}",
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
    run([cast, "send", target, signature, *args, "--private-key", ANVIL_KEY0, "--rpc-url", RPC], root, env)


def cast_storage(cast: str, root: Path, env: dict[str, str], target: str, slot: str) -> str:
    value = run([cast, "storage", target, slot, "--rpc-url", RPC], root, env).stdout.strip().lower()
    if len(value) != 66 or not value.startswith("0x"):
        raise AssertionError(f"Malformed storage response for {target}:{slot}: {value!r}")
    return value


def cast_hash(cast: str, root: Path, env: dict[str, str], value: str) -> str:
    result = run([cast, "keccak", value], root, env).stdout.strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{64}", result):
        raise AssertionError(f"cast keccak returned a malformed value for {value!r}: {result!r}")
    return result


def cast_selector(cast: str, root: Path, env: dict[str, str], signature: str) -> str:
    result = run([cast, "sig", signature], root, env).stdout.strip().lower()
    if not re.fullmatch(r"0x[0-9a-f]{8}", result):
        raise AssertionError(f"cast sig returned a malformed selector for {signature!r}: {result!r}")
    return result


def mapping_slot(cast: str, root: Path, env: dict[str, str], key_type: str, key: str, mapping_seed: str) -> str:
    encoded = run(
        [cast, "abi-encode", f"f({key_type},uint256)", key, str(int(mapping_seed, 16))],
        root,
        env,
    ).stdout.strip()
    return cast_hash(cast, root, env, encoded)


def word(value: int) -> str:
    return "0x" + f"{value:064x}"


def make_manifest(
    forge: str,
    fork_block: int,
    diamond: str,
    actor: str,
    function_signature: str,
    test_name: str,
    prefix: str,
    same_calls_id: str,
    metric_name: str,
    cut_selector: str,
    prestate_addresses: list[str],
    prestate_slots: list[dict[str, str]],
    mode_slot: str,
) -> dict:
    argv = [
        forge, "test", "--match-path", "test/DiamondControls.t.sol",
        "--match-test", test_name, "--fork-url", RPC,
        "--fork-block-number", str(fork_block), "-vv",
    ]
    return {
        "trace_backend": "forge-state-diff",
        "paired_forge_experiment": True,
        "target_authenticity": "fixture",
        "family": "proxy",
        "proxy_family": "DIAMOND",
        "non_economic": True,
        "expected_chain_id": 31337,
        "expected_fork_block": fork_block,
        "target_address": diamond,
        "function": function_signature,
        "same_calls_id": same_calls_id,
        "metric_name": metric_name,
        "prestate_addresses": prestate_addresses,
        "prestate_slots": prestate_slots,
        "metric_addresses": [actor],
        "metric_storage": {
            "address": actor,
            "slot": "0x0",
            "kind": "uint256_delta",
            "description": "DiamondUpgradeActor.successfulCalls; increments only when the attempted diamond operation succeeds.",
        },
        "scenario_parameters": [{
            "name": "secureMode",
            "address": diamond,
            "slot": mode_slot,
            "control_value": word(1),
            "attack_value": word(0),
            "description": "The sole declared scenario difference; the owner-controlled Diamond authorization flag.",
        }],
        "trace_expectations": [{
            "address": diamond,
            "selector": cut_selector,
            "control_min_calls": 1,
            "control_max_calls": 1,
            "attack_min_calls": 1,
            "attack_max_calls": 1,
            "description": "Both branches execute the same diamondCut entry selector through the same actor against the same Diamond.",
        }],
        "evidence_requirements": {"call_tree": "exact", "calldata": "exact", "storage": "derived"},
        "require_trace_storage": True,
        "control": {
            "harness": "test/DiamondControls.t.sol",
            "support_files": ["src/DiamondFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": f".audit/godmode/control-{prefix}-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": test_name,
        },
        "attack": {
            "harness": "test/DiamondControls.t.sol",
            "support_files": ["src/DiamondFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
            "state_diff_file": f".audit/godmode/attack-{prefix}-state-diff.json",
            "argv": argv,
            "semantic_check_argv": argv,
            "semantic_check_test": test_name,
        },
        "fidelity_sources": ["test/DiamondControls.t.sol", "src/DiamondFixtures.sol", "src/LowkeyForgeStateDiffRecorder.sol"],
        "notes": (
            "Local Anvil EIP-2535 Diamond fixture. Forge control and attack traces use the same Diamond, "
            "actor, diamondCut selector, call arguments and pinned fork block. Fixture, vm.prank and "
            "synthetic implementations remain SIMULATED_BREAK and cannot confirm production exploitability."
        ),
    }


def _scenario_summary(report: dict) -> dict:
    runs = report.get("runs") or {}
    summary = {}
    for name in ("control", "attack"):
        row = runs.get(name) or {}
        summary[name] = {
            "trace_error": row.get("trace_error"),
            "metric": row.get("metric"),
            "metric_evidence": row.get("metric_evidence"),
            "entry_call_sha256": row.get("entry_call_sha256"),
            "prestate_sha256": row.get("prestate_sha256"),
            "scenario_parameters": row.get("scenario_parameters"),
            "prestate_comparison": row.get("prestate_comparison"),
            "execution_verified": row.get("execution_verified"),
        }
    return summary


def preserve_failure_evidence(repo_root: Path, root: Path, campaign_name: str, error: BaseException) -> Path:
    destination = repo_root / ".audit" / "proxy-diamond-acceptance"
    destination.mkdir(parents=True, exist_ok=True)
    manifest = root / f"{campaign_name}-control.json"
    if manifest.is_file():
        shutil.copy2(manifest, destination / manifest.name)
    source_audit = root / ".audit"
    copied = []
    for folder in ("godmode", "proxy", "campaign-logs"):
        source = source_audit / folder
        if source.is_dir():
            shutil.copytree(source, destination / folder, dirs_exist_ok=True)
            copied.append(folder)
    reports = {}
    godmode = source_audit / "godmode"
    for candidate in [godmode / "control.json", *sorted(godmode.glob("diamond-*-control.json"))]:
        if not candidate.is_file():
            continue
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            reports[candidate.name] = {"read_error": str(exc)}
        else:
            reports[candidate.name] = {
                "status": payload.get("status") if isinstance(payload, dict) else None,
                "rejection_codes": payload.get("rejection_codes") if isinstance(payload, dict) else None,
                "reasons": payload.get("reasons") if isinstance(payload, dict) else None,
                "scenarios": _scenario_summary(payload) if isinstance(payload, dict) else {},
            }
    diagnostics = {
        "gate": "Lowkey EIP-2535 Diamond paired-control acceptance",
        "status": "FAILED_WITH_EVIDENCE_PRESERVED",
        "campaign": campaign_name,
        "error": repr(error),
        "copied_directories": copied,
        "reports": reports,
        "note": "Raw Forge state-diffs, freeze files, manifests and control reports are copied before TemporaryDirectory cleanup.",
    }
    (destination / "failure-diagnostics.json").write_text(
        json.dumps(diagnostics, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def execute_campaign(
    lk: str,
    root: Path,
    env: dict[str, str],
    manifest_name: str,
    campaign_name: str,
    evidence_root: Path,
) -> dict:
    freeze_path = f".audit/godmode/{campaign_name}.freeze.json"
    common = [
        lk, "proxy", "campaign", "--manifest", manifest_name,
        "--root", str(root), "--rpc-url", RPC, "--freeze-file", freeze_path,
    ]
    logs = root / ".audit" / "campaign-logs"
    run(common + ["--freeze"], root, env, diagnostic_path=logs / f"{campaign_name}-freeze.json")
    run(common + ["--validate"], root, env, diagnostic_path=logs / f"{campaign_name}-validate.json")
    report_path = f".audit/godmode/{campaign_name}-control.json"
    run(
        common + ["--output", report_path, "--non-economic"],
        root,
        env,
        diagnostic_path=logs / f"{campaign_name}-execute.json",
    )
    report_file = root / report_path
    if not report_file.is_file():
        raise AssertionError(f"lk proxy campaign did not write {report_path}.")
    report = json.loads(report_file.read_text(encoding="utf-8"))
    if report.get("status") != "SIMULATED_BREAK" or report.get("legacy_status") != "SIMULATED_BREAK":
        raise AssertionError(f"Diamond {campaign_name} fixture must remain SIMULATED_BREAK: {report}")
    if report.get("target_authenticity") != "fixture" or report.get("control_delta") != 1:
        raise AssertionError(f"Diamond {campaign_name} fidelity or paired metric delta is incomplete: {report}")
    runs = report.get("runs") or {}
    control, attack = runs.get("control") or {}, runs.get("attack") or {}
    if control.get("trace_error") or attack.get("trace_error"):
        raise AssertionError(f"Diamond {campaign_name} trace error: {runs}")
    if control.get("metric") != 0 or attack.get("metric") != 1:
        raise AssertionError(f"Diamond {campaign_name} metrics must be secure=0/vulnerable=1: {runs}")
    if control.get("execution_verified") is not True or attack.get("execution_verified") is not True:
        raise AssertionError(f"Diamond {campaign_name} Forge executions were not independently verified: {runs}")
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
            raise AssertionError(f"Diamond {campaign_name} independent control did not verify {field}: {report}")
    proof_axes = report.get("proof_axes") or {}
    if proof_axes.get("fidelity") not in {"synthetic_state", "fixture"}:
        raise AssertionError(f"Diamond {campaign_name} fixture fidelity label is not simulation-specific: {proof_axes}")

    destination = evidence_root / campaign_name
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / manifest_name, destination / "control-manifest.json")
    shutil.copy2(report_file, destination / "control-report.json")
    freeze_file = root / ".audit" / "godmode" / f"{campaign_name}.freeze.json"
    if freeze_file.is_file():
        shutil.copy2(freeze_file, destination / "freeze.json")
    for scenario in ("control", "attack"):
        raw_name = f"{scenario}-{campaign_name}-state-diff.json"
        raw_path = root / ".audit" / "godmode" / raw_name
        if not raw_path.is_file():
            raise AssertionError(f"Diamond {campaign_name} state-diff evidence missing: {raw_path}")
        shutil.copy2(raw_path, destination / f"{scenario}-state-diff.json")
    return report


def _entry_calldata(raw_path: Path, target: str, selector: str, actor: str) -> str:
    payload = json.loads(raw_path.read_text(encoding="utf-8"))
    for access in payload.get("accesses", []):
        if (
            str(access.get("account") or "").lower() == target.lower()
            and str(access.get("accessor") or "").lower() == actor.lower()
            and str(access.get("data") or "").lower().startswith(selector.lower())
        ):
            return str(access.get("data")).lower()
    raise AssertionError(f"Could not locate the recorded Diamond entry calldata in {raw_path}.")


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
    evidence_root = repo_root / ".audit" / "proxy-diamond-acceptance"
    if evidence_root.exists():
        shutil.rmtree(evidence_root)
    evidence_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="lowkey-diamond-acceptance-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "lib").mkdir()
        (root / ".audit" / "godmode").mkdir(parents=True)
        (root / "lib" / "forge-std").symlink_to(FORGE_STD, target_is_directory=True)
        fixture_root = repo_root / "tests" / "fixtures" / "acceptance" / "proxy-diamond"
        shutil.copy2(fixture_root / "src" / "DiamondFixtures.sol", root / "src" / "DiamondFixtures.sol")
        shutil.copy2(fixture_root / "test" / "DiamondControls.t.sol", root / "test" / "DiamondControls.t.sol")
        shutil.copy2(repo_root / "docs" / "LowkeyForgeStateDiffRecorder.sol", root / "src" / "LowkeyForgeStateDiffRecorder.sol")
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\nout = "out"\nlibs = ["lib"]\n'
            'solc_version = "0.8.20"\noptimizer = true\noptimizer_runs = 200\n'
            'fs_permissions = [{ access = "read-write", path = "./.audit/godmode" }]\n',
            encoding="utf-8",
        )

        host = urlparse(RPC).hostname
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise AssertionError(f"Refusing Diamond fixture deployment to non-loopback RPC host {host!r}.")
        client_version = run([cast, "rpc", "web3_clientVersion", "--rpc-url", RPC], root, env).stdout.strip().strip('"')
        if "anvil" not in client_version.lower():
            raise AssertionError(f"Refusing Diamond fixtures on a non-Anvil RPC endpoint: {client_version!r}")
        chain_id = int(run([cast, "chain-id", "--rpc-url", RPC], root, env).stdout.strip(), 0)
        if chain_id != 31337:
            raise AssertionError(f"Refusing Diamond fixture deployment on chain ID {chain_id}; expected 31337.")

        run([forge, "build"], root, env, timeout=600)
        cut_facet = deploy(forge, root, env, "DiamondCutFacet")
        loupe_facet = deploy(forge, root, env, "DiamondLoupeFacet")
        facet_v1 = deploy(forge, root, env, "DiamondAppFacetV1")
        facet_v2 = deploy(forge, root, env, "DiamondAppFacetV2")
        facet_v3 = deploy(forge, root, env, "DiamondAppFacetV3")
        corrupt_facet = deploy(forge, root, env, "DiamondAppFacetCorrupt")
        init_facet = deploy(forge, root, env, "DiamondInitTakeover")
        migration_init = deploy(forge, root, env, "DiamondMigrationInitV2")
        actor = deploy(forge, root, env, "DiamondUpgradeActor")
        diamond = deploy(forge, root, env, "DiamondProxy", OWNER, cut_facet, loupe_facet, facet_v1)
        cast_send(cast, root, env, diamond, "setValue(uint256)", "4242")

        signatures = {
            "diamond_cut": "diamondCut((address,uint8,bytes4[])[],address,bytes)",
            "version": "version()",
            "value": "value()",
            "ping": "ping()",
            "new_feature": "newFeature()",
        }
        selectors = {name: cast_selector(cast, root, env, signature) for name, signature in signatures.items()}
        diamond_storage_slot = cast_hash(cast, root, env, "diamond.standard.diamond.storage")
        app_v1_slot = cast_hash(cast, root, env, "lowkey.diamond.app.storage.v1")
        app_v2_slot = cast_hash(cast, root, env, "lowkey.diamond.app.storage.v2")
        owner_slot = diamond_storage_slot
        mode_slot = word(int(diamond_storage_slot, 16) + 1)
        selector_map_seed = word(int(diamond_storage_slot, 16) + 2)
        diamond_cut_map_slot = mapping_slot(cast, root, env, "bytes4", selectors["diamond_cut"], selector_map_seed)
        version_map_slot = mapping_slot(cast, root, env, "bytes4", selectors["version"], selector_map_seed)
        fork_block = int(run([cast, "block-number", "--rpc-url", RPC], root, env).stdout.strip(), 0)

        env.update({
            "DIAMOND_ADDRESS": diamond,
            "DIAMOND_OWNER": OWNER,
            "DIAMOND_ATTACKER": ATTACKER,
            "DIAMOND_ACTOR": actor,
            "DIAMOND_CUT_FACET": cut_facet,
            "DIAMOND_LOUPE_FACET": loupe_facet,
            "DIAMOND_FACET_V1": facet_v1,
            "DIAMOND_FACET_V2": facet_v2,
            "DIAMOND_FACET_V3": facet_v3,
            "DIAMOND_CORRUPT_FACET": corrupt_facet,
            "DIAMOND_INIT": init_facet,
            "DIAMOND_MIGRATION_INIT": migration_init,
        })

        inspection = run([lk, "proxy", "inspect", diamond, "--rpc-url", RPC, "--json"], root, env, timeout=180)
        inspection_payload = json.loads(inspection.stdout)
        loupe = (inspection_payload.get("checks") or {}).get("diamond_loupe") or {}
        if inspection_payload.get("architecture") != "DIAMOND_LOUPE_AND_DELEGATECALL_CANDIDATE":
            raise AssertionError(f"Lowkey did not classify the EIP-2535 Diamond fixture: {inspection_payload}")
        if loupe.get("facet_count") != 3 or loupe.get("selector_count") != 13:
            raise AssertionError(f"Lowkey Loupe verification did not enumerate 3 facets / 13 selectors: {inspection_payload}")

        forge_result = run([
            forge, "test", "--match-path", "test/DiamondControls.t.sol",
            "--fork-url", RPC, "--fork-block-number", str(fork_block), "-vv",
        ], root, env, timeout=900)
        summary = re.search(r"(\d+)\s+passed;\s*(\d+)\s+failed", forge_result.stdout)
        if not summary or int(summary.group(1)) < 8 or int(summary.group(2)) != 0:
            raise AssertionError(f"Diamond Foundry suite did not pass all executable cases:\n{forge_result.stdout[-16000:]}")

        function_signature = signatures["diamond_cut"]
        common_addresses = [diamond, actor, cut_facet, loupe_facet]
        common_slots = [
            {"address": diamond, "slot": owner_slot},
            {"address": diamond, "slot": mode_slot},
            {"address": diamond, "slot": diamond_cut_map_slot},
            {"address": diamond, "slot": version_map_slot},
            {"address": diamond, "slot": app_v1_slot},
            {"address": actor, "slot": "0x0"},
            {"address": actor, "slot": "0x1"},
        ]
        init_addresses = [diamond, actor, cut_facet]
        init_slots = [
            {"address": diamond, "slot": owner_slot},
            {"address": diamond, "slot": mode_slot},
            {"address": actor, "slot": "0x0"},
            {"address": actor, "slot": "0x1"},
        ]

        campaign_specs = [
            ("diamond-cut", "test_paired_diamond_cut", "diamond-cut-same-target-same-actor-same-replace-v1",
             "successful_unauthorized_diamond_cuts", common_addresses, common_slots),
            ("diamond-remove", "test_paired_diamond_remove_selector", "diamond-remove-same-target-same-actor-same-remove-v1",
             "successful_unauthorized_diamond_selector_removals", common_addresses, common_slots),
            ("diamond-init", "test_paired_diamond_initializer_takeover", "diamond-init-same-target-same-actor-same-init-v1",
             "successful_unauthorized_diamond_initializers", init_addresses, init_slots),
        ]
        reports = {}
        for name, test_name, calls_id, metric_name, addresses, slots in campaign_specs:
            manifest = make_manifest(
                forge, fork_block, diamond, actor, function_signature, test_name,
                name, calls_id, metric_name, selectors["diamond_cut"], addresses, slots, mode_slot,
            )
            manifest_name = f"{name}-control.json"
            (root / manifest_name).write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            try:
                reports[name] = execute_campaign(lk, root, env, manifest_name, name, evidence_root)
            except Exception as exc:
                evidence = preserve_failure_evidence(repo_root, root, name, exc)
                print(f"DIAMOND DIAGNOSTICS PRESERVED: {evidence}", flush=True)
                raise

        # Forge campaigns run on pinned forks; all original Anvil state must remain unchanged.
        if cast_call(cast, root, env, diamond, "owner()(address)").lower() != OWNER.lower():
            raise AssertionError("Diamond campaign mutated source Anvil owner.")
        if cast_call(cast, root, env, diamond, "facetAddress(bytes4)(address)", selectors["version"]).lower() != facet_v1:
            raise AssertionError("Diamond campaign mutated source Anvil version selector mapping.")
        if cast_call(cast, root, env, diamond, "value()(uint256)") != "4242":
            raise AssertionError("Diamond campaign mutated source Anvil application value.")
        if cast_call(cast, root, env, diamond, "version()(uint256)") != "1":
            raise AssertionError("Diamond campaign mutated source Anvil application version.")
        ping_expected = cast_hash(cast, root, env, "LOWKEY_DIAMOND_PING")
        if cast_call(cast, root, env, diamond, "ping()(bytes32)").lower() != ping_expected:
            raise AssertionError("Diamond campaign changed source Anvil unrelated-function behavior.")
        if cast_storage(cast, root, env, diamond, owner_slot) != "0x" + OWNER[2:].lower().rjust(64, "0"):
            raise AssertionError("Diamond campaign changed source Anvil owner storage.")
        if cast_storage(cast, root, env, diamond, app_v1_slot) != word(4242):
            raise AssertionError("Diamond campaign changed source Anvil V1 application storage.")
        if cast_storage(cast, root, env, actor, "0x0") != word(0):
            raise AssertionError("Diamond campaign changed source Anvil actor metric.")

        cut_raw = json.loads((root / ".audit" / "godmode" / "attack-diamond-cut-state-diff.json").read_text(encoding="utf-8"))
        remove_raw = json.loads((root / ".audit" / "godmode" / "attack-diamond-remove-state-diff.json").read_text(encoding="utf-8"))
        init_raw = json.loads((root / ".audit" / "godmode" / "attack-diamond-init-state-diff.json").read_text(encoding="utf-8"))
        cut_entry = _entry_calldata(root / ".audit" / "godmode" / "attack-diamond-cut-state-diff.json", diamond, selectors["diamond_cut"], actor)
        remove_entry = _entry_calldata(root / ".audit" / "godmode" / "attack-diamond-remove-state-diff.json", diamond, selectors["diamond_cut"], actor)
        init_entry = _entry_calldata(root / ".audit" / "godmode" / "attack-diamond-init-state-diff.json", diamond, selectors["diamond_cut"], actor)

        final = {
            "gate": "Lowkey EIP-2535 Diamond independent paired-control acceptance",
            "status": "PASS",
            "chain_id": chain_id,
            "fork_block": fork_block,
            "diamond": diamond,
            "owner": OWNER,
            "attacker": ATTACKER,
            "facets": {
                "diamond_cut": cut_facet,
                "diamond_loupe": loupe_facet,
                "application_v1": facet_v1,
                "application_v2_compatible": facet_v2,
                "application_v3_migrated": facet_v3,
                "application_incompatible": corrupt_facet,
                "initializer_takeover": init_facet,
                "migration_initializer": migration_init,
            },
            "selectors": selectors,
            "selector_mapping_before": {
                "diamondCut": {"selector": selectors["diamond_cut"], "facet": cut_facet},
                "version": {"selector": selectors["version"], "facet": facet_v1},
                "value": {"selector": selectors["value"], "facet": facet_v1},
                "ping": {"selector": selectors["ping"], "facet": facet_v1},
            },
            "same_entry_calldata": {
                "diamond_cut_control_and_attack": "verified by the Lowkey report",
                "diamond_cut_attack": cut_entry,
                "diamond_remove_attack": remove_entry,
                "diamond_initializer_attack": init_entry,
            },
            "events": {
                "diamond_cut": cut_raw.get("domain_events", []),
                "diamond_remove": remove_raw.get("domain_events", []),
                "diamond_initializer": init_raw.get("domain_events", []),
            },
            "storage_snapshots": {
                "v1_slot": app_v1_slot,
                "v2_slot": app_v2_slot,
                "initial_v1_value": 4242,
                "source_anvil_v1_value_after_campaigns": 4242,
            },
            "paired_campaigns": reports,
            "additional_forge_scenarios": {
                "authorized_facet_replacement": "PASS",
                "selector_collision_rejected": "PASS",
                "selector_add_and_remove": "PASS",
                "malicious_initializer_control_and_takeover": "PASS",
                "valid_storage_migration": "PASS",
                "incompatible_facet_storage_detected": "PASS",
                "unrelated_functionality_preserved": "PASS",
                "loupe_selector_facet_consistency": "PASS",
            },
            "source_anvil_unchanged": True,
            "classification_policy": (
                "Fixture-only EIP-2535 execution. Unauthorized cut, selector removal and initializer takeover "
                "are reproduced under paired secure/vulnerable controls. Compatible upgrade, migration, "
                "selector collision, removal, incompatible storage and Loupe checks are executable Forge tests. "
                "All independent pair results remain SIMULATED_BREAK with confirmation_eligible=false."
            ),
        }
        (evidence_root / "report.json").write_text(
            json.dumps(final, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (evidence_root / "lowkey-diamond-inspection.json").write_text(inspection.stdout, encoding="utf-8")
        print(json.dumps(final, indent=2, sort_keys=True))
        print("PASS: EIP-2535 Diamond cut, removal and initializer takeover controls verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
