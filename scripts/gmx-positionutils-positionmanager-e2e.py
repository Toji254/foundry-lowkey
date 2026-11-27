#!/usr/bin/env python3
"""Compile, link, deploy and verify real GMX V1 PositionUtils/PositionManager."""
from __future__ import annotations

import argparse
import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from itertools import count
from pathlib import Path
from typing import Any

LOWKEY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LOWKEY_ROOT))

from lowkey import lk as lowkey_cli  # noqa: E402
# Reuse the exact linker module object imported by lowkey.lk. Importing
# lowkey.library_linker separately can create a second module/class identity
# and dataclass equality then rejects otherwise identical source-qualified refs.
ArtifactIdentity = lowkey_cli.library_linker.ArtifactIdentity  # noqa: E402
extract_link_references = lowkey_cli.library_linker.extract_link_references  # noqa: E402
from lowkey.network_manager import NetworkManager  # noqa: E402

GMX_REPOSITORY = "https://github.com/gmx-io/gmx-contracts.git"
GMX_REVISION = "fe55c4ba8911ae2378b50bfb9bece5ee50cf2af8"
EXPECTED_OFFSETS = [15857, 16472]
EXPECTED_LINK_LENGTH = 20
MINIMAL_FIXTURE_INIT_CODE = "0x6001600c60003960016000f300"
RPC_IDS = count(1)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def rpc(url: str, method: str, params: list[Any] | None = None) -> Any:
    payload = {
        "jsonrpc": "2.0",
        "id": next(RPC_IDS),
        "method": method,
        "params": params or [],
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=12) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, dict) or result.get("error") is not None or "result" not in result:
        raise RuntimeError(f"RPC {method} failed at {url}: {result!r}")
    return result["result"]


def quantity(value: Any) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise RuntimeError(f"Invalid RPC quantity: {value!r}")
    return int(value, 16)


def wait_receipt(url: str, tx_hash: str) -> dict[str, Any]:
    for _ in range(400):
        receipt = rpc(url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            if not isinstance(receipt, dict) or quantity(receipt.get("status")) != 1:
                raise RuntimeError(f"Transaction failed: {tx_hash}: {receipt!r}")
            return receipt
        time.sleep(0.05)
    raise TimeoutError(f"Receipt timeout for {tx_hash}")


def deploy_fixture(url: str, sender: str, label: str) -> dict[str, Any]:
    tx_hash = rpc(url, "eth_sendTransaction", [{
        "from": sender,
        "data": MINIMAL_FIXTURE_INIT_CODE,
        "gas": "0x186a0",
    }])
    receipt = wait_receipt(url, tx_hash)
    address = str(receipt.get("contractAddress") or "").lower()
    code = rpc(url, "eth_getCode", [address, "latest"])
    if not address.startswith("0x") or code in {"0x", "0x0", None}:
        raise RuntimeError(f"Local {label} address anchor did not deploy code.")
    return {
        "name": label,
        "address": address,
        "transaction_hash": tx_hash,
        "block_number": quantity(receipt["blockNumber"]),
        "runtime_code": code,
        "fixture_kind": "one-byte STOP runtime; address/code-presence fixture only",
        "interface_support": "NOT_IMPLEMENTED",
    }


def clean_config(rpc_url: str, deployer: str) -> dict[str, Any]:
    return {
        "rpc": rpc_url,
        "actor": "lab-deployer",
        "wallets": {
            "lab-deployer": {
                "source": "anvil-default",
                "anvil_index": 0,
                "address": deployer,
                "internal": True,
            }
        },
        "target": deployer,
        "target_contract": "PreexistingAuditContext",
        "lab_system": {
            "root": deployer,
            "target": deployer,
            "root_model": "PreexistingAuditContext",
            "target_model": "PreexistingAuditContext",
        },
        "project_target_registry": {},
        "aliases": {},
        "targets": {},
        "rpc_profiles": {},
        "labels": {},
        "abi_paths": {},
        "project_roots": {},
        "target_owners": {},
        "_ephemeral": True,
    }


def locate_build_info(root: Path) -> tuple[Path, dict[str, Any]]:
    build_dir = root / "artifacts" / "build-info"
    for path in sorted(build_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        contracts = ((payload.get("output") or {}).get("contracts") or {})
        if (
            "contracts/core/PositionManager.sol" in contracts
            and "PositionManager" in contracts["contracts/core/PositionManager.sol"]
            and "contracts/core/PositionUtils.sol" in contracts
            and "PositionUtils" in contracts["contracts/core/PositionUtils.sol"]
        ):
            return path, payload
    raise RuntimeError("Hardhat build-info containing both actual GMX contracts was not found.")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def session_snapshot(manager: NetworkManager, name: str) -> dict[str, Any]:
    row = manager.status(name)
    if not row or not row.get("process_owned") or not row.get("rpc_healthy") or not row.get("identity_block_matches"):
        raise RuntimeError(f"Managed network {name!r} did not pass process/RPC/identity checks.")
    return row


def supporting_record(manager: NetworkManager, session_id: str, role: str, qualified_identity: str) -> dict[str, Any]:
    matches = [
        item for item in manager.get_deployments(session_id).values()
        if item.get("role") == role and item.get("qualified_identity") == qualified_identity
    ]
    if not matches:
        raise RuntimeError(f"No {role} record was persisted for {qualified_identity} on {session_id}.")
    matches.sort(key=lambda item: str(item.get("recorded_at") or ""), reverse=True)
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gmx-root", required=True, help="GMX V1 checkout at the pinned revision")
    args = parser.parse_args()
    root = Path(args.gmx_root).expanduser().resolve()
    output_dir = root / ".audit" / "gmx-positionutils-acceptance"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "latest.json"

    evidence: dict[str, Any] = {
        "schema": "lowkey.gmx-positionutils-positionmanager.v1",
        "status": "RUNNING",
        "source": {"repository": GMX_REPOSITORY, "revision": None},
        "compiler": {},
        "artifacts": {},
        "link_references": [],
        "linked_creation_bytecode": None,
        "networks": {},
        "fixtures": [],
        "deployments": {},
        "checks": {},
        "cleanup": {},
        "reproduction": [
            f"git clone {GMX_REPOSITORY} gmx-contracts",
            f"git -C gmx-contracts checkout --detach {GMX_REVISION}",
            "cp env.example.json env.json && npm ci && npx hardhat compile",
            "python3 scripts/gmx-positionutils-positionmanager-e2e.py --gmx-root ./gmx-contracts",
        ],
        "error": None,
    }

    manager: NetworkManager | None = None
    failure: str | None = None
    anvil = shutil.which("anvil")
    cast = shutil.which("cast")
    try:
        require(root.is_dir() and (root / ".git").exists(), "The GMX checkout is not a git repository.")
        require(anvil is not None and cast is not None, "Pinned Foundry anvil and cast binaries must be on PATH.")
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, timeout=15, check=True
        ).stdout.strip()
        evidence["source"]["revision"] = revision
        require(revision == GMX_REVISION, f"GMX source revision mismatch: expected {GMX_REVISION}, received {revision}.")

        source_pm = root / "contracts" / "core" / "PositionManager.sol"
        source_lib = root / "contracts" / "core" / "PositionUtils.sol"
        artifact_pm_path = root / "artifacts" / "contracts" / "core" / "PositionManager.sol" / "PositionManager.json"
        artifact_lib_path = root / "artifacts" / "contracts" / "core" / "PositionUtils.sol" / "PositionUtils.json"
        for path in (source_pm, source_lib, artifact_pm_path, artifact_lib_path):
            require(path.is_file(), f"Required actual GMX source/artifact file is missing: {path}")

        build_info_path, build_info = locate_build_info(root)
        compiler_version = str(build_info.get("solcVersion") or "")
        compiler_input = build_info.get("input") or {}
        optimizer = ((compiler_input.get("settings") or {}).get("optimizer") or {})
        evidence["compiler"] = {
            "solc_version": compiler_version,
            "solc_long_version": build_info.get("solcLongVersion"),
            "optimizer_enabled": optimizer.get("enabled"),
            "optimizer_runs": optimizer.get("runs"),
            "build_info_sha256": sha256_file(build_info_path),
            "build_info_file": str(build_info_path.relative_to(root)),
            "hardhat_config_solidity_version": "0.6.12",
            "hardhat_config_optimizer_runs": 10,
        }
        require(compiler_version == "0.6.12", f"Unexpected GMX compiler version {compiler_version!r}.")
        require(optimizer.get("enabled") is True and optimizer.get("runs") == 10, "Actual compiler settings differ from GMX hardhat.config.js (optimizer runs 10).")

        pm_artifact = lowkey_cli.read_artifact(artifact_pm_path)
        lib_artifact = lowkey_cli.read_artifact(artifact_lib_path)
        require(isinstance(pm_artifact, dict) and isinstance(lib_artifact, dict), "Could not parse actual Hardhat artifacts.")
        require(pm_artifact.get("sourceName") == "contracts/core/PositionManager.sol", "PositionManager artifact source identity mismatch.")
        require(lib_artifact.get("sourceName") == "contracts/core/PositionUtils.sol", "PositionUtils artifact source identity mismatch.")
        require(pm_artifact.get("contractName") == "PositionManager", "PositionManager artifact contract identity mismatch.")
        require(lib_artifact.get("contractName") == "PositionUtils", "PositionUtils artifact contract identity mismatch.")

        refs = extract_link_references(pm_artifact, "creation")
        identities = {ref.identity.qualified_name for ref in refs}
        observed_offsets = sorted(ref.start for ref in refs)
        observed_lengths = sorted(ref.length for ref in refs)
        evidence["link_references"] = [
            {
                "library": ref.identity.qualified_name,
                "start": ref.start,
                "length": ref.length,
            }
            for ref in refs
        ]
        require(
            identities == {"contracts/core/PositionUtils.sol:PositionUtils"},
            f"PositionManager link references do not uniquely identify actual PositionUtils: {identities!r}.",
        )
        require(len(refs) == 2 and all(ref.length == EXPECTED_LINK_LENGTH for ref in refs), "Expected exactly two 20-byte PositionUtils references.")
        require(
            observed_offsets == EXPECTED_OFFSETS,
            f"Compiler-derived PositionUtils offsets differ from the pinned GMX artifact expectation: {observed_offsets!r}.",
        )

        catalog = lowkey_cli._artifact_catalog(root)
        library_identity = ArtifactIdentity("contracts/core/PositionUtils.sol", "PositionUtils")
        resolved_lib = lowkey_cli.library_linker.resolve_library_artifact(library_identity, catalog)
        library_artifact_path = Path(resolved_lib["_lowkeyArtifactPath"]).resolve()
        require(lowkey_cli._compiler_contract_kind(root, library_artifact_path, resolved_lib) == "library", "Compiler AST did not verify PositionUtils as a Solidity library.")
        constructor_inputs = lowkey_cli.artifact_constructor_inputs(pm_artifact)
        constructor_signature = [item.get("type") for item in constructor_inputs]
        require(
            constructor_signature == ["address", "address", "address", "address", "uint256", "address"],
            f"Unexpected real PositionManager constructor ABI: {constructor_signature!r}.",
        )
        evidence["artifacts"] = {
            "PositionUtils": {
                "source": str(source_lib.relative_to(root)),
                "source_sha256": sha256_file(source_lib),
                "artifact": str(artifact_lib_path.relative_to(root)),
                "artifact_sha256": sha256_file(artifact_lib_path),
                "compiler_kind": "library",
            },
            "PositionManager": {
                "source": str(source_pm.relative_to(root)),
                "source_sha256": sha256_file(source_pm),
                "artifact": str(artifact_pm_path.relative_to(root)),
                "artifact_sha256": sha256_file(artifact_pm_path),
                "constructor_inputs": constructor_inputs,
            },
        }
        evidence["checks"]["actual_compiler_metadata"] = True
        evidence["checks"]["link_offsets_match_pinned_artifact"] = True
        evidence["checks"]["source_qualified_library_identity"] = True

        manager = NetworkManager(root, anvil_binary=anvil)
        session_a = manager.create("gmx-dev", chain_id=31337)
        session_b = manager.create("gmx-attack", chain_id=31337)
        session_a = session_snapshot(manager, "gmx-dev")
        session_b = session_snapshot(manager, "gmx-attack")
        require(
            session_a["id"] != session_b["id"]
            and session_a["pid"] != session_b["pid"]
            and session_a["port"] != session_b["port"]
            and session_a["actors"]["lab-deployer"] != session_b["actors"]["lab-deployer"],
            "Managed Anvil sessions are not independently isolated by session, process, port and account seed.",
        )
        require(
            isinstance(session_a.get("genesis_hash"), str)
            and session_a["genesis_hash"].startswith("0x")
            and len(session_a["genesis_hash"]) == 66
            and isinstance(session_b.get("genesis_hash"), str)
            and session_b["genesis_hash"].startswith("0x")
            and len(session_b["genesis_hash"]) == 66,
            "Each managed Anvil session must record its own valid genesis identity.",
        )
        require(
            rpc(session_a["rpc"], "eth_getBlockByNumber", ["0x0", False]).get("hash", "").lower()
            == session_a["genesis_hash"].lower()
            and rpc(session_b["rpc"], "eth_getBlockByNumber", ["0x0", False]).get("hash", "").lower()
            == session_b["genesis_hash"].lower(),
            "A managed Anvil session's recorded genesis identity does not match its live RPC.",
        )
        evidence["checks"] = {
            "distinct_session_ids": session_a["id"] != session_b["id"],
            "distinct_processes": session_a["pid"] != session_b["pid"],
            "distinct_ports": session_a["port"] != session_b["port"],
            "independent_account_seeds": session_a["actors"]["lab-deployer"] != session_b["actors"]["lab-deployer"],
            "per_session_genesis_identity_verified": True,
        }
        evidence["networks"] = {
            name: {
                "session_id": session["id"],
                "pid": session["pid"],
                "rpc": session["rpc"],
                "chain_id": session["chain_id"],
                "genesis_hash": session["genesis_hash"],
                "identity_block_number": session["identity_block_number"],
                "identity_block_hash": session["identity_block_hash"],
                "deployer": session["actors"]["lab-deployer"],
            }
            for name, session in (("gmx-dev", session_a), ("gmx-attack", session_b))
        }

        # These are deliberately nonfunctional address/code-presence fixtures.
        # PositionManager's constructor only stores these addresses; no protocol
        # action is run, and the result must not be labelled operationally ready.
        manager.use("gmx-dev")
        fixture_values = {}
        for label in ("VaultFixture", "RouterFixture", "ShortsTrackerFixture", "WETHFixture", "OrderBookFixture"):
            row = deploy_fixture(session_a["rpc"], session_a["actors"]["lab-deployer"], label)
            fixture_values[label] = row["address"]
            manager.record_deployment(
                session_a["id"],
                {
                    "role": "test_infrastructure_fixture",
                    "qualified_identity": f"GMXIntegration:{label}",
                    "address": row["address"],
                    "deployment_transaction": row["transaction_hash"],
                    "chain_id": session_a["chain_id"],
                    "genesis_hash": session_a["genesis_hash"],
                    "fixture_kind": row["fixture_kind"],
                    "interface_support": row["interface_support"],
                    "operational_readiness": "NOT_TESTED",
                },
                operation_key=f"gmx-fixture:{label}:{row['transaction_hash']}",
            )
            evidence["fixtures"].append(row)

        constructor_values = [
            fixture_values["VaultFixture"],
            fixture_values["RouterFixture"],
            fixture_values["ShortsTrackerFixture"],
            fixture_values["WETHFixture"],
            "30",
            fixture_values["OrderBookFixture"],
        ]
        config_a = clean_config(session_a["rpc"], session_a["actors"]["lab-deployer"])
        identity_a = lowkey_cli._current_deployment_network_identity(config_a, root, session_a["rpc"])
        require(identity_a.get("reuse_permitted") is True and identity_a.get("network_session_id") == session_a["id"], "Lowkey did not resolve the selected managed network identity.")

        capture: list[dict[str, Any]] = []
        original_collect = lowkey_cli._collect_constructor_deployment_values
        original_library_deploy = lowkey_cli._deploy_artifact_library_dependencies

        def reviewed_constructor_values(*_args: Any, **_kwargs: Any):
            # Values are the five code-bearing local fixture addresses plus 0.3%.
            # Their exact semantics are recorded above; no production address is used.
            return list(constructor_values), None

        def capture_library_deployment(*call_args: Any, **call_kwargs: Any):
            result = original_library_deploy(*call_args, **call_kwargs)
            capture.append({"result": result, "network": call_kwargs.get("network_identity")})
            return result

        lowkey_cli._collect_constructor_deployment_values = reviewed_constructor_values
        lowkey_cli._deploy_artifact_library_dependencies = capture_library_deployment
        try:
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stdout):
                deployment_result = lowkey_cli.run_generic_lab(
                    config_a,
                    root,
                    session_a["rpc"],
                    [session_a["actors"]["lab-deployer"]],
                    "",
                    requested="PositionManager",
                    mode="artifact",
                    target_scope=root / "contracts" / "core",
                    source_file=source_pm,
                    _network_identity=identity_a,
                )
            evidence["deployments"]["PositionManager_lowkey_output"] = stdout.getvalue()[-14000:]
        finally:
            lowkey_cli._collect_constructor_deployment_values = original_collect
            lowkey_cli._deploy_artifact_library_dependencies = original_library_deploy

        require(deployment_result == 0, f"Lowkey's real artifact deployment path returned {deployment_result!r}.")
        require(len(capture) == 1, f"Expected one Lowkey library-link execution during PositionManager deployment; observed {len(capture)}.")
        linked_artifact, library_addresses_a, link_result_a, link_error_a = capture[0]["result"]
        require(link_error_a is None and linked_artifact is not None and link_result_a is not None, f"Lowkey library linking failed: {link_error_a}")
        library_address_a = str(library_addresses_a.get(library_identity.qualified_name) or "").lower()
        require(library_address_a.startswith("0x") and len(library_address_a) == 42, "Lowkey did not return a valid PositionUtils deployment address.")
        linked_evidence = link_result_a.evidence()
        require(len(link_result_a.links) == 2, "Lowkey's actual link result does not contain both compiler references.")
        require(all(item.address.lower() == library_address_a for item in link_result_a.links), "PositionManager references do not all resolve to one verified PositionUtils address.")
        linked_bytecode = link_result_a.linked_bytecode
        linked_body = linked_bytecode[2:] if linked_bytecode.startswith("0x") else linked_bytecode
        for reference in refs:
            start = reference.start * 2
            end = (reference.start + reference.length) * 2
            require(linked_body[start:end].lower() == library_address_a[2:].lower(), f"Linked bytecode at compiler reference {reference.start} does not contain the PositionUtils address.")
        evidence["linked_creation_bytecode"] = linked_bytecode
        evidence["link_result"] = linked_evidence
        evidence["checks"]["all_positionmanager_refs_use_same_library"] = True
        evidence["checks"]["linked_bytecode_bytes_verified"] = True

        records_a = manager.get_deployments(session_a["id"])
        library_record_a = supporting_record(manager, session_a["id"], "solidity_library", library_identity.qualified_name)
        primary_record = supporting_record(manager, session_a["id"], "primary_audit_target", "contracts/core/PositionManager.sol:PositionManager")
        position_manager_address = str(primary_record.get("address") or "").lower()
        require(position_manager_address == str(config_a.get("target") or "").lower(), "PositionManager was not retained as Lowkey's primary target.")
        require(library_record_a.get("runtime_verification") == "MATCHED", f"PositionUtils runtime verification was not MATCHED: {library_record_a.get('runtime_verification')!r}.")
        require(primary_record.get("runtime_verification") == "MATCHED", f"PositionManager runtime verification was not MATCHED: {primary_record.get('runtime_verification')!r}.")
        require(library_record_a.get("deployment_transaction"), "PositionUtils supporting record is missing its deployment transaction.")
        require(primary_record.get("deployment_transaction"), "PositionManager primary record is missing its deployment transaction.")
        code_pm = rpc(session_a["rpc"], "eth_getCode", [position_manager_address, "latest"])
        code_lib_a = rpc(session_a["rpc"], "eth_getCode", [library_address_a, "latest"])
        require(code_pm not in {"0x", "0x0", None} and code_lib_a not in {"0x", "0x0", None}, "Actual GMX runtime code is missing after deployment.")
        require(sum(1 for item in records_a.values() if item.get("role") == "primary_audit_target") == 1, "Supporting deployment changed or duplicated the primary audit target record.")
        evidence["deployments"]["PositionUtils"] = {
            "address": library_address_a,
            "transaction_hash": library_record_a.get("deployment_transaction"),
            "runtime_verification": library_record_a.get("runtime_verification"),
            "runtime_code_hash": library_record_a.get("runtime_code_hash"),
            "artifact_sha256": library_record_a.get("artifact_sha256"),
            "network_session_id": session_a["id"],
            "role": library_record_a.get("role"),
        }
        evidence["deployments"]["PositionManager"] = {
            "address": position_manager_address,
            "transaction_hash": primary_record.get("deployment_transaction"),
            "runtime_verification": primary_record.get("runtime_verification"),
            "runtime_code_hash": primary_record.get("runtime_code_hash"),
            "artifact_sha256": evidence["artifacts"]["PositionManager"]["artifact_sha256"],
            "network_session_id": session_a["id"],
            "role": primary_record.get("role"),
            "runtime_code": code_pm,
        }
        evidence["checks"]["support_library_is_not_primary_target"] = (
            library_record_a.get("role") == "solidity_library"
            and str(config_a.get("target") or "").lower() == position_manager_address
        )
        evidence["checks"]["primary_target_is_positionmanager"] = primary_record.get("qualified_identity") == "contracts/core/PositionManager.sol:PositionManager"

        match_a = lowkey_cli._matching_supporting_deployment(
            config_a, root, session_a["rpc"], library_identity,
            library_artifact_path, resolved_lib, identity_a,
            role="solidity_library", dependencies={},
        )
        require(match_a is not None and str(match_a.get("address", "")).lower() == library_address_a, "PositionUtils could not be reused on its own verified managed session.")
        evidence["checks"]["same_session_library_reuse_is_runtime_verified"] = True

        # A second live session must not see or reuse the first session's library.
        manager.use("gmx-attack")
        identity_b = lowkey_cli._current_deployment_network_identity(
            clean_config(session_b["rpc"], session_b["actors"]["lab-deployer"]),
            root,
            session_b["rpc"],
        )
        require(identity_b.get("network_session_id") == session_b["id"] and identity_b.get("reuse_permitted") is True, "Lowkey did not resolve the second managed session identity.")
        config_b = clean_config(session_b["rpc"], session_b["actors"]["lab-deployer"])
        before_b = lowkey_cli._matching_supporting_deployment(
            config_b, root, session_b["rpc"], library_identity,
            library_artifact_path, resolved_lib, identity_b,
            role="solidity_library", dependencies={},
        )
        require(before_b is None, "A deployment from gmx-dev was incorrectly considered reusable on gmx-attack.")
        linked_b, library_addresses_b, link_result_b, error_b = original_library_deploy(
            config_b, root, session_b["rpc"], [session_b["actors"]["lab-deployer"]],
            pm_artifact, artifact_pm_path, identity_b,
        )
        require(error_b is None and linked_b is not None and link_result_b is not None, f"PositionUtils deployment on the second network failed: {error_b}")
        library_address_b = str(library_addresses_b.get(library_identity.qualified_name) or "").lower()
        require(library_address_b and library_address_b != library_address_a, "PositionUtils was silently reused across two distinct Anvil sessions.")
        record_b = supporting_record(manager, session_b["id"], "solidity_library", library_identity.qualified_name)
        record_b_address = str(record_b.get("address") or "").lower()
        evidence["deployments"]["PositionUtils_second_session"] = {
            "address": library_address_b,
            "recorded_address": record_b.get("address"),
            "transaction_hash": record_b.get("deployment_transaction"),
            "runtime_verification": record_b.get("runtime_verification"),
            "artifact_sha256": record_b.get("artifact_sha256"),
            "network_session_id": session_b["id"],
            "role": record_b.get("role"),
            "link_evidence": link_result_b.evidence(),
        }
        require(
            record_b.get("runtime_verification") == "MATCHED"
            and record_b_address == library_address_b,
            "Second-session PositionUtils runtime or registry verification failed.",
        )
        after_b = lowkey_cli._matching_supporting_deployment(
            config_b, root, session_b["rpc"], library_identity,
            library_artifact_path, resolved_lib, identity_b,
            role="solidity_library", dependencies={},
        )
        require(after_b is not None and str(after_b.get("address", "")).lower() == library_address_b, "PositionUtils did not become reusable after verification on its own second session.")
        evidence["checks"]["cross_session_library_reuse_is_rejected"] = before_b is None and library_address_b != library_address_a
        evidence["checks"]["second_session_library_deployed_and_verified"] = after_b is not None

        manager.use("gmx-dev")
        evidence["checks"]["primary_target_preserved_after_second_session"] = (
            str(config_a.get("target") or "").lower() == position_manager_address
            and sum(1 for item in manager.get_deployments(session_a["id"]).values() if item.get("role") == "primary_audit_target") == 1
        )
        evidence["operational_readiness"] = {
            "PositionUtils": "DEPLOYED_AND_CODE_VERIFIED",
            "PositionManager": "DEPLOYED_AND_CODE_VERIFIED",
            "constructor_fixture_interfaces": "NOT_IMPLEMENTED",
            "initialization": "NOT_APPLICABLE_TO_THIS_CONSTRUCTOR_DEPLOYMENT",
            "roles_and_external_protocol_configuration": "NOT_EXECUTED",
            "protocol_invariants": "NOT_TESTED",
            "operational_readiness": "UNVERIFIED",
        }
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        if manager is not None:
            cleaned = []
            try:
                for row in reversed(manager.list()):
                    if row.get("name") in {"gmx-dev", "gmx-attack"}:
                        try:
                            result = manager.stop_session(str(row["id"]))
                            cleaned.append({"name": row.get("name"), "id": row.get("id"), "status": result.get("status")})
                        except Exception as stop_error:
                            cleaned.append({"name": row.get("name"), "id": row.get("id"), "error": str(stop_error)})
                evidence["cleanup"]["sessions"] = cleaned
                evidence["cleanup"]["remaining_owned"] = [
                    {"name": row.get("name"), "id": row.get("id"), "pid": row.get("pid")}
                    for row in manager.list()
                    if row.get("name") in {"gmx-dev", "gmx-attack"} and row.get("process_owned")
                ]
            except Exception as cleanup_error:
                evidence["cleanup"]["error"] = str(cleanup_error)

    if failure is None and (
        evidence["cleanup"].get("remaining_owned")
        or evidence["cleanup"].get("error")
        or any("error" in row for row in evidence["cleanup"].get("sessions", []))
    ):
        failure = "Managed Anvil cleanup was incomplete; inspect the cleanup evidence."
    evidence["status"] = "PASS" if failure is None else "FAILED"
    evidence["error"] = failure
    output_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(output_path),
        "source_revision": evidence["source"].get("revision"),
        "compiler": evidence["compiler"],
        "link_references": evidence["link_references"],
        "deployments": evidence["deployments"],
        "checks": evidence["checks"],
        "cleanup": evidence["cleanup"],
        "error": failure,
    }, indent=2, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
