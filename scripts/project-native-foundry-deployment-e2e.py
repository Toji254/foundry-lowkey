#!/usr/bin/env python3
"""Live acceptance for a reviewed project-native Foundry broadcast on managed Anvil."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Compile at import time so malformed target parsing is caught before the
# acceptance creates Anvil or starts a deployment broadcast.
TARGET_LINE_RE = re.compile(
    r"(?im)^\s*Target\s*:\s*NativeTarget\s*(?:->|@)\s*"
    r"(?:NativeTarget\s*)?\(?\s*(0x[0-9a-fA-F]{40})\s*\)?\s*$"
)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lowkey.network_manager import NetworkManager  # noqa: E402


def run(argv: list[str], cwd: Path, env: dict[str, str], timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv, cwd=cwd, env=env, text=True, capture_output=True,
        stdin=subprocess.DEVNULL, timeout=timeout, check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-12000:]}\n"
            f"--- stderr ---\n{result.stderr[-12000:]}"
        )
    return result


def main() -> int:
    anvil = shutil.which("anvil")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    forge_std = Path("/tmp/lowkey-fixture/lib/forge-std")
    if not anvil:
        raise AssertionError("anvil is unavailable on PATH")
    if not Path(lk).is_file() and not shutil.which(lk):
        raise AssertionError("installed Lowkey executable is unavailable")
    if not forge_std.is_dir():
        raise AssertionError(f"CI forge-std dependency is unavailable: {forge_std}")

    evidence: dict[str, object] = {
        "schema": "lowkey.native-foundry-deployment.v1",
        "status": "RUNNING",
        "project_script": "script/Deploy.s.sol",
        "network": {},
        "deployment": {},
        "review": {},
        "cleanup": {},
    }
    manager: NetworkManager | None = None
    session_id: str | None = None
    temporary_context: tempfile.TemporaryDirectory[str] | None = None
    failure: str | None = None

    try:
        temporary_context = tempfile.TemporaryDirectory(prefix="lowkey-native-foundry-")
        temporary = temporary_context.name
        root = Path(temporary).resolve()
        for directory in ("src", "script", "lib"):
            (root / directory).mkdir(parents=True, exist_ok=True)
        (root / "lib" / "forge-std").symlink_to(forge_std, target_is_directory=True)

        (root / "foundry.toml").write_text(
            '[profile.default]\n'
            'src = "src"\n'
            'out = "out"\n'
            'script = "script"\n'
            'libs = ["lib"]\n'
            'remappings = ["forge-std/=lib/forge-std/src/"]\n'
            'solc_version = "0.8.20"\n',
            encoding="utf-8",
        )
        (root / "src" / "NativeTarget.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "contract NativeTarget {\n"
            "    address public immutable owner;\n"
            "    uint256 public value;\n"
            "    constructor() { owner = msg.sender; value = 7; }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "script" / "Deploy.s.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            'import {Script} from "forge-std/Script.sol";\n'
            'import {console2} from "forge-std/console2.sol";\n'
            'import {NativeTarget} from "../src/NativeTarget.sol";\n'
            "contract Deploy is Script {\n"
            "    function run() external {\n"
            "        vm.startBroadcast();\n"
            "        NativeTarget target = new NativeTarget();\n"
            "        vm.stopBroadcast();\n"
            '        console2.log("LOWKEY_TARGET", address(target));\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env["LOWKEY_NONINTERACTIVE_DEPLOY"] = "1"
        manager = NetworkManager(root, anvil_binary=anvil)

        run([lk, "lab", "network", "create", "--name", "native-deploy"], root, env)
        run([lk, "lab", "network", "use", "native-deploy"], root, env)
        session = manager.status("native-deploy")
        if isinstance(session, dict) and session.get("id"):
            session_id = str(session["id"])
        if not session or not session.get("process_owned") or not session.get("rpc_healthy"):
            raise AssertionError("Lowkey did not establish an owned, healthy managed Anvil session.")
        evidence["network"] = {
            "id": session.get("id"),
            "rpc": session.get("rpc"),
            "chain_id": session.get("chain_id"),
            "genesis_hash": session.get("genesis_hash"),
        }

        lab = run([lk, "lab"], root, env, timeout=300)
        target_match = TARGET_LINE_RE.search(lab.stdout)
        if not target_match:
            raise AssertionError(
                "Lowkey did not preserve the project-native LOWKEY_TARGET marker as its primary target.\n"
                + lab.stdout[-12000:]
            )
        target = target_match.group(1).lower()
        if "Mode    : project-native deployment script" not in lab.stdout:
            raise AssertionError("Lowkey did not select the native Foundry script path.")
        if "Deployment verified: LIVE" not in lab.stdout:
            raise AssertionError("Lowkey did not verify the native script target runtime.")

        code = run(
            ["cast", "code", target, "--rpc-url", str(session["rpc"])],
            root, env,
        ).stdout.strip()
        if code in {"", "0x", "0X"}:
            raise AssertionError("Native Foundry target has no runtime code on its selected managed network.")
        owner = run(
            ["cast", "call", target, "owner()(address)", "--rpc-url", str(session["rpc"])],
            root, env,
        ).stdout.strip().lower()
        expected_owner = str(session["actors"]["lab-deployer"]).lower()
        if owner != expected_owner:
            raise AssertionError(f"Native target owner mismatch: expected {expected_owner}, got {owner}")

        records = manager.get_deployments(str(session["id"]))
        matches = [
            item for item in records.values()
            if str(item.get("address") or "").lower() == target
            and item.get("role") == "primary_audit_target"
        ]
        if len(matches) != 1:
            raise AssertionError(
                "The native script target was not recorded exactly once in its owning network session: "
                + json.dumps(list(records.values()), indent=2)
            )
        record = matches[0]
        tx_hash = record.get("deployment_transaction")
        if not isinstance(tx_hash, str) or not re.fullmatch(r"0x[0-9a-fA-F]{64}", tx_hash):
            raise AssertionError("The primary deployment registry record is missing its broadcast transaction hash.")
        if not record.get("reuse_permitted"):
            raise AssertionError("A verified managed native deployment was not marked reusable within its own session.")
        if (record.get("network") or {}).get("network_session_id") != session["id"]:
            raise AssertionError("Native deployment was registered under a different network session.")

        review_files = list((root / ".audit").rglob("*.json"))
        review_payloads = []
        for path in review_files:
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if payload.get("schema") == "lowkey.foundry-script-review.v1":
                review_payloads.append(payload)
        if len(review_payloads) != 1 or review_payloads[0].get("approval_state") != "FORGE_SUCCEEDED":
            raise AssertionError(
                "The deployment review did not retain a successful post-broadcast evidence state: "
                + json.dumps(review_payloads, indent=2)
            )

        evidence["deployment"] = {
            "target": target,
            "runtime_bytes": (len(code) - 2) // 2,
            "owner": owner,
            "transaction_hash": tx_hash,
            "registry_role": record.get("role"),
            "network_session_id": (record.get("network") or {}).get("network_session_id"),
            "reuse_permitted": record.get("reuse_permitted"),
        }
        evidence["review"] = {
            "schema": review_payloads[0].get("schema"),
            "approval_state": review_payloads[0].get("approval_state"),
            "review_id": review_payloads[0].get("review_id"),
        }
        print("PASS: reviewed native Foundry script broadcast, target validation, runtime/owner checks,")
        print("      transaction provenance and managed-session primary-target registration.")
    except Exception as exc:
        failure = f"{type(exc).__name__}: {exc}"
    finally:
        cleanup = []
        if manager is not None:
            try:
                owned = [
                    row for row in manager.list()
                    if row.get("name") == "native-deploy" and row.get("process_owned")
                ]
                selected = next(
                    (row for row in owned if session_id and str(row.get("id")) == session_id),
                    owned[0] if owned else None,
                )
                if selected is not None:
                    selected_id = str(selected["id"])
                    if session_id is not None and selected_id != session_id:
                        raise AssertionError("Refusing to stop a different native deployment session.")
                    session_id = selected_id
                    stopped = manager.stop_session(selected_id)
                    cleanup.append({
                        "id": selected_id,
                        "status": stopped.get("status"),
                        "process_owned_before_stop": True,
                    })
                evidence["cleanup"] = {
                    "session_id": session_id,
                    "stop_attempted": bool(cleanup),
                    "sessions": cleanup,
                    "remaining_owned": [
                        {"id": row.get("id"), "pid": row.get("pid")}
                        for row in manager.list()
                        if row.get("name") == "native-deploy" and row.get("process_owned")
                    ],
                }
            except Exception as cleanup_error:
                evidence["cleanup"] = {"error": str(cleanup_error), "sessions": cleanup}
        try:
            if temporary_context is not None:
                temporary_context.cleanup()
                evidence.setdefault("cleanup", {})["workspace_removed"] = True
        except Exception as temp_cleanup_error:
            evidence.setdefault("cleanup", {})["workspace_cleanup_error"] = str(temp_cleanup_error)

    cleanup = evidence.get("cleanup") or {}
    if failure is None and (
        cleanup.get("error")
        or cleanup.get("remaining_owned")
        or not cleanup.get("stop_attempted")
        or not cleanup.get("workspace_removed")
        or any("error" in item for item in cleanup.get("sessions", []))
    ):
        failure = "The native deployment acceptance did not clean up its owned Anvil process."

    evidence["status"] = "PASS" if failure is None else "FAILED"
    evidence["error"] = failure
    evidence_path = ROOT / ".audit" / "native-foundry-deployment-acceptance" / "latest.json"
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": evidence["status"],
        "evidence": str(evidence_path),
        "network": evidence.get("network"),
        "deployment": evidence.get("deployment"),
        "review": evidence.get("review"),
        "cleanup": evidence.get("cleanup"),
        "error": failure,
    }, indent=2, sort_keys=True))
    return 0 if failure is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
