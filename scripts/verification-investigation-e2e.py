#!/usr/bin/env python3
"""Live end-to-end regression for Lowkey's targeted finding investigation.

The fixture deliberately has a broken onlyOwner modifier. A correct targeted test
must fail because an arbitrary caller can change state; Lowkey must classify that
as a review lead and attach the exact Forge evidence to the original signal.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(argv: list[str], cwd: Path, *, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AssertionError(f"Could not complete command {argv!r}: {exc}") from exc
    if result.returncode != 0:
        raise AssertionError(
            f"Command failed ({result.returncode}): {argv!r}\n"
            f"--- stdout ---\n{result.stdout[-8000:]}\n"
            f"--- stderr ---\n{result.stderr[-8000:]}"
        )
    return result


def main() -> int:
    forge = shutil.which("forge")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge:
        raise AssertionError("forge is unavailable on PATH")
    if not Path(lk).is_file() and not shutil.which(lk):
        raise AssertionError("installed lk executable is unavailable")

    runtime_root = Path.home() / ".lowkey"
    if not (runtime_root / "audit_context.py").is_file():
        raise AssertionError(f"installed Lowkey runtime is missing: {runtime_root}")
    sys.path.insert(0, str(runtime_root))
    import audit_context  # noqa: E402 - import the exact runtime installed by CI

    with tempfile.TemporaryDirectory(prefix="lowkey-investigation-e2e-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        (root / "foundry.toml").write_text(
            '[profile.default]\n'
            'src = "src"\n'
            'test = "test"\n'
            'out = "out"\n'
            'libs = ["lib"]\n'
            'solc_version = "0.8.20"\n',
            encoding="utf-8",
        )
        (root / "src" / "Vault.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n\n"
            "contract Vault {\n"
            "    address public owner;\n"
            "    uint256 public balance;\n"
            "    constructor() { owner = msg.sender; }\n"
            "    // Deliberate bug: this modifier has no authorization check.\n"
            "    modifier onlyOwner() { _; }\n"
            "    function setBalance(uint256 nextValue) external onlyOwner {\n"
            "        balance = nextValue;\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )

        # Foundry installs dependencies into a Git-managed project, even with
        # --no-commit; this fixture owns the repository and has no external state.
        run(["git", "init", "-q"], root)
        run(["git", "config", "user.email", "lowkey-ci@example.invalid"], root)
        run(["git", "config", "user.name", "Lowkey CI"], root)
        run(["forge", "install", "foundry-rs/forge-std", "--no-commit"], root)
        run([forge, "build"], root)

        signal = audit_context.add_signal(
            {
                "tool": "slither",
                "category": "static-analysis",
                "check": "access-control",
                "title": "Access-control modifier does not enforce ownership",
                "description": "The onlyOwner modifier executes without checking msg.sender.",
                "impact": "High",
                "confidence": "High",
                "file": "src/Vault.sol",
                "line": 9,
                "function": "setBalance(uint256)",
            },
            root,
        )
        signal_id = str(signal["id"])
        completed = subprocess.run(
            [lk, "verification", "investigate", signal_id],
            cwd=root,
            text=True,
            capture_output=True,
            timeout=360,
            check=False,
        )
        # Exit 1 is expected here: the generated negative authorization test
        # should discover the deliberately broken modifier.
        if completed.returncode != 1:
            raise AssertionError(
                "Expected Lowkey to report an identified target-test failure (exit 1); "
                f"got {completed.returncode}.\n"
                f"--- stdout ---\n{completed.stdout[-10000:]}\n"
                f"--- stderr ---\n{completed.stderr[-10000:]}"
            )
        if "test-failed-needs-review" not in completed.stdout:
            raise AssertionError(f"CLI did not report the expected review status:\n{completed.stdout}")
        if "Evidence       : attached" not in completed.stdout:
            raise AssertionError(f"CLI did not confirm evidence attachment:\n{completed.stdout}")

        reports = list((root / ".audit" / "investigations").glob("*/investigation.json"))
        if len(reports) != 1:
            raise AssertionError(f"Expected exactly one investigation report; found {len(reports)}")
        report_path = reports[0]
        report = json.loads(report_path.read_text(encoding="utf-8"))
        expected = {
            "status": "test-failed-needs-review",
            "target_test_status": "failed-needs-review",
            "evidence_attached": True,
            "signal_id": signal_id,
        }
        for field, value in expected.items():
            if report.get(field) != value:
                raise AssertionError(f"Unexpected report field {field}: {report.get(field)!r}; expected {value!r}")
        if report.get("validation", {}).get("status") != "failed":
            raise AssertionError(f"Forge validation did not record the target test failure: {report.get('validation')!r}")
        test_relative = report.get("targeted_test")
        if not test_relative:
            raise AssertionError("No targeted test path was recorded")
        test_file = (root / test_relative).resolve()
        if not test_file.is_relative_to(root) or not test_file.is_file():
            raise AssertionError(f"Generated target test is missing or outside the fixture: {test_relative!r}")
        test_bytes = test_file.read_bytes()
        if hashlib.sha256(test_bytes).hexdigest() != report.get("targeted_test_sha256"):
            raise AssertionError("Generated test digest does not match the saved report")
        if "function test_nonOwnerCannotCall_setBalance" not in test_bytes.decode("utf-8"):
            raise AssertionError("Generated test is not the exact targeted non-owner test")

        native = report.get("native_evidence") or {}
        execution = native.get("execution")
        if not isinstance(execution, dict) or execution.get("exit_code") == 0:
            raise AssertionError(f"No real failed Forge execution was retained: {execution!r}")
        output = "\n".join(str(execution.get(key) or "") for key in ("stdout_tail", "stderr_tail"))
        if report.get("target_test_name") not in output or "did not revert" not in output.lower():
            raise AssertionError(f"Forge evidence does not show the expected authorization failure:\n{output}")

        stored_signal = next(
            (item for item in audit_context.signals(root) if item.get("id") == signal_id), None
        )
        if not stored_signal:
            raise AssertionError("Original audit signal disappeared from the project context")
        evidence = [
            item for item in stored_signal.get("evidence", [])
            if isinstance(item, dict)
            and item.get("kind") == "targeted-test-investigation"
            and item.get("id") == report.get("evidence_id")
        ]
        if len(evidence) != 1:
            raise AssertionError(f"Expected exactly one attached evidence record; found {len(evidence)}")
        record = evidence[0]
        if record.get("status") != "test-failed-needs-review":
            raise AssertionError(f"Unexpected attached evidence status: {record.get('status')!r}")
        if record.get("security_finding_confirmed") is not False:
            raise AssertionError("Evidence must not automatically confirm a security finding")
        if record.get("targeted_test_sha256") != hashlib.sha256(test_bytes).hexdigest():
            raise AssertionError("Attached evidence points to a different generated test")

        print("PASS: installed lk used the real generator and Forge on a deliberate authorization defect")
        print(f"Signal: {signal_id}")
        print(f"Generated test: {test_relative}")
        print(f"Forge result: {report['status']} (expected review lead)")
        print(f"Evidence: {record['id']} attached to the original signal; finding remains unconfirmed")

        # Additional supported pattern: an outsider must not satisfy onlyRole.
        role_source = root / "src" / "RoleVault.sol"
        role_source.write_text(
            """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RoleVault {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) private roleMembers;
    uint256 public limit;

    constructor() { roleMembers[OPERATOR_ROLE][msg.sender] = true; }

    modifier onlyRole(bytes32 role) {
        require(roleMembers[role][msg.sender], "missing role");
        _;
    }

    function setLimit(uint256 nextValue) external onlyRole(OPERATOR_ROLE) {
        limit = nextValue;
    }
}
""",
            encoding="utf-8",
        )
        run([forge, "build"], root)
        role_signal = audit_context.add_signal(
            {
                "tool": "slither",
                "category": "static-analysis",
                "check": "access-control",
                "title": "Role authorization boundary review",
                "description": "A caller without OPERATOR_ROLE must not change the configured limit.",
                "impact": "Medium",
                "confidence": "Medium",
                "file": "src/RoleVault.sol",
                "line": 12,
                "function": "setLimit(uint256)",
            },
            root,
        )
        role_run = subprocess.run(
            [lk, "verification", "investigate", str(role_signal["id"])],
            cwd=root, text=True, capture_output=True, timeout=360, check=False,
        )
        if role_run.returncode != 0:
            raise AssertionError(
                "Expected the real onlyRole investigation test to pass (exit 0); "
                f"got {role_run.returncode}.\nstdout:\n{role_run.stdout[-10000:]}\nstderr:\n{role_run.stderr[-10000:]}"
            )
        if "Status         : passed" not in role_run.stdout or "Evidence       : attached" not in role_run.stdout:
            raise AssertionError(f"onlyRole result/evidence missing from CLI output:\n{role_run.stdout}")
        role_reports = []
        for path in (root / ".audit" / "investigations").glob("*/investigation.json"):
            candidate_report = json.loads(path.read_text(encoding="utf-8"))
            if candidate_report.get("signal_id") == role_signal["id"]:
                role_reports.append((path, candidate_report))
        if len(role_reports) != 1:
            raise AssertionError(f"Expected one onlyRole report; found {len(role_reports)}")
        _, role_report = role_reports[0]
        if role_report.get("status") != "passed" or role_report.get("target_test_name") != "test_nonRoleHolderCannotCall_setLimit":
            raise AssertionError(f"onlyRole property was not targeted: {role_report}")
        role_test_path = (root / str(role_report.get("targeted_test"))).resolve()
        if not role_test_path.is_relative_to(root) or not role_test_path.is_file():
            raise AssertionError(f"onlyRole generated test is missing/outside the project: {role_test_path}")
        if hashlib.sha256(role_test_path.read_bytes()).hexdigest() != role_report.get("targeted_test_sha256"):
            raise AssertionError("onlyRole test digest does not match its report")
        role_native = role_report.get("native_evidence") or {}
        role_execution = role_native.get("execution")
        if not isinstance(role_execution, dict) or role_execution.get("exit_code") != 0:
            raise AssertionError(f"onlyRole test lacks real passing Forge evidence: {role_execution!r}")
        role_output = "\n".join(str(role_execution.get(key) or "") for key in ("stdout_tail", "stderr_tail"))
        if "test_nonRoleHolderCannotCall_setLimit" not in role_output or "[PASS]" not in role_output:
            raise AssertionError(f"onlyRole execution output does not show its exact passing test:\n{role_output}")
        stored_role_signal = next(
            (item for item in audit_context.signals(root) if item.get("id") == role_signal["id"]), None
        )
        role_evidence = [
            item for item in (stored_role_signal or {}).get("evidence", [])
            if isinstance(item, dict) and item.get("kind") == "targeted-test-investigation"
        ]
        if len(role_evidence) != 1 or role_evidence[0].get("security_finding_confirmed") is not False:
            raise AssertionError("onlyRole result was not attached once as unconfirmed evidence")
        print("PASS: onlyRole targeted investigation generated and executed a real passing outsider-revert test")
        print(f"Role signal: {role_signal['id']}")
        print(f"Generated test: {role_report['targeted_test']}")

        # Third supported property family: reentrancy in ETH withdrawal where
        # a mapping credit is reset after an external value transfer.
        reentrancy_source = root / "src" / "ReentrantVault.sol"
        reentrancy_source.write_text(
            """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ReentrantVault {
    mapping(address => uint256) public credits;

    function deposit() external payable {
        credits[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "no credit");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        credits[msg.sender] = 0;
    }
}
""",
            encoding="utf-8",
        )
        run([forge, "build"], root)
        reentrancy_signal = audit_context.add_signal(
            {
                "tool": "slither",
                "category": "static-analysis",
                "check": "reentrancy-eth",
                "title": "Potential ETH reentrancy in withdraw",
                "description": "ETH is transferred before credits[msg.sender] is cleared.",
                "impact": "High",
                "confidence": "High",
                "file": "src/ReentrantVault.sol",
                "line": 12,
                "function": "withdraw()",
            },
            root,
        )
        reentrancy_run = subprocess.run(
            [lk, "verification", "investigate", str(reentrancy_signal["id"])],
            cwd=root, text=True, capture_output=True, timeout=360, check=False,
        )
        if reentrancy_run.returncode != 1:
            raise AssertionError(
                "Expected the ETH reentrancy probe to identify a failing assertion (exit 1); "
                f"got {reentrancy_run.returncode}.\nstdout:\n{reentrancy_run.stdout[-12000:]}\nstderr:\n{reentrancy_run.stderr[-12000:]}"
            )
        if "Status         : test-failed-needs-review" not in reentrancy_run.stdout or "Evidence       : attached" not in reentrancy_run.stdout:
            raise AssertionError(f"Reentrancy outcome/evidence missing:\n{reentrancy_run.stdout}")
        reentrancy_reports = []
        for path in (root / ".audit" / "investigations").glob("*/investigation.json"):
            candidate_report = json.loads(path.read_text(encoding="utf-8"))
            if candidate_report.get("signal_id") == reentrancy_signal["id"]:
                reentrancy_reports.append((path, candidate_report))
        if len(reentrancy_reports) != 1:
            raise AssertionError(f"Expected one reentrancy report; found {len(reentrancy_reports)}")
        _, reentrancy_report = reentrancy_reports[0]
        if reentrancy_report.get("investigation_kind") != "reentrancy-eth":
            raise AssertionError(f"Wrong investigation kind: {reentrancy_report.get('investigation_kind')!r}")
        if reentrancy_report.get("status") != "test-failed-needs-review":
            raise AssertionError(f"Reentrancy did not become a review lead: {reentrancy_report}")
        if reentrancy_report.get("target_test_name") != "test_reentrancyCannotPayMoreThanCredited":
            raise AssertionError(f"Wrong reentrancy property: {reentrancy_report.get('target_test_name')!r}")
        reentrancy_test_path = (root / str(reentrancy_report.get("targeted_test"))).resolve()
        if not reentrancy_test_path.is_relative_to(root) or not reentrancy_test_path.is_file():
            raise AssertionError(f"Reentrancy test is missing/outside the fixture: {reentrancy_test_path}")
        if hashlib.sha256(reentrancy_test_path.read_bytes()).hexdigest() != reentrancy_report.get("targeted_test_sha256"):
            raise AssertionError("Reentrancy test digest does not match report")
        reentrancy_native = reentrancy_report.get("native_evidence") or {}
        reentrancy_execution = reentrancy_native.get("execution")
        if not isinstance(reentrancy_execution, dict) or reentrancy_execution.get("exit_code") == 0:
            raise AssertionError(f"Expected a real failed Forge reentrancy assertion: {reentrancy_execution!r}")
        reentrancy_output = "\n".join(str(reentrancy_execution.get(key) or "") for key in ("stdout_tail", "stderr_tail"))
        if "test_reentrancyCannotPayMoreThanCredited" not in reentrancy_output or "credit paid more than once" not in reentrancy_output:
            raise AssertionError(f"Reentrancy failure evidence does not show the exact overpayment assertion:\n{reentrancy_output}")
        stored_reentrancy = next(
            (item for item in audit_context.signals(root) if item.get("id") == reentrancy_signal["id"]), None
        )
        reentrancy_evidence = [
            item for item in (stored_reentrancy or {}).get("evidence", [])
            if isinstance(item, dict) and item.get("kind") == "targeted-test-investigation"
        ]
        if len(reentrancy_evidence) != 1 or reentrancy_evidence[0].get("security_finding_confirmed") is not False:
            raise AssertionError("Reentrancy result not attached once as unconfirmed evidence")
        print("PASS: real ETH reentrancy probe reproduced overpayment and attached a review lead")
        print(f"Reentrancy signal: {reentrancy_signal['id']}")
        print(f"Generated test: {reentrancy_report['targeted_test']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
