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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
