#!/usr/bin/env python3
"""Live E2E regression: real Forge campaign result -> existing finding evidence."""
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
    import audit_context  # noqa: E402

    with tempfile.TemporaryDirectory(prefix="lowkey-correlation-e2e-") as temp:
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
            "pragma solidity ^0.8.20;\n"
            "contract Vault {\n"
            "    bool public withdrawn;\n"
            "    modifier onlyOwner() { _; } // Deliberately broken.\n"
            "    function withdraw() external onlyOwner { withdrawn = true; }\n"
            "}\n",
            encoding="utf-8",
        )
        (root / "test" / "Vault.t.sol").write_text(
            "// SPDX-License-Identifier: MIT\n"
            "pragma solidity ^0.8.20;\n"
            "import {Test} from \"forge-std/Test.sol\";\n"
            "import {Vault} from \"../src/Vault.sol\";\n"
            "contract VaultTest is Test {\n"
            "    Vault internal target;\n"
            "    function setUp() public { target = new Vault(); }\n"
            "    function testUnauthorizedWithdrawFails() public {\n"
            "        vm.prank(address(0xBEEF));\n"
            "        vm.expectRevert();\n"
            "        target.withdraw();\n"
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
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
                "title": "Unauthorized withdraw call does not revert",
                "description": "A caller outside the owner role can reach withdraw().",
                "impact": "High",
                "confidence": "High",
                "file": "src/Vault.sol",
                "line": 6,
                "function": "withdraw()",
            },
            root,
        )
        manifest_path = root / "campaign.json"
        manifest = {
            "test_kind": "unit",
            "profile": "light",
            "project": ".",
            "budget": {"timeout_seconds": 60},
            "request": {
                "argv_by_engine": {
                    "forge": ["test", "--match-test", "testUnauthorizedWithdrawFails", "-vv"]
                }
            },
            "investigation": {
                "signal_id": signal["id"],
                "property_id": "unauthorized-withdraw-reverts",
                "source_file": "src/Vault.sol",
                "function": "withdraw()",
                "description": "Unauthorized callers must not withdraw.",
            },
        }
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        campaign_path = root / ".audit" / "verification" / "campaign.json"
        campaign_path.parent.mkdir(parents=True, exist_ok=True)
        campaign = subprocess.run(
            [lk, "verification", "run", str(manifest_path), "--profile", "light", "--output", str(campaign_path)],
            cwd=root, text=True, capture_output=True, timeout=360, check=False,
        )
        # Expected regression: completed campaign, with one failing Forge test.
        if campaign.returncode != 1:
            raise AssertionError(
                f"Expected one failing Forge test (exit 1), got {campaign.returncode}.\n"
                f"stdout:\n{campaign.stdout[-10000:]}\nstderr:\n{campaign.stderr[-10000:]}"
            )
        if not campaign_path.is_file():
            raise AssertionError("Lowkey did not save the native campaign report")
        native_report = json.loads(campaign_path.read_text(encoding="utf-8"))
        if native_report.get("project", {}).get("root") != str(root):
            raise AssertionError(f"Campaign report lost project provenance: {native_report.get('project')}")
        forge_results = [
            row["result"] for row in native_report.get("results", [])
            if isinstance(row, dict) and isinstance(row.get("result"), dict)
            and row["result"].get("engine") == "forge"
        ]
        if len(forge_results) != 1 or forge_results[0].get("status") != "failed":
            raise AssertionError(f"Campaign did not preserve a failed Forge result: {forge_results}")
        native = forge_results[0]
        native_output = str(native.get("raw_stdout") or "") + "\n" + str(native.get("raw_stderr") or "")
        if "testUnauthorizedWithdrawFails" not in native_output or "[FAIL" not in native_output:
            raise AssertionError(f"Native report lacks the actual failing test output:\n{native_output}")

        correlation_path = root / ".audit" / "verification" / "correlation.json"
        correlated = subprocess.run(
            [lk, "verification", "correlate", str(campaign_path),
             "--signal", str(signal["id"]), "--output", str(correlation_path)],
            cwd=root, text=True, capture_output=True, timeout=120, check=False,
        )
        if correlated.returncode != 0:
            raise AssertionError(
                f"Correlation command failed ({correlated.returncode}).\n"
                f"stdout:\n{correlated.stdout[-10000:]}\nstderr:\n{correlated.stderr[-10000:]}"
            )
        if "Evidence attached : 1" not in correlated.stdout:
            raise AssertionError(f"CLI did not attach campaign evidence:\n{correlated.stdout}")
        report = json.loads(correlation_path.read_text(encoding="utf-8"))
        if report.get("coverage_status") != "engine_results_available":
            raise AssertionError(f"Correlation misreported campaign coverage: {report.get('coverage_status')}")
        if report.get("campaign_report_sha256") != hashlib.sha256(campaign_path.read_bytes()).hexdigest():
            raise AssertionError("Correlation did not preserve the source campaign report hash")
        if report.get("target_signal_ids") != [signal["id"]] or report.get("attached_signal_ids") != [signal["id"]]:
            raise AssertionError(f"Correlation attached the wrong signal: {report}")
        if report.get("summary", {}).get("reported_test_or_property_failures") != 1:
            raise AssertionError(f"Correlation did not classify the failure as a review lead: {report.get('summary')}")
        if report.get("summary", {}).get("security_finding_confirmed") is not False:
            raise AssertionError("Correlation must not automatically confirm a security finding")
        engine_results = report.get("engine_results", [])
        if len(engine_results) != 1 or engine_results[0].get("engine") != "forge":
            raise AssertionError(f"Expected exactly one correlated Forge result: {engine_results}")
        if engine_results[0].get("status") != "failed" or engine_results[0].get("interpretation") != "test_failure_requires_triage":
            raise AssertionError(f"Forge failure was not retained conservatively: {engine_results[0]}")
        stored_signal = next(
            (item for item in audit_context.signals(root) if item.get("id") == signal["id"]), None
        )
        if not stored_signal:
            raise AssertionError("Original finding disappeared from audit context")
        evidence = [
            item for item in stored_signal.get("evidence", [])
            if isinstance(item, dict) and item.get("kind") == "verification-correlation"
        ]
        if len(evidence) != 1:
            raise AssertionError(f"Expected one correlation evidence record; found {len(evidence)}")
        record = evidence[0]
        if record.get("campaign_report_sha256") != report["campaign_report_sha256"]:
            raise AssertionError("Attached evidence references a different campaign report")
        if record.get("security_finding_confirmed") is not False:
            raise AssertionError("Attached evidence automatically confirmed the finding")
        if not record.get("engine_results") or record["engine_results"][0].get("status") != "failed":
            raise AssertionError(f"Attached evidence lost the engine outcome: {record}")

        print("PASS: a real failing Forge campaign was correlated to its original audit signal")
        print(f"Signal: {signal['id']}")
        print(f"Campaign: {campaign_path.relative_to(root)}")
        print(f"Correlation: {correlation_path.relative_to(root)}")
        print(f"Engine outcome: {engine_results[0]['status']} (review lead, not automatic confirmation)")
        print(f"Evidence: {record['id']} attached once with campaign hash and engine results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
