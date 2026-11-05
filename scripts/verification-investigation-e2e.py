#!/usr/bin/env python3
"""Plan-first, explicitly inspected Foundry test integration acceptance."""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(argv: list[str], cwd: Path, timeout: int = 300) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(argv, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise AssertionError(f"Command failed: {argv!r}; stdout={result.stdout[-5000:]}; stderr={result.stderr[-5000:]}")
    return result


def write(root: Path, path: str, body: str) -> Path:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    return target


def add_signal(audit_context, root: Path, file: str, function: str, title: str, check: str = "access-control") -> str:
    signal = audit_context.add_signal({
        "tool": "slither", "category": "static-analysis", "check": check,
        "title": title, "description": title, "impact": "High",
        "confidence": "High", "file": file, "line": 1, "function": function,
    }, root)
    return str(signal["id"])


def plan(lk: str, root: Path, signal_id: str) -> str:
    result = subprocess.run([lk, "verification", "investigate", signal_id],
        cwd=root, text=True, capture_output=True, timeout=120, check=False)
    if result.returncode != 0 or "plan-only" not in result.stdout or "read-only" not in result.stdout.lower():
        raise AssertionError(f"Expected read-only source plan; rc={result.returncode}; out={result.stdout}; err={result.stderr}")
    if "run-test" not in result.stdout:
        raise AssertionError(f"Plan did not show explicit test execution path: {result.stdout}")
    if (root / ".audit" / "investigations").exists():
        raise AssertionError("Read-only plan wrote an investigation report")
    return result.stdout


def inspected_test(lk: str, root: Path, audit_context, signal_id: str,
                   test_path: str, test_name: str, expected_exit: int) -> tuple[str, dict]:
    result = subprocess.run([lk, "verification", "run-test", signal_id, test_path, test_name],
        cwd=root, text=True, capture_output=True, timeout=360, check=False)
    if result.returncode != expected_exit:
        raise AssertionError(f"Expected test rc={expected_exit}, got {result.returncode}; stdout={result.stdout[-10000:]}; stderr={result.stderr[-10000:]}")
    status = "passed" if expected_exit == 0 else "failed"
    missing = [
        label for label, present in (
            ("status", status in result.stdout),
            ("evidence attachment", "attached" in result.stdout),
            ("unchanged disposition", "Disposition: unchanged" in result.stdout),
        ) if not present
    ]
    if missing:
        raise AssertionError(
            f"CLI result/evidence/disposition missing {missing}; rc={result.returncode}\\n"
            f"stdout:\\n{result.stdout[-10000:]}\\nstderr:\\n{result.stderr[-10000:]}"
        )
    file_path = (root / test_path).resolve(strict=True)
    signal = next((item for item in audit_context.signals(root) if item.get("id") == signal_id), None)
    if not signal:
        raise AssertionError("Native signal was lost")
    entries = [item for item in signal.get("evidence", [])
        if isinstance(item, dict) and item.get("kind") == "inspected-native-test-execution"
        and item.get("test_file") == test_path and item.get("test_name") == test_name]
    if len(entries) != 1:
        raise AssertionError(f"Expected one exact attached test record; got {len(entries)}")
    evidence = entries[0]
    if evidence.get("status") != status or evidence.get("security_finding_confirmed") is not False:
        raise AssertionError(f"Test evidence has unsafe status: {evidence}")
    if evidence.get("human_disposition_changed") is not False:
        raise AssertionError("Test execution changed human disposition")
    if evidence.get("test_sha256") != hashlib.sha256(file_path.read_bytes()).hexdigest():
        raise AssertionError("Evidence is not bound to the inspected test bytes")
    expected_match = "^" + test_name + r"(?:\(\))?$"
    if evidence.get("forge_argv", [])[-1:] != [expected_match]:
        raise AssertionError("Forge command was not constrained to the exact test function signature")
    output = result.stdout + result.stderr + str(evidence.get("stdout_tail") or "") + str(evidence.get("stderr_tail") or "")
    return output, evidence


def main() -> int:
    forge = shutil.which("forge")
    lk = shutil.which("lk") or str(Path.home() / ".foundry" / "bin" / "lk")
    if not forge:
        raise AssertionError("forge is unavailable")
    if not Path(lk).is_file() and not shutil.which(lk):
        raise AssertionError("installed lk executable is unavailable")
    runtime_root = Path.home() / ".lowkey"
    if not (runtime_root / "audit_context.py").is_file():
        raise AssertionError(f"Lowkey runtime missing: {runtime_root}")
    sys.path.insert(0, str(runtime_root))
    import audit_context

    with tempfile.TemporaryDirectory(prefix="lowkey-plan-first-e2e-") as temp:
        root = Path(temp).resolve()
        (root / "src").mkdir()
        (root / "test").mkdir()
        write(root, "foundry.toml", """[profile.default]
src = "src"
test = "test"
out = "out"
libs = ["lib"]
solc_version = "0.8.20"
""")
        write(root, "src/Vault.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    uint256 public balance;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { _; }
    function setBalance(uint256 nextValue) external onlyOwner { balance = nextValue; }
}
""")
        write(root, "test/VaultAccess.t.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";
contract VaultAccessTest is Test {
    Vault internal vault;
    function setUp() public { vault = new Vault(); }
    function test_nonOwnerCannotSetBalance() public {
        vm.expectRevert();
        vm.prank(address(0xBEEF));
        vault.setBalance(99);
    }
}
""")
        write(root, "src/RoleVault.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RoleVault {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) private roleMembers;
    uint256 public limit;
    constructor() { roleMembers[OPERATOR_ROLE][msg.sender] = true; }
    modifier onlyRole(bytes32 role) { require(roleMembers[role][msg.sender], "missing role"); _; }
    function setLimit(uint256 nextValue) external onlyRole(OPERATOR_ROLE) { limit = nextValue; }
}
""")
        write(root, "test/RoleVault.t.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {RoleVault} from "../src/RoleVault.sol";
contract RoleVaultTest is Test {
    function test_nonRoleHolderCannotSetLimit() public {
        RoleVault target = new RoleVault();
        vm.expectRevert();
        vm.prank(address(0xBEEF));
        target.setLimit(100);
        assertEq(target.limit(), 0);
    }
}
""")
        write(root, "src/ReentrantVault.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract ReentrantVault {
    mapping(address => uint256) public credits;
    function deposit() external payable { credits[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amount = credits[msg.sender];
        require(amount > 0, "no credit");
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "transfer failed");
        credits[msg.sender] = 0;
    }
}
""")
        write(root, "test/ReentrantVault.t.sol", """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {Test} from "forge-std/Test.sol";
import {ReentrantVault} from "../src/ReentrantVault.sol";
contract ReenteringAttacker {
    ReentrantVault immutable vault;
    uint256 public receipts;
    constructor(ReentrantVault target) { vault = target; }
    function depositAndWithdraw() external payable {
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }
    receive() external payable {
        receipts += 1;
        if (receipts == 1) vault.withdraw();
    }
}
contract ReentrantVaultTest is Test {
    function test_reentrancyCannotPayMoreThanCredited() public {
        ReentrantVault vault = new ReentrantVault();
        ReenteringAttacker attacker = new ReenteringAttacker(vault);
        vm.deal(address(this), 1 ether);
        vault.deposit{value: 1 ether}();
        attacker.depositAndWithdraw{value: 1 ether}();
        assertEq(address(attacker).balance, 1 ether, "credit paid more than once");
    }
}
""")

        run(["git", "init", "-q"], root)
        run(["git", "config", "user.email", "lowkey-ci@example.invalid"], root)
        run(["git", "config", "user.name", "Lowkey CI"], root)
        run(["forge", "install", "foundry-rs/forge-std", "--no-commit"], root)
        run([forge, "build"], root)

        broken = add_signal(audit_context, root, "src/Vault.sol", "setBalance(uint256)", "Broken onlyOwner")
        if "setBalance" not in plan(lk, root, broken):
            raise AssertionError("Source-only plan was not anchored to setBalance")
        output, evidence = inspected_test(lk, root, audit_context, broken,
            "test/VaultAccess.t.sol", "test_nonOwnerCannotSetBalance", 1)
        if "did not revert" not in output.lower():
            raise AssertionError(f"Expected broken onlyOwner test assertion: {output}")
        print(f"PASS: broken onlyOwner produced unconfirmed evidence {evidence['id']}")

        role = add_signal(audit_context, root, "src/RoleVault.sol", "setLimit(uint256)", "Role policy")
        plan(lk, root, role)
        _output, role_evidence = inspected_test(lk, root, audit_context, role,
            "test/RoleVault.t.sol", "test_nonRoleHolderCannotSetLimit", 0)
        print(f"PASS: real onlyRole outsider test passed; evidence {role_evidence['id']}")

        reentry = add_signal(audit_context, root, "src/ReentrantVault.sol", "withdraw()", "ETH reentrancy", "reentrancy-eth")
        plan(lk, root, reentry)
        output, reentry_evidence = inspected_test(lk, root, audit_context, reentry,
            "test/ReentrantVault.t.sol", "test_reentrancyCannotPayMoreThanCredited", 1)
        if "credit paid more than once" not in output.lower():
            raise AssertionError(f"Expected reentrancy overpayment assertion: {output}")
        print(f"PASS: reentrancy reproduced as an unconfirmed review lead; evidence {reentry_evidence['id']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
